//! B69: what loading a transaction's modules costs.
//!
//! The VM loads a module with its dependencies and friends, transitively,
//! and verifies each one it has not loaded yet; none of that was metered,
//! so one cheap call into the top of a large closure made every validator
//! verify it again in every block (each block runs on a fresh VM). A
//! transaction now pays for the closure it loads, whether or not the VM has
//! it cached (the cache is not deterministic across nodes, the closure is),
//! and a closure past Aptos's limits is refused before the VM loads it.
//! Aptos's schedule (read 2026-10-04): `dependency_per_module` 744,600 and
//! `dependency_per_byte` 420 internal units against 5,880 for an `add`;
//! `max_num_dependencies` 768, `max_total_dependency_size` 1.8 MB.

use move_binary_format::access::ModuleAccess;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::{ModuleId, TypeTag};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;
use storage::StateDB;

/// The most modules one transaction may load.
pub const MAX_DEPENDENCIES: u64 = 768;
/// The most module bytes one transaction may load.
pub const MAX_DEPENDENCY_BYTES: u64 = 1024 * 1024 * 18 / 10;
/// Gas a module loaded: 744,600 / 5,880, rounded.
pub const GAS_PER_DEPENDENCY: u64 = 127;
/// Module bytes loaded per gas: 5,880 / 420.
pub const DEPENDENCY_BYTES_PER_GAS: u64 = 14;
/// B92: the longest chain of modules a load may recurse through (move's
/// suggested `max_dependency_depth`, 100). Enforced here, from storage: the
/// VM's own depth check counts only modules its block-wide cache does not
/// hold yet, so in a parallel batch it passed or failed by thread timing,
/// and nodes could disagree on a block.
pub const MAX_DEPENDENCY_DEPTH: u64 = 100;

/// The modules a transaction loads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Closure {
    pub modules: u64,
    pub bytes: u64,
}

impl Closure {
    /// What loading them costs.
    pub fn gas(&self) -> u64 {
        self.modules
            .saturating_mul(GAS_PER_DEPENDENCY)
            .saturating_add(self.bytes.div_ceil(DEPENDENCY_BYTES_PER_GAS))
    }
}

/// A module's size and the modules loading it pulls in.
type Parsed = (u64, Vec<ModuleId>);

/// Parsed modules, keyed by their bytes' hash: a publish changes the bytes,
/// so an entry is never stale, and what it returns does not depend on what
/// was asked before.
#[derive(Default)]
pub struct ModuleIndex {
    parsed: Mutex<HashMap<[u8; 32], Parsed>>,
}

/// The modules a module pulls in when the VM loads it: its dependencies
/// and its friends.
fn pulled_in(module: &CompiledModule) -> Vec<ModuleId> {
    let mut out = module.immediate_dependencies();
    out.extend(module.immediate_friends());
    out
}

/// B92: an upper bound on how deep the VM's loader recurses through these
/// modules (dependencies and friends): the longest path through their
/// strongly connected components, a component counted as all its modules
/// (friends make cycles, as `coin` and its friends do). From storage alone,
/// so every node computes the same bound whatever its module cache holds.
fn load_depth(edges: &BTreeMap<ModuleId, Vec<ModuleId>>) -> u64 {
    struct Tarjan<'a> {
        edges: &'a BTreeMap<ModuleId, Vec<ModuleId>>,
        index: BTreeMap<&'a ModuleId, usize>,
        low: BTreeMap<&'a ModuleId, usize>,
        stack: Vec<&'a ModuleId>,
        on_stack: BTreeSet<&'a ModuleId>,
        component: BTreeMap<&'a ModuleId, usize>,
        depth: Vec<u64>,
    }
    impl<'a> Tarjan<'a> {
        fn visit(&mut self, v: &'a ModuleId) {
            let i = self.index.len();
            self.index.insert(v, i);
            self.low.insert(v, i);
            self.stack.push(v);
            self.on_stack.insert(v);
            for w in self.edges.get(v).into_iter().flatten() {
                let Some((w, _)) = self.edges.get_key_value(w) else {
                    continue;
                };
                if !self.index.contains_key(w) {
                    self.visit(w);
                    let low = self.low[v].min(self.low[w]);
                    self.low.insert(v, low);
                } else if self.on_stack.contains(w) {
                    let low = self.low[v].min(self.index[w]);
                    self.low.insert(v, low);
                }
            }
            if self.low[v] == self.index[v] {
                let id = self.depth.len();
                let mut members = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on_stack.remove(w);
                    self.component.insert(w, id);
                    members.push(w);
                    if w == v {
                        break;
                    }
                }
                // Components reachable from this one were finished first.
                let below = members
                    .iter()
                    .flat_map(|m| self.edges.get(*m).into_iter().flatten())
                    .filter_map(|w| self.component.get(w))
                    .filter(|c| **c != id)
                    .map(|c| self.depth[*c])
                    .max()
                    .unwrap_or(0);
                self.depth.push(members.len() as u64 + below);
            }
        }
    }
    let mut t = Tarjan {
        edges,
        index: BTreeMap::new(),
        low: BTreeMap::new(),
        stack: Vec::new(),
        on_stack: BTreeSet::new(),
        component: BTreeMap::new(),
        depth: Vec::new(),
    };
    for v in edges.keys() {
        if !t.index.contains_key(v) {
            t.visit(v);
        }
    }
    t.depth.into_iter().max().unwrap_or(0)
}

/// The modules naming the struct types in `tag`.
pub fn type_modules(tag: &TypeTag, out: &mut Vec<ModuleId>) {
    match tag {
        TypeTag::Struct(s) => {
            out.push(ModuleId::new(s.address, s.module.clone()));
            for t in &s.type_params {
                type_modules(t, out);
            }
        }
        TypeTag::Vector(inner) => type_modules(inner, out),
        _ => {}
    }
}

/// The modules a bundle being published pulls in from the chain: its
/// modules' dependencies and friends that are not in the bundle.
pub fn bundle_roots(bundle: &[Vec<u8>]) -> Result<Vec<ModuleId>, String> {
    let modules = bundle
        .iter()
        .map(|bytes| {
            CompiledModule::deserialize(bytes).map_err(|e| format!("a module does not parse: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let own: BTreeSet<ModuleId> = modules.iter().map(|m| m.self_id()).collect();
    Ok(modules
        .iter()
        .flat_map(pulled_in)
        .filter(|id| !own.contains(id))
        .collect())
}

impl ModuleIndex {
    /// The modules `roots` load, transitively, from `db`. Past
    /// `MAX_DEPENDENCIES` or `MAX_DEPENDENCY_BYTES` it stops with an error,
    /// before the VM loads anything. A module the chain does not hold is
    /// skipped: the VM's own load fails on it.
    pub fn closure(
        &self,
        db: &StateDB,
        roots: impl IntoIterator<Item = ModuleId>,
    ) -> Result<Closure, String> {
        let mut seen = BTreeSet::new();
        let mut queue: VecDeque<ModuleId> = roots.into_iter().collect();
        let mut closure = Closure::default();
        let mut edges: BTreeMap<ModuleId, Vec<ModuleId>> = BTreeMap::new();
        while let Some(id) = queue.pop_front() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let key = vm_move::state_keys::module_key(id.address(), id.name().as_str());
            let Some(stored) = db
                .get(&key)
                .expect("CRITICAL: a module read for the dependency charge failed")
            else {
                continue;
            };
            let bytes = hex::decode(&stored).map_err(|_| format!("module {id} is not hex"))?;
            let (size, next) = self.parse(&bytes, &id)?;
            closure.modules += 1;
            closure.bytes = closure.bytes.saturating_add(size);
            if closure.modules > MAX_DEPENDENCIES || closure.bytes > MAX_DEPENDENCY_BYTES {
                return Err(format!(
                    "its modules exceed the dependency limits ({MAX_DEPENDENCIES} modules, \
                     {MAX_DEPENDENCY_BYTES} bytes)"
                ));
            }
            queue.extend(next.iter().cloned());
            edges.insert(id, next);
        }
        let depth = load_depth(&edges);
        if depth > MAX_DEPENDENCY_DEPTH {
            return Err(format!(
                "its modules exceed the dependency limits (a chain of {depth} modules, \
                 at most {MAX_DEPENDENCY_DEPTH})"
            ));
        }
        Ok(closure)
    }

    fn parse(&self, bytes: &[u8], id: &ModuleId) -> Result<Parsed, String> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if let Some(parsed) = self
            .parsed
            .lock()
            .ok()
            .and_then(|p| p.get(&digest).cloned())
        {
            return Ok(parsed);
        }
        let module = CompiledModule::deserialize(bytes)
            .map_err(|e| format!("module {id} does not parse: {e}"))?;
        let parsed = (bytes.len() as u64, pulled_in(&module));
        if let Ok(mut cache) = self.parsed.lock() {
            cache.insert(digest, parsed.clone());
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;

    fn id(name: &str) -> ModuleId {
        ModuleId::new(AccountAddress::ONE, Identifier::new(name).unwrap())
    }

    /// B93 witness: a cycle (friends make them) counts as all its modules,
    /// and a module's depth is its deepest branch: x -> {a, d}, a -> b ->
    /// c -> a, c -> d -> e: x, the 3-cycle, d, e = 6.
    #[test]
    fn a_cycle_counts_as_its_modules_and_the_deepest_branch_counts() {
        let edges: BTreeMap<ModuleId, Vec<ModuleId>> = [
            ("x", vec!["a", "d"]),
            ("a", vec!["b"]),
            ("b", vec!["c"]),
            ("c", vec!["a", "d"]),
            ("d", vec!["e"]),
            ("e", vec![]),
        ]
        .into_iter()
        .map(|(m, to)| (id(m), to.into_iter().map(id).collect()))
        .collect();
        assert_eq!(load_depth(&edges), 6);
    }
}
