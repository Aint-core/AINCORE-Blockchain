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
use std::collections::{BTreeSet, HashMap, VecDeque};
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
            queue.extend(next);
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
