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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
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

/// B316: the longest identifier a published module may hold: Aptos's
/// `IDENTIFIER_SIZE_MAX` (255 bytes; move allows 65,535). The VM clones and
/// hashes identifiers wherever it builds a type's tag, at a flat price.
pub const MAX_IDENTIFIER_BYTES: usize = 255;

/// The modules a bundle being published pulls in from the chain: its
/// modules' dependencies and friends that are not in the bundle, and (B170)
/// its own modules' stored versions: a republish's compatibility check loads
/// the version it replaces with that version's closure, which the publish
/// did not pay for. A new module is not stored, so the closure skips it.
pub fn bundle_roots(bundle: &[Vec<u8>]) -> Result<Vec<ModuleId>, String> {
    let modules = bundle
        .iter()
        .map(|bytes| {
            CompiledModule::deserialize(bytes).map_err(|e| format!("a module does not parse: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // B316: no identifier past `MAX_IDENTIFIER_BYTES`.
    if let Some(long) = modules
        .iter()
        .flat_map(|m| m.identifiers())
        .find(|i| i.as_str().len() > MAX_IDENTIFIER_BYTES)
    {
        return Err(format!(
            "an identifier of {} bytes (at most {MAX_IDENTIFIER_BYTES})",
            long.as_str().len()
        ));
    }
    let own: BTreeSet<ModuleId> = modules.iter().map(|m| m.self_id()).collect();
    Ok(modules
        .iter()
        .flat_map(pulled_in)
        .filter(|id| !own.contains(id))
        .chain(own.iter().cloned())
        .collect())
}

/// B343: the deepest a struct's values may nest (Aptos's
/// `max_value_nest_depth`).
pub const MAX_STRUCT_DEPTH: u64 = 128;

/// B343: the most a generic struct may add to the depth of a type it is
/// instantiated with. With `MAX_STRUCT_DEPTH` and the VM's own bound on a
/// type's depth at run time (move-vm `TYPE_DEPTH_MAX`, 256), no value nests
/// past 128 + 256 * 4 = 1,152 levels: move-vm copies, compares and drops a
/// value, and the meter sizes it, one stack frame or two a level.
pub const MAX_DEPTH_STEP: u64 = 4;

/// B458: the most nodes the type arguments of any struct instantiation laid
/// out below a struct may hold together, its own type arguments
/// `MAX_TYPE_ARGUMENT_NODES` together (B465: as every layout root's are,
/// `MAX_LAYOUT_WORK_NODES`). The loader builds a resource's type layout by
/// substituting each field with the resource's type arguments (move-vm
/// `struct_gidx_to_type_layout` -> `Loader::subst`), unmetered and
/// on first access (`data_cache.rs` `load_resource`, the `TODO(Gas)` line),
/// whether or not the resource exists, and clones and hashes each nested
/// instantiation's arguments for its cache. A field under a vector is
/// substituted whole without its result being measured (`subst`'s Vector arm
/// counts the pre-subst field), and `MAX_TYPE_TO_LAYOUT_NODES` (256) counts
/// layout nodes, not argument nodes, so nothing there bounds how large the
/// carried arguments grow level by level. B343's depth check misses it when
/// the threaded parameter reaches no value (a phantom slot, or a wrapper
/// whose only field is a `u64`): `Depth::substitute` carries no step for a
/// parameter the nested struct lays out nowhere. A struct's bound is affine
/// in its type arguments (`Carried`), resolved through the bundle and the
/// chain alongside the depth (`Depths`): all the positions of one nested
/// instantiation are summed (a parameter named once in each of two positions
/// counts twice), each scaled by what the nested struct carries from that
/// position, plus every constant node added on the way, so neither
/// multiplying nor additive growth along a chain escapes it. B465: the bound
/// is evaluated with the arguments together, the most-scaled parameter
/// taking all 128 (`Carried::together`); it gave each parameter 192 of its
/// own, so a struct of 6 parameters, each in a `Coin` of its own, carried
/// 1,152 and was refused. The stdlib's most is 128 (`coin::CoinStore`,
/// `dex::LiquidityPool`), as is a 6-coin basket; an 8-parameter weighted pool
/// with its LP coin (`Coin<LP<A0, .., W3>>`) is 129, as is a Liquidswap event
/// store's `EventHandle<E<X, Y, Curve>>`; one nested instantiation naming a
/// parameter the 4 times `MAX_TYPE_PARAMETERS` allows (`vector<Q<T, T, T,
/// T>>`) is 512, B422's widest accepted field (`Q<T, T, T, vector^57<T>>`)
/// 569. It bounds one instantiation's arguments (before it they grew 2^k for
/// k levels), not how many instantiations a layout holds nor what
/// substituting their fields builds: `MAX_LAYOUT_WORK_NODES` bounds those.
/// `Work` counts every instantiation's arguments, so it is at least `Carried`
/// term by term, but its cap is 9 times this one: this cap is kept.
pub const MAX_LAYOUT_ARGUMENT_NODES: u64 = 1024;

/// B458 (round 29b): the most type nodes laying out one struct may build, its
/// type arguments `MAX_TYPE_ARGUMENT_NODES` together (every root's are:
/// move-vm's instantiation checks leave a resource's and a native's at most
/// 127, an entry function's at most 128, and an entry function returns
/// nothing, `check_type_work`; B465: they were taken as 192, half again what
/// any root holds, and an ordinary 3x3x2 market was refused). For every
/// struct instantiation a layout lays out, the loader clones its arguments
/// for its cache's key (hashing them twice) and substitutes each of its
/// fields with them, all before any charge: ~256 instantiations
/// (`MAX_TYPE_TO_LAYOUT_NODES`) of up to 1,024 argument nodes each, with
/// their fields, were ~1M nodes for a first access priced 16 gas. `Work`
/// bounds the sum, through the bundle and the chain: an instantiation's
/// arguments, each field substituted, and what each field lays out (a
/// vector's element once, an instantiation inside an argument as if laid
/// out), summed over the fields. The cap is B422's accepted ratio, 576 type
/// nodes a gas (a generic `CopyLoc` of a 576-node local), times the cheapest
/// first access, 16 gas (`exists` of an absent resource: `load_base` 10,
/// `exists` 5, and its name, at least 34 bytes at 42 a gas, 1). The stdlib's
/// most is 390 (`dex::LiquidityPool`: its arguments, its fields and the two
/// `Coin`s, 3 * 128 + 6), `Coin<C>` 129, a Liquidswap event store of 8
/// `Q<X, Y, Curve, u64>` 2,208 (~3,300 with real `EventHandle<E<X, Y,
/// Curve>>`s), the terminal reach-4 wrapper `P<T>{f: vector<Q<T, T, T, T>>}`
/// 1,155, B422's widest field 1,268, a 3x3x2 market (`Market<C>` of 3
/// `Reserve<C>` of 3 `Pool<C>` of 2 `Coin<C>`) 7,856. Each struct in a root's
/// own type arguments can build its own bounded layout too. The VM meter
/// charges another `LAYOUT_GAS_PER_STRUCT` for each such occurrence on a
/// first resource access; natives pay for every struct in their type
/// arguments before running, even with an empty vector value. This pays
/// for the sum of the roots' work, not just one root. The upstream resource
/// loader still builds the layout before calling the meter, so this is an
/// accounting bound, not a preemptive per-node layout meter.
pub const MAX_LAYOUT_WORK_NODES: u64 = vm_move::LAYOUT_GAS_PER_STRUCT * 576;

/// B343: how deep the values of a type nest, from the depths of its type
/// parameters: `max(base, depth(T_i) + steps[i])` (`base` 0: none).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Depth {
    pub base: u64,
    pub steps: BTreeMap<u16, u64>,
}

impl Depth {
    fn constant(base: u64) -> Self {
        Self {
            base,
            steps: BTreeMap::new(),
        }
    }

    fn parameter(index: u16) -> Self {
        Self {
            base: 0,
            steps: BTreeMap::from([(index, 0)]),
        }
    }

    /// One level more: a vector, or a struct, around it.
    fn deeper(mut self) -> Self {
        if self.base > 0 {
            self.base = self.base.saturating_add(1);
        }
        for step in self.steps.values_mut() {
            *step = step.saturating_add(1);
        }
        self
    }

    fn max(mut self, other: Self) -> Self {
        self.base = self.base.max(other.base);
        for (index, step) in other.steps {
            let held = self.steps.entry(index).or_insert(step);
            *held = (*held).max(step);
        }
        self
    }

    /// The depth with each type parameter `i` given `args[i]`'s.
    fn substitute(&self, args: &[Depth]) -> Depth {
        let mut out = Depth::constant(self.base);
        for (&index, &step) in &self.steps {
            let Some(arg) = args.get(index as usize) else {
                continue;
            };
            out = out.max(Depth {
                base: if arg.base > 0 {
                    arg.base.saturating_add(step)
                } else {
                    0
                },
                steps: arg
                    .steps
                    .iter()
                    .map(|(&j, &s)| (j, s.saturating_add(step)))
                    .collect(),
            });
        }
        out
    }
}

/// B458: an affine bound on the type arguments a struct's layout carries:
/// every struct instantiation laid out below it, from its own fields and the
/// structs they instantiate, holds type arguments of at most
/// `nodes + sum(scale[i] * |T_i|)` nodes all together, `|T_i|` the nodes of
/// its type argument `i` (an absent index scales by 0). Round 29b: the same
/// form bounds the type nodes laying it out builds (`Work`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Carried {
    scale: BTreeMap<u16, u64>,
    nodes: u64,
}

/// B458 (round 29b): an affine bound on the type nodes laying out a struct
/// builds (`MAX_LAYOUT_WORK_NODES`), in its type arguments' nodes.
type Work = Carried;

impl Carried {
    /// A bound on both: the larger of each term (none is negative).
    fn max(mut self, other: Self) -> Self {
        self.nodes = self.nodes.max(other.nodes);
        for (index, scale) in other.scale {
            let held = self.scale.entry(index).or_insert(scale);
            *held = (*held).max(scale);
        }
        self
    }

    /// B458 (round 29b): both, each term summed (work done one after the
    /// other).
    fn plus(mut self, other: Self) -> Self {
        self.nodes = self.nodes.saturating_add(other.nodes);
        for (index, scale) in other.scale {
            let held = self.scale.entry(index).or_insert(0);
            *held = held.saturating_add(scale);
        }
        self
    }

    /// B458 (round 29b): `times` copies of a type of `nodes` nodes naming
    /// each type parameter `uses` times, its parameters substituted, added.
    fn add_type(&mut self, times: u64, nodes: u64, uses: &ParameterUses) {
        let named: u64 = uses.values().sum();
        let constant = nodes.saturating_sub(named);
        self.nodes = self.nodes.saturating_add(times.saturating_mul(constant));
        for (index, count) in uses {
            let held = self.scale.entry(*index).or_insert(0);
            *held = held.saturating_add(times.saturating_mul(*count));
        }
    }

    /// B458 (round 29b): the bound with the type arguments `argument` nodes
    /// all together: the most-scaled parameter takes them all
    /// (`sum(scale[i] * |T_i|) <= max(scale) * sum(|T_i|)`). B465: both
    /// bounds are evaluated so, at `MAX_TYPE_ARGUMENT_NODES`, what every
    /// layout root's arguments hold together (`MAX_LAYOUT_WORK_NODES`).
    fn together(&self, argument: u64) -> u64 {
        let most = self.scale.values().copied().max().unwrap_or(0);
        self.nodes.saturating_add(most.saturating_mul(argument))
    }
}

/// B343: a struct, by its module and name.
type StructKey = (ModuleId, String);

/// B343: the depth of every struct a publish's modules define, resolved
/// through the bundle and the chain (its modules first: a republish's own
/// definitions count).
struct Depths<'a> {
    db: &'a StateDB,
    /// The modules whose definitions `defs` holds.
    loaded: HashSet<ModuleId>,
    /// Each struct's module and the index of its definition there.
    defs: HashMap<StructKey, (std::rc::Rc<CompiledModule>, usize)>,
    known: HashMap<StructKey, Depth>,
    /// B458: what each struct's layout carries below it (`Carried`).
    carried: HashMap<StructKey, Carried>,
    /// B458 (round 29b): what laying out each struct builds (`Work`).
    layout_work: HashMap<StructKey, Work>,
}

impl Depths<'_> {
    fn index(&mut self, id: ModuleId, module: CompiledModule) {
        let module = std::rc::Rc::new(module);
        let own = module.self_id();
        for (index, def) in module.struct_defs().iter().enumerate() {
            let name = module.identifier_at(module.struct_handle_at(def.struct_handle).name);
            self.defs
                .insert((own.clone(), name.to_string()), (module.clone(), index));
        }
        self.loaded.insert(own);
        self.loaded.insert(id);
    }

    /// The module defining struct `key` and the index of its definition.
    fn definition(
        &mut self,
        key: &StructKey,
    ) -> Result<(std::rc::Rc<CompiledModule>, usize), String> {
        let (id, name) = key;
        if !self.loaded.contains(id) {
            let module_key = vm_move::state_keys::module_key(id.address(), id.name().as_str());
            let stored = self
                .db
                .get(&module_key)
                .expect("CRITICAL: a module read for the struct depth check failed")
                .ok_or_else(|| format!("module {id} is not on chain"))?;
            let bytes = hex::decode(&stored).map_err(|_| format!("module {id} is not hex"))?;
            let module = CompiledModule::deserialize(&bytes)
                .map_err(|e| format!("module {id} does not parse: {e}"))?;
            self.index(id.clone(), module);
        }
        self.defs
            .get(key)
            .cloned()
            .ok_or_else(|| format!("module {id} defines no struct {name}"))
    }

    /// Resolve the depth of struct `root` and of every struct it holds,
    /// each refused once it is past the bounds. B357: it walks the
    /// definitions from a stack of its own, the deepest resolved first. It
    /// recursed a frame per struct and per type level, and only on the
    /// way back did it learn a depth: a chain of 257 definitions, each
    /// holding the next inside 255 vectors, went ~65,000 frames deep, past
    /// any thread's stack, and every node re-executing the publish
    /// crashed.
    fn resolve(&mut self, root: &StructKey) -> Result<(), String> {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        enum Visit {
            Enter(StructKey),
            /// B375: a struct a field names, by its module's handle: named
            /// (two identifiers) only when it is walked.
            Named(std::rc::Rc<CompiledModule>, StructHandleIndex),
            Exit(StructKey),
        }
        let mut path = HashSet::new();
        let mut work = vec![Visit::Enter(root.clone())];
        while let Some(visit) = work.pop() {
            #[cfg(test)]
            tests::WALK_PEAK.with(|peak| peak.set(peak.get().max(work.len() + 1)));
            match visit {
                Visit::Named(module, handle) => {
                    work.push(Visit::Enter(struct_named(&module, handle)));
                }
                Visit::Enter(key) => {
                    if self.known.contains_key(&key) {
                        continue;
                    }
                    if !path.insert(key.clone()) {
                        return Err(format!("struct {}::{} contains itself", key.0, key.1));
                    }
                    let (module, index) = self.definition(&key)?;
                    let fields = declared(&module, index, &key)?;
                    // Below the structs its fields name: resolved after them.
                    // B375: each named once, by handle: every struct token of
                    // every struct on the path was held at once, each with
                    // its two names (~0.6 KB), several hundred MB for one
                    // publish.
                    let named: std::collections::BTreeSet<StructHandleIndex> = fields
                        .iter()
                        .flat_map(|field| field.signature.0.preorder_traversal())
                        .filter_map(|token| match token {
                            T::Struct(handle) | T::StructInstantiation(handle, _) => Some(*handle),
                            _ => None,
                        })
                        .collect();
                    work.push(Visit::Exit(key));
                    for handle in named {
                        work.push(Visit::Named(module.clone(), handle));
                    }
                }
                Visit::Exit(key) => {
                    let (module, index) = self.definition(&key)?;
                    let mut depth = Depth::default();
                    for field in declared(&module, index, &key)? {
                        depth = depth.max(self.of_token(&module, &field.signature.0)?);
                    }
                    let depth = depth.deeper();
                    let (id, name) = &key;
                    if depth.base > MAX_STRUCT_DEPTH {
                        return Err(format!(
                            "struct {id}::{name} nests {} deep (at most {MAX_STRUCT_DEPTH})",
                            depth.base
                        ));
                    }
                    if let Some(step) = depth.steps.values().find(|step| **step > MAX_DEPTH_STEP) {
                        return Err(format!(
                            "struct {id}::{name} adds {step} to a type argument's depth (at most \
                             {MAX_DEPTH_STEP})"
                        ));
                    }
                    // B458: what its layout carries, each field's merged in.
                    let mut carried = Carried::default();
                    for field in declared(&module, index, &key)? {
                        let (below, _, _) = self.carried_of_token(&module, &field.signature.0)?;
                        carried = carried.max(below);
                    }
                    // B465: its arguments together, as every root's are: each
                    // parameter given 192 of its own refused a 6-coin basket.
                    let most = carried.together(MAX_TYPE_ARGUMENT_NODES);
                    #[cfg(test)]
                    tests::LAYOUT_PEAK.with(|peak| peak.set(peak.get().max(most)));
                    if most > MAX_LAYOUT_ARGUMENT_NODES {
                        return Err(format!(
                            "struct {id}::{name}'s layout carries type arguments of {most} \
                             nodes (at most {MAX_LAYOUT_ARGUMENT_NODES})"
                        ));
                    }
                    // B458 (round 29b): what laying it out builds: its type
                    // arguments (cloned for the loader's cache), and each
                    // field substituted and what it lays out, summed.
                    let arity = module
                        .struct_handle_at(module.struct_defs()[index].struct_handle)
                        .type_parameters
                        .len();
                    let mut built = Work {
                        scale: (0..arity as u16).map(|i| (i, 1)).collect(),
                        nodes: 0,
                    };
                    for field in declared(&module, index, &key)? {
                        let (mut laid, uses, nodes) =
                            self.work_of_token(&module, &field.signature.0)?;
                        laid.add_type(1, nodes, &uses);
                        built = built.plus(laid);
                    }
                    let cost = built.together(MAX_TYPE_ARGUMENT_NODES);
                    #[cfg(test)]
                    tests::WORK_PEAK.with(|peak| peak.set(peak.get().max(cost)));
                    if cost > MAX_LAYOUT_WORK_NODES {
                        return Err(format!(
                            "struct {id}::{name}'s layout builds {cost} type nodes (at most \
                             {MAX_LAYOUT_WORK_NODES})"
                        ));
                    }
                    path.remove(&key);
                    self.known.insert(key.clone(), depth);
                    self.carried.insert(key.clone(), carried);
                    self.layout_work.insert(key, built);
                }
            }
        }
        Ok(())
    }

    /// The depth of a type `module` names, every struct in it resolved
    /// (the deserializer bounds a type's nesting at 256, so this recursion
    /// is bounded).
    fn of_token(
        &self,
        module: &CompiledModule,
        token: &move_binary_format::file_format::SignatureToken,
    ) -> Result<Depth, String> {
        use move_binary_format::file_format::SignatureToken as T;
        let resolved = |handle| {
            let key = struct_named(module, handle);
            self.known
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("struct {}::{} is not resolved", key.0, key.1))
        };
        Ok(match token {
            T::Bool | T::U8 | T::U16 | T::U32 | T::U64 | T::U128 | T::U256 | T::Address => {
                Depth::constant(1)
            }
            T::Signer => Depth::constant(2),
            T::Vector(inner) | T::Reference(inner) | T::MutableReference(inner) => {
                self.of_token(module, inner)?.deeper()
            }
            T::TypeParameter(index) => Depth::parameter(*index),
            T::Struct(handle) => resolved(*handle)?,
            T::StructInstantiation(handle, args) => {
                let generic = resolved(*handle)?;
                let args = args
                    .iter()
                    .map(|arg| self.of_token(module, arg))
                    .collect::<Result<Vec<_>, _>>()?;
                generic.substitute(&args)
            }
        })
    }

    /// B458: what laying out a type `module` names carries below it, in the
    /// current struct's type arguments (`Carried`), with the type's nodes and
    /// the times it names each type parameter (as `type_work` counts them).
    /// A nested struct instantiation carries its type arguments, all its
    /// positions together (a position's constant nodes, and a parameter's
    /// argument once each time it is named), and, laid out, what that struct
    /// carries from them in turn: each position scaled by that struct's own
    /// scale for it (at least once: its own arguments), plus its constant.
    /// An instantiation inside an argument counts as if laid out. A
    /// non-generic struct carries nothing of these arguments (what it carries
    /// is its own bound, checked when it was resolved). Every referenced
    /// struct is resolved before this one, as for the depth; the deserializer
    /// bounds a type's nesting at 256, so this recursion is bounded.
    fn carried_of_token(
        &self,
        module: &CompiledModule,
        token: &move_binary_format::file_format::SignatureToken,
    ) -> Result<(Carried, ParameterUses, u64), String> {
        use move_binary_format::file_format::SignatureToken as T;
        Ok(match token {
            T::Vector(inner) | T::Reference(inner) | T::MutableReference(inner) => {
                let (carried, uses, nodes) = self.carried_of_token(module, inner)?;
                (carried, uses, nodes.saturating_add(1))
            }
            T::TypeParameter(index) => (Carried::default(), ParameterUses::from([(*index, 1)]), 1),
            T::StructInstantiation(handle, args) => {
                let key = struct_named(module, *handle);
                let child = self
                    .carried
                    .get(&key)
                    .ok_or_else(|| format!("struct {}::{} layout is not resolved", key.0, key.1))?;
                // Its own arguments and what the child carries from them.
                let mut direct = Carried {
                    scale: BTreeMap::new(),
                    nodes: child.nodes,
                };
                let mut carried = Carried::default();
                let (mut uses, mut nodes) = (ParameterUses::new(), 1u64);
                for (position, arg) in args.iter().enumerate() {
                    let (inner, named, size) = self.carried_of_token(module, arg)?;
                    carried = carried.max(inner);
                    // At least once (a scale held is at least 1).
                    let factor = child.scale.get(&(position as u16)).copied().unwrap_or(1);
                    let constant = size.saturating_sub(named.values().sum());
                    direct.nodes = direct.nodes.saturating_add(factor.saturating_mul(constant));
                    for (p, count) in &named {
                        let held = direct.scale.entry(*p).or_insert(0);
                        *held = held.saturating_add(factor.saturating_mul(*count));
                    }
                    add_uses(&mut uses, &named);
                    nodes = nodes.saturating_add(size);
                }
                (carried.max(direct), uses, nodes)
            }
            _ => (Carried::default(), ParameterUses::new(), 1),
        })
    }

    /// B458 (round 29b): what laying out the structs a type `module` names
    /// builds, in the current struct's type arguments (`Work`), with the
    /// type's nodes and the times it names each type parameter. Every struct
    /// it names counts once (a vector lays out its element once), one inside
    /// an argument too, as if laid out (the loader lays it out wherever the
    /// struct given the argument lays that parameter out). Every referenced
    /// struct is resolved before this one; the deserializer bounds a type's
    /// nesting at 256, so this recursion is bounded.
    fn work_of_token(
        &self,
        module: &CompiledModule,
        token: &move_binary_format::file_format::SignatureToken,
    ) -> Result<(Work, ParameterUses, u64), String> {
        use move_binary_format::file_format::SignatureToken as T;
        match token {
            T::Vector(inner) | T::Reference(inner) | T::MutableReference(inner) => {
                let (work, uses, nodes) = self.work_of_token(module, inner)?;
                Ok((work, uses, nodes.saturating_add(1)))
            }
            T::TypeParameter(index) => Ok((Work::default(), BTreeMap::from([(*index, 1)]), 1)),
            T::Struct(handle) => self.work_of_instance(module, *handle, &[]),
            T::StructInstantiation(handle, args) => self.work_of_instance(module, *handle, args),
            _ => Ok((Work::default(), ParameterUses::new(), 1)),
        }
    }

    /// B458 (round 29b): `work_of_token` for the struct `handle` names in
    /// `module`, given the type arguments `args`: its own work, each
    /// argument's size substituted for its parameter, and what each argument
    /// names.
    fn work_of_instance(
        &self,
        module: &CompiledModule,
        handle: move_binary_format::file_format::StructHandleIndex,
        args: &[move_binary_format::file_format::SignatureToken],
    ) -> Result<(Work, ParameterUses, u64), String> {
        let key = struct_named(module, handle);
        let child = self
            .layout_work
            .get(&key)
            .ok_or_else(|| format!("struct {}::{} layout work is not resolved", key.0, key.1))?;
        let mut work = Work {
            scale: BTreeMap::new(),
            nodes: child.nodes,
        };
        let (mut uses, mut nodes) = (ParameterUses::new(), 1u64);
        for (position, arg) in args.iter().enumerate() {
            let (inner, named, size) = self.work_of_token(module, arg)?;
            work = work.plus(inner);
            // Every parameter of a resolved struct is scaled at least once
            // (its arguments are cloned): 0 only past its arity, which the
            // verifier refuses.
            let factor = child.scale.get(&(position as u16)).copied().unwrap_or(0);
            work.add_type(factor, size, &named);
            add_uses(&mut uses, &named);
            nodes = nodes.saturating_add(size);
        }
        Ok((work, uses, nodes))
    }
}

/// The fields of the struct defined at `index` of `module` (`key`).
fn declared<'m>(
    module: &'m CompiledModule,
    index: usize,
    (id, name): &StructKey,
) -> Result<&'m [move_binary_format::file_format::FieldDefinition], String> {
    match &module.struct_defs()[index].field_information {
        move_binary_format::file_format::StructFieldInformation::Declared(fields) => Ok(fields),
        move_binary_format::file_format::StructFieldInformation::Native => {
            Err(format!("struct {id}::{name} is native"))
        }
    }
}

/// The module and name of the struct `handle` names in `module`.
fn struct_named(
    module: &CompiledModule,
    handle: move_binary_format::file_format::StructHandleIndex,
) -> (ModuleId, String) {
    let handle = module.struct_handle_at(handle);
    let owner = module.module_handle_at(handle.module);
    (
        ModuleId::new(
            *module.address_identifier_at(owner.address),
            module.identifier_at(owner.name).to_owned(),
        ),
        module.identifier_at(handle.name).to_string(),
    )
}

/// B343: refuse a bundle defining a struct whose values nest past
/// `MAX_STRUCT_DEPTH`, or that adds more than `MAX_DEPTH_STEP` to a type
/// argument's depth. This move-vm bounds a value's depth only where it
/// builds a layout (storage, arguments): a chain of structs across modules
/// packed in memory nested ~20,000 deep for ~0.12M gas, and move-vm's copy,
/// comparison and drop, and the meter's size, recurse a frame or two a
/// level: the stack overflowed and aborted every node re-executing the
/// block. Call it once the bundle's closure is within the dependency limits
/// (`closure_in_block`). B422: then the bundle's types are within the type
/// work bounds (`check_type_work`). B458: and no struct's layout carries or
/// builds past its bounds (`MAX_LAYOUT_ARGUMENT_NODES`,
/// `MAX_LAYOUT_WORK_NODES`).
pub fn check_struct_depths(db: &StateDB, bundle: &[Vec<u8>]) -> Result<(), String> {
    let mut depths = Depths {
        db,
        loaded: HashSet::new(),
        defs: HashMap::new(),
        known: HashMap::new(),
        carried: HashMap::new(),
        layout_work: HashMap::new(),
    };
    let mut defined = Vec::new();
    let mut types = Ok(());
    for bytes in bundle {
        let module = CompiledModule::deserialize(bytes)
            .map_err(|e| format!("a module does not parse: {e}"))?;
        if types.is_ok() {
            types = check_type_work(&module);
        }
        let id = module.self_id();
        for def in module.struct_defs() {
            let name = module.identifier_at(module.struct_handle_at(def.struct_handle).name);
            defined.push((id.clone(), name.to_string()));
        }
        depths.index(id, module);
    }
    for key in defined {
        depths.resolve(&key)?;
    }
    types
}

/// B422: the most nodes one type a published module names may hold (a
/// vector, a reference, a struct, a type parameter and a primitive are a
/// node each). The runtime type checks (B211) clone, walk or compare such a
/// type at an instruction priced a gas or two (`CopyLoc`, `Pop`, `StLoc`,
/// `Eq`, a field or vector access); the verifier allowed 256 weighted
/// nodes. The stdlib's largest is 4. A struct or function instantiation is
/// held to it as a whole (all its type arguments together).
pub const MAX_TYPE_NODES: u64 = 64;

/// B422: the most nodes a frame's type arguments hold together: move-vm
/// refuses an entry function's past 128 (`load_function`) and a generic
/// call's past 127 with the caller's (`instantiate_generic_function`),
/// `MAX_TYPE_INSTANTIATION_NODES` (B212). Every bound below that counts a
/// type parameter's uses substitutes each with at most this. B465: the
/// layout bounds take a root's type arguments as this many nodes together
/// (`MAX_LAYOUT_WORK_NODES`).
pub const MAX_TYPE_ARGUMENT_NODES: u64 = 128;

/// B422: the most times one type a published module names may name any one
/// of its type parameters. Each use is substituted at run time, and the
/// frame's type arguments share `MAX_TYPE_ARGUMENT_NODES`, so a type of a
/// generic function is at most 64 + 4 * 128 = 576 nodes once instantiated
/// (it was up to 128 * 128). Distinct parameters share the 128
/// (`Pool<A, B, C, D, E>` is at most 64 + 128 nodes), so the most-named
/// parameter's uses bound the work, not all the uses (B422 counted all of
/// them, and refused `Pool<A, B, C, D, E>` for the work of one). The
/// stdlib's most is 1.
pub const MAX_TYPE_PARAMETERS: u64 = 4;

/// B422 (round 28): the most times a struct or field instantiation (the
/// type arguments of `PackGeneric`, `UnpackGeneric`, a generic field
/// borrow, `MoveFrom`, `BorrowGlobal`, `Exists`) may name any one type
/// parameter, all its arguments together. With `MAX_TYPE_NODES` its
/// arguments are at most `MAX_INSTANTIATED_ARGUMENT_NODES` once
/// instantiated, which a struct's fields multiply (`MAX_STRUCT_FIELD_NODES`).
/// Was up to 32 arguments of 4 uses each, 32 * 576 = 18,432 nodes, before
/// a field was instantiated. A function instantiation is held to
/// `MAX_TYPE_PARAMETERS` instead: move-vm refuses a callee's type arguments
/// past 127 nodes once instantiated, so its work is at most 576 nodes once.
/// `Pair<T, T>` cannot be packed in generic code; `Pair<T, U>` can. The
/// stdlib's most is 1.
pub const MAX_INSTANTIATION_REACH: u64 = 1;

/// B422 (round 28): the most nodes a struct or field instantiation's type
/// arguments hold together once instantiated: 64 + 1 * 128.
pub const MAX_INSTANTIATED_ARGUMENT_NODES: u64 =
    MAX_TYPE_NODES + MAX_INSTANTIATION_REACH * MAX_TYPE_ARGUMENT_NODES;

/// B422 (round 28): the most nodes a struct's fields may expand to once
/// instantiated: their nodes, plus the uses of the type parameter they name
/// most times each `MAX_INSTANTIATED_ARGUMENT_NODES` (its arguments share
/// those, so the most-named parameter's uses bound the work). move-vm
/// instantiates every field afresh on each `PackGeneric` and
/// `UnpackGeneric` (raw `Type::subst`, no node bound) and checks, walks and
/// clones each for 5 gas and a gas per 4 fields: B422 bounded a field, not
/// a struct, and 64 fields naming a parameter 4 times each, packed with an
/// argument of ~490 nodes, built ~125,000 nodes an instruction, ~3,000 a
/// gas. Now an `UnpackGeneric` builds at most 2 * (192 + 2,048) nodes and a
/// `PackGeneric` 2 * 192 + 2,048 (the arguments for the fields and for the
/// struct type, the fields, and the unpacked fields' copies on the stack):
/// an unpack and pack of 3 or 4 fields, 12 gas, at most 6,912, ~576 a gas,
/// what B422 already allows a generic `CopyLoc` (a 576-node local for a
/// gas); of one field (832 nodes at most) ~272, of 64 ~165. A generic field
/// borrow builds at most 2 * 192 + 832 (the struct type twice and the
/// field), with a `CopyLoc` and a `Pop` around it ~470 a gas. B422's ~307
/// would need a bound near 1,000, refusing the Liquidswap pool's event
/// store (8 handles naming `<X, Y, Curve>`: 1,576 here). The stdlib's
/// largest is 198 (`dex::LiquidityPool`).
pub const MAX_STRUCT_FIELD_NODES: u64 = 2048;

/// B422: the most type nodes a function's parameters and locals may hold
/// together. move-vm clones them all into every frame it makes (`Call`,
/// priced 10 gas and a gas a local): up to 255 locals of 256 nodes, 65,280
/// nodes for 13 gas (with `Ret` and the frame's drop), ~5,000 a gas, and
/// 1,024 nested frames held ~67M nodes (GBs) outside the memory quota.
/// Now at most 1,024 nodes for 14 gas or more (one local): 73 a gas, and
/// 1,024 frames hold at most ~1M nodes. The stdlib's largest is 43
/// (`delegation::settle_due`).
pub const MAX_FRAME_TYPE_NODES: u64 = 1024;

/// B422: the most times a function's parameters and locals may name any
/// one type parameter, all together. A generic call substitutes every use
/// in every local (move-vm `make_new_frame` substitutes each local on its
/// own, a duplicate signature too, so distinct signatures are no measure),
/// for the frame and again for the parameters' check: 255 locals of 127
/// uses each built ~4M nodes for one `CallGeneric` (15 gas). The type
/// arguments share `MAX_TYPE_ARGUMENT_NODES`, so the uses of the most-named
/// parameter bound it: at most 2 * (1,024 + 16 * 128) = 6,144 nodes for 20
/// gas or more (15 + a local + a type argument, `Ret` 1, the drop 2): 307 a
/// gas, the order of what B228 accepted for one instruction (a type of 256
/// nodes for a gas); 1,024 nested generic frames hold at most ~3M nodes.
/// B422 counted every use of every parameter: `swap<X, Y, Curve>` with six
/// `&mut Pool<X, Y, Curve>` temporaries named 18 and was refused, for the
/// work of 6. The stdlib's most is 6 (`dex::add_liquidity`).
pub const MAX_FRAME_TYPE_PARAMETERS: u64 = 16;

/// B422: how many times types name each type parameter (by index).
type ParameterUses = BTreeMap<u16, u64>;

/// B422: a type's nodes; the times it names each type parameter are added
/// to `uses`.
fn type_work(
    token: &move_binary_format::file_format::SignatureToken,
    uses: &mut ParameterUses,
) -> u64 {
    use move_binary_format::file_format::SignatureToken as T;
    let mut nodes = 0;
    for t in token.preorder_traversal() {
        nodes += 1;
        if let T::TypeParameter(index) = t {
            *uses.entry(*index).or_default() += 1;
        }
    }
    nodes
}

/// B422: the most times any one type parameter is named.
fn reach(uses: &ParameterUses) -> u64 {
    uses.values().copied().max().unwrap_or(0)
}

/// B422: `more` added to `uses`.
fn add_uses(uses: &mut ParameterUses, more: &ParameterUses) {
    for (index, count) in more {
        *uses.entry(*index).or_default() += count;
    }
}

/// B422 (round 28): the most nodes a struct's `fields` expand to once
/// instantiated (`MAX_STRUCT_FIELD_NODES`).
fn struct_field_nodes(fields: &[move_binary_format::file_format::FieldDefinition]) -> u64 {
    let mut uses = ParameterUses::new();
    let nodes: u64 = fields
        .iter()
        .map(|field| type_work(&field.signature.0, &mut uses))
        .sum();
    nodes.saturating_add(reach(&uses).saturating_mul(MAX_INSTANTIATED_ARGUMENT_NODES))
}

/// B422: refuse a module naming a type past `MAX_TYPE_NODES` or
/// `MAX_TYPE_PARAMETERS` (in its signatures or its structs' fields), or
/// defining a function whose parameters and locals hold past
/// `MAX_FRAME_TYPE_NODES` or name a type parameter past
/// `MAX_FRAME_TYPE_PARAMETERS`. Round 28: or a struct whose fields expand
/// past `MAX_STRUCT_FIELD_NODES`, or an instantiation past `MAX_TYPE_NODES`
/// as a whole or `MAX_INSTANTIATION_REACH` (a function's,
/// `MAX_TYPE_PARAMETERS`). The runtime type checks (B211) build these types
/// on every call and instruction, and the meter cannot see them: the work a
/// gas is bounded here, at publish. B458 (round 29b): or an entry function
/// returning a value (Aptos refuses one too; the stdlib has none).
pub fn check_type_work(module: &CompiledModule) -> Result<(), String> {
    use move_binary_format::file_format::{SignatureIndex, SignatureToken, StructFieldInformation};
    let id = module.self_id();
    let one = |token: &SignatureToken, uses: &mut ParameterUses| -> Result<u64, String> {
        let mut own = ParameterUses::new();
        let nodes = type_work(token, &mut own);
        if nodes > MAX_TYPE_NODES {
            return Err(format!(
                "module {id} names a type of {nodes} nodes (at most {MAX_TYPE_NODES})"
            ));
        }
        let named = reach(&own);
        if named > MAX_TYPE_PARAMETERS {
            return Err(format!(
                "module {id} names a type naming a type parameter {named} times (at most \
                 {MAX_TYPE_PARAMETERS})"
            ));
        }
        add_uses(uses, &own);
        Ok(nodes)
    };
    // Each signature measured once: functions and instantiations may share
    // one. Its nodes, and the times it names each type parameter.
    let mut signatures = Vec::with_capacity(module.signatures().len());
    for signature in module.signatures() {
        let (mut nodes, mut uses) = (0u64, ParameterUses::new());
        for token in &signature.0 {
            nodes += one(token, &mut uses)?;
        }
        signatures.push((nodes, uses));
    }
    let signature = |index: SignatureIndex| signatures.get(index.0 as usize);
    let instantiation = |what: &str, index: SignatureIndex, most: u64| -> Result<(), String> {
        let Some((nodes, uses)) = signature(index) else {
            return Err(format!("module {id} names no signature {}", index.0));
        };
        if *nodes > MAX_TYPE_NODES {
            return Err(format!(
                "module {id} names a {what} instantiation of {nodes} nodes (at most \
                 {MAX_TYPE_NODES})"
            ));
        }
        let named = reach(uses);
        if named > most {
            return Err(format!(
                "module {id} names a {what} instantiation naming a type parameter {named} \
                 times (at most {most})"
            ));
        }
        Ok(())
    };
    for inst in module.struct_instantiations() {
        instantiation("struct", inst.type_parameters, MAX_INSTANTIATION_REACH)?;
    }
    for inst in module.field_instantiations() {
        instantiation("field", inst.type_parameters, MAX_INSTANTIATION_REACH)?;
    }
    for inst in module.function_instantiations() {
        instantiation("function", inst.type_parameters, MAX_TYPE_PARAMETERS)?;
    }
    for def in module.struct_defs() {
        if let StructFieldInformation::Declared(fields) = &def.field_information {
            for field in fields {
                one(&field.signature.0, &mut ParameterUses::new())?;
            }
            let expanded = struct_field_nodes(fields);
            if expanded > MAX_STRUCT_FIELD_NODES {
                let name = module.identifier_at(module.struct_handle_at(def.struct_handle).name);
                return Err(format!(
                    "struct {id}::{name}'s fields expand to {expanded} type nodes (at most \
                     {MAX_STRUCT_FIELD_NODES})"
                ));
            }
        }
    }
    for def in module.function_defs() {
        let handle = module.function_handle_at(def.function);
        let name = module.identifier_at(handle.name);
        // B458 (round 29b): move-vm lays an entry function's return values
        // out with the transaction's type arguments substituted
        // (`serialize_return_values`), and a return type may name each 4
        // times: a root whose arguments hold past the 128 nodes together
        // the layout bounds assume (`MAX_LAYOUT_WORK_NODES`).
        if def.is_entry && !module.signature_at(handle.return_).is_empty() {
            return Err(format!(
                "entry function {id}::{name} returns a value (an entry function returns nothing)"
            ));
        }
        let Some(code) = &def.code else {
            continue;
        };
        let params = signature(handle.parameters);
        let (Some(params), Some(locals)) = (params, signature(code.locals)) else {
            return Err(format!("function {id}::{name} names no signature"));
        };
        let nodes = params.0 + locals.0;
        if nodes > MAX_FRAME_TYPE_NODES {
            return Err(format!(
                "function {id}::{name}'s parameters and locals hold {nodes} type nodes (at \
                 most {MAX_FRAME_TYPE_NODES})"
            ));
        }
        let mut uses = params.1.clone();
        add_uses(&mut uses, &locals.1);
        let named = reach(&uses);
        if named > MAX_FRAME_TYPE_PARAMETERS {
            return Err(format!(
                "function {id}::{name}'s parameters and locals name a type parameter {named} \
                 times (at most {MAX_FRAME_TYPE_PARAMETERS})"
            ));
        }
    }
    Ok(())
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
        self.closure_in_block(db, roots, &HashSet::new())
    }

    /// `closure`, refusing (B170) a module republished earlier in the block
    /// (`upgraded`, its module keys): it runs from the next block. The
    /// block's VM still holds the code it replaced, and flushing that cache
    /// mid-block made every later transaction load and verify the stdlib
    /// again, uncharged, once per upgrade.
    pub fn closure_in_block(
        &self,
        db: &StateDB,
        roots: impl IntoIterator<Item = ModuleId>,
        upgraded: &HashSet<String>,
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
            if upgraded.contains(&key) {
                return Err(format!(
                    "module {id} was upgraded in this block: it runs from the next one"
                ));
            }
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
pub(crate) mod tests {
    use super::*;

    thread_local! {
        /// B375: the most entries the struct walk held at once.
        pub(crate) static WALK_PEAK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        /// B458: the largest layout bound a resolved struct had.
        pub(crate) static LAYOUT_PEAK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        /// B458 (round 29b): the most type nodes a resolved struct's layout
        /// builds.
        pub(crate) static WORK_PEAK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
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

    /// B343: a module (`deep`) of `levels` structs, each holding the next
    /// inside `wrap` vectors (the last a u64), and a generic `W<T>` holding
    /// `T` inside `vectors` vectors.
    pub(crate) fn deep_module(
        address: AccountAddress,
        levels: usize,
        vectors: usize,
        wrap: usize,
    ) -> Vec<u8> {
        use move_binary_format::file_format::{
            empty_module, AbilitySet, FieldDefinition, IdentifierIndex, ModuleHandleIndex,
            SignatureToken, StructDefinition, StructFieldInformation, StructHandle,
            StructHandleIndex, StructTypeParameter, TypeSignature,
        };
        let mut m = empty_module();
        m.address_identifiers = vec![address];
        m.identifiers = vec![Identifier::new("deep").unwrap()];
        let add = |m: &mut move_binary_format::CompiledModule,
                   name: String,
                   generic: bool,
                   field: SignatureToken| {
            let index = m.identifiers.len() as u16;
            m.identifiers.push(Identifier::new(name).unwrap());
            m.identifiers
                .push(Identifier::new(format!("f{index}")).unwrap());
            m.struct_handles.push(StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(index),
                abilities: AbilitySet::EMPTY,
                type_parameters: if generic {
                    vec![StructTypeParameter {
                        constraints: AbilitySet::EMPTY,
                        is_phantom: false,
                    }]
                } else {
                    vec![]
                },
            });
            m.struct_defs.push(StructDefinition {
                struct_handle: StructHandleIndex(m.struct_handles.len() as u16 - 1),
                field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                    name: IdentifierIndex(index + 1),
                    signature: TypeSignature(field),
                }]),
            });
        };
        // S0 holds S1, ... (top down: S0 is the deepest and checked first).
        for i in 0..levels {
            let mut field = if i + 1 == levels {
                SignatureToken::U64
            } else {
                SignatureToken::Struct(StructHandleIndex(i as u16 + 1))
            };
            if i + 1 < levels {
                for _ in 0..wrap {
                    field = SignatureToken::Vector(Box::new(field));
                }
            }
            add(&mut m, format!("S{i}"), false, field);
        }
        let mut field = SignatureToken::TypeParameter(0);
        for _ in 0..vectors {
            field = SignatureToken::Vector(Box::new(field));
        }
        add(&mut m, "W".to_string(), true, field);
        let mut bytes = vec![];
        m.serialize(&mut bytes).unwrap();
        bytes
    }

    fn depth_db(name: &str) -> StateDB {
        let path =
            storage::test_dir::process_dir().join(format!("b343_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        StateDB::open(path.to_str().unwrap()).unwrap()
    }

    /// B343 witness: a struct whose values nest past 128 levels is refused,
    /// and one at 128 is not (the last of the chain is 2 deep: itself and
    /// its u64); so is a generic struct adding more than 4 to its
    /// argument's depth. A chain
    /// packed in memory nested ~20,000 deep, and move-vm and the meter
    /// recurse a frame or two a level: the stack overflowed on every node.
    #[test]
    fn a_struct_nesting_too_deep_is_refused() {
        let db = depth_db("depth");
        let at = AccountAddress::from_hex_literal("0xdee").unwrap();
        assert_eq!(
            check_struct_depths(&db, &[deep_module(at, 127, 3, 0)]),
            Ok(())
        );
        let err = check_struct_depths(&db, &[deep_module(at, 128, 3, 0)]).unwrap_err();
        assert!(err.contains("::S0 nests 129 deep"), "{err}");
        let err = check_struct_depths(&db, &[deep_module(at, 1, 4, 0)]).unwrap_err();
        assert!(err.contains("adds 5"), "{err}");
        // A longer chain is refused at its first struct past the bound,
        // the deepest resolved first (S_i of 400 is 401 - i deep).
        let err = check_struct_depths(&db, &[deep_module(at, 400, 0, 0)]).unwrap_err();
        assert!(err.contains("::S272 nests 129 deep"), "{err}");
    }

    /// B357 witness: a chain of definitions is walked without recursing,
    /// on a thread with a node's 2 MiB stack. The check recursed a frame
    /// per struct and per type level before it learned a depth: 300
    /// structs, each holding the next inside 250 vectors, went ~65,000
    /// frames deep and the stack overflowed on every node executing the
    /// publish. It is refused at the deepest struct past the bound: the
    /// last holds a u64 (2), the one before it that inside 250 vectors.
    #[test]
    fn a_chain_of_definitions_is_walked_without_recursing() {
        let db = depth_db("chain");
        let at = AccountAddress::from_hex_literal("0xdee").unwrap();
        let module = deep_module(at, 300, 0, 250);
        let err = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || check_struct_depths(&db, &[module]))
            .unwrap()
            .join()
            .unwrap()
            .unwrap_err();
        assert!(err.contains("::S298 nests 253 deep"), "{err}");
    }

    /// B375 witness: the walk holds each struct a struct's fields name once,
    /// by its handle. It held every struct token of every struct on its path
    /// at once, each with its two names: a struct of 64 fields naming one
    /// struct held 64 entries.
    #[test]
    fn the_walk_holds_each_named_struct_once() {
        use move_binary_format::file_format::{
            empty_module, AbilitySet, FieldDefinition, IdentifierIndex, ModuleHandleIndex,
            SignatureToken, StructDefinition, StructFieldInformation, StructHandle,
            StructHandleIndex, TypeSignature,
        };
        let mut m = empty_module();
        m.address_identifiers = vec![AccountAddress::from_hex_literal("0xdee").unwrap()];
        m.identifiers = ["deep", "A", "B", "x"]
            .into_iter()
            .map(|name| Identifier::new(name).unwrap())
            .chain((0..64).map(|i| Identifier::new(format!("f{i}")).unwrap()))
            .collect();
        for name in [1, 2] {
            m.struct_handles.push(StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(name),
                abilities: AbilitySet::EMPTY,
                type_parameters: vec![],
            });
        }
        m.struct_defs.push(StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Declared(
                (0..64)
                    .map(|i| FieldDefinition {
                        name: IdentifierIndex(4 + i),
                        signature: TypeSignature(SignatureToken::Struct(StructHandleIndex(1))),
                    })
                    .collect(),
            ),
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: StructHandleIndex(1),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(3),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        let mut bytes = vec![];
        m.serialize(&mut bytes).unwrap();
        WALK_PEAK.with(|peak| peak.set(0));
        assert_eq!(check_struct_depths(&depth_db("peak"), &[bytes]), Ok(()));
        let peak = WALK_PEAK.with(|peak| peak.get());
        assert!(
            peak > 0 && peak <= 4,
            "the walk held {peak} entries at once"
        );
    }

    /// B357 witness: a struct holding itself (here inside a vector) is
    /// refused when the walk reaches it again, which would never end.
    #[test]
    fn a_struct_holding_itself_is_refused() {
        use move_binary_format::file_format::{
            empty_module, AbilitySet, FieldDefinition, IdentifierIndex, ModuleHandleIndex,
            SignatureToken, StructDefinition, StructFieldInformation, StructHandle,
            StructHandleIndex, TypeSignature,
        };
        let mut m = empty_module();
        m.address_identifiers = vec![AccountAddress::from_hex_literal("0xdee").unwrap()];
        m.identifiers = ["deep", "A", "f"]
            .into_iter()
            .map(|name| Identifier::new(name).unwrap())
            .collect();
        m.struct_handles.push(StructHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        let itself = SignatureToken::Struct(StructHandleIndex(0));
        m.struct_defs.push(StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::Vector(Box::new(itself))),
            }]),
        });
        let mut bytes = vec![];
        m.serialize(&mut bytes).unwrap();
        let err = check_struct_depths(&depth_db("itself"), &[bytes]).unwrap_err();
        assert!(err.contains("::A contains itself"), "{err}");
    }

    /// B343 witness: every stdlib struct is within the depth bounds (an
    /// upgrade republishes a module's structs, and they are checked then).
    /// B458: its largest layout bound, its type arguments 128 nodes together
    /// (B465), is 128 (`coin::CoinStore`'s `Coin<C>`, `dex::LiquidityPool`'s
    /// `Coin<X>` and `Coin<Y>`), within an eighth of the bound (B458 gave
    /// each parameter 192: 384). Round 29b: `dex::LiquidityPool` builds the
    /// most laid out: the arguments, its fields substituted (`Coin<X>` and
    /// `Coin<Y>` 1 + 128 together, a `u128` and a `u64`) and the two `Coin`s
    /// laid out (128 + 1 together), 3 * 128 + 6 = 390 (`coin::CoinStore`
    /// 386, `option::Option` 257, `coin::Coin` 129; at 192, 582), within a
    /// twentieth of the bound.
    #[test]
    fn the_stdlib_structs_are_within_the_depth_bounds() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vm_move/stdlib/bytecode");
        let bundle: Vec<Vec<u8>> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "mv"))
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        assert!(bundle.len() > 10, "vacuous: no stdlib");
        LAYOUT_PEAK.with(|peak| peak.set(0));
        WORK_PEAK.with(|peak| peak.set(0));
        assert_eq!(check_struct_depths(&depth_db("stdlib"), &bundle), Ok(()));
        let peak = LAYOUT_PEAK.with(|peak| peak.get());
        assert_eq!(
            peak, MAX_TYPE_ARGUMENT_NODES,
            "the stdlib's largest layout carries {peak} argument nodes"
        );
        assert!(peak <= MAX_LAYOUT_ARGUMENT_NODES / 8);
        let built = WORK_PEAK.with(|peak| peak.get());
        assert_eq!(
            built,
            3 * MAX_TYPE_ARGUMENT_NODES + 6,
            "the stdlib's largest layout builds {built} type nodes"
        );
        assert!(built <= MAX_LAYOUT_WORK_NODES / 20);
    }

    /// B422: `inner` inside `levels` vectors.
    pub(crate) fn vectors(
        levels: usize,
        inner: move_binary_format::file_format::SignatureToken,
    ) -> move_binary_format::file_format::SignatureToken {
        (0..levels).fold(inner, |token, _| {
            move_binary_format::file_format::SignatureToken::Vector(Box::new(token))
        })
    }

    /// B422: a module (`frame`) with a struct `P` of `arity` type
    /// parameters (`StructHandleIndex(0)`) and a function `f` of `generics`
    /// type parameters whose locals are `locals`.
    pub(crate) fn frame_module(
        address: AccountAddress,
        locals: Vec<move_binary_format::file_format::SignatureToken>,
        generics: usize,
        arity: usize,
    ) -> Vec<u8> {
        use move_binary_format::file_format::{
            empty_module, AbilitySet, Bytecode, CodeUnit, FieldDefinition, FunctionDefinition,
            FunctionHandle, FunctionHandleIndex, IdentifierIndex, ModuleHandleIndex, Signature,
            SignatureIndex, SignatureToken, StructDefinition, StructFieldInformation, StructHandle,
            StructHandleIndex, StructTypeParameter, TypeSignature, Visibility,
        };
        let mut m = empty_module();
        m.address_identifiers = vec![address];
        m.identifiers = ["frame", "P", "f", "x"]
            .into_iter()
            .map(|name| Identifier::new(name).unwrap())
            .collect();
        m.struct_handles.push(StructHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: (0..arity)
                .map(|_| StructTypeParameter {
                    constraints: AbilitySet::EMPTY,
                    is_phantom: false,
                })
                .collect(),
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(3),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        m.signatures.push(Signature(locals));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![AbilitySet::EMPTY; generics],
        });
        m.function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(1),
                code: vec![Bytecode::Ret],
            }),
        });
        let mut bytes = vec![];
        m.serialize(&mut bytes).unwrap();
        bytes
    }

    fn type_work_of(bytes: &[u8]) -> Result<(), String> {
        check_type_work(&CompiledModule::deserialize(bytes).unwrap())
    }

    /// B422 witness: a type past 64 nodes is refused, one of 64 is not. The
    /// finding's callee (180 locals of `vector^255<u8>`, each cloned into
    /// every frame for a flat 10 gas) is refused at publish.
    #[test]
    fn a_type_past_the_node_bound_is_refused() {
        use move_binary_format::file_format::SignatureToken as T;
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let module = |locals| frame_module(at, locals, 0, 0);
        assert_eq!(type_work_of(&module(vec![vectors(63, T::U8)])), Ok(()));
        let err = type_work_of(&module(vec![vectors(64, T::U8)])).unwrap_err();
        assert!(err.contains("a type of 65 nodes"), "{err}");
        let callee = module(vec![vectors(255, T::U8); 180]);
        let err = type_work_of(&callee).unwrap_err();
        assert!(err.contains("a type of 256 nodes"), "{err}");
    }

    /// B422 witness: a function whose parameters and locals hold past 1,024
    /// type nodes is refused, through the publish check, though each of its
    /// types is within the bound; one of 1,024 is not.
    #[test]
    fn a_frame_past_the_node_bound_is_refused() {
        use move_binary_format::file_format::SignatureToken as T;
        let db = depth_db("frame_nodes");
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let module = |count| frame_module(at, vec![vectors(63, T::U8); count], 0, 0);
        assert_eq!(check_struct_depths(&db, &[module(16)]), Ok(()));
        let err = check_struct_depths(&db, &[module(17)]).unwrap_err();
        assert!(
            err.contains("::f's parameters and locals hold 1088 type nodes"),
            "{err}"
        );
    }

    /// B422 witness: a generic function whose locals name its type
    /// parameter more than 16 times is refused (each is substituted with up
    /// to 128 nodes on every call); 16 times is not.
    #[test]
    fn a_frame_naming_too_many_type_parameters_is_refused() {
        use move_binary_format::file_format::SignatureToken as T;
        let db = depth_db("frame_params");
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let module = |count| frame_module(at, vec![T::TypeParameter(0); count], 1, 0);
        assert_eq!(check_struct_depths(&db, &[module(16)]), Ok(()));
        let err = check_struct_depths(&db, &[module(17)]).unwrap_err();
        assert!(err.contains("name a type parameter 17 times"), "{err}");
    }

    /// B422 witness: one type naming a type parameter more than 4 times is
    /// refused; 4 times is not.
    #[test]
    fn a_type_naming_too_many_type_parameters_is_refused() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let module = |named: usize| {
            let mut args = vec![T::TypeParameter(0); named];
            args.resize(5, T::U64);
            let local = T::StructInstantiation(StructHandleIndex(0), args);
            frame_module(at, vec![local], 1, 5)
        };
        assert_eq!(type_work_of(&module(4)), Ok(()));
        let err = type_work_of(&module(5)).unwrap_err();
        assert!(err.contains("naming a type parameter 5 times"), "{err}");
    }

    /// B422 witness (round 28): a frame is bounded by the uses of the type
    /// parameter it names most, not by all uses: the frame's type arguments
    /// share 128 nodes. `swap<X, Y, Curve>` with ten `&mut Pool<X, Y,
    /// Curve>` temporaries names 30 uses and 10 of each, and is accepted
    /// (B422 refused it past 16 uses); seventeen are refused.
    #[test]
    fn a_frame_is_bounded_by_its_most_named_type_parameter() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let db = depth_db("frame_reach");
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let p = T::TypeParameter;
        let pool = T::StructInstantiation(StructHandleIndex(0), vec![p(0), p(1), p(2)]);
        let pool = T::MutableReference(Box::new(pool));
        let module = |count| frame_module(at, vec![pool.clone(); count], 3, 3);
        assert_eq!(check_struct_depths(&db, &[module(10)]), Ok(()));
        assert_eq!(check_struct_depths(&db, &[module(16)]), Ok(()));
        let err = check_struct_depths(&db, &[module(17)]).unwrap_err();
        assert!(err.contains("name a type parameter 17 times"), "{err}");
    }

    /// B422 (round 28): a module (`fields`) with a struct `P` of `arity`
    /// type parameters holding `fields` (`StructHandleIndex(0)`), a struct
    /// `Q` of 4 holding a u64 (`StructHandleIndex(1)`), the instantiations
    /// of `Q` `structs`, and the instantiations of a function `g` of 4 type
    /// parameters `functions`.
    pub(crate) fn fields_module(
        address: AccountAddress,
        fields: Vec<move_binary_format::file_format::SignatureToken>,
        arity: usize,
        structs: Vec<Vec<move_binary_format::file_format::SignatureToken>>,
        functions: Vec<Vec<move_binary_format::file_format::SignatureToken>>,
    ) -> Vec<u8> {
        use move_binary_format::file_format::{
            empty_module, AbilitySet, FieldDefinition, FunctionHandle, FunctionHandleIndex,
            FunctionInstantiation, IdentifierIndex, ModuleHandleIndex, Signature, SignatureIndex,
            SignatureToken, StructDefInstantiation, StructDefinition, StructDefinitionIndex,
            StructFieldInformation, StructHandle, StructHandleIndex, StructTypeParameter,
            TypeSignature,
        };
        let mut m = empty_module();
        m.address_identifiers = vec![address];
        m.identifiers = ["fields", "P", "Q", "g", "x"]
            .into_iter()
            .map(|name| Identifier::new(name).unwrap())
            .chain((0..fields.len()).map(|i| Identifier::new(format!("f{i}")).unwrap()))
            .collect();
        for (name, count) in [(1, arity), (2, 4)] {
            m.struct_handles.push(StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(name),
                abilities: AbilitySet::EMPTY,
                type_parameters: (0..count)
                    .map(|_| StructTypeParameter {
                        constraints: AbilitySet::EMPTY,
                        is_phantom: false,
                    })
                    .collect(),
            });
        }
        m.struct_defs.push(StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Declared(
                fields
                    .into_iter()
                    .enumerate()
                    .map(|(i, field)| FieldDefinition {
                        name: IdentifierIndex(5 + i as u16),
                        signature: TypeSignature(field),
                    })
                    .collect(),
            ),
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: StructHandleIndex(1),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(4),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(3),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![AbilitySet::EMPTY; 4],
        });
        for args in structs {
            m.signatures.push(Signature(args));
            m.struct_def_instantiations.push(StructDefInstantiation {
                def: StructDefinitionIndex(1),
                type_parameters: SignatureIndex(m.signatures.len() as u16 - 1),
            });
        }
        for args in functions {
            m.signatures.push(Signature(args));
            m.function_instantiations.push(FunctionInstantiation {
                handle: FunctionHandleIndex(0),
                type_parameters: SignatureIndex(m.signatures.len() as u16 - 1),
            });
        }
        let mut bytes = vec![];
        m.serialize(&mut bytes).unwrap();
        bytes
    }

    /// B422 witness (round 28): `P<T>` of 64 fields each `Q<T, T, T,
    /// vector^57<T>>` (62 nodes naming `T` 4 times, within the bound on one
    /// type) is refused: move-vm instantiated all 64 afresh on every
    /// `PackGeneric` and `UnpackGeneric`, ~125,000 nodes for ~40 gas with
    /// an argument of ~490 nodes. Its fields expand to 64 * 62 + 256 * 192.
    /// One such field (62 + 4 * 192) is accepted, and so is a Liquidswap
    /// style event store, 8 fields of `Q<X, Y, Curve, u64>` (40 + 8 * 192).
    #[test]
    fn a_generic_struct_expanding_past_the_bound_is_refused() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let p = T::TypeParameter;
        let args = vec![p(0), p(0), p(0), vectors(57, p(0))];
        let wide = T::StructInstantiation(StructHandleIndex(1), args);
        let module = |count| fields_module(at, vec![wide.clone(); count], 1, vec![], vec![]);
        assert_eq!(type_work_of(&module(1)), Ok(()));
        let err = type_work_of(&module(64)).unwrap_err();
        assert!(
            err.contains("::P's fields expand to 53120 type nodes (at most 2048)"),
            "{err}"
        );
        let handle = T::StructInstantiation(StructHandleIndex(1), vec![p(0), p(1), p(2), T::U64]);
        let events = fields_module(at, vec![handle; 8], 3, vec![], vec![]);
        assert_eq!(type_work_of(&events), Ok(()));
    }

    /// B422 witness (round 28): a struct whose fields expand just within
    /// the bound is accepted through the publish check, one past it is
    /// not: `P<T>` of 10 fields `T` expands to 10 + 10 * 192 = 1,930 nodes,
    /// of 11 to 11 + 11 * 192 = 2,123.
    #[test]
    fn a_generic_struct_just_within_the_bound_is_accepted() {
        use move_binary_format::file_format::SignatureToken as T;
        let db = depth_db("struct_fields");
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let module = |count| fields_module(at, vec![T::TypeParameter(0); count], 1, vec![], vec![]);
        assert_eq!(check_struct_depths(&db, &[module(10)]), Ok(()));
        let err = check_struct_depths(&db, &[module(11)]).unwrap_err();
        assert!(
            err.contains("::P's fields expand to 2123 type nodes"),
            "{err}"
        );
    }

    /// B422 witness (round 28): an instantiation is bounded as a whole. A
    /// struct instantiation naming a type parameter twice is refused (its
    /// arguments would be up to 2 * 128 nodes, which a struct's fields
    /// multiply), distinct ones are not; one of 65 nodes is refused, though
    /// each argument is within the bound on one type. A function
    /// instantiation may name one 4 times, not 5.
    #[test]
    fn an_instantiation_is_bounded_as_a_whole() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let at = AccountAddress::from_hex_literal("0xf4a").unwrap();
        let p = T::TypeParameter;
        let structs = |args| fields_module(at, vec![T::U64], 0, vec![args], vec![]);
        let functions = |args| fields_module(at, vec![T::U64], 0, vec![], vec![args]);
        let distinct = structs(vec![p(0), p(1), p(2), T::U64]);
        assert_eq!(type_work_of(&distinct), Ok(()));
        let twice = structs(vec![p(0), p(0), T::U64, T::U64]);
        let err = type_work_of(&twice).unwrap_err();
        assert!(
            err.contains("a struct instantiation naming a type parameter 2 times"),
            "{err}"
        );
        let wide = |levels| structs(vec![vectors(levels, T::U8), T::U64, T::U64, T::U64]);
        assert_eq!(type_work_of(&wide(60)), Ok(()));
        let err = type_work_of(&wide(61)).unwrap_err();
        assert!(err.contains("a struct instantiation of 65 nodes"), "{err}");
        let pair = T::StructInstantiation(StructHandleIndex(1), vec![p(0), p(0), T::U64, T::U64]);
        let four = functions(vec![p(0), p(0), p(1), pair.clone()]);
        assert_eq!(type_work_of(&four), Ok(()));
        let five = functions(vec![p(0), p(0), p(0), pair]);
        let err = type_work_of(&five).unwrap_err();
        assert!(
            err.contains("a function instantiation naming a type parameter 5 times"),
            "{err}"
        );
    }

    /// B422 witness: every stdlib module is within the type work bounds,
    /// and (round 28) its largest struct, `dex::LiquidityPool` (6 nodes
    /// naming each parameter once, 6 + 192), is within an eighth of the
    /// struct bound.
    #[test]
    fn the_stdlib_is_within_the_type_work_bounds() {
        use move_binary_format::file_format::StructFieldInformation;
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vm_move/stdlib/bytecode");
        let (mut checked, mut largest) = (0, 0);
        for path in std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()) {
            if path.extension().is_some_and(|ext| ext == "mv") {
                let bytes = std::fs::read(&path).unwrap();
                assert_eq!(type_work_of(&bytes), Ok(()), "{}", path.display());
                let module = CompiledModule::deserialize(&bytes).unwrap();
                for def in module.struct_defs() {
                    if let StructFieldInformation::Declared(fields) = &def.field_information {
                        largest = largest.max(struct_field_nodes(fields));
                    }
                }
                checked += 1;
            }
        }
        assert!(checked > 10, "vacuous: no stdlib");
        assert!(
            (MAX_INSTANTIATED_ARGUMENT_NODES..=MAX_STRUCT_FIELD_NODES / 8).contains(&largest),
            "the stdlib's largest struct expands to {largest} type nodes"
        );
    }

    /// B458: a module (`deep`) of structs `(name, arity, fields)`, each the
    /// handle at its place in the list (`StructHandleIndex(i)`), holding the
    /// fields (each named `f`).
    fn structs_module(
        address: AccountAddress,
        structs: Vec<(
            String,
            usize,
            Vec<move_binary_format::file_format::SignatureToken>,
        )>,
    ) -> Vec<u8> {
        use move_binary_format::file_format::{
            empty_module, AbilitySet, FieldDefinition, IdentifierIndex, ModuleHandleIndex,
            StructDefinition, StructFieldInformation, StructHandle, StructHandleIndex,
            StructTypeParameter, TypeSignature,
        };
        let mut m = empty_module();
        m.address_identifiers = vec![address];
        m.identifiers = vec![
            Identifier::new("deep").unwrap(),
            Identifier::new("f").unwrap(),
        ];
        let parameter = StructTypeParameter {
            constraints: AbilitySet::EMPTY,
            is_phantom: false,
        };
        for (i, (name, arity, fields)) in structs.into_iter().enumerate() {
            m.identifiers.push(Identifier::new(name).unwrap());
            m.struct_handles.push(StructHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(m.identifiers.len() as u16 - 1),
                abilities: AbilitySet::EMPTY,
                type_parameters: vec![parameter; arity],
            });
            m.struct_defs.push(StructDefinition {
                struct_handle: StructHandleIndex(i as u16),
                field_information: StructFieldInformation::Declared(
                    fields
                        .into_iter()
                        .map(|field| FieldDefinition {
                            name: IdentifierIndex(1),
                            signature: TypeSignature(field),
                        })
                        .collect(),
                ),
            });
        }
        let mut bytes = vec![];
        m.serialize(&mut bytes).unwrap();
        bytes
    }

    /// B458: a wrapper `P<X, Y> { f: u64 }` (handle 0), then `levels`
    /// structs `L_i` of `arity` type parameters (handles `1..`), each
    /// `L_i { f: vector<L_{i+1}<args>> }`, the last holding a `u64`. No
    /// parameter reaches a value, so the depth check (B343) carries none.
    fn chain_module(
        address: AccountAddress,
        levels: usize,
        arity: usize,
        args: &[move_binary_format::file_format::SignatureToken],
    ) -> Vec<u8> {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let mut structs = vec![("P".to_string(), 2, vec![T::U64])];
        for i in 0..levels {
            let field = if i + 1 == levels {
                T::U64
            } else {
                let next = StructHandleIndex(i as u16 + 2);
                vectors(1, T::StructInstantiation(next, args.to_vec()))
            };
            structs.push((format!("L{i}"), arity, vec![field]));
        }
        structs_module(address, structs)
    }

    /// B458: the wrapper `P` (handle 0), then `S_0 .. S_pairs` of one type
    /// parameter (handles `1 ..= pairs + 1`) and `N_0 .. N_{pairs - 1}` of
    /// two (handles `pairs + 2 ..`): `S_i<A> { f: vector<N_i<A, A>> }`,
    /// `N_i<X, Y> { f: vector<S_{i+1}<P<X, Y>>> }`, the last `S` holding a
    /// `u64`. Every argument names each parameter once, yet the argument
    /// doubles every two levels.
    fn alternating_module(address: AccountAddress, pairs: usize) -> Vec<u8> {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let p = T::TypeParameter;
        let mut structs = vec![("P".to_string(), 2, vec![T::U64])];
        for i in 0..=pairs {
            let field = if i == pairs {
                T::U64
            } else {
                let n = StructHandleIndex((pairs + 2 + i) as u16);
                vectors(1, T::StructInstantiation(n, vec![p(0), p(0)]))
            };
            structs.push((format!("S{i}"), 1, vec![field]));
        }
        for i in 0..pairs {
            let pair = T::StructInstantiation(StructHandleIndex(0), vec![p(0), p(1)]);
            let s = StructHandleIndex(i as u16 + 2);
            let field = vectors(1, T::StructInstantiation(s, vec![pair]));
            structs.push((format!("N{i}"), 2, vec![field]));
        }
        structs_module(address, structs)
    }

    /// B458: `P<X, Y> { f: u64 }` (handle 0), `Q<A, B, C, D> { f: u64 }`
    /// (1), then `levels` structs `K_i` of one type parameter (handles
    /// `2..`): `K_i<A> { f: vector<K_{i+1}<P<A, vector^59<u8>>>> }` (61
    /// constant nodes in its argument), the last `K<C> { f: vector<Q<C, C, C,
    /// vector<C>>> }` (4 times its argument).
    fn scaled_module(address: AccountAddress, levels: usize) -> Vec<u8> {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let p = T::TypeParameter;
        let mut structs = vec![
            ("P".to_string(), 2, vec![T::U64]),
            ("Q".to_string(), 4, vec![T::U64]),
        ];
        for i in 0..levels {
            let field = if i + 1 == levels {
                let args = vec![p(0), p(0), p(0), vectors(1, p(0))];
                vectors(1, T::StructInstantiation(StructHandleIndex(1), args))
            } else {
                let constant = vec![p(0), vectors(59, T::U8)];
                let constant = T::StructInstantiation(StructHandleIndex(0), constant);
                let next = StructHandleIndex(i as u16 + 3);
                vectors(1, T::StructInstantiation(next, vec![constant]))
            };
            structs.push((format!("K{i}"), 1, vec![field]));
        }
        structs_module(address, structs)
    }

    /// B458 (round 29b): `Q<A, B, C, D> { f: u64 }` (handle 0), `count`
    /// distinct structs `B_j<A> { f: vector<Q<A, A, A, A>> }` (handles
    /// `1 ..= count`), and `W<A>` of `count` fields `vector<B_j<A>>`.
    fn wide_module(address: AccountAddress, count: usize) -> Vec<u8> {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let p = T::TypeParameter;
        let quad = T::StructInstantiation(StructHandleIndex(0), vec![p(0); 4]);
        let mut structs = vec![("Q".to_string(), 4, vec![T::U64])];
        for j in 0..count {
            structs.push((format!("B{j}"), 1, vec![vectors(1, quad.clone())]));
        }
        let fields = (0..count)
            .map(|j| {
                let big = StructHandleIndex(j as u16 + 1);
                vectors(1, T::StructInstantiation(big, vec![p(0)]))
            })
            .collect();
        structs.push(("W".to_string(), 1, fields));
        structs_module(address, structs)
    }

    /// B458 witness: a struct whose layout would carry type arguments past
    /// `MAX_LAYOUT_ARGUMENT_NODES` (its own of 128 nodes together, B465) is
    /// refused, one level shorter is not. Each chain passes every other
    /// publish check (no parameter reaches a value, each field is within the
    /// type work bounds, each layout builds within `MAX_LAYOUT_WORK_NODES`),
    /// and the first fix's per-position multiplier missed all but the first:
    /// it stayed 1 where an argument names each parameter once.
    /// - `L_i<A> { f: vector<L_{i+1}<P<A, A>>> }`: `L_0` of 3 levels carries
    ///   4 * 128 + 3 = 515 nodes, of 4 levels 8 * 128 + 7 = 1,031.
    /// - `L_i<A, B> { f: vector<L_{i+1}<P<A, B>, P<A, B>>> }` (both positions
    ///   summed, the two parameters sharing the 128): of 3 levels 4 * 128 + 6
    ///   = 518, of 4 levels 8 * 128 + 14 = 1,038 (B458's 192 each refused 3).
    /// - the alternating one-parameter chain (`alternating_module`): of 2
    ///   pairs `S_0` carries 4 * 128 + 3 = 515, of 3 pairs 8 * 128 + 7.
    /// - constants added at each level, scaled by the struct below
    ///   (`scaled_module`): of 3 levels 4 * 128 + 1 + 8 * 61 = 1,001, of 4
    ///   levels 4 * 128 + 1 + 12 * 61 = 1,245 (B458's 192 refused 3). Round
    ///   29b: it replaces the additive chain (61 nodes a level, refused past
    ///   15 levels), which the work bound now refuses first, past 8
    ///   (`a_layout_building_too_many_nodes_is_refused`).
    ///
    /// Ordinary shapes are accepted: the terminal wrapper `P<T> { f:
    /// vector<Q<T, T, T, T>> }` (512), B422's widest accepted field `Q<T, T,
    /// T, vector^57<T>>` (569) and a Liquidswap event store of 8 `Q<X, Y,
    /// Curve, u64>` (129); B465's multi-asset shapes in
    /// `a_multi_asset_layout_is_accepted`.
    #[test]
    fn a_layout_multiplying_chain_is_refused() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let db = depth_db("layout_mult");
        let at = AccountAddress::from_hex_literal("0x458").unwrap();
        let p = T::TypeParameter;
        let pair = |x, y| T::StructInstantiation(StructHandleIndex(0), vec![x, y]);
        let refused = |bytes: Vec<u8>, what: &str| {
            let err = check_struct_depths(&db, &[bytes]).unwrap_err();
            assert!(
                err.contains(what) && err.contains("(at most 1024)"),
                "{err}"
            );
        };
        let carried = |bytes: Vec<u8>| {
            LAYOUT_PEAK.with(|peak| peak.set(0));
            assert_eq!(check_struct_depths(&db, &[bytes]), Ok(()));
            LAYOUT_PEAK.with(|peak| peak.get())
        };
        // The original phantom doubling chain.
        let doubling = [pair(p(0), p(0))];
        assert_eq!(carried(chain_module(at, 3, 1, &doubling)), 515);
        refused(
            chain_module(at, 4, 1, &doubling),
            "::L0's layout carries type arguments of 1031 nodes",
        );
        // Two parameters, each named once in each of two positions.
        let sum = [pair(p(0), p(1)), pair(p(0), p(1))];
        assert_eq!(carried(chain_module(at, 3, 2, &sum)), 518);
        refused(
            chain_module(at, 4, 2, &sum),
            "::L0's layout carries type arguments of 1038 nodes",
        );
        // One parameter, alternating through a two-parameter struct.
        assert_eq!(carried(alternating_module(at, 2)), 515);
        refused(
            alternating_module(at, 3),
            "::S0's layout carries type arguments of 1031 nodes",
        );
        // Constants added at every level, scaled by the struct below.
        assert_eq!(carried(scaled_module(at, 3)), 1001);
        refused(
            scaled_module(at, 4),
            "::K0's layout carries type arguments of 1245 nodes",
        );
        // Ordinary shapes: accepted.
        let quad = T::StructInstantiation(StructHandleIndex(1), vec![p(0), p(0), p(0), p(0)]);
        let terminal = fields_module(at, vec![vectors(1, quad)], 1, vec![], vec![]);
        assert_eq!(carried(terminal), 512);
        let args = vec![p(0), p(0), p(0), vectors(57, p(0))];
        let wide = T::StructInstantiation(StructHandleIndex(1), args);
        let wide = fields_module(at, vec![wide], 1, vec![], vec![]);
        assert_eq!(carried(wide), 569);
        let handle = T::StructInstantiation(StructHandleIndex(1), vec![p(0), p(1), p(2), T::U64]);
        let events = fields_module(at, vec![handle; 8], 3, vec![], vec![]);
        assert_eq!(carried(events), 129);
    }

    /// B458 witness (round 29b): a struct whose layout builds past
    /// `MAX_LAYOUT_WORK_NODES` type nodes (its type arguments 128 nodes
    /// together, B465) is refused, though no instantiation in it carries
    /// arguments past `MAX_LAYOUT_ARGUMENT_NODES`; a smaller one is not.
    /// Every one of them passes the other publish checks. The work was
    /// unbounded but for move-vm's 256 layout nodes, ~1M nodes for a first
    /// access of 16 gas.
    /// - wide (`wide_module`): each `B_j<A>` builds A + (2 + 4 * A) +
    ///   (4 * A + 1) = 9 * A + 3 (carrying 512), and each field of `W`
    ///   substitutes 2 + A and lays out a `B_j`: `W` of n fields builds A +
    ///   n * (10 * A + 5), of 7 fields 71 * 128 + 35 = 9,123, of 8 fields
    ///   81 * 128 + 40 = 10,408 (B458's 192 refused 5).
    /// - additive (`L_i<A> { f: vector<L_{i+1}<P<A, vector^59<u8>>>> }`):
    ///   every level re-clones the constants below it: 8 levels build 22 *
    ///   128 + 5,139 = 7,955 nodes, 9 levels 25 * 128 + 6,605 = 9,805
    ///   (carrying only 616; B458's 192 refused 8).
    ///
    /// Ordinary shapes build far less: the terminal wrapper `P<T> { f:
    /// vector<Q<T, T, T, T>> }` 9 * 128 + 3 = 1,155, B422's widest field
    /// `Q<T, T, T, vector^57<T>>` 9 * 128 + 116 = 1,268, a Liquidswap event
    /// store of 8 `Q<X, Y, Curve, u64>` 17 * 128 + 32 = 2,208 (its 3
    /// arguments at 128 nodes each, 6,560: they are bounded together).
    #[test]
    fn a_layout_building_too_many_nodes_is_refused() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let db = depth_db("layout_work");
        let at = AccountAddress::from_hex_literal("0x458").unwrap();
        let p = T::TypeParameter;
        let built = |bytes: Vec<u8>| {
            WORK_PEAK.with(|peak| peak.set(0));
            assert_eq!(check_struct_depths(&db, &[bytes]), Ok(()));
            WORK_PEAK.with(|peak| peak.get())
        };
        let refused = |bytes: Vec<u8>, what: &str| {
            let err = check_struct_depths(&db, &[bytes]).unwrap_err();
            assert!(
                err.contains(what) && err.contains("(at most 9216)"),
                "{err}"
            );
        };
        assert_eq!(built(wide_module(at, 7)), 9123);
        refused(wide_module(at, 8), "::W's layout builds 10408 type nodes");
        let constant = vec![p(0), vectors(59, T::U8)];
        let additive = [T::StructInstantiation(StructHandleIndex(0), constant)];
        assert_eq!(built(chain_module(at, 8, 1, &additive)), 7955);
        refused(
            chain_module(at, 9, 1, &additive),
            "::L0's layout builds 9805 type nodes",
        );
        // Ordinary shapes.
        let quad = T::StructInstantiation(StructHandleIndex(1), vec![p(0), p(0), p(0), p(0)]);
        let terminal = fields_module(at, vec![vectors(1, quad)], 1, vec![], vec![]);
        assert_eq!(built(terminal), 1155);
        let args = vec![p(0), p(0), p(0), vectors(57, p(0))];
        let wide = T::StructInstantiation(StructHandleIndex(1), args);
        let wide = fields_module(at, vec![wide], 1, vec![], vec![]);
        assert_eq!(built(wide), 1268);
        let handle = T::StructInstantiation(StructHandleIndex(1), vec![p(0), p(1), p(2), T::U64]);
        let events = fields_module(at, vec![handle; 8], 3, vec![], vec![]);
        assert_eq!(built(events), 2208);
    }

    /// B465 witness: ordinary multi-asset structs are accepted, both layout
    /// bounds taking their type arguments as 128 nodes together (every
    /// root's are). Each was refused: `Carried` gave every parameter 192
    /// nodes of its own, and `Work` took the arguments as 192 together.
    /// `Coin<T> { u128 }` is handle 0.
    /// - a 6-coin basket `Basket<A, .., F> { Coin<A>, .., Coin<F> }`
    ///   carries 128 (it carried 6 * 192 = 1,152 and was refused) and
    ///   builds 3 * 128 + 12 = 396;
    /// - an 8-parameter weighted pool (4 assets and 4 weights) holding its 4
    ///   coins and its LP coin `Coin<LP<A0, .., W3>>` carries 129 (it
    ///   carried 8 * 192 + 1 = 1,537 and was refused) and builds 6 * 128 +
    ///   13 = 781;
    /// - a 3x3x2 market `Market<C> { 3 Reserve<C> }`, `Reserve<C> { 3
    ///   Pool<C> }`, `Pool<C> { 2 Coin<C> }` carries 128 and builds 61 *
    ///   128 + 48 = 7,856 (it built 61 * 192 + 48 = 11,760 and was refused).
    #[test]
    fn a_multi_asset_layout_is_accepted() {
        use move_binary_format::file_format::{SignatureToken as T, StructHandleIndex};
        let db = depth_db("layout_assets");
        let at = AccountAddress::from_hex_literal("0x465").unwrap();
        let p = T::TypeParameter;
        let of = |handle, args| T::StructInstantiation(StructHandleIndex(handle), args);
        // The bounds of the structs `Coin` and then `structs`, the most any
        // of them carries and builds.
        let bounds = |structs: Vec<(&str, usize, Vec<T>)>| {
            let coin = ("Coin".to_string(), 1, vec![T::U128]);
            let named = structs
                .into_iter()
                .map(|(name, arity, fields)| (name.to_string(), arity, fields));
            let bytes = structs_module(at, std::iter::once(coin).chain(named).collect());
            LAYOUT_PEAK.with(|peak| peak.set(0));
            WORK_PEAK.with(|peak| peak.set(0));
            assert_eq!(check_struct_depths(&db, &[bytes]), Ok(()));
            let carried = LAYOUT_PEAK.with(|peak| peak.get());
            (carried, WORK_PEAK.with(|peak| peak.get()))
        };
        let coins = (0..6).map(|i| of(0, vec![p(i)])).collect();
        assert_eq!(bounds(vec![("Basket", 6, coins)]), (128, 396));
        // `LP<A0, .., W3> { u64 }` is handle 1.
        let mut pool: Vec<T> = (0..4).map(|i| of(0, vec![p(i)])).collect();
        pool.push(of(0, vec![of(1, (0..8).map(p).collect())]));
        let weighted = vec![("LP", 8, vec![T::U64]), ("Pool", 8, pool)];
        assert_eq!(bounds(weighted), (129, 781));
        let field = |handle| of(handle, vec![p(0)]);
        let market = vec![
            ("Pool", 1, vec![field(0); 2]),
            ("Reserve", 1, vec![field(1); 3]),
            ("Market", 1, vec![field(2); 3]),
        ];
        assert_eq!(bounds(market), (128, 7856));
    }

    /// B458 witness (round 29b): an entry function returning a value is
    /// refused at publish (move-vm lays its return values out with the
    /// transaction's type arguments substituted, a root past the arguments
    /// the layout bounds assume); one returning nothing is accepted, and so
    /// is a public function returning a value (not a root: its caller takes
    /// the values on the stack).
    #[test]
    fn an_entry_function_returning_a_value_is_refused() {
        use move_binary_format::file_format::{SignatureIndex, SignatureToken as T};
        let db = depth_db("entry_returns");
        let at = AccountAddress::from_hex_literal("0x458").unwrap();
        // `f`'s locals are a `u64` (signature 1), its return nothing (0).
        let module = |entry: bool, returns: bool| {
            let bytes = frame_module(at, vec![T::U64], 0, 0);
            let mut m = CompiledModule::deserialize(&bytes).unwrap();
            m.function_defs[0].is_entry = entry;
            if returns {
                m.function_handles[0].return_ = SignatureIndex(1);
            }
            let mut bytes = vec![];
            m.serialize(&mut bytes).unwrap();
            bytes
        };
        let err = check_struct_depths(&db, &[module(true, true)]).unwrap_err();
        assert!(err.contains("::frame::f returns a value"), "{err}");
        assert_eq!(check_struct_depths(&db, &[module(true, false)]), Ok(()));
        assert_eq!(check_struct_depths(&db, &[module(false, true)]), Ok(()));
    }

    /// B316 witness: a published module's identifiers are at most
    /// `MAX_IDENTIFIER_BYTES` (move allows 65,535, which the VM clones and
    /// hashes wherever it builds a type's tag).
    #[test]
    fn a_published_identifier_is_at_most_255_bytes() {
        use move_binary_format::file_format::empty_module;
        let module = |name: String| {
            let mut m = empty_module();
            m.identifiers = vec![Identifier::new(name).unwrap()];
            let mut bytes = vec![];
            m.serialize(&mut bytes).unwrap();
            bytes
        };
        assert!(bundle_roots(&[module("m".repeat(MAX_IDENTIFIER_BYTES))]).is_ok());
        let err = bundle_roots(&[module("m".repeat(MAX_IDENTIFIER_BYTES + 1))]).unwrap_err();
        assert!(err.contains("256 bytes"), "{err}");
    }
}
