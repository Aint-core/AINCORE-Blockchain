use move_binary_format::errors::PartialVMError;
use move_core_types::gas_algebra::{Arg, InternalGas, NumBytes};
use move_core_types::vm_status::StatusCode;
use move_vm_types::gas::GasMeter;
use move_vm_types::views::{TypeView, ValueView, ValueVisitor};
use std::iter::ExactSizeIterator;

// Simple constants for now
#[allow(dead_code)]
pub const GAS_UNIT_PRICE: u64 = 1;

#[derive(Clone, Debug)]
pub struct GasSchedule {
    pub instruction_cost: u64,
    pub storage_per_byte: u64,
    pub load_base: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            instruction_cost: 1,
            storage_per_byte: 2,
            load_base: 10,
        }
    }
}

/// B49: abstract value units (`units`) per gas unit, for the operations
/// whose work grows with the value (copy, read, compare, write a resource).
/// Aptos prices them at 140 internal units per abstract unit against 5,880
/// for an `add` (`aptos-gas-schedule`, instr.rs): one simple instruction per
/// 42 units. They were flat (1 gas to deep-copy a megabyte).
pub const ABSTRACT_UNITS_PER_GAS: u64 = 42;

/// B315: Aptos's abstract value size (`aptos-gas-schedule`, misc.rs, from
/// feature version 3): 40 units a scalar, a reference, a struct and a vector
/// (its header), and a primitive vector's elements their packed bytes.
const ABS_SCALAR: u64 = 40;
const ABS_REFERENCE: u64 = 40;
const ABS_STRUCT: u64 = 40;
const ABS_VECTOR: u64 = 40;

/// B49: the abstract value units a transaction may hold at once (Aptos
/// `memory_quota`, 10,000,000). B246: what is counted is the heap (`heap`:
/// containers; scalars, addresses and references are not), held when a
/// container reaches the operand stack (a copy, a read, a constant, a pack,
/// a vector grown or packed, a move from global storage, a native's result)
/// or (B252) a resource is loaded from storage, and credited when it leaves
/// it (popped, compared, overwritten through a reference, dropped with its
/// frame, taken apart, handed to a native); a value overwritten in a local
/// is not credited, and one moved to global storage stays held (stricter
/// than Aptos, which holds it again). An entry function's arguments are
/// credited once each though never held (move-vm builds them with no meter
/// call): B450, at most 40 units an argument byte (an empty inner vector is
/// one BCS byte and a 40-unit header), ~2M units in the ~51 KB a payload's
/// arguments can hold: a fifth of the quota, once a transaction (accepted).
/// B315: in Aptos's abstract sizes (`units`), as Aptos counts its quota.
pub const MEMORY_QUOTA: u64 = 10_000_000;

/// B315: `val`'s abstract size (`ABS_*`), what gas and the memory quota
/// price it by. It was move-vm's legacy size, which counts 2 for a struct or
/// a vector of containers and no header for a primitive vector: a vector of
/// ten thousand empty vectors measured 2 units, so copying, reading or
/// comparing it cost about 2 gas while the VM allocated and walked every
/// element, and the quota never counted them.
fn units(val: &impl ValueView) -> u64 {
    sized(val, false)
}

/// B341: `units`, a reference counted as what it refers to (Aptos's
/// `abstract_value_size_dereferenced`): comparing two references compares
/// the values behind them, which cost 40 units each, so a value near the
/// quota was compared over and over for 3 gas. B461: a native's arguments
/// are priced so too (`bcs::to_bytes` copies what its reference points to).
fn deref_units(val: &impl ValueView) -> u64 {
    sized(val, true)
}

/// `units`, or with `deref` `deref_units`.
fn sized(val: &impl ValueView, deref: bool) -> u64 {
    struct Size(u64, bool);
    impl Size {
        fn add(&mut self, units: u64) {
            self.0 = self.0.saturating_add(units);
        }
        fn packed(&mut self, len: usize, bytes: u64) {
            self.add(ABS_VECTOR.saturating_add((len as u64).saturating_mul(bytes)));
        }
    }
    impl ValueVisitor for Size {
        fn visit_u8(&mut self, _: usize, _: u8) {
            self.add(ABS_SCALAR);
        }
        fn visit_u16(&mut self, _: usize, _: u16) {
            self.add(ABS_SCALAR);
        }
        fn visit_u32(&mut self, _: usize, _: u32) {
            self.add(ABS_SCALAR);
        }
        fn visit_u64(&mut self, _: usize, _: u64) {
            self.add(ABS_SCALAR);
        }
        fn visit_u128(&mut self, _: usize, _: u128) {
            self.add(ABS_SCALAR);
        }
        fn visit_u256(&mut self, _: usize, _: move_core_types::u256::U256) {
            self.add(ABS_SCALAR);
        }
        fn visit_bool(&mut self, _: usize, _: bool) {
            self.add(ABS_SCALAR);
        }
        fn visit_address(&mut self, _: usize, _: move_core_types::account_address::AccountAddress) {
            self.add(ABS_SCALAR);
        }
        fn visit_struct(&mut self, _: usize, _: usize) -> bool {
            self.add(ABS_STRUCT);
            true
        }
        fn visit_vec(&mut self, _: usize, _: usize) -> bool {
            self.add(ABS_VECTOR);
            true
        }
        fn visit_ref(&mut self, depth: usize, _: bool) -> bool {
            if self.1 && depth == 0 {
                return true;
            }
            self.add(ABS_REFERENCE);
            false
        }
        fn visit_vec_u8(&mut self, _: usize, vals: &[u8]) {
            self.packed(vals.len(), 1);
        }
        fn visit_vec_u16(&mut self, _: usize, vals: &[u16]) {
            self.packed(vals.len(), 2);
        }
        fn visit_vec_u32(&mut self, _: usize, vals: &[u32]) {
            self.packed(vals.len(), 4);
        }
        fn visit_vec_u64(&mut self, _: usize, vals: &[u64]) {
            self.packed(vals.len(), 8);
        }
        fn visit_vec_u128(&mut self, _: usize, vals: &[u128]) {
            self.packed(vals.len(), 16);
        }
        fn visit_vec_u256(&mut self, _: usize, vals: &[move_core_types::u256::U256]) {
            self.packed(vals.len(), 32);
        }
        fn visit_vec_bool(&mut self, _: usize, vals: &[bool]) {
            self.packed(vals.len(), 1);
        }
        fn visit_vec_address(
            &mut self,
            _: usize,
            vals: &[move_core_types::account_address::AccountAddress],
        ) {
            self.packed(vals.len(), 32);
        }
    }
    let mut size = Size(0, deref);
    val.visit(&mut size);
    size.0
}

/// B246: the units `val` holds on the heap, what the memory quota counts: a
/// container's (a vector's or a struct's) abstract size, nothing for a
/// scalar, an address or a reference, which live on the operand stack.
/// They were held when copied and credited when popped, consumed or
/// dropped, against what was held for containers: `LdU64; Pop` credited 16
/// units for 2 gas, and an honest loop's copied counters were held for good.
/// Gas still prices every value by `units`.
fn heap(val: &impl ValueView) -> u64 {
    if is_container(val) {
        units(val)
    } else {
        0
    }
}

/// Whether `val` is a vector or a struct (its top level only).
fn is_container(val: &impl ValueView) -> bool {
    struct Top(bool);
    impl ValueVisitor for Top {
        fn visit_u8(&mut self, _: usize, _: u8) {}
        fn visit_u16(&mut self, _: usize, _: u16) {}
        fn visit_u32(&mut self, _: usize, _: u32) {}
        fn visit_u64(&mut self, _: usize, _: u64) {}
        fn visit_u128(&mut self, _: usize, _: u128) {}
        fn visit_u256(&mut self, _: usize, _: move_core_types::u256::U256) {}
        fn visit_bool(&mut self, _: usize, _: bool) {}
        fn visit_address(&mut self, _: usize, _: move_core_types::account_address::AccountAddress) {
        }
        fn visit_struct(&mut self, depth: usize, _: usize) -> bool {
            self.0 |= depth == 0;
            false
        }
        fn visit_vec(&mut self, depth: usize, _: usize) -> bool {
            self.0 |= depth == 0;
            false
        }
        fn visit_ref(&mut self, _: usize, _: bool) -> bool {
            false
        }
        fn visit_vec_u8(&mut self, depth: usize, _: &[u8]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_u16(&mut self, depth: usize, _: &[u16]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_u32(&mut self, depth: usize, _: &[u32]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_u64(&mut self, depth: usize, _: &[u64]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_u128(&mut self, depth: usize, _: &[u128]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_u256(&mut self, depth: usize, _: &[move_core_types::u256::U256]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_bool(&mut self, depth: usize, _: &[bool]) {
            self.0 |= depth == 0;
        }
        fn visit_vec_address(
            &mut self,
            depth: usize,
            _: &[move_core_types::account_address::AccountAddress],
        ) {
            self.0 |= depth == 0;
        }
    }
    let mut top = Top(false);
    val.visit(&mut top);
    top.0
}

/// B246: what an element adds to its vector's heap: a primitive its packed
/// bytes (as a primitive vector counts them), a container nothing more (its
/// own heap, already held, moves into the vector). B315: read from the
/// value: the element type's `TypeTag` was built on every push, pop, pack
/// and unpack, hashing its type arguments and cloning their identifiers,
/// for a flat few gas.
fn element_heap(val: &impl ValueView) -> u64 {
    struct Packed(u64);
    impl ValueVisitor for Packed {
        fn visit_u8(&mut self, _: usize, _: u8) {
            self.0 = 1;
        }
        fn visit_u16(&mut self, _: usize, _: u16) {
            self.0 = 2;
        }
        fn visit_u32(&mut self, _: usize, _: u32) {
            self.0 = 4;
        }
        fn visit_u64(&mut self, _: usize, _: u64) {
            self.0 = 8;
        }
        fn visit_u128(&mut self, _: usize, _: u128) {
            self.0 = 16;
        }
        fn visit_u256(&mut self, _: usize, _: move_core_types::u256::U256) {
            self.0 = 32;
        }
        fn visit_bool(&mut self, _: usize, _: bool) {
            self.0 = 1;
        }
        fn visit_address(&mut self, _: usize, _: move_core_types::account_address::AccountAddress) {
            self.0 = 32;
        }
        // A container adds nothing: none of it is visited.
        fn visit_struct(&mut self, _: usize, _: usize) -> bool {
            false
        }
        fn visit_vec(&mut self, _: usize, _: usize) -> bool {
            false
        }
        fn visit_ref(&mut self, _: usize, _: bool) -> bool {
            false
        }
        fn visit_vec_u8(&mut self, _: usize, _: &[u8]) {}
        fn visit_vec_u16(&mut self, _: usize, _: &[u16]) {}
        fn visit_vec_u32(&mut self, _: usize, _: &[u32]) {}
        fn visit_vec_u64(&mut self, _: usize, _: &[u64]) {}
        fn visit_vec_u128(&mut self, _: usize, _: &[u128]) {}
        fn visit_vec_u256(&mut self, _: usize, _: &[move_core_types::u256::U256]) {}
        fn visit_vec_bool(&mut self, _: usize, _: &[bool]) {}
        fn visit_vec_address(
            &mut self,
            _: usize,
            _: &[move_core_types::account_address::AccountAddress],
        ) {
        }
    }
    let mut packed = Packed(0);
    val.visit(&mut packed);
    packed.0
}

/// B246: what packing `fields` into a struct adds to the heap: the struct's
/// header and its scalar fields (its container fields' heap, already held,
/// moves into it). B339: read from each field's top only (Aptos holds a
/// pack by its fields' abstract stack size): `units(f) - heap(f)` walked a
/// container field whole, twice, on every Pack and Unpack, for a flat few
/// gas, so a loop taking apart and rebuilding a struct around a large value
/// stalled every node.
fn packed_heap<V: ValueView>(fields: impl Iterator<Item = V>) -> u64 {
    fields
        .map(|f| if is_container(&f) { 0 } else { units(&f) })
        .fold(ABS_STRUCT, u64::saturating_add)
}

/// B422: a call's base (a gas a local, and a type argument, more).
const CALL_BASE: u64 = 10;
/// B422: a generic call's base.
const CALL_GENERIC_BASE: u64 = 15;

fn by_size(units: u64) -> u64 {
    units.div_ceil(ABSTRACT_UNITS_PER_GAS)
}

/// B346: what a resource's entry in the session's cache holds besides its
/// type's name: the type, its layout and the global value's slot (a choice,
/// above their sizes for a type of a few nodes).
const RESOURCE_ENTRY_UNITS: u64 = 1_000;

/// B458: each struct layout root may expand to 9,216 type nodes under the
/// publish-time bound. Sixteen gas keeps that work at most 576 nodes/gas.
/// The executor derives its work cap from this price.
pub const LAYOUT_GAS_PER_STRUCT: u64 = 16;

/// B346/B458: bytes of a type's name and the number of struct layout roots,
/// including struct occurrences below vectors and inside type arguments.
fn tag_cost(tag: &move_core_types::language_storage::TypeTag) -> (u64, u64) {
    use move_core_types::language_storage::TypeTag;
    match tag {
        TypeTag::Struct(s) => s.type_params.iter().map(tag_cost).fold(
            (
                (move_core_types::account_address::AccountAddress::LENGTH as u64)
                    .saturating_add(s.module.as_str().len() as u64)
                    .saturating_add(s.name.as_str().len() as u64),
                1,
            ),
            |(bytes, roots), (child_bytes, child_roots)| {
                (
                    bytes.saturating_add(child_bytes),
                    roots.saturating_add(child_roots),
                )
            },
        ),
        TypeTag::Vector(inner) => {
            let (bytes, roots) = tag_cost(inner);
            (bytes.saturating_add(1), roots)
        }
        _ => (1, 0),
    }
}

pub struct AINCOREGasMeter {
    gas_limit: u64,
    gas_consumed: u64,
    schedule: GasSchedule,
    /// B49: abstract units held in copies (`MEMORY_QUOTA`).
    memory_held: u64,
    /// B346: a resource was loaded into the session's cache (a first access
    /// of its address and type) and the access's typed charge, which names
    /// the type, is still to come.
    load_pending: bool,
}

impl AINCOREGasMeter {
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            gas_consumed: 0,
            schedule: GasSchedule::default(),
            memory_held: 0,
            load_pending: false,
        }
    }

    /// B346: a resource access that loaded its (address, type) into the
    /// session's cache pays for its type's name, which the VM built and
    /// keyed storage by, and holds the entry against the quota. The first
    /// access was flat (10 gas, +5 for `exists`) however long the name (up to
    /// ~70 KB: 128 type nodes, 255-byte identifiers), and the cache entries,
    /// kept for the transaction, were never counted.
    fn charge_resource_entry(&mut self, ty: &impl TypeView) -> Result<(), PartialVMError> {
        if !std::mem::take(&mut self.load_pending) {
            return Ok(());
        }
        let (name, roots) = tag_cost(&ty.to_type_tag());
        // The existing load + operation + name charge covers the root's
        // 16 gas. Structs inside its type arguments need their own charge.
        let layouts = roots
            .saturating_sub(1)
            .saturating_mul(LAYOUT_GAS_PER_STRUCT);
        self.charge(by_size(name).saturating_add(layouts))?;
        self.hold(RESOURCE_ENTRY_UNITS.saturating_add(name))
    }

    /// B49: a copy of `units` is held.
    fn hold(&mut self, units: u64) -> Result<(), PartialVMError> {
        self.memory_held = self.memory_held.saturating_add(units);
        if self.memory_held > MEMORY_QUOTA {
            return Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED));
        }
        Ok(())
    }

    /// B49: `units` held are dropped.
    fn release(&mut self, units: u64) {
        self.memory_held = self.memory_held.saturating_sub(units);
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_consumed
    }

    fn charge(&mut self, amount: u64) -> Result<(), PartialVMError> {
        // ATOMIC AUDIT FIX: Use checked_add to prevent overflow wrapping in Release mode
        match self.gas_consumed.checked_add(amount) {
            Some(new_consumed) if new_consumed <= self.gas_limit => {
                self.gas_consumed = new_consumed;
                Ok(())
            }
            _ => {
                self.gas_consumed = self.gas_limit;
                Err(PartialVMError::new(StatusCode::EXECUTION_LIMIT_REACHED))
            }
        }
    }
}

impl GasMeter for AINCOREGasMeter {
    fn balance_internal(&self) -> InternalGas {
        InternalGas::new(self.gas_limit.saturating_sub(self.gas_consumed))
    }

    fn charge_simple_instr(
        &mut self,
        _instr: move_vm_types::gas::SimpleInstruction,
    ) -> Result<(), PartialVMError> {
        self.charge(self.schedule.instruction_cost)
    }

    // B227: what a native returns is held (Aptos's memory tracker does the
    // same), as its arguments are credited before it runs.
    fn charge_native_function(
        &mut self,
        amount: InternalGas,
        ret_vals: Option<impl ExactSizeIterator<Item = impl ValueView>>,
    ) -> Result<(), PartialVMError> {
        self.charge(amount.into())?;
        if let Some(vals) = ret_vals {
            let held: u64 = vals.map(|v| heap(&v)).fold(0, u64::saturating_add);
            self.hold(held)?;
        }
        Ok(())
    }

    fn charge_load_resource(
        &mut self,
        loaded: Option<(NumBytes, impl ValueView)>,
    ) -> Result<(), PartialVMError> {
        // B346: paid by the typed charge that follows (`charge_resource_entry`).
        self.load_pending = true;
        if let Some((k, val)) = loaded {
            let k_val: u64 = k.into();
            // B461: priced by its bytes and (B49) its size: move-vm
            // deserialized it whole, allocating each struct and vector, and a
            // byte of BCS can hold a chain of 124 single-field structs, so its
            // bytes alone priced up to ~62 structs a gas. What
            // `Session::finish` serializes again (a dirty resource, once a
            // session) was priced by its size when it was loaded or made.
            let read = self.schedule.load_base + k_val * self.schedule.storage_per_byte;
            self.charge(read.saturating_add(by_size(units(&val))))?;
            // B252: a resource loaded is held while it is in memory (as
            // Aptos's memory tracker holds it), so a container field of it
            // overwritten through a reference is credited what was held: it
            // was credited though never held.
            self.hold(heap(&val))
        } else {
            self.charge(self.schedule.load_base)
        }
    }

    // B422: a call costs a gas a local (parameters and locals: the runtime
    // type checks clone each local's type into the frame), and a generic
    // call a gas a type argument, besides the base: Aptos's
    // `call.per_local`, `call_generic.per_local` and
    // `call_generic.per_ty_arg`, 3,670 against 5,880 for an `add`, rounded
    // up. They were flat. The executor bounds the types themselves at
    // publish (`deps::check_type_work`): the meter does not see them.
    fn charge_call(
        &mut self,
        _module_id: &move_core_types::language_storage::ModuleId,
        _func_name: &str,
        _args: impl ExactSizeIterator<Item = impl Sized>,
        num_locals: move_core_types::gas_algebra::NumArgs,
    ) -> Result<(), PartialVMError> {
        let locals: u64 = num_locals.into();
        self.charge(CALL_BASE.saturating_add(locals))
    }

    fn charge_call_generic(
        &mut self,
        _module_id: &move_core_types::language_storage::ModuleId,
        _func_name: &str,
        ty_args: impl ExactSizeIterator<Item = impl Sized>,
        _args: impl ExactSizeIterator<Item = impl Sized>,
        num_locals: move_core_types::gas_algebra::NumArgs,
    ) -> Result<(), PartialVMError> {
        let locals: u64 = num_locals.into();
        let per_call = locals.saturating_add(ty_args.len() as u64);
        self.charge(CALL_GENERIC_BASE.saturating_add(per_call))
    }

    fn charge_ld_const(&mut self, _size: NumBytes) -> Result<(), PartialVMError> {
        let val: u64 = _size.into();
        self.charge(val)
    }

    fn charge_ld_const_after_deserialization(
        &mut self,
        val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(1)?;
        self.hold(heap(&val))
    }

    fn charge_copy_loc(&mut self, val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1 + by_size(units(&val)))?;
        self.hold(heap(&val))
    }

    fn charge_move_loc(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_store_loc(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    // B49: packing and unpacking move fields, so they cost by the field
    // count (Aptos: a base of ~1.4 `add` and a quarter of one a field).
    fn charge_pack(
        &mut self,
        _is_generic: bool,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5 + (args.len() as u64).div_ceil(4))?;
        // B246: the struct made is held.
        self.hold(packed_heap(args))
    }

    fn charge_unpack(
        &mut self,
        _is_generic: bool,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5 + (args.len() as u64).div_ceil(4))?;
        // B246: and credited when it is taken apart.
        self.release(packed_heap(args));
        Ok(())
    }

    fn charge_read_ref(&mut self, val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1 + by_size(units(&val)))?;
        self.hold(heap(&val))
    }

    fn charge_write_ref(
        &mut self,
        _new_val: impl ValueView,
        old_val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(1 + by_size(units(&old_val)))?;
        self.release(heap(&old_val));
        Ok(())
    }

    fn charge_eq(
        &mut self,
        lhs: impl ValueView,
        rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        let units = deref_units(&lhs).saturating_add(deref_units(&rhs));
        self.charge(1 + by_size(units))?;
        self.release(heap(&lhs).saturating_add(heap(&rhs)));
        Ok(())
    }

    fn charge_neq(
        &mut self,
        lhs: impl ValueView,
        rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        let units = deref_units(&lhs).saturating_add(deref_units(&rhs));
        self.charge(1 + by_size(units))?;
        self.release(heap(&lhs).saturating_add(heap(&rhs)));
        Ok(())
    }

    fn charge_pop(&mut self, val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)?;
        self.release(heap(&val));
        Ok(())
    }

    fn charge_vec_pack<'a>(
        &mut self,
        _ty: impl TypeView + 'a,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5 + (args.len() as u64).div_ceil(4))?;
        // B246/B315: the vector made is held: its header and its primitive
        // elements' bytes (containers' heap moves into it).
        let elements = args.map(|a| element_heap(&a)).fold(0, u64::saturating_add);
        self.hold(ABS_VECTOR.saturating_add(elements))
    }

    fn charge_vec_len(&mut self, _ty: impl TypeView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_vec_borrow(
        &mut self,
        _is_mut: bool,
        _ty: impl TypeView,
        _is_success: bool,
    ) -> Result<(), PartialVMError> {
        self.charge(2)
    }

    // B213: what a vector grows by is held against the memory quota, and
    // what it pops is credited: growth was flat-priced and uncounted, so a
    // transaction's gas grew one vector by ~2M elements (tens of MB held).
    fn charge_vec_push_back(
        &mut self,
        _ty: impl TypeView,
        val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(5)?;
        self.hold(element_heap(&val))
    }

    fn charge_vec_pop_back(
        &mut self,
        _ty: impl TypeView,
        val: Option<impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(3)?;
        if let Some(val) = val {
            self.release(element_heap(&val));
        }
        Ok(())
    }

    fn charge_vec_swap(&mut self, _ty: impl TypeView) -> Result<(), PartialVMError> {
        self.charge(3)
    }

    fn charge_drop_frame(
        &mut self,
        locals: impl Iterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(2)?;
        let dropped: u64 = locals.map(|l| heap(&l)).fold(0, u64::saturating_add);
        self.release(dropped);
        Ok(())
    }

    fn charge_borrow_global(
        &mut self,
        _is_mut: bool,
        _is_generic: bool,
        ty: impl TypeView,
        _is_alignment: bool,
    ) -> Result<(), PartialVMError> {
        self.charge_resource_entry(&ty)?;
        self.charge(10)
    }

    fn charge_exists(
        &mut self,
        _is_generic: bool,
        ty: impl TypeView,
        _exists: bool,
    ) -> Result<(), PartialVMError> {
        self.charge_resource_entry(&ty)?;
        self.charge(5)
    }

    fn charge_move_from(
        &mut self,
        _is_generic: bool,
        ty: impl TypeView,
        val: Option<impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge_resource_entry(&ty)?;
        // Charge base + size if value exists (B49: by its size)
        if let Some(val) = val {
            self.charge(
                self.schedule.load_base
                    + self.schedule.storage_per_byte * 100
                    + by_size(units(&val)),
            )?;
            // B246: what global storage hands the stack is held (popped or
            // dropped, it was credited though never held).
            self.hold(heap(&val))
        } else {
            self.charge(self.schedule.load_base)
        }
    }

    fn charge_move_to(
        &mut self,
        _is_generic: bool,
        ty: impl TypeView,
        val: impl ValueView,
        _already_exists: bool,
    ) -> Result<(), PartialVMError> {
        self.charge_resource_entry(&ty)?;
        // A write: 500 gas to discourage spam, and (B49) its size.
        self.charge(500 + by_size(units(&val)))
    }

    fn charge_vec_unpack(
        &mut self,
        _ty: impl TypeView,
        _expect_num_elements: move_core_types::gas_algebra::GasQuantity<Arg>,
        elems: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5)?;
        // B246: the vector taken apart is credited as `charge_vec_pack` held
        // it (its containers' heap moves onto the stack, still held).
        let elements = elems.map(|e| element_heap(&e)).fold(0, u64::saturating_add);
        self.release(ABS_VECTOR.saturating_add(elements));
        Ok(())
    }

    // B227: a native's arguments leave the operand stack, credited (Aptos's
    // memory tracker releases them too): a value a native consumed (hashed,
    // serialized) stayed held for the rest of the transaction, so an honest
    // loop building and hashing vectors ran into the quota. B461: and each is
    // priced by the size behind it (`deref_units`, as B341 prices `Eq`)
    // before the native runs, which is handed it whole and may walk all of
    // it: `bcs::to_bytes` deep-copies the value behind its reference
    // (`read_ref`) and serializes the copy, priced only by the bytes it
    // writes, and a chain of 124 single-field structs is one byte. A value
    // near the quota (~245,000 structs) was copied and walked for ~4,000 gas,
    // a 60th of what a `CopyLoc` of it costs (~236,000).
    fn charge_native_function_before_execution(
        &mut self,
        ty_args: impl ExactSizeIterator<Item = impl TypeView>,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        // A native can request a layout even for an empty vector whose
        // elements name large structs. Pay before entering the native.
        for ty in ty_args {
            let (name, roots) = tag_cost(&ty.to_type_tag());
            self.charge(by_size(name).saturating_add(roots.saturating_mul(LAYOUT_GAS_PER_STRUCT)))?;
        }
        let (mut walked, mut consumed) = (0u64, 0u64);
        for arg in args {
            walked = walked.saturating_add(deref_units(&arg));
            consumed = consumed.saturating_add(heap(&arg));
        }
        self.charge(2u64.saturating_add(by_size(walked)))?;
        self.release(consumed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use move_vm_types::values::Value;

    #[derive(Clone)]
    struct LayoutType(move_core_types::language_storage::TypeTag);

    impl TypeView for LayoutType {
        fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
            self.0.clone()
        }
    }

    fn nested_layout_type(depth: usize, width: usize) -> (LayoutType, u64) {
        use move_core_types::language_storage::{StructTag, TypeTag};
        use move_core_types::{account_address::AccountAddress, identifier::Identifier};
        let mut tag = TypeTag::U8;
        let mut roots = 0;
        for _ in 0..depth {
            tag = TypeTag::Struct(Box::new(StructTag {
                address: AccountAddress::ONE,
                module: Identifier::new("m").unwrap(),
                name: Identifier::new("S").unwrap(),
                type_params: vec![TypeTag::Vector(Box::new(tag)); width],
            }));
            roots = 1 + width as u64 * roots;
        }
        (LayoutType(tag), roots)
    }

    #[test]
    fn a_first_access_pays_for_nested_layout_roots() {
        for width in 0..=3 {
            for depth in 1..=3 {
                let (ty, roots) = nested_layout_type(depth, width);
                let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
                meter
                    .charge_load_resource(None::<(NumBytes, Value)>)
                    .unwrap();
                meter.charge_exists(true, ty.clone(), false).unwrap();
                assert!(
                    meter.gas_used() >= 16 * roots,
                    "{roots} roots cost {}",
                    meter.gas_used()
                );
                let first = meter.gas_used();
                let held = meter.memory_held;
                meter.charge_exists(true, ty.clone(), false).unwrap();
                assert_eq!(
                    meter.gas_used() - first,
                    5,
                    "cache hit charged layout again"
                );
                assert_eq!(meter.memory_held, held);

                let mut short = AINCOREGasMeter::new(first - 1);
                short
                    .charge_load_resource(None::<(NumBytes, Value)>)
                    .unwrap();
                assert_eq!(
                    short
                        .charge_exists(true, ty, false)
                        .unwrap_err()
                        .major_status(),
                    StatusCode::EXECUTION_LIMIT_REACHED
                );
                assert_eq!(short.gas_used(), first - 1);
            }
        }
    }

    #[test]
    fn a_native_pays_for_type_layouts_even_without_values() {
        for width in 0..=3 {
            for depth in 1..=3 {
                let (ty, roots) = nested_layout_type(depth, width);
                let types = [ty.clone(), ty];
                let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
                meter
                    .charge_native_function_before_execution(
                        types.iter(),
                        std::iter::empty::<&Value>(),
                    )
                    .unwrap();
                assert!(
                    meter.gas_used() >= 16 * 2 * roots,
                    "native with {} layout roots cost {}",
                    2 * roots,
                    meter.gas_used()
                );
                assert_eq!(meter.memory_held, 0);
                let mut short = AINCOREGasMeter::new(meter.gas_used() - 1);
                assert_eq!(
                    short
                        .charge_native_function_before_execution(
                            types.iter(),
                            std::iter::empty::<&Value>()
                        )
                        .unwrap_err()
                        .major_status(),
                    StatusCode::EXECUTION_LIMIT_REACHED
                );
            }
        }
    }

    /// B49 witness: a copy costs by its size (a megabyte vector, ~25,000
    /// gas, was 1), and a comparison by both sides.
    #[test]
    fn copies_and_comparisons_cost_by_size() {
        let small = Value::u64(7);
        let big = Value::vector_u8(vec![0u8; 1 << 20]);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_copy_loc(&small).unwrap();
        let small_cost = meter.gas_used();
        assert!(small_cost <= 2, "a scalar copy costs {small_cost}");
        meter.charge_copy_loc(&big).unwrap();
        let big_cost = meter.gas_used() - small_cost;
        assert!(
            big_cost >= (1 << 20) / ABSTRACT_UNITS_PER_GAS,
            "a megabyte copy costs {big_cost}"
        );
        let before = meter.gas_used();
        meter.charge_eq(&big, &big).unwrap();
        assert!(meter.gas_used() - before >= 2 * (1 << 20) / ABSTRACT_UNITS_PER_GAS);
    }

    /// B315 witness: a vector of empty vectors is priced and held by its
    /// count. The legacy size measured it 2 units however many it held, so a
    /// copy that allocated ten thousand vectors cost ~2 gas and held nothing
    /// against the quota, and a comparison walked them all for as little.
    #[test]
    fn a_vector_of_empty_vectors_costs_by_its_count() {
        let n = 10_000u64;
        let empties = Value::vector_for_testing_only((0..n).map(|_| Value::vector_u8(vec![])));
        assert_eq!(units(&empties), ABS_VECTOR * (n + 1));
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_copy_loc(&empties).unwrap();
        assert!(
            meter.gas_used() >= n * ABS_VECTOR / ABSTRACT_UNITS_PER_GAS,
            "the copy cost {}",
            meter.gas_used()
        );
        assert_eq!(
            meter.memory_held,
            ABS_VECTOR * (n + 1),
            "the copy was not held by its count"
        );
        let before = meter.gas_used();
        meter.charge_eq(&empties, &empties).unwrap();
        assert!(meter.gas_used() - before >= 2 * n * ABS_VECTOR / ABSTRACT_UNITS_PER_GAS);
    }

    /// B316 witness: the meter never builds an element type's `TypeTag`
    /// (hashing its arguments and cloning their identifiers on every push,
    /// pop, pack and unpack, for a flat few gas): what a vector holds is read
    /// from its values.
    #[test]
    fn a_vector_operation_reads_no_element_type() {
        struct Unread;
        impl TypeView for Unread {
            fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
                panic!("the meter built an element type's TypeTag")
            }
        }
        let element = Value::u64(1);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_vec_push_back(Unread, &element).unwrap();
        meter.charge_vec_pop_back(Unread, Some(&element)).unwrap();
        meter
            .charge_vec_pack(Unread, [&element].into_iter())
            .unwrap();
        meter
            .charge_vec_unpack(
                Unread,
                move_core_types::gas_algebra::NumArgs::new(1),
                [&element].into_iter(),
            )
            .unwrap();
        assert_eq!(meter.memory_held, 0, "push, pop, pack and unpack balance");
    }

    /// B339 witness: packing and unpacking read each field's top only (a
    /// container field was walked whole, twice, on every Pack and Unpack,
    /// for a flat few gas); a scalar field is still held by its size.
    #[test]
    fn a_pack_reads_only_its_fields_tops() {
        struct Deep;
        impl ValueView for Deep {
            fn visit(&self, visitor: &mut impl ValueVisitor) {
                if visitor.visit_vec(0, 1_000_000) {
                    panic!("the meter walked into a packed field");
                }
            }
        }
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_pack(false, [Deep, Deep].into_iter()).unwrap();
        assert_eq!(meter.memory_held, ABS_STRUCT);
        meter
            .charge_unpack(false, [Deep, Deep].into_iter())
            .unwrap();
        assert_eq!(meter.memory_held, 0);
        meter
            .charge_pack(false, [Value::u64(1), Value::bool(true)].into_iter())
            .unwrap();
        assert_eq!(meter.memory_held, ABS_STRUCT + 2 * ABS_SCALAR);
    }

    /// B341 witness: comparing two references is priced by the values they
    /// point to, which the VM compares: a reference counted 40 units, so
    /// comparing references to a megabyte cost 3 gas.
    #[test]
    fn comparing_references_costs_what_they_point_to() {
        use move_vm_types::values::Locals;
        let mut locals = Locals::new(2);
        for i in 0..2 {
            locals
                .store_loc(i, Value::vector_u8(vec![7u8; 1 << 20]), true)
                .unwrap();
        }
        let (a, b) = (locals.borrow_loc(0).unwrap(), locals.borrow_loc(1).unwrap());
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_eq(&a, &b).unwrap();
        assert!(
            meter.gas_used() >= 2 * (1 << 20) / ABSTRACT_UNITS_PER_GAS,
            "comparing two references cost {}",
            meter.gas_used()
        );
        let before = meter.gas_used();
        meter.charge_neq(&a, &b).unwrap();
        assert!(meter.gas_used() - before >= 2 * (1 << 20) / ABSTRACT_UNITS_PER_GAS);
        assert_eq!(meter.memory_held, 0, "a reference holds nothing");
    }

    /// B343 witness: a value at the deepest the publish check allows (128 +
    /// 256 * 4 levels: executor `deps::MAX_STRUCT_DEPTH`, move-vm's
    /// `TYPE_DEPTH_MAX` and `deps::MAX_DEPTH_STEP`) is sized, copied,
    /// compared and dropped on the VM's stack (B430: `VM_STACK_BYTES`), here
    /// in an unoptimized build (larger frames than a release node's). It
    /// claimed a default 2 MiB stack, which overflowed when first run.
    #[test]
    fn a_value_at_the_depth_bound_fits_the_vm_stack() {
        crate::on_vm_stack(|| {
            let mut v = Value::u64(1);
            for _ in 0..128 + 256 * 4 {
                v = Value::struct_(move_vm_types::values::Struct::pack(vec![v]));
            }
            assert_eq!(units(&v), ABS_SCALAR + (128 + 256 * 4) * ABS_STRUCT);
            let copy = v.copy_value().unwrap();
            assert!(copy.equals(&v).unwrap());
            drop(copy);
            drop(v);
        });
    }

    /// B346 witness: an access that loaded a resource into the session's
    /// cache pays for its type's name and holds the entry against the quota
    /// (it was flat however long the name, and the entries were uncounted);
    /// an access of a cached resource builds no name.
    #[test]
    fn a_first_resource_access_pays_for_its_types_name() {
        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::{StructTag, TypeTag};
        #[derive(Clone)]
        struct Named(std::rc::Rc<std::cell::Cell<usize>>, TypeTag);
        impl TypeView for Named {
            fn to_type_tag(&self) -> TypeTag {
                self.0.set(self.0.get() + 1);
                self.1.clone()
            }
        }
        let long = Identifier::new("x".repeat(255)).unwrap();
        let tag = TypeTag::Struct(Box::new(StructTag {
            address: AccountAddress::ONE,
            module: long.clone(),
            name: long,
            type_params: vec![TypeTag::U64],
        }));
        let built = std::rc::Rc::new(std::cell::Cell::new(0));
        let ty = Named(built.clone(), tag);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter
            .charge_load_resource(None::<(NumBytes, Value)>)
            .unwrap();
        let before = meter.gas_used();
        meter.charge_exists(false, ty.clone(), false).unwrap();
        let name = 32 + 255 + 255 + 1;
        assert_eq!(built.get(), 1);
        assert_eq!(meter.gas_used() - before, 5 + by_size(name));
        assert_eq!(meter.memory_held, RESOURCE_ENTRY_UNITS + name);
        meter.charge_borrow_global(false, false, ty, true).unwrap();
        assert_eq!(built.get(), 1, "a cached resource's access built its name");
    }

    /// B213 witness: what a vector grows by is held against the quota (a
    /// transaction's gas grew one vector by ~2M elements, uncounted), and
    /// what it pops is credited, so a push-and-pop loop is bounded by gas.
    #[test]
    fn vector_growth_is_held() {
        struct U128;
        impl TypeView for U128 {
            fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
                move_core_types::language_storage::TypeTag::U128
            }
        }
        let element = Value::u128(7);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        for _ in 0..1_000 {
            meter.charge_vec_push_back(U128, &element).unwrap();
            meter.charge_vec_pop_back(U128, Some(&element)).unwrap();
        }
        let fits = MEMORY_QUOTA / element_heap(&element);
        for _ in 0..fits {
            meter.charge_vec_push_back(U128, &element).unwrap();
        }
        assert_eq!(
            meter
                .charge_vec_push_back(U128, &element)
                .unwrap_err()
                .major_status(),
            StatusCode::MEMORY_LIMIT_EXCEEDED
        );
    }

    /// B227 witness: a native's arguments are credited before it runs and
    /// its results held after, so a loop that builds a vector and hands it
    /// to a native (a hash) is bounded by gas, not the quota.
    #[test]
    fn a_native_consumes_its_arguments_and_holds_its_results() {
        struct U8;
        impl TypeView for U8 {
            fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
                move_core_types::language_storage::TypeTag::U8
            }
        }
        let big = Value::vector_u8(vec![0u8; 1 << 20]);
        let digest = Value::vector_u8(vec![0u8; 32]);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        let rounds = 2 * MEMORY_QUOTA / units(&big) + 2;
        for _ in 0..rounds {
            meter.charge_copy_loc(&big).unwrap();
            meter
                .charge_native_function_before_execution(
                    std::iter::empty::<U8>(),
                    [&big].into_iter(),
                )
                .unwrap();
            meter
                .charge_native_function(InternalGas::new(1), Some([&digest].into_iter()))
                .unwrap();
            meter.charge_pop(&digest).unwrap();
        }
        assert_eq!(meter.memory_held, 0, "a consumed argument stayed held");
        let fits = MEMORY_QUOTA / units(&big);
        let held: Vec<&Value> = (0..fits).map(|_| &big).collect();
        meter
            .charge_native_function(InternalGas::new(1), Some(held.into_iter()))
            .unwrap();
        assert_eq!(
            meter
                .charge_native_function(InternalGas::new(1), Some([&big].into_iter()))
                .unwrap_err()
                .major_status(),
            StatusCode::MEMORY_LIMIT_EXCEEDED,
            "a native's results were not held"
        );
    }

    /// B246 witness: the quota counts the heap: a scalar is neither held nor
    /// credited (`LdU64; Pop` credited 16 units for 2 gas, and a copied
    /// counter was held for good, so an honest loop ran into the quota), and
    /// a container made on the stack (packed, or moved from global storage)
    /// is held, so what its pop credits was held.
    #[test]
    fn only_what_is_held_is_credited() {
        struct Any;
        impl TypeView for Any {
            fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
                move_core_types::language_storage::TypeTag::U64
            }
        }
        let big = Value::vector_u8(vec![0u8; 1 << 20]);
        let scalar = Value::u64(7);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_copy_loc(&big).unwrap();
        let held = meter.memory_held;
        assert!(held > 0, "vacuous: the copy was not held");
        for _ in 0..1_000 {
            meter.charge_pop(&scalar).unwrap();
        }
        assert_eq!(
            meter.memory_held, held,
            "a scalar's pop credited what was not held"
        );
        for _ in 0..1_000_000 {
            meter.charge_copy_loc(&scalar).unwrap();
        }
        assert_eq!(meter.memory_held, held, "a scalar's copy was held");
        let fields = [Value::u64(1), Value::u64(2)];
        meter.charge_pack(false, fields.iter()).unwrap();
        let made =
            move_vm_types::values::Value::struct_(move_vm_types::values::Struct::pack(vec![
                Value::u64(1),
                Value::u64(2),
            ]));
        assert_eq!(
            meter.memory_held - held,
            units(&made),
            "a packed struct was not held"
        );
        meter.charge_pop(&made).unwrap();
        assert_eq!(meter.memory_held, held);
        meter.charge_move_from(false, Any, Some(&made)).unwrap();
        assert_eq!(
            meter.memory_held - held,
            units(&made),
            "a resource moved out was not held"
        );
        meter.charge_pop(&made).unwrap();
        assert_eq!(meter.memory_held, held);
        // Taken apart, a struct and a vector are credited what they held.
        meter.charge_pack(false, fields.iter()).unwrap();
        meter.charge_unpack(false, fields.iter()).unwrap();
        assert_eq!(meter.memory_held, held, "an unpacked struct stayed held");
        let elements = [Value::u64(1), Value::u64(2), Value::u64(3)];
        meter.charge_vec_pack(Any, elements.iter()).unwrap();
        assert_eq!(
            meter.memory_held - held,
            units(&Value::vector_u64(vec![1, 2, 3])),
            "a packed vector was not held"
        );
        meter
            .charge_vec_unpack(
                Any,
                move_core_types::gas_algebra::NumArgs::new(3),
                elements.iter(),
            )
            .unwrap();
        assert_eq!(meter.memory_held, held, "an unpacked vector stayed held");
    }

    /// B252 witness: a resource loaded from storage is held, so a container
    /// field of it overwritten through a reference is credited what the load
    /// held, not a live copy's units (credited though never held, the
    /// counter could be driven down while copies stayed live).
    #[test]
    fn a_loaded_resource_is_held_before_its_fields_are_credited() {
        let field = Value::vector_u8(vec![0u8; 1 << 20]);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter.charge_copy_loc(&field).unwrap();
        let live = meter.memory_held;
        assert!(live > 0, "vacuous: the copy was not held");
        let resource =
            move_vm_types::values::Value::struct_(move_vm_types::values::Struct::pack(vec![
                Value::vector_u8(vec![0u8; 1 << 20]),
            ]));
        meter
            .charge_load_resource(Some((NumBytes::new(1 << 20), &resource)))
            .unwrap();
        // `*&mut resource.field = vector[]`: the field's old value is credited.
        meter
            .charge_write_ref(Value::vector_u8(vec![]), &field)
            .unwrap();
        assert!(
            meter.memory_held >= live,
            "a loaded resource's field was credited though never held"
        );
    }

    /// B461: the round-30 shape, a chain of `CHAIN` single-field structs over
    /// a `u8` (B343 lets a struct nest 128 deep): `CHAIN + 1` nodes in one
    /// byte of BCS.
    const CHAIN: usize = 124;

    fn chain() -> Value {
        (0..CHAIN).fold(Value::u8(7), |inner, _| {
            Value::struct_(move_vm_types::values::Struct::pack(vec![inner]))
        })
    }

    fn chain_layout() -> move_core_types::value::MoveTypeLayout {
        use move_core_types::value::{MoveStructLayout, MoveTypeLayout};
        (0..CHAIN).fold(MoveTypeLayout::U8, |inner, _| {
            MoveTypeLayout::Struct(MoveStructLayout::new(vec![inner]))
        })
    }

    /// B461 witness: a native's reference argument costs what a copy of the
    /// value behind it costs. `bcs::to_bytes` deep-copies that value and
    /// serializes the copy, priced by the bytes it writes: here 24,800
    /// structs in 202 bytes. A reference counted 40 units, so the call cost
    /// a flat 2 gas besides those bytes, a copy of the value 23,812.
    #[test]
    fn a_natives_reference_argument_costs_what_it_refers_to() {
        struct U8;
        impl TypeView for U8 {
            fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
                move_core_types::language_storage::TypeTag::U8
            }
        }
        let chains = 200u64;
        let value = Value::vector_for_testing_only((0..chains).map(|_| chain()));
        let layout = move_core_types::value::MoveTypeLayout::Vector(Box::new(chain_layout()));
        let bytes = value
            .simple_serialize(&layout)
            .expect("the value serializes");
        assert_eq!(bytes.len() as u64, 2 + chains, "a chain is one byte");
        assert_eq!(
            units(&value),
            ABS_VECTOR + chains * (CHAIN as u64 * ABS_STRUCT + ABS_SCALAR)
        );
        let mut copied = AINCOREGasMeter::new(u64::MAX / 2);
        copied.charge_copy_loc(&value).unwrap();
        let mut locals = move_vm_types::values::Locals::new(1);
        locals.store_loc(0, value, true).unwrap();
        let reference = locals.borrow_loc(0).unwrap();
        let mut native = AINCOREGasMeter::new(u64::MAX / 2);
        native
            .charge_native_function_before_execution(
                std::iter::empty::<U8>(),
                [&reference].into_iter(),
            )
            .unwrap();
        assert!(
            native.gas_used() >= copied.gas_used(),
            "a native's reference to {} bytes of chains cost {}, a copy of them {}",
            bytes.len(),
            native.gas_used(),
            copied.gas_used()
        );
        assert_eq!(native.memory_held, 0, "a reference holds nothing");
    }

    /// B461 witness: a resource loaded from storage costs at least what a
    /// copy of it costs (B49: resource reads by their size). move-vm
    /// deserializes it whole, and it was priced by its bytes: this one,
    /// 24,800 structs in 202 bytes, loaded for 414 gas against 23,813 for a
    /// copy.
    #[test]
    fn a_loaded_resource_costs_by_its_size() {
        use move_core_types::value::{MoveStructLayout, MoveTypeLayout};
        let chains = 200u64;
        let resource = Value::struct_(move_vm_types::values::Struct::pack(vec![
            Value::vector_for_testing_only((0..chains).map(|_| chain())),
        ]));
        let field = MoveTypeLayout::Vector(Box::new(chain_layout()));
        let layout = MoveTypeLayout::Struct(MoveStructLayout::new(vec![field]));
        let bytes = resource
            .simple_serialize(&layout)
            .expect("the resource serializes")
            .len() as u64;
        assert_eq!(bytes, 2 + chains, "a chain is one byte");
        let mut copied = AINCOREGasMeter::new(u64::MAX / 2);
        copied.charge_copy_loc(&resource).unwrap();
        let mut loaded = AINCOREGasMeter::new(u64::MAX / 2);
        loaded
            .charge_load_resource(Some((NumBytes::new(bytes), &resource)))
            .unwrap();
        assert!(
            loaded.gas_used() >= copied.gas_used(),
            "a resource of {bytes} bytes loaded for {}, a copy of it {}",
            loaded.gas_used(),
            copied.gas_used()
        );
        assert_eq!(
            loaded.memory_held,
            units(&resource),
            "a loaded resource is held (B252)"
        );
    }

    /// B422 witness: a call costs a gas a local, and a generic call a gas a
    /// type argument, besides the base (both were flat whatever the frame
    /// the runtime type checks built).
    #[test]
    fn a_call_costs_by_its_locals_and_type_arguments() {
        use move_core_types::gas_algebra::NumArgs;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;
        let id = ModuleId::new(
            move_core_types::account_address::AccountAddress::ONE,
            Identifier::new("m").unwrap(),
        );
        let no_args = || std::iter::empty::<&Value>();
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter
            .charge_call(&id, "f", no_args(), NumArgs::new(0))
            .unwrap();
        assert_eq!(meter.gas_used(), CALL_BASE);
        meter
            .charge_call(&id, "f", no_args(), NumArgs::new(200))
            .unwrap();
        assert_eq!(meter.gas_used(), 2 * CALL_BASE + 200);
        struct U8;
        impl TypeView for U8 {
            fn to_type_tag(&self) -> move_core_types::language_storage::TypeTag {
                move_core_types::language_storage::TypeTag::U8
            }
        }
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        meter
            .charge_call_generic(
                &id,
                "f",
                [U8, U8, U8].into_iter(),
                no_args(),
                NumArgs::new(7),
            )
            .unwrap();
        assert_eq!(meter.gas_used(), CALL_GENERIC_BASE + 3 + 7);
    }

    /// B49 witness: copies held at once are bounded by the memory quota; a
    /// copy that is popped is credited, so a copy-and-pop loop is bounded by
    /// gas alone.
    #[test]
    fn held_copies_are_bounded_and_popped_ones_credited() {
        let big = Value::vector_u8(vec![0u8; 1 << 20]);
        let mut meter = AINCOREGasMeter::new(u64::MAX / 2);
        for _ in 0..100 {
            meter.charge_copy_loc(&big).unwrap();
            meter.charge_pop(&big).unwrap();
        }
        let fits = MEMORY_QUOTA / units(&big);
        for _ in 0..fits {
            meter.charge_copy_loc(&big).unwrap();
        }
        assert_eq!(
            meter.charge_copy_loc(&big).unwrap_err().major_status(),
            StatusCode::MEMORY_LIMIT_EXCEEDED
        );
    }
}
