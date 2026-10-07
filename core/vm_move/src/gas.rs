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

/// B49: abstract value units (move-vm's abstract memory size: the bytes of a
/// vector's elements, 16 a scalar, 40 a container) per gas unit, for the
/// operations whose work grows with the value (copy, read, compare, write a
/// resource). Aptos prices them at 140 internal units per abstract unit
/// against 5,880 for an `add` (`aptos-gas-schedule`, instr.rs): one simple
/// instruction per 42 units. They were flat (1 gas to deep-copy a megabyte).
pub const ABSTRACT_UNITS_PER_GAS: u64 = 42;

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
/// credited once each though never held: at most the transaction's bytes.
pub const MEMORY_QUOTA: u64 = 10_000_000;

fn units(val: &impl ValueView) -> u64 {
    val.legacy_abstract_memory_size().into()
}

/// B246: the units `val` holds on the heap, what the memory quota counts: a
/// container's (a vector's or a struct's) legacy abstract size, nothing for
/// a scalar, an address or a reference, which live on the operand stack.
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

/// B246: what an element of type `ty` adds to its vector's heap: a primitive
/// its bytes (as the legacy size counts a primitive vector), a container
/// nothing more (its own heap, already held, moves into the vector).
fn element_heap(ty: &impl TypeView, val: &impl ValueView) -> u64 {
    if is_container(val) {
        return 0;
    }
    use move_core_types::language_storage::TypeTag;
    match ty.to_type_tag() {
        TypeTag::U8 | TypeTag::Bool => 1,
        TypeTag::U16 => 2,
        TypeTag::U32 => 4,
        TypeTag::U64 => 8,
        TypeTag::U128 => 16,
        TypeTag::U256 | TypeTag::Address => 32,
        _ => units(val),
    }
}

/// B246: what packing `fields` into a struct adds to the heap: the struct's
/// header and its scalar fields (its container fields' heap, already held,
/// moves into it).
fn packed_heap<V: ValueView>(fields: impl Iterator<Item = V>) -> u64 {
    const LEGACY_STRUCT_SIZE: u64 = 2;
    fields
        .map(|f| units(&f) - heap(&f))
        .fold(LEGACY_STRUCT_SIZE, u64::saturating_add)
}

fn by_size(units: u64) -> u64 {
    units.div_ceil(ABSTRACT_UNITS_PER_GAS)
}

pub struct AINCOREGasMeter {
    gas_limit: u64,
    gas_consumed: u64,
    schedule: GasSchedule,
    /// B49: abstract units held in copies (`MEMORY_QUOTA`).
    memory_held: u64,
}

impl AINCOREGasMeter {
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            gas_consumed: 0,
            schedule: GasSchedule::default(),
            memory_held: 0,
        }
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
        if let Some((k, val)) = loaded {
            let k_val: u64 = k.into();
            self.charge(self.schedule.load_base + k_val * self.schedule.storage_per_byte)?;
            // B252: a resource loaded is held while it is in memory (as
            // Aptos's memory tracker holds it), so a container field of it
            // overwritten through a reference is credited what was held: it
            // was credited though never held.
            self.hold(heap(&val))
        } else {
            self.charge(self.schedule.load_base)
        }
    }

    fn charge_call(
        &mut self,
        _module_id: &move_core_types::language_storage::ModuleId,
        _func_name: &str,
        _args: impl ExactSizeIterator<Item = impl Sized>,
        _num_locals: move_core_types::gas_algebra::NumArgs,
    ) -> Result<(), PartialVMError> {
        self.charge(10)
    }

    fn charge_call_generic(
        &mut self,
        _module_id: &move_core_types::language_storage::ModuleId,
        _func_name: &str,
        _ty_args: impl ExactSizeIterator<Item = impl Sized>,
        _args: impl ExactSizeIterator<Item = impl Sized>,
        _num_locals: move_core_types::gas_algebra::NumArgs,
    ) -> Result<(), PartialVMError> {
        self.charge(15)
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
        let units = units(&lhs).saturating_add(units(&rhs));
        self.charge(1 + by_size(units))?;
        self.release(heap(&lhs).saturating_add(heap(&rhs)));
        Ok(())
    }

    fn charge_neq(
        &mut self,
        lhs: impl ValueView,
        rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        let units = units(&lhs).saturating_add(units(&rhs));
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
        ty: impl TypeView + 'a,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5 + (args.len() as u64).div_ceil(4))?;
        // B246: the vector made is held (a primitive one its elements'
        // bytes; one of containers its header, their heap moving into it).
        let primitive = !matches!(
            ty.to_type_tag(),
            move_core_types::language_storage::TypeTag::Struct(_)
                | move_core_types::language_storage::TypeTag::Vector(_)
                | move_core_types::language_storage::TypeTag::Signer
        );
        let elements = args
            .map(|a| element_heap(&ty, &a))
            .fold(0, u64::saturating_add);
        self.hold(if primitive { elements } else { elements + 2 })
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
        ty: impl TypeView,
        val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(5)?;
        self.hold(element_heap(&ty, &val))
    }

    fn charge_vec_pop_back(
        &mut self,
        ty: impl TypeView,
        val: Option<impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(3)?;
        if let Some(val) = val {
            self.release(element_heap(&ty, &val));
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
        _ty: impl TypeView,
        _is_alignment: bool,
    ) -> Result<(), PartialVMError> {
        self.charge(10)
    }

    fn charge_exists(
        &mut self,
        _is_generic: bool,
        _ty: impl TypeView,
        _exists: bool,
    ) -> Result<(), PartialVMError> {
        self.charge(5)
    }

    fn charge_move_from(
        &mut self,
        _is_generic: bool,
        _ty: impl TypeView,
        val: Option<impl ValueView>,
    ) -> Result<(), PartialVMError> {
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
        _ty: impl TypeView,
        val: impl ValueView,
        _already_exists: bool,
    ) -> Result<(), PartialVMError> {
        // A write: 500 gas to discourage spam, and (B49) its size.
        self.charge(500 + by_size(units(&val)))
    }

    fn charge_vec_unpack(
        &mut self,
        ty: impl TypeView,
        _expect_num_elements: move_core_types::gas_algebra::GasQuantity<Arg>,
        elems: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5)?;
        // B246: the vector taken apart is credited as `charge_vec_pack` held
        // it (its containers' heap moves onto the stack, still held).
        let primitive = !matches!(
            ty.to_type_tag(),
            move_core_types::language_storage::TypeTag::Struct(_)
                | move_core_types::language_storage::TypeTag::Vector(_)
                | move_core_types::language_storage::TypeTag::Signer
        );
        let elements = elems
            .map(|e| element_heap(&ty, &e))
            .fold(0, u64::saturating_add);
        self.release(if primitive { elements } else { elements + 2 });
        Ok(())
    }

    // B227: a native's arguments leave the operand stack, credited (Aptos's
    // memory tracker releases them too): a value a native consumed (hashed,
    // serialized) stayed held for the rest of the transaction, so an honest
    // loop building and hashing vectors ran into the quota.
    fn charge_native_function_before_execution(
        &mut self,
        _ty_args: impl ExactSizeIterator<Item = impl TypeView>,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(2)?;
        let consumed: u64 = args.map(|a| heap(&a)).fold(0, u64::saturating_add);
        self.release(consumed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use move_vm_types::values::Value;

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
        let fits = MEMORY_QUOTA / units(&element);
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
