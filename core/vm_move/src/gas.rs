use move_binary_format::errors::PartialVMError;
use move_core_types::gas_algebra::{Arg, InternalGas, NumBytes};
use move_core_types::vm_status::StatusCode;
use move_vm_types::gas::GasMeter;
use move_vm_types::views::{TypeView, ValueView};
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

/// B49: the abstract value units a transaction may hold in copies at once
/// (Aptos `memory_quota`, 10,000,000). A copy counts when it is made and is
/// credited when it is popped, compared, overwritten through a reference or
/// dropped with its frame; a value overwritten in a local is not credited
/// (stricter than Aptos, which tracks every drop).
pub const MEMORY_QUOTA: u64 = 10_000_000;

fn units(val: &impl ValueView) -> u64 {
    val.legacy_abstract_memory_size().into()
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

    fn charge_native_function(
        &mut self,
        _amount: InternalGas,
        _ret_vals: Option<impl ExactSizeIterator<Item = impl Sized>>,
    ) -> Result<(), PartialVMError> {
        let val: u64 = _amount.into();
        self.charge(val)
    }

    fn charge_load_resource(
        &mut self,
        _loaded: Option<(NumBytes, impl ValueView)>,
    ) -> Result<(), PartialVMError> {
        if let Some((k, _)) = _loaded {
            let k_val: u64 = k.into();
            self.charge(self.schedule.load_base + k_val * self.schedule.storage_per_byte)
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
        self.hold(units(&val))
    }

    fn charge_copy_loc(&mut self, val: impl ValueView) -> Result<(), PartialVMError> {
        let units = units(&val);
        self.charge(1 + by_size(units))?;
        self.hold(units)
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
        self.charge(5 + (args.len() as u64).div_ceil(4))
    }

    fn charge_unpack(
        &mut self,
        _is_generic: bool,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5 + (args.len() as u64).div_ceil(4))
    }

    fn charge_read_ref(&mut self, val: impl ValueView) -> Result<(), PartialVMError> {
        let units = units(&val);
        self.charge(1 + by_size(units))?;
        self.hold(units)
    }

    fn charge_write_ref(
        &mut self,
        _new_val: impl ValueView,
        old_val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        let old = units(&old_val);
        self.charge(1 + by_size(old))?;
        self.release(old);
        Ok(())
    }

    fn charge_eq(
        &mut self,
        lhs: impl ValueView,
        rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        let units = units(&lhs).saturating_add(units(&rhs));
        self.charge(1 + by_size(units))?;
        self.release(units);
        Ok(())
    }

    fn charge_neq(
        &mut self,
        lhs: impl ValueView,
        rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        let units = units(&lhs).saturating_add(units(&rhs));
        self.charge(1 + by_size(units))?;
        self.release(units);
        Ok(())
    }

    fn charge_pop(&mut self, val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)?;
        self.release(units(&val));
        Ok(())
    }

    fn charge_vec_pack<'a>(
        &mut self,
        _ty: impl TypeView + 'a,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5 + (args.len() as u64).div_ceil(4))
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

    fn charge_vec_push_back(
        &mut self,
        _ty: impl TypeView,
        _val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(5)
    }

    fn charge_vec_pop_back(
        &mut self,
        _ty: impl TypeView,
        _val: Option<impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(3)
    }

    fn charge_vec_swap(&mut self, _ty: impl TypeView) -> Result<(), PartialVMError> {
        self.charge(3)
    }

    fn charge_drop_frame(
        &mut self,
        locals: impl Iterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(2)?;
        let dropped: u64 = locals.map(|l| units(&l)).fold(0, u64::saturating_add);
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
            )
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
        _ty: impl TypeView,
        _expect_num_elements: move_core_types::gas_algebra::GasQuantity<Arg>,
        _elems: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5)
    }

    fn charge_native_function_before_execution(
        &mut self,
        _ty_args: impl ExactSizeIterator<Item = impl TypeView>,
        _args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(2)
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
