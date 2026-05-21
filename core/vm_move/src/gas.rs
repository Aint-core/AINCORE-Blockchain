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

pub struct AINCOREGasMeter {
    gas_limit: u64,
    gas_consumed: u64,
    schedule: GasSchedule,
}

impl AINCOREGasMeter {
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            gas_consumed: 0,
            schedule: GasSchedule::default(),
        }
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
        _val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_copy_loc(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_move_loc(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_store_loc(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_pack(
        &mut self,
        _is_generic: bool,
        _args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5)
    }

    fn charge_unpack(
        &mut self,
        _is_generic: bool,
        _args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5)
    }

    fn charge_read_ref(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_write_ref(
        &mut self,
        _new_val: impl ValueView,
        _old_val: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_eq(
        &mut self,
        _lhs: impl ValueView,
        _rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_neq(
        &mut self,
        _lhs: impl ValueView,
        _rhs: impl ValueView,
    ) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_pop(&mut self, _val: impl ValueView) -> Result<(), PartialVMError> {
        self.charge(1)
    }

    fn charge_vec_pack<'a>(
        &mut self,
        _ty: impl TypeView + 'a,
        _args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(5)
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
        _locals: impl Iterator<Item = impl ValueView>,
    ) -> Result<(), PartialVMError> {
        self.charge(2)
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
        _val: Option<impl ValueView>,
    ) -> Result<(), PartialVMError> {
        // Charge base + size if value exists
        if let Some(_val) = _val {
            // Approximation of size cost
            self.charge(self.schedule.load_base + self.schedule.storage_per_byte * 100)
        // Simplified size
        } else {
            self.charge(self.schedule.load_base)
        }
    }

    fn charge_move_to(
        &mut self,
        _is_generic: bool,
        _ty: impl TypeView,
        _val: impl ValueView,
        _already_exists: bool,
    ) -> Result<(), PartialVMError> {
        // Charge stricter storage fee for writing logic
        // We can't easily get exact byte size from ValueView without serialization cost,
        // so we charge a higher base cost + heuristic.
        // For prototype, we charge 500 gas units per write to discourage spam.
        self.charge(500)
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
