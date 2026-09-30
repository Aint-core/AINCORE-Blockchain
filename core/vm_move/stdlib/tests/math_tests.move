#[test_only]
/// Move unit tests for 0x1::math on the production VM: u256 intermediates
/// work under the production gas meter, and rounding is exact.
///   0x10001 invalid_argument(EDIVIDE_BY_ZERO)
///   0x20002 out_of_range(EOVERFLOW)
module 0xcafe::math_tests {
    use 0x1::math;

    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    #[test]
    fun products_beyond_u128_divide_back_exactly() {
        // 1.5e26 x 1.5e26 = 2.25e52, far past u128, then / 1.5e26.
        let big: u128 = 150000000000000000000000000;
        assert!(math::mul_div_floor(big, big, big) == big, 0);
        assert!(math::mul_div_ceil(big, big, big) == big, 1);
        assert!(math::mul_div_floor(MAX_U128, MAX_U128, MAX_U128) == MAX_U128, 2);
    }

    #[test]
    fun floor_and_ceil_differ_only_on_a_remainder() {
        assert!(math::mul_div_floor(10, 10, 3) == 33, 0);
        assert!(math::mul_div_ceil(10, 10, 3) == 34, 1);
        assert!(math::mul_div_floor(9, 10, 3) == 30, 2);
        assert!(math::mul_div_ceil(9, 10, 3) == 30, 3);
        assert!(math::mul_div_ceil(0, 10, 3) == 0, 4);
    }

    #[test]
    fun a_carried_remainder_loses_nothing() {
        // 10 split over 3, three times with the carry: 3 + 3 + 4 = 10.
        let (q1, r1) = math::mul_add_div(10, 1, 0, 3);
        let (q2, r2) = math::mul_add_div(10, 1, r1, 3);
        let (q3, r3) = math::mul_add_div(10, 1, r2, 3);
        assert!(q1 == 3 && r1 == 1 && q2 == 3 && r2 == 2 && q3 == 4 && r3 == 0, 0);
        // The largest operands stay inside u256: (M^2 + M - 1) / M = M rem M - 1.
        let (q, r) = math::mul_add_div(MAX_U128, MAX_U128, MAX_U128 - 1, MAX_U128);
        assert!(q == MAX_U128 && r == MAX_U128 - 1, 1);
    }

    #[test]
    #[expected_failure(abort_code = 0x10001, location = 0x1::math)]
    fun division_by_zero_is_refused() {
        math::mul_div_floor(1, 1, 0);
    }

    #[test]
    #[expected_failure(abort_code = 0x20002, location = 0x1::math)]
    fun a_result_beyond_u128_is_refused() {
        math::mul_div_floor(MAX_U128, 2, 1);
    }
}
