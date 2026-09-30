#[test_only]
/// Move unit tests for G5 SL-4 and SL-6 on the production VM: the slash
/// fraction by the weight that equivocated together, and who pays it.
///   0x10008 invalid_argument(EINVALID_OFFENSE)
module 0xcafe::slash_policy_tests {
    use 0x1::delegation;

    #[test]
    fun the_fraction_is_the_square_of_three_times_the_share() {
        // One of four equal validators: (3/4)^2 = 56.25 %.
        assert!(delegation::equivocation_bps(1, 4) == 5625, 0);
        // A tenth: 9 %. A fifth: 36 %. Three tenths: 81 %.
        assert!(delegation::equivocation_bps(10, 100) == 900, 1);
        assert!(delegation::equivocation_bps(20, 100) == 3600, 2);
        assert!(delegation::equivocation_bps(30, 100) == 8100, 3);
        // Rounded up against the offender: 9e4 x 1 / 49 = 1836.7.
        assert!(delegation::equivocation_bps(1, 7) == 1837, 4);
    }

    #[test]
    fun a_third_costs_everything() {
        assert!(delegation::equivocation_bps(1, 3) == 10000, 0);
        assert!(delegation::equivocation_bps(34, 100) == 10000, 1);
        // Just below a third: 3 x 33 < 100.
        assert!(delegation::equivocation_bps(33, 100) == 9801, 2);
        // More than the committee (neighbouring epochs): still 100 %.
        assert!(delegation::equivocation_bps(500, 100) == 10000, 3);
        // The largest weights stay inside the arithmetic: (3 x 0.98 / 3)^2.
        assert!(delegation::equivocation_bps(49000000, 150000000) == 9604, 4);
    }

    #[test]
    fun an_isolated_fault_costs_at_least_one_percent() {
        assert!(delegation::equivocation_bps(1, 100) == 100, 0);
        assert!(delegation::equivocation_bps(1, 1000) == 100, 1);
        // At 1/30 the square is exactly the floor.
        assert!(delegation::equivocation_bps(1, 30) == 100, 2);
        assert!(delegation::equivocation_bps(2, 30) == 400, 3);
    }

    #[test]
    #[expected_failure(abort_code = 0x10008, location = 0x1::delegation)]
    fun an_empty_committee_is_refused() {
        delegation::equivocation_bps(1, 0);
    }

    #[test]
    fun the_operator_pays_first() {
        // 1 % of 1,000 + 9,000 = 100 <= own 1,000: delegators untouched.
        let (own, pool) = delegation::waterfall(100, 1000, 9000);
        assert!(own == 1000 && pool == 0, 0);
        // 56.25 % of 1,000 + 1,000 = 1,125: own 100 %, pool 12.5 %.
        let (own, pool) = delegation::waterfall(5625, 1000, 1000);
        assert!(own == 10000 && pool == 1250, 1);
        // 100 %: both 100 %.
        let (own, pool) = delegation::waterfall(10000, 1000, 9000);
        assert!(own == 10000 && pool == 10000, 2);
        // No pool: the operator's own stake alone.
        let (own, pool) = delegation::waterfall(5625, 1000, 0);
        assert!(own == 5625 && pool == 0, 3);
        // Rounded up against the offender: 1 % of 1,001 over an own
        // 1,000 is 100.1 bps -> 101.
        let (own, pool) = delegation::waterfall(100, 1000, 1);
        assert!(own == 101 && pool == 0, 4);
    }
}
