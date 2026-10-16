#[test_only]
/// Move unit tests for G5 SL-4 and SL-6 on the production VM: the slash
/// fraction by the weight that equivocated together, and who pays it.
///   0x10008 invalid_argument(EINVALID_OFFENSE)
module 0xcafe::slash_policy_tests {
    use std::vector;
    use 0x1::delegation;
    use 0x1::staking;

    /// One AIN in coin units.
    const AIN: u128 = 1000000000000000000;

    fun one(a: u128): vector<u128> {
        let v = vector::empty<u128>();
        vector::push_back(&mut v, a);
        v
    }

    fun two(a: u128, b: u128): vector<u128> {
        let v = one(a);
        vector::push_back(&mut v, b);
        v
    }

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

    /// B392 witness: the operator's own stake is cut by its fraction of what
    /// it had at stake in the offense's committee (its frozen own weight,
    /// plus the part of an AIN whole-AIN weights drop), never of stake added
    /// after the offense epoch began. Own 1,000 with a pool of 99,000: a 1 %
    /// fault is 100 % of the own stake. Before, every in-scope entry was cut
    /// by that fraction of all it held, so an `add_stake` of 9,000 after the
    /// epoch began (one entry of 10,000 at acceptance) lost all 10,000, and
    /// fresh coins after leaving and joining again (a second entry) all of
    /// them. `add_stake` is an entry function a test module cannot call, so
    /// the entries are given as `slash_unbonding` hands them over.
    #[test]
    fun stake_added_after_the_offense_epoch_is_not_cut() {
        let (own, pool) = delegation::waterfall(100, 1000, 99000);
        assert!(own == 10000 && pool == 0, 0);
        // An add_stake of 9,000 after the epoch began: 1,001 of 10,000
        // (all 10,000 before).
        let cuts = staking::own_slash_cuts(&one(10000 * AIN), 1000, own);
        assert!(cuts == one(1001 * AIN), 1);
        // Left in the epoch (1,000), then joined again with 5,000 fresh
        // coins: the oldest entry pays first, the rejoin at most the part
        // of an AIN (all 5,000 before).
        let cuts = staking::own_slash_cuts(&two(1000 * AIN, 5000 * AIN), 1000, own);
        assert!(cuts == two(1000 * AIN, AIN), 2);
        // A partial fraction: 56.25 % of the 1,001 at stake, all from the
        // oldest entry.
        let cuts = staking::own_slash_cuts(&two(1000 * AIN, 5000 * AIN), 1000, 5625);
        assert!(cuts == two(5630625 * AIN / 10000, 0), 3);
        // Nothing added: as before, the fraction of what the entry holds.
        let cuts = staking::own_slash_cuts(&one(1000 * AIN), 1000, 5625);
        assert!(cuts == one(5625 * AIN / 10), 4);
        // Rounded up against the offender: 1 bps of 10,001 units is 2.
        let cuts = staking::own_slash_cuts(&one(10001), 0, 1);
        assert!(cuts == one(2), 5);
    }

    /// B411 witness: a certificate conflict that raises a lesser offense of
    /// an earlier epoch is cut by what its own committee had at stake. A
    /// twin in epoch 5 at own 1,000 and no pool, then the stake grown to
    /// 1,000,000 own and 5,000,000 delegated, and a conflict in epoch 7:
    /// the scope stays 5 and the split is epoch 7's. Before, the twin's
    /// split was kept, so the 100 % cut 1,001 of the 1,000,000 own and 1 AIN
    /// of the pool. Only pure functions are reachable from a test module
    /// (no @0x1 signer), so the raise is checked through `raised_split` and
    /// the own cut through `own_slash_cuts`, as `record` hands them over.
    #[test]
    fun a_later_conflict_cuts_what_its_committee_had_at_stake() {
        let (scope, s, d) = delegation::raised_split(5, 1000, 0, 7, 1000000, 5000000);
        assert!(scope == 5 && s == 1000000 && d == 5000000, 0);
        let (own, pool) = delegation::waterfall(10000, s, d);
        assert!(own == 10000 && pool == 10000, 1);
        // All 1,000,000 own coins, unbonded in one entry at acceptance
        // (1,001 before).
        let cuts = staking::own_slash_cuts(&one(1000000 * AIN), s, own);
        assert!(cuts == one(1000000 * AIN), 2);
        // A stake that shrank between them keeps the larger, earlier side;
        // the pool side is still the conflict's.
        let (scope, s, d) = delegation::raised_split(5, 2000, 300, 7, 1000, 500);
        assert!(scope == 5 && s == 2000 && d == 500, 3);
        // A conflict before the offense (B161): its scope and its split.
        let (scope, s, d) = delegation::raised_split(7, 1000000, 5000000, 5, 1000, 0);
        assert!(scope == 5 && s == 1000 && d == 0, 4);
    }
}
