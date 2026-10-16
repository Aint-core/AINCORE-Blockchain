#[test_only]
/// Move unit tests for G5 DL-2 on the production VM: what a pool's
/// delegators and its commission take from the pool's part of a payout.
/// The part is sized by the pool's frozen weight in the committee; only the
/// principal still in the pool earns it (B451). A test module cannot mint
/// AIN or move the clock, so `pay_rewards` draws nothing here; the split is
/// checked through `delegation::pool_payout`, the function `pay_member`
/// computes it with. The call in `pay_member` is pinned through real blocks
/// by the executor's `g5_a_pool_pays_only_the_principal_still_at_stake`.
module 0xcafe::pool_reward_tests {
    use 0x1::delegation;

    /// One AIN in coin units.
    const AIN: u128 = 1000000000000000000;
    const MAX_U128: u128 = 340282366920938463463374607431768211455;
    const MAX_U64: u64 = 18446744073709551615;
    /// A pool's part of one payout at launch: about 12.3 AIN drawn every
    /// 135 s, a pool of 1,000,000 AIN against W = s_min = 18.5 M.
    const PART: u128 = 665000000000000000;
    /// A payout's pot at launch: about 12.3 AIN every 135 s.
    const POT: u128 = 12300000000000000000;

    /// B451 witness: every delegator of a pool that weighed 1,000,000 AIN in
    /// the committee left early in the epoch, and a 2 AIN position stayed.
    /// It earns 2 / 1,000,000 of the part, as it would have had nobody left,
    /// and the commission is on that; the rest stays in the reserve. Before,
    /// the whole part was spread over its points: 0.5985 AIN a payout, about
    /// 30 AIN over the epoch's 50 payouts, 15 times its stake, and the
    /// validator kept the commission on the leavers' weight.
    #[test]
    fun a_pool_its_delegators_left_pays_only_what_stayed() {
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 2 * AIN, 1000);
        // floor(0.665e18 x 2e18 / 1e24) = 1.33e12, 10 % of it the commission.
        assert!(commission == 133000000000 && reward == 1197000000000, 0);
        assert!((commission + reward) * 1000000 <= PART * 2, 1);
        // Half the pool left: the half that stayed earns its rate per AIN
        // unchanged, and the commission is 10 % of what it earns. Of the
        // whole part it would be 66.5e15, leaving 266e15 to the pool.
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 500000 * AIN, 1000);
        assert!(commission == 33250000000000000 && reward == 299250000000000000, 2);
        // No commission: the reward is the earned part itself.
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 500000 * AIN, 0);
        assert!(commission == 0 && reward == PART / 2, 3);
    }

    /// The same exodus, then a 1 AIN joiner: no one needs to hold dust in
    /// advance to collect the leavers' part, a delegation made after they
    /// left earned from the next payout. Now the 3 AIN left in the pool earn
    /// 3 / 1,000,000 of the part, the joiner its third: exactly the rate the
    /// frozen weight earns per AIN, never more (about 0.22 AIN a payout
    /// before, 11 AIN an epoch for 1 AIN).
    #[test]
    fun a_joiner_after_an_exodus_earns_no_more_than_the_frozen_rate() {
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 3 * AIN, 0);
        assert!(commission == 0 && reward == 1995000000000, 0);
        assert!(reward * 1000000 == PART * 3, 1);
        // Rounded down, toward the reserve: 1,000 units of a 1 AIN weight
        // on one unit less than 1 AIN.
        let (commission, reward) = delegation::pool_payout(1000, 1, AIN - 1, 0);
        assert!(commission == 0 && reward == 999, 2);
        // Nothing left: nothing earned.
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 0, 1000);
        assert!(commission == 0 && reward == 0, 3);
    }

    /// A pool that still holds its weight is paid the whole part, as before:
    /// the executor records the weight as the principal's whole AIN, so with
    /// nobody leaving the principal is never below it. Joiners share the
    /// part (DL-2's accepted residual: their weight counts from the next
    /// epoch). The largest weight the executor can pass cannot overflow.
    #[test]
    fun a_pool_that_holds_its_weight_is_paid_its_whole_part() {
        // Exactly the weight, and the 0.7 AIN the whole-AIN weight drops.
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 1000000 * AIN, 1000);
        assert!(commission == 66500000000000000 && reward == 598500000000000000, 0);
        let (commission, reward) =
            delegation::pool_payout(PART, 3000, 3000 * AIN + 7 * AIN / 10, 1000);
        assert!(commission == 66500000000000000 && reward == 598500000000000000, 1);
        // 500 AIN joined during the epoch: still the part, no more.
        let (commission, reward) = delegation::pool_payout(PART, 1000000, 1000500 * AIN, 1000);
        assert!(commission == 66500000000000000 && reward == 598500000000000000, 2);
        // u64::MAX whole AIN is 1.8e37 coins, inside u128.
        let (commission, reward) =
            delegation::pool_payout(150000000 * AIN, MAX_U64, MAX_U128, 3000);
        assert!(commission == 45000000 * AIN && reward == 105000000 * AIN, 3);
        let (commission, reward) = delegation::pool_payout(150000000 * AIN, MAX_U64, 0, 3000);
        assert!(commission == 0 && reward == 0, 4);
    }

    /// B464 witness (G5 PA-2): a member's share is its weight's share of the
    /// pot times its participation in the period paid, in parts per million,
    /// rounded down; what it did not take part for stays in the reserve. A
    /// member of 1,000,000 of 18,500,000 that took part in every round is
    /// paid 0.6649 AIN, in half of them half, in none nothing (it was paid in
    /// full before). A count above one million is a full share, never more.
    #[test]
    fun a_member_is_paid_by_its_participation() {
        let full = delegation::participation_share(POT, 1000000, 18500000, 1000000);
        assert!(full == 664864864864864864, 0);
        assert!(delegation::participation_share(POT, 1000000, 18500000, 500000) == full / 2, 1);
        assert!(delegation::participation_share(POT, 1000000, 18500000, 0) == 0, 2);
        assert!(delegation::participation_share(POT, 1000000, 18500000, 2000000) == full, 3);
        // Rounded down at both steps, toward the reserve: floor(10 / 3) = 3,
        // then floor(3 x 999,999 / 1,000,000) = 2.
        assert!(delegation::participation_share(10, 1, 3, 999999) == 2, 4);
        // The whole supply as one member's weight and the pot cannot
        // overflow.
        let all = delegation::participation_share(150000000 * AIN, 150000000, 150000000, 1000000);
        assert!(all == 150000000 * AIN, 5);
    }
}
