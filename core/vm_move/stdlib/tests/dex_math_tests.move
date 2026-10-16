#[test_only]
/// The DEX's arithmetic at real pool sizes (AIN 18 decimals, wBTC 8), on the
/// production VM against the committed stdlib bytecode
/// (core/vm_move/src/move_unit_tests.rs). The products of two balances used
/// to be formed in u128 and abort with EOVERFLOW: at 10M AIN / 100 wBTC one
/// remove_liquidity could take ~0.01% of the pool, one add_liquidity ~1,076
/// AIN, and with 100M AIN pooled one swap ~3.4 wBTC. A test module cannot
/// mint AIN, so the entry functions' arithmetic is tested through the public
/// helpers they call; the expected values are exact constant-product amounts
/// (Python integer arithmetic), not numbers read back from a run.
module 0xcafe::dex_math_tests {
    use 0x1::coin;
    use 0x1::dex;
    use 0x1::wbtc::{Self, WBTC};

    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    /// 10M AIN and 100 wBTC in coin units.
    const POOL_AIN: u128 = 10000000000000000000000000;
    const POOL_WBTC: u128 = 10000000000;
    /// floor(sqrt(1e25 x 1e10)): the seed's LP, 1000 of it locked.
    const SEED_LP: u128 = 316227766016837933;

    #[test]
    fun the_first_deposit_takes_its_root_in_u256() {
        assert!(dex::first_liquidity(POOL_AIN, POOL_WBTC) == SEED_LP, 0);
        // The whole AIN supply against 21M BTC: 3.15e41, past u128.
        assert!(
            dex::first_liquidity(150000000000000000000000000, 2100000000000000)
                == 561248608016091207837,
            1
        );
        assert!(dex::first_liquidity(MAX_U128, MAX_U128) == MAX_U128, 2);
    }

    #[test]
    fun the_seed_position_leaves_in_one_call() {
        let (x, y) = dex::withdrawal_amounts(SEED_LP - 1000, POOL_AIN, POOL_WBTC, SEED_LP);
        // Rounded down: 9999999999.99... wBTC units pays 9999999999.
        assert!(x == 9999999999999968377223398, 0);
        assert!(y == 9999999999, 1);
    }

    #[test]
    fun a_deposit_past_1076_ain_is_taken_and_rounded_for_the_pool() {
        // 2,000 AIN and 0.02 wBTC, at the pool's price.
        let (lp, used_x, used_y) = dex::deposit_amounts(
            2000000000000000000000, 2000000, POOL_AIN, POOL_WBTC, SEED_LP
        );
        assert!(lp == 63245553203367, 0);
        // Taken rounded up: floor would take 1999999999999981450079 and
        // 1999999, a sub-unit less than the LP is worth.
        assert!(used_x == 1999999999999981450080, 1);
        assert!(used_y == 2000000, 2);
    }

    #[test]
    fun a_deposit_never_takes_more_than_it_offers() {
        // The scarcer side sets the LP; the other is taken at the pool price.
        let (lp, used_x, used_y) = dex::deposit_amounts(10, 10, 1000, 3000, 1000);
        // shares 10 and 3: lp 3, x ceil(3 x 1000 / 1000) = 3, y 9.
        assert!(lp == 3 && used_x == 3 && used_y == 9, 0);
        assert!(used_x <= 10 && used_y <= 10, 1);
    }

    #[test]
    fun a_10_wbtc_swap_is_quoted_exactly() {
        // wBTC in, AIN out, at 10M AIN and at 100M AIN pooled.
        assert!(dex::quote_out(1000000000, POOL_WBTC, POOL_AIN, 30) == 906610893880149131581340, 0);
        assert!(
            dex::quote_out(1000000000, POOL_WBTC, 100000000000000000000000000, 30)
                == 9066108938801491315813403,
            1
        );
        // AIN in: 1M AIN buys 9.06610893 wBTC, rounded down.
        assert!(dex::quote_out(1000000000000000000000000, POOL_AIN, POOL_WBTC, 30) == 906610893, 2);
    }

    #[test]
    fun a_quote_rounds_down() {
        // 9.97e9 / 1.997e7 = 499.25.
        assert!(dex::quote_out(1000, 1000, 1000, 30) == 499, 0);
    }

    /// Finding 2: a swap pays a trader who never held the output coin (the
    /// swaps pay through deposit_to_signer), and a held store is kept.
    #[test(system = @0x1, bridge = @0xb41d, bob = @0xb0b, alice = @0xa11ce)]
    fun a_payout_makes_the_missing_store(
        system: signer,
        bridge: signer,
        bob: signer,
        alice: signer
    ) {
        wbtc::initialize(&system, @0xb41d);
        wbtc::register(&bob);
        wbtc::mint(&bridge, @0xb0b, 500);
        assert!(!coin::has_store<WBTC>(@0xa11ce), 0);
        dex::deposit_to_signer(&alice, coin::withdraw<WBTC>(&bob, 300));
        assert!(coin::balance<WBTC>(@0xa11ce) == 300, 1);
        dex::deposit_to_signer(&alice, coin::withdraw<WBTC>(&bob, 200));
        assert!(coin::balance<WBTC>(@0xa11ce) == 500, 2);
        assert!(coin::balance<WBTC>(@0xb0b) == 0, 3);
    }
}
