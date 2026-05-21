/// AINCORE Native Liquidity Protocol
/// Phase 1: registry-driven CPMM pool manager.
module 0x1::dex {
    use std::ascii;
    use std::error;
    use std::signer;
    use std::type_name;
    use std::vector;
    use 0x1::coin::{Self, Coin};

    /// Error codes
    const EINVALID_LIQUIDITY: u64 = 1;
    const EINSUFFICIENT_OUTPUT: u64 = 2;
    const EPOOL_NOT_FOUND: u64 = 3;
    const EOVERFLOW: u64 = 4;
    const EDUPLICATE_POOL: u64 = 5;
    const EINVALID_PAIR: u64 = 6;
    const ENOT_SYSTEM: u64 = 7;
    const EINVALID_AMOUNT: u64 = 8;

    const MINIMUM_LIQUIDITY: u128 = 1000;
    const FIXED_FEE_BP: u64 = 30;
    const BPS_DENOMINATOR: u128 = 10000;
    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    /// Global registry for all canonical pools.
    struct PoolRegistry has key {
        pools: vector<PoolInfo>,
    }

    /// Pool metadata used by RPC/indexer/SDK clients.
    struct PoolInfo has copy, drop, store {
        pool_key: vector<u8>,
        pool_addr: address,
        token_x_name: vector<u8>,
        token_y_name: vector<u8>,
        fee_bp: u64,
        creator: address,
        active: bool,
    }

    /// Liquidity pool for canonical pair X/Y.
    struct LiquidityPool<phantom X, phantom Y> has key {
        coin_x: Coin<X>,
        coin_y: Coin<Y>,
        lp_supply: u128,
        fee_bp: u64,
    }

    /// Simplified LP balance for Phase 1.
    struct LPToken<phantom X, phantom Y> has key {
        balance: u128,
    }

    /// Initialize DEX registry at genesis.
    public fun initialize(admin: &signer) {
        assert!(signer::address_of(admin) == @0x1, error::permission_denied(ENOT_SYSTEM));
        assert!(!exists<PoolRegistry>(@0x1), error::already_exists(EDUPLICATE_POOL));
        move_to(admin, PoolRegistry { pools: vector::empty() });
    }

    /// Initialize a new canonical CPMM pool.
    public entry fun create_pool<X, Y>(creator: &signer) acquires PoolRegistry {
        let creator_addr = signer::address_of(creator);
        let (token_x_name, token_y_name) = canonical_token_names<X, Y>();
        let pool_key = make_pool_key(copy token_x_name, copy token_y_name);

        assert!(exists<PoolRegistry>(@0x1), error::not_found(EPOOL_NOT_FOUND));
        assert!(!exists<LiquidityPool<X, Y>>(creator_addr), error::already_exists(EDUPLICATE_POOL));

        let registry = borrow_global_mut<PoolRegistry>(@0x1);
        assert!(!pool_exists(&registry.pools, &pool_key), error::already_exists(EDUPLICATE_POOL));

        move_to(creator, LiquidityPool<X, Y> {
            coin_x: coin::mint<X>(0),
            coin_y: coin::mint<Y>(0),
            lp_supply: 0,
            fee_bp: FIXED_FEE_BP,
        });

        vector::push_back(&mut registry.pools, PoolInfo {
            pool_key,
            pool_addr: creator_addr,
            token_x_name,
            token_y_name,
            fee_bp: FIXED_FEE_BP,
            creator: creator_addr,
            active: true,
        });
    }

    /// Add liquidity to a canonical pool.
    public entry fun add_liquidity<X, Y>(
        account: &signer,
        pool_addr: address,
        amount_x: u128,
        amount_y: u128,
        min_lp: u128
    ) acquires PoolRegistry, LiquidityPool, LPToken {
        assert!(amount_x > 0 && amount_y > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert_registered_pool<X, Y>(pool_addr);

        let pool = borrow_global_mut<LiquidityPool<X, Y>>(pool_addr);
        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);

        let liquidity: u128;
        if (pool.lp_supply == 0) {
            assert_mul_safe(amount_x, amount_y);
            let raw_liquidity = sqrt(amount_x * amount_y);
            assert!(raw_liquidity > MINIMUM_LIQUIDITY, error::invalid_argument(EINVALID_LIQUIDITY));
            liquidity = raw_liquidity - MINIMUM_LIQUIDITY;
            pool.lp_supply = pool.lp_supply + MINIMUM_LIQUIDITY;
        } else {
            assert!(reserve_x > 0 && reserve_y > 0, error::invalid_state(EINVALID_LIQUIDITY));
            assert_mul_safe(amount_x, pool.lp_supply);
            assert_mul_safe(amount_y, pool.lp_supply);
            let share_x = (amount_x * pool.lp_supply) / reserve_x;
            let share_y = (amount_y * pool.lp_supply) / reserve_y;
            if (share_x < share_y) {
                liquidity = share_x;
            } else {
                liquidity = share_y;
            }
        };

        assert!(liquidity > 0, error::invalid_argument(EINVALID_LIQUIDITY));
        assert!(liquidity >= min_lp, error::invalid_argument(EINVALID_LIQUIDITY));

        let input_x = coin::withdraw<X>(account, amount_x);
        let input_y = coin::withdraw<Y>(account, amount_y);
        coin::merge(&mut pool.coin_x, input_x);
        coin::merge(&mut pool.coin_y, input_y);
        pool.lp_supply = pool.lp_supply + liquidity;

        let user_addr = signer::address_of(account);
        if (!exists<LPToken<X, Y>>(user_addr)) {
            move_to(account, LPToken<X, Y> { balance: 0 });
        };
        let user_lp = borrow_global_mut<LPToken<X, Y>>(user_addr);
        user_lp.balance = user_lp.balance + liquidity;
    }

    /// Remove liquidity from a canonical pool.
    public entry fun remove_liquidity<X, Y>(
        account: &signer,
        pool_addr: address,
        lp_amount: u128,
        min_x: u128,
        min_y: u128
    ) acquires PoolRegistry, LiquidityPool, LPToken {
        assert!(lp_amount > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert_registered_pool<X, Y>(pool_addr);

        let user_addr = signer::address_of(account);
        assert!(exists<LPToken<X, Y>>(user_addr), error::not_found(EINVALID_LIQUIDITY));
        let user_lp = borrow_global_mut<LPToken<X, Y>>(user_addr);
        assert!(user_lp.balance >= lp_amount, error::invalid_argument(EINVALID_LIQUIDITY));

        let pool = borrow_global_mut<LiquidityPool<X, Y>>(pool_addr);
        assert!(pool.lp_supply > 0, error::invalid_state(EINVALID_LIQUIDITY));

        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);
        assert_mul_safe(lp_amount, reserve_x);
        assert_mul_safe(lp_amount, reserve_y);
        let amount_x = (lp_amount * reserve_x) / pool.lp_supply;
        let amount_y = (lp_amount * reserve_y) / pool.lp_supply;

        assert!(amount_x >= min_x && amount_y >= min_y, error::invalid_argument(EINVALID_LIQUIDITY));
        assert!(amount_x > 0 || amount_y > 0, error::invalid_argument(EINVALID_LIQUIDITY));

        user_lp.balance = user_lp.balance - lp_amount;
        pool.lp_supply = pool.lp_supply - lp_amount;

        if (amount_x > 0) {
            let coin_x = coin::split(&mut pool.coin_x, amount_x);
            coin::deposit<X>(user_addr, coin_x);
        };
        if (amount_y > 0) {
            let coin_y = coin::split(&mut pool.coin_y, amount_y);
            coin::deposit<Y>(user_addr, coin_y);
        };
    }

    /// Swap X to Y in a canonical pool.
    public entry fun swap_x_to_y<X, Y>(
        account: &signer,
        pool_addr: address,
        amount_x_in: u128,
        min_y_out: u128
    ) acquires PoolRegistry, LiquidityPool {
        assert!(amount_x_in > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert_registered_pool<X, Y>(pool_addr);

        let pool = borrow_global_mut<LiquidityPool<X, Y>>(pool_addr);
        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);
        assert!(reserve_x > 0 && reserve_y > 0, error::invalid_state(EPOOL_NOT_FOUND));

        let amount_y_out = quote_out(amount_x_in, reserve_x, reserve_y, pool.fee_bp);
        assert!(amount_y_out >= min_y_out, error::invalid_argument(EINSUFFICIENT_OUTPUT));
        assert!(amount_y_out < reserve_y, error::invalid_argument(EINSUFFICIENT_OUTPUT));

        let coin_x = coin::withdraw<X>(account, amount_x_in);
        coin::merge(&mut pool.coin_x, coin_x);

        let coin_y = coin::split(&mut pool.coin_y, amount_y_out);
        coin::deposit<Y>(signer::address_of(account), coin_y);
    }

    /// Swap Y to X in a canonical pool.
    public entry fun swap_y_to_x<X, Y>(
        account: &signer,
        pool_addr: address,
        amount_y_in: u128,
        min_x_out: u128
    ) acquires PoolRegistry, LiquidityPool {
        assert!(amount_y_in > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert_registered_pool<X, Y>(pool_addr);

        let pool = borrow_global_mut<LiquidityPool<X, Y>>(pool_addr);
        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);
        assert!(reserve_x > 0 && reserve_y > 0, error::invalid_state(EPOOL_NOT_FOUND));

        let amount_x_out = quote_out(amount_y_in, reserve_y, reserve_x, pool.fee_bp);
        assert!(amount_x_out >= min_x_out, error::invalid_argument(EINSUFFICIENT_OUTPUT));
        assert!(amount_x_out < reserve_x, error::invalid_argument(EINSUFFICIENT_OUTPUT));

        let coin_y = coin::withdraw<Y>(account, amount_y_in);
        coin::merge(&mut pool.coin_y, coin_y);

        let coin_x = coin::split(&mut pool.coin_x, amount_x_out);
        coin::deposit<X>(signer::address_of(account), coin_x);
    }

    /// Get current reserves and pool fee.
    public fun get_reserves<X, Y>(pool_addr: address): (u128, u128, u128, u64) acquires PoolRegistry, LiquidityPool {
        assert_registered_pool<X, Y>(pool_addr);
        let pool = borrow_global<LiquidityPool<X, Y>>(pool_addr);
        (coin::value(&pool.coin_x), coin::value(&pool.coin_y), pool.lp_supply, pool.fee_bp)
    }

    fun assert_registered_pool<X, Y>(pool_addr: address) acquires PoolRegistry {
        let (token_x_name, token_y_name) = canonical_token_names<X, Y>();
        let pool_key = make_pool_key(token_x_name, token_y_name);
        assert!(exists<PoolRegistry>(@0x1), error::not_found(EPOOL_NOT_FOUND));
        let registry = borrow_global<PoolRegistry>(@0x1);
        let (found, active) = pool_status(&registry.pools, &pool_key, pool_addr);
        assert!(found && active, error::not_found(EPOOL_NOT_FOUND));
    }

    fun canonical_token_names<X, Y>(): (vector<u8>, vector<u8>) {
        let type_x = type_name::get<X>();
        let type_y = type_name::get<Y>();
        let name_x_ref = ascii::as_bytes(type_name::borrow_string(&type_x));
        let name_y_ref = ascii::as_bytes(type_name::borrow_string(&type_y));
        let name_x = *name_x_ref;
        let name_y = *name_y_ref;
        assert!(bytes_lt(&name_x, &name_y), error::invalid_argument(EINVALID_PAIR));
        (name_x, name_y)
    }

    fun make_pool_key(token_x_name: vector<u8>, token_y_name: vector<u8>): vector<u8> {
        let key = token_x_name;
        vector::push_back(&mut key, 58);
        vector::push_back(&mut key, 58);
        vector::append(&mut key, token_y_name);
        key
    }

    fun pool_exists(pools: &vector<PoolInfo>, pool_key: &vector<u8>): bool {
        let len = vector::length(pools);
        let i = 0;
        while (i < len) {
            let info = vector::borrow(pools, i);
            if (info.pool_key == *pool_key) {
                return true
            };
            i = i + 1;
        };
        false
    }

    fun pool_status(pools: &vector<PoolInfo>, pool_key: &vector<u8>, pool_addr: address): (bool, bool) {
        let len = vector::length(pools);
        let i = 0;
        while (i < len) {
            let info = vector::borrow(pools, i);
            if (info.pool_key == *pool_key && info.pool_addr == pool_addr) {
                return (true, info.active)
            };
            i = i + 1;
        };
        (false, false)
    }

    fun quote_out(amount_in: u128, reserve_in: u128, reserve_out: u128, fee_bp: u64): u128 {
        assert!(fee_bp < 10000, error::invalid_state(EINVALID_LIQUIDITY));
        let fee_multiplier = BPS_DENOMINATOR - (fee_bp as u128);
        assert_mul_safe(amount_in, fee_multiplier);
        let amount_in_with_fee = amount_in * fee_multiplier;
        assert_mul_safe(amount_in_with_fee, reserve_out);
        assert_mul_safe(reserve_in, BPS_DENOMINATOR);
        let numerator = amount_in_with_fee * reserve_out;
        let denominator = (reserve_in * BPS_DENOMINATOR) + amount_in_with_fee;
        numerator / denominator
    }

    fun assert_mul_safe(a: u128, b: u128) {
        if (a != 0) {
            assert!(b <= MAX_U128 / a, error::invalid_argument(EOVERFLOW));
        };
    }

    fun bytes_lt(left: &vector<u8>, right: &vector<u8>): bool {
        let left_len = vector::length(left);
        let right_len = vector::length(right);
        let i = 0;
        while (i < left_len && i < right_len) {
            let l = *vector::borrow(left, i);
            let r = *vector::borrow(right, i);
            if (l < r) {
                return true
            };
            if (l > r) {
                return false
            };
            i = i + 1;
        };
        left_len < right_len
    }

    fun sqrt(y: u128): u128 {
        if (y < 4) {
            if (y == 0) return 0;
            return 1
        };
        let z = y;
        let x = y / 2 + 1;
        while (x < z) {
            z = x;
            x = (y / x + x) / 2;
        };
        z
    }
}
