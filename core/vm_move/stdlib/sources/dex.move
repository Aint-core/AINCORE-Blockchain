/// Decentralized Exchange (DEX) Module
/// Implements Constant Product AMM (x * y = k)
module 0x1::dex {
    use std::signer;
    use 0x1::coin::{Self, Coin};

    /// Error codes
    const EINVALID_LIQUIDITY: u64 = 1;
    const EINSUFFICIENT_OUTPUT: u64 = 2;
    const EPOOL_NOT_FOUND: u64 = 3;

    /// Liquidity Pool for pair X/Y
    struct LiquidityPool<phantom X, phantom Y> has key {
        coin_x: Coin<X>,
        coin_y: Coin<Y>,
        lp_supply: u128,
        fee_bp: u64, // 30 = 0.3%
    }

    /// Tracking User LP tokens (simplified)
    struct LPToken<phantom X, phantom Y> has key {
        balance: u128
    }

    /// Helper for square root
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

    /// Initialize a new pool for X/Y pair
    public entry fun create_pool<X, Y>(admin: &signer) {
        move_to(admin, LiquidityPool<X, Y> {
            coin_x: coin::mint<X>(0),
            coin_y: coin::mint<Y>(0),
            lp_supply: 0,
            fee_bp: 30,
        });
    }

    /// Add liquidity to the pool
    public entry fun add_liquidity<X, Y>(
        account: &signer,
        amount_x: u128,
        amount_y: u128
    ) acquires LiquidityPool, LPToken {
        let pool = borrow_global_mut<LiquidityPool<X, Y>>(@0x1);
        
        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);
        
        let liquidity: u128;
        if (pool.lp_supply == 0) {
            liquidity = sqrt(amount_x * amount_y);
        } else {
            let share_x = (amount_x * pool.lp_supply) / reserve_x;
            let share_y = (amount_y * pool.lp_supply) / reserve_y;
            if (share_x < share_y) {
                liquidity = share_x;
            } else {
                liquidity = share_y;
            }
        };
        
        assert!(liquidity > 0, EINVALID_LIQUIDITY);
        
        // Transfer tokens to pool
        let input_x = coin::withdraw<X>(account, amount_x);
        let input_y = coin::withdraw<Y>(account, amount_y);
        
        coin::merge(&mut pool.coin_x, input_x);
        coin::merge(&mut pool.coin_y, input_y);
        
        pool.lp_supply = pool.lp_supply + liquidity;
        
        // Mint LP tokens to user
        let user_addr = signer::address_of(account);
        if (!exists<LPToken<X, Y>>(user_addr)) {
            move_to(account, LPToken<X, Y> { balance: 0 });
        };
        let user_lp = borrow_global_mut<LPToken<X, Y>>(user_addr);
        user_lp.balance = user_lp.balance + liquidity;
    }

    /// Swap X to Y
    public entry fun swap_x_to_y<X, Y>(
        account: &signer,
        amount_x_in: u128,
        min_y_out: u128
    ) acquires LiquidityPool {
        let pool = borrow_global_mut<LiquidityPool<X, Y>>(@0x1);
        
        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);
        
        // Calculate output with 0.3% fee
        let amount_x_with_fee = amount_x_in * (10000 - (pool.fee_bp as u128));
        let numerator = amount_x_with_fee * reserve_y;
        let denominator = (reserve_x * 10000) + amount_x_with_fee;
        let amount_y_out = numerator / denominator;
        
        assert!(amount_y_out >= min_y_out, EINSUFFICIENT_OUTPUT);
        
        // Execute swap
        let coin_x = coin::withdraw<X>(account, amount_x_in);
        coin::merge(&mut pool.coin_x, coin_x);
        
        let coin_y = coin::split(&mut pool.coin_y, amount_y_out);
        coin::deposit<Y>(signer::address_of(account), coin_y);
    }
    
    /// Swap Y to X
    public entry fun swap_y_to_x<X, Y>(
        account: &signer,
        amount_y_in: u128,
        min_x_out: u128
    ) acquires LiquidityPool {
        let pool = borrow_global_mut<LiquidityPool<X, Y>>(@0x1);
        
        let reserve_x = coin::value(&pool.coin_x);
        let reserve_y = coin::value(&pool.coin_y);
        
        // Calculate output with 0.3% fee
        let amount_y_with_fee = amount_y_in * (10000 - (pool.fee_bp as u128));
        let numerator = amount_y_with_fee * reserve_x;
        let denominator = (reserve_y * 10000) + amount_y_with_fee;
        let amount_x_out = numerator / denominator;
        
        assert!(amount_x_out >= min_x_out, EINSUFFICIENT_OUTPUT);
        
        // Execute swap
        let coin_y = coin::withdraw<Y>(account, amount_y_in);
        coin::merge(&mut pool.coin_y, coin_y);
        
        let coin_x = coin::split(&mut pool.coin_x, amount_x_out);
        coin::deposit<X>(signer::address_of(account), coin_x);
    }
    
    /// Get current reserves
    public fun get_reserves<X, Y>(): (u128, u128) acquires LiquidityPool {
        let pool = borrow_global<LiquidityPool<X, Y>>(@0x1);
        (coin::value(&pool.coin_x), coin::value(&pool.coin_y))
    }
}
