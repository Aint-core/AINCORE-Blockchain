module 0x1::coin {
    use std::signer;
    use std::error;

    /// Error codes
    const EINSUFFICIENT_BALANCE: u64 = 1;
    const EALREADY_INITIALIZED: u64 = 2;
    const ENOT_SYSTEM_MODULE: u64 = 3;

    /// === FRIEND MODULE DECLARATIONS (C1 SECURITY FIX) ===
    /// Only these system modules can call mint() and burn().
    /// User-deployed scripts CANNOT call coin::mint — preventing infinite coin exploit.
    friend 0x1::staking;
    friend 0x1::dex;
    friend 0x1::delegation;
    friend 0x1::token_factory;
    friend 0x1::treasury;
    friend 0x1::universal_mining;

    struct Coin<phantom CoinType> has store {
        value: u128,
    }

    struct CoinStore<phantom CoinType> has key {
        coin: Coin<CoinType>,
    }

    /// Mint new coins — RESTRICTED to friend modules only (C1 FIX)
    /// User scripts CANNOT call this function.
    public(friend) fun mint<CoinType>(amount: u128): Coin<CoinType> {
        Coin { value: amount }
    }

    /// Burn coins — RESTRICTED to friend modules only
    public(friend) fun burn<CoinType>(coin: Coin<CoinType>) {
        let Coin { value: _ } = coin;
    }

    /// Register an account to receive coins
    public fun register<CoinType>(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<CoinStore<CoinType>>(addr), error::already_exists(EALREADY_INITIALIZED));
        
        move_to(account, CoinStore<CoinType> {
            coin: Coin { value: 0 }
        });
    }

    /// Deposit coins into an account
    public fun deposit<CoinType>(addr: address, coin: Coin<CoinType>) acquires CoinStore {
        assert!(exists<CoinStore<CoinType>>(addr), error::not_found(EINSUFFICIENT_BALANCE));
        let store = borrow_global_mut<CoinStore<CoinType>>(addr);
        store.coin.value = store.coin.value + coin.value;
        let Coin { value: _ } = coin;
    }

    /// Withdraw coins from an account
    public fun withdraw<CoinType>(account: &signer, amount: u128): Coin<CoinType> acquires CoinStore {
        let addr = signer::address_of(account);
        assert!(exists<CoinStore<CoinType>>(addr), error::not_found(EINSUFFICIENT_BALANCE));
        
        let store = borrow_global_mut<CoinStore<CoinType>>(addr);
        assert!(store.coin.value >= amount, error::invalid_argument(EINSUFFICIENT_BALANCE));
        
        store.coin.value = store.coin.value - amount;
        Coin { value: amount }
    }

    /// Get balance of an account
    public fun balance<CoinType>(addr: address): u128 acquires CoinStore {
        if (!exists<CoinStore<CoinType>>(addr)) {
            return 0
        };
        borrow_global<CoinStore<CoinType>>(addr).coin.value
    }

    /// Transfer coins between accounts
    public entry fun transfer<CoinType>(from: &signer, to: address, amount: u128) acquires CoinStore {
        let coin = withdraw<CoinType>(from, amount);
        deposit<CoinType>(to, coin);
    }

    /// Merge two coins
    public fun merge<CoinType>(dst_coin: &mut Coin<CoinType>, src_coin: Coin<CoinType>) {
        dst_coin.value = dst_coin.value + src_coin.value;
        let Coin { value: _ } = src_coin;
    }

    /// Get value of a coin
    public fun value<CoinType>(coin: &Coin<CoinType>): u128 {
        coin.value
    }

    /// Split coin into two
    public fun split<CoinType>(coin: &mut Coin<CoinType>, amount: u128): Coin<CoinType> {
        assert!(coin.value >= amount, error::invalid_argument(EINSUFFICIENT_BALANCE));
        coin.value = coin.value - amount;
        Coin { value: amount }
    }

    /// Extract a specific amount from a coin (like split but takes amount)
    public fun extract<CoinType>(coin: &mut Coin<CoinType>, amount: u128): Coin<CoinType> {
        split(coin, amount)
    }
}
