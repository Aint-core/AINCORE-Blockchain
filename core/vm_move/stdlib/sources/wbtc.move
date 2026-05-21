/// Wrapped Bitcoin (wBTC) Module for AINCORE
/// 
/// This module implements a wrapped Bitcoin token that represents BTC 
/// locked in the Bitcoin multisig wallet.
/// 
/// Only the bridge authority can mint/burn wBTC.
/// 1 wBTC = 1 BTC (always 1:1 backed)
module 0x1::wbtc {
    use std::signer;
    use std::error;
    use std::vector;
    use 0x1::coin;

    /// Error codes
    const ENOT_BRIDGE_AUTHORITY: u64 = 1;
    const EINSUFFICIENT_BALANCE: u64 = 2;
    const EALREADY_INITIALIZED: u64 = 3;
    const ENOT_INITIALIZED: u64 = 4;
    const EINVALID_BTC_ADDRESS: u64 = 5;
    const MIN_BTC_ADDRESS_LEN: u64 = 14;
    const MAX_BTC_ADDRESS_LEN: u64 = 90;

    /// The wBTC coin type marker
    struct WBTC has drop {}

    /// Bridge configuration - stores the authorized bridge address
    struct BridgeConfig has key {
        authority: address,
        total_minted: u128,
        total_burned: u128,
    }

    /// Initialize the wBTC module with bridge authority
    public entry fun initialize(admin: &signer, bridge_authority: address) {
        let admin_addr = signer::address_of(admin);
        assert!(!exists<BridgeConfig>(admin_addr), error::already_exists(EALREADY_INITIALIZED));
        
        move_to(admin, BridgeConfig {
            authority: bridge_authority,
            total_minted: 0,
            total_burned: 0,
        });
    }

    /// Mint wBTC (only bridge authority can call this)
    /// Called when BTC is deposited to the multisig wallet
    public entry fun mint(
        bridge: &signer, 
        to: address, 
        amount: u128
    ) acquires BridgeConfig {
        let bridge_addr = signer::address_of(bridge);
        
        // Check bridge authority
        assert!(exists<BridgeConfig>(@0x1), error::not_found(ENOT_INITIALIZED));
        let config = borrow_global_mut<BridgeConfig>(@0x1);
        assert!(bridge_addr == config.authority, error::permission_denied(ENOT_BRIDGE_AUTHORITY));
        
        // Note: Recipient must call register() first to hold wBTC
        
        // Mint wBTC
        let wbtc_coin = coin::mint<WBTC>(amount);
        coin::deposit<WBTC>(to, wbtc_coin);
        
        // Update stats
        config.total_minted = config.total_minted + amount;
    }

    /// Burn wBTC (anyone can burn their own wBTC to withdraw BTC)
    /// Emits event for bridge to release BTC from multisig
    public entry fun burn(
        account: &signer,
        amount: u128,
        btc_address: vector<u8>  // Bitcoin address to receive BTC
    ) acquires BridgeConfig {
        let addr = signer::address_of(account);
        let btc_len = vector::length(&btc_address);
        assert!(
            btc_len >= MIN_BTC_ADDRESS_LEN && btc_len <= MAX_BTC_ADDRESS_LEN,
            error::invalid_argument(EINVALID_BTC_ADDRESS)
        );
        
        // Check balance
        assert!(coin::balance<WBTC>(addr) >= amount, error::invalid_argument(EINSUFFICIENT_BALANCE));
        
        // Withdraw and burn wBTC
        let wbtc_coin = coin::withdraw<WBTC>(account, amount);
        coin::burn<WBTC>(wbtc_coin);
        
        // Update stats
        let config = borrow_global_mut<BridgeConfig>(@0x1);
        config.total_burned = config.total_burned + amount;
        
        // Event will be emitted here for bridge to pick up
        // Bridge will then release BTC to btc_address
    }

    /// Register account to hold wBTC
    public entry fun register(account: &signer) {
        coin::register<WBTC>(account);
    }

    /// Transfer wBTC between accounts
    public entry fun transfer(from: &signer, to: address, amount: u128) {
        coin::transfer<WBTC>(from, to, amount);
    }

    /// Get wBTC balance
    public fun balance(addr: address): u128 {
        coin::balance<WBTC>(addr)
    }

    /// Get total wBTC supply (minted - burned)
    public fun total_supply(): u128 acquires BridgeConfig {
        let config = borrow_global<BridgeConfig>(@0x1);
        config.total_minted - config.total_burned
    }

    /// Get bridge authority address
    public fun get_bridge_authority(): address acquires BridgeConfig {
        borrow_global<BridgeConfig>(@0x1).authority
    }

    /// Update bridge authority (only current authority can call)
    public entry fun update_authority(
        current_authority: &signer,
        new_authority: address
    ) acquires BridgeConfig {
        let caller = signer::address_of(current_authority);
        let config = borrow_global_mut<BridgeConfig>(@0x1);
        assert!(caller == config.authority, error::permission_denied(ENOT_BRIDGE_AUTHORITY));
        
        config.authority = new_authority;
    }
}
