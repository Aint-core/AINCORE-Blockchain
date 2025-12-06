module 0x1::staking {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};

    /// Error codes
    const ENOT_VALIDATOR: u64 = 1;
    const EALREADY_VALIDATOR: u64 = 2;
    const EINSUFFICIENT_STAKE: u64 = 3;

    /// Minimum stake required to join validator set (1000 AIN)
    const MIN_STAKE: u128 = 1000000000000000000000; 

    /// Tokenomics Constants (Year 3000 Ready)
    /// Max Supply: 1 Trillion AIN (10^12) * 10^18 decimals = 10^30 units
    const MAX_SUPPLY: u128 = 1000000000000000000000000000000; 
    
    /// Base Reward: 50 AIN per epoch
    const BASE_REWARD: u128 = 50000000000000000000; 
    
    /// Halving Interval: 10 Years (approx 315M blocks @ 1s)
    const HALVING_INTERVAL: u64 = 315360000; 
    
    /// Marker struct for AINCORE Coin
    struct AincoreCoin has drop {}

    /// Validator configuration
    struct ValidatorConfig has key, store {
        validator_addr: address,
        stake: Coin<AincoreCoin>,
        public_key: vector<u8>,
    }

    /// Global set of active validators
    struct ValidatorSet has key {
        validators: vector<ValidatorConfig>,
        total_supply: u128, // Track minted supply (u128)
        current_epoch: u64,
    }

    /// Initialize the staking module (called at genesis)
    public fun initialize(account: &signer) {
        move_to(account, ValidatorSet {
            validators: vector::empty(),
            total_supply: 0,
            current_epoch: 0,
        });
    }

    /// Join the validator set
    public entry fun join_validator_set(
        account: &signer,
        stake_amount: u128,
        public_key: vector<u8>
    ) acquires ValidatorSet {
        let addr = signer::address_of(account);
        assert!(stake_amount >= MIN_STAKE, error::invalid_argument(EINSUFFICIENT_STAKE));

        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        
        // Check if already a validator
        let len = vector::length(&validator_set.validators);
        let i = 0;
        while (i < len) {
            let v = vector::borrow(&validator_set.validators, i);
            assert!(v.validator_addr != addr, error::already_exists(EALREADY_VALIDATOR));
            i = i + 1;
        };

        // Withdraw stake from user account
        let stake = coin::withdraw<AincoreCoin>(account, stake_amount);

        // Add to validator set
        vector::push_back(&mut validator_set.validators, ValidatorConfig {
            validator_addr: addr,
            stake,
            public_key,
        });
    }

    /// Leave the validator set
    public entry fun leave_validator_set(account: &signer) acquires ValidatorSet {
        let addr = signer::address_of(account);
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        
        let len = vector::length(&validator_set.validators);
        let i = 0;
        let found = false;
        let index = 0;

        while (i < len) {
            let v = vector::borrow(&validator_set.validators, i);
            if (v.validator_addr == addr) {
                found = true;
                index = i;
                break
            };
            i = i + 1;
        };

        assert!(found, error::not_found(ENOT_VALIDATOR));

        // Remove from set and return stake
        let config = vector::remove(&mut validator_set.validators, index);
        let ValidatorConfig { validator_addr: _, stake, public_key: _ } = config;
        
        // Return stake to user
        coin::deposit<AincoreCoin>(addr, stake);
    }

    /// Add more stake
    public entry fun add_stake(account: &signer, amount: u128) acquires ValidatorSet {
        let addr = signer::address_of(account);
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        
        let len = vector::length(&validator_set.validators);
        let i = 0;
        while (i < len) {
            let v = vector::borrow_mut(&mut validator_set.validators, i);
            if (v.validator_addr == addr) {
                let new_stake = coin::withdraw<AincoreCoin>(account, amount);
                coin::merge(&mut v.stake, new_stake);
                return
            };
            i = i + 1;
        };
        abort error::not_found(ENOT_VALIDATOR)
    }

    /// Calculate Halving Reward
    fun calculate_reward(epoch: u64): u128 {
        let halvings = epoch / HALVING_INTERVAL;
        if (halvings >= 128) { return 0 }; // u128 limit
        let reward = BASE_REWARD >> (halvings as u8);
        reward
    }

    /// Distribute rewards to all validators (Inflation Logic)
    public fun distribute_rewards(account: &signer) acquires ValidatorSet {
        let addr = signer::address_of(account);
        // Only 0x1 can call this (system)
        assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));

        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        
        // Update Epoch
        validator_set.current_epoch = validator_set.current_epoch + 1;
        let current_reward = calculate_reward(validator_set.current_epoch);

        // Stop minting if Max Supply reached
        if (validator_set.total_supply >= MAX_SUPPLY) {
            return
        };

        let len = vector::length(&validator_set.validators);
        let i = 0;
        while (i < len) {
            let v = vector::borrow_mut(&mut validator_set.validators, i);
            
            // Mint calculated reward
            let reward_coins = coin::mint<AincoreCoin>(current_reward);
            
            // Update total supply tracker
            validator_set.total_supply = validator_set.total_supply + current_reward;
            
            coin::merge(&mut v.stake, reward_coins);
            i = i + 1;
        };
    }

    /// Slash a validator (burn stake and remove)
    public fun slash_validator(account: &signer, validator_addr: address) acquires ValidatorSet {
        let addr = signer::address_of(account);
        // Only 0x1 can call this (system)
        assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));

        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let len = vector::length(&validator_set.validators);
        let i = 0;
        let found = false;
        let index = 0;

        while (i < len) {
            let v = vector::borrow(&validator_set.validators, i);
            if (v.validator_addr == validator_addr) {
                found = true;
                index = i;
                break
            };
            i = i + 1;
        };

        if (found) {
            let config = vector::remove(&mut validator_set.validators, index);
            let ValidatorConfig { validator_addr: _, stake, public_key: _ } = config;
            // Burn the stake (Deflationary Event)
            coin::burn(stake);
        };
    }
}
