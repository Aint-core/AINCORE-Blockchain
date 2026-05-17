module 0x1::staking {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};

    /// Error codes
    const ENOT_VALIDATOR: u64 = 1;
    const EALREADY_VALIDATOR: u64 = 2;
    const EINSUFFICIENT_STAKE: u64 = 3;
    const EUNBONDING_NOT_READY: u64 = 4;
    const ENO_UNBONDING_REQUEST: u64 = 5;

    /// Minimum stake required to join validator set (1000 AIN)
    const MIN_STAKE: u128 = 1000000000000000000000; 

    /// Tokenomics Constants (V3.0 FINAL)
    /// Max Supply: 150 Million AIN
    const MAX_SUPPLY: u128 = 150000000000000000000000000; 
    
    /// Base Reward: 36 AIN per block
    const BASE_REWARD: u128 = 36000000000000000000; 
    
    /// Halving Interval: 4 Years (2,102,400 blocks @ 60s)
    const HALVING_INTERVAL: u64 = 2102400;
    
    /// Unbonding Period: 21 days (1,814,400 seconds)
    /// This prevents Nothing-at-Stake attacks by locking stake after leaving
    const UNBONDING_PERIOD: u64 = 1814400; 
    
    /// Marker struct for AINCORE Coin
    struct AincoreCoin has drop {}

    /// Validator configuration
    struct ValidatorConfig has key, store {
        validator_addr: address,
        stake: Coin<AincoreCoin>,
        public_key: vector<u8>,
    }
    
    /// Unbonding request (stake locked for 21 days)
    struct UnbondingRequest has store, drop {
        validator_addr: address,
        stake: u128,
        unlock_time: u64, // Timestamp when stake can be withdrawn
    }

    /// Global set of active validators
    struct ValidatorSet has key {
        validators: vector<ValidatorConfig>,
        unbonding_queue: vector<UnbondingRequest>,
        total_supply: u128, // Track minted supply (u128)
        current_epoch: u64,
    }

    /// Initialize the staking module (called at genesis)
    public fun initialize(account: &signer) {
        move_to(account, ValidatorSet {
            validators: vector::empty(),
            unbonding_queue: vector::empty(),
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

    /// Request to leave the validator set (starts 21-day unbonding)
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

        // Remove from active set
        let config = vector::remove(&mut validator_set.validators, index);
        let ValidatorConfig { validator_addr: _, stake, public_key: _ } = config;
        
        // CRITICAL: Do NOT return stake immediately!
        // Lock it for 21 days to prevent Nothing-at-Stake attacks
        // Use current_epoch * 60 as proxy timestamp (each epoch ~60s)
        let current_time = validator_set.current_epoch * 60;
        let unlock_time = current_time + UNBONDING_PERIOD;
        
        let stake_amount = coin::value(&stake);
        coin::burn(stake); // Burn the coin (will re-mint on withdrawal)
        
        let unbonding_req = UnbondingRequest {
            validator_addr: addr,
            stake: stake_amount,
            unlock_time,
        };
        
        vector::push_back(&mut validator_set.unbonding_queue, unbonding_req);
    }
    /// Clean up unbonding requests that are older than grace period
    /// Called periodically by epoch::advance_epoch
    public fun cleanup_old_unbonding(account: &signer) acquires ValidatorSet {
        let addr = signer::address_of(account);
        assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));
        
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let current_time = validator_set.current_epoch * 60; // ~60s per epoch
        
        // Grace period: 21 days (unbonding) + 10 days (claim buffer) = 31 days
        let grace_period: u64 = 2678400; // 31 days in seconds
        
        let queue_len = vector::length(&validator_set.unbonding_queue);
        let i = 0;
        
        while (i < queue_len) {
            let req = vector::borrow(&validator_set.unbonding_queue, i);
            
            // If request is older than grace period, auto-burn
            if (current_time >= req.unlock_time + grace_period) {
                let old_req = vector::remove(&mut validator_set.unbonding_queue, i);
                let UnbondingRequest { validator_addr: _, stake: amount, unlock_time: _ } = old_req;
                
                // Auto-burn unclaimed stake (deflationary penalty for not withdrawing)
                // Reduce total_supply accordingly
                validator_set.total_supply = 
                    if (validator_set.total_supply >= amount) {
                        validator_set.total_supply - amount
                    } else {
                        0
                    };
                
                queue_len = queue_len - 1;
                // Don't increment i (next item shifts down)
            } else {
                i = i + 1;
            };
        };
    }

    /// Withdraw unbonded stake (after 21 days)
    public entry fun withdraw_unbonded(account: &signer) acquires ValidatorSet {
        let addr = signer::address_of(account);
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let current_time = validator_set.current_epoch * 60;
        
        let len = vector::length(&validator_set.unbonding_queue);
        let i = 0;
        let found = false;
        let index = 0;
        
        while (i < len) {
            let req = vector::borrow(&validator_set.unbonding_queue, i);
            if (req.validator_addr == addr) {
                assert!(current_time >= req.unlock_time, error::invalid_state(EUNBONDING_NOT_READY));
                found = true;
                index = i;
                break
            };
            i = i + 1;
        };
        
        assert!(found, error::not_found(ENO_UNBONDING_REQUEST));
        
        let unbonding_req = vector::remove(&mut validator_set.unbonding_queue, index);
        let UnbondingRequest { validator_addr: _, stake: amount, unlock_time: _ } = unbonding_req;
        
        // Re-mint and return stake
        let coins = coin::mint<AincoreCoin>(amount);
        coin::deposit<AincoreCoin>(addr, coins);
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

        let len = vector::length(&validator_set.validators);
        let i = 0;
        while (i < len) {
            // C2 FIX: Check supply cap INSIDE loop for EACH validator reward
            // This prevents total minted from exceeding MAX_SUPPLY with many validators
            if (validator_set.total_supply + current_reward > MAX_SUPPLY) {
                // Cap reached mid-loop -- stop minting for remaining validators
                break
            };

            let v = vector::borrow_mut(&mut validator_set.validators, i);
            
            // Mint calculated reward
            let reward_coins = coin::mint<AincoreCoin>(current_reward);
            
            // Update total supply tracker
            validator_set.total_supply = validator_set.total_supply + current_reward;
            
            coin::merge(&mut v.stake, reward_coins);
            i = i + 1;
        };
    }

    /// Safe Minting for Ecosystem Rewards (DePIN/Mining)
    /// Enforces MAX_SUPPLY hard cap.
    public fun mint_reward(amount: u128): Coin<AincoreCoin> acquires ValidatorSet {
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        
        // Hard Cap Check
        if (validator_set.total_supply + amount > MAX_SUPPLY) {
            // Cap reached: Return 0 value coin (No reward)
            return coin::mint<AincoreCoin>(0)
        };
        
        validator_set.total_supply = validator_set.total_supply + amount;
        coin::mint<AincoreCoin>(amount)
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
            let ValidatorConfig { validator_addr, stake, public_key: _ } = config;
            
            // JAIL SYSTEM: Instead of 100% burn, we slash 5% and force-unbond the rest (21 days jail)
            let total_val = coin::value(&stake);
            let slash_amount = (total_val * 5) / 100; // 5% Slashing
            let remaining_amount = total_val - slash_amount;
            
            // Extract and Burn 5% (Deflationary Penalty)
            let slash_coins = coin::extract(&mut stake, slash_amount);
            coin::burn(slash_coins);
            
            // Burn the rest to re-mint on withdrawal (same as leave_validator_set)
            coin::burn(stake);
            
            let current_time = validator_set.current_epoch * 60;
            let unlock_time = current_time + UNBONDING_PERIOD;
            
            // Push to Jail / Unbonding Queue
            vector::push_back(&mut validator_set.unbonding_queue, UnbondingRequest {
                validator_addr,
                stake: remaining_amount,
                unlock_time,
            });
        };
    }
}
