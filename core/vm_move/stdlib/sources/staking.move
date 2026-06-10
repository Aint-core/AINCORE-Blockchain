module 0x1::staking {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};

    // FIX #2: mint_reward inflates AIN supply and must only be reachable from
    // other system (0x1) modules. Declare the legitimate in-0x1 callers as
    // friends so `public(friend) fun mint_reward` is link-time restricted to
    // them (enforced by the Move bytecode verifier; does NOT depend on F1).
    friend 0x1::delegation;
    friend 0x1::universal_mining;

    /// Error codes
    const ENOT_VALIDATOR: u64 = 1;
    const EALREADY_VALIDATOR: u64 = 2;
    const EINSUFFICIENT_STAKE: u64 = 3;
    const EUNBONDING_NOT_READY: u64 = 4;
    const ENO_UNBONDING_REQUEST: u64 = 5;
    const EINVALID_SLASH_BPS: u64 = 6;
    const EINVALID_BLS_KEY: u64 = 7;
    const EINVALID_BLS_POP: u64 = 8;

    /// Minimum stake required to join validator set (1000 AIN)
    const MIN_STAKE: u128 = 1000000000000000000000; 

    /// Tokenomics Constants (V3.0 FINAL)
    /// Max Supply: 150 Million AIN
    const MAX_SUPPLY: u128 = 150000000000000000000000000; 
    
    /// Base Reward: 36 AIN per block
    const BASE_REWARD: u128 = 36000000000000000000; 
    
    /// Halving Interval: 4 Years (2,102,400 blocks @ 60s)
    const HALVING_INTERVAL: u64 = 2102400;
    const COIN_SCALE: u128 = 1000000000000000000;
    const EPOCH_SECONDS: u64 = 60;
    
    /// Unbonding Period: 21 days (1,814,400 seconds)
    /// This prevents Nothing-at-Stake attacks by locking stake after leaving
    const UNBONDING_PERIOD: u64 = 1814400; 
    const MAX_BPS: u64 = 10000;
    
    /// Marker struct for AINCORE Coin
    struct AincoreCoin has drop {}

    /// Validator configuration
    /// bls_public_key: 48-byte compressed BLS12-381 G1 pubkey (MinPk).
    /// bls_pop: 96-byte proof-of-possession over bls_public_key (DST_POP).
    /// PoP is verified off-chain (Rust) at genesis and join; recorded here
    /// so any node can rebuild the QC verifier set from the resource.
    struct ValidatorConfig has key, store {
        validator_addr: address,
        stake: Coin<AincoreCoin>,
        public_key: vector<u8>,
        bls_public_key: vector<u8>,
        bls_pop: vector<u8>,
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
        public_key: vector<u8>,
        bls_public_key: vector<u8>,
        bls_pop: vector<u8>
    ) acquires ValidatorSet {
        let addr = signer::address_of(account);
        assert!(stake_amount >= MIN_STAKE, error::invalid_argument(EINSUFFICIENT_STAKE));
        // BLS sizes are MinPk: pk=48 bytes (G1), pop=96 bytes (G2). The
        // pairing-based PoP check itself is done in the Rust executor BEFORE
        // dispatching this entry (Move has no BLS verifier); here we enforce
        // the structural invariant so a malformed entry can never be stored.
        assert!(vector::length(&bls_public_key) == 48, error::invalid_argument(EINVALID_BLS_KEY));
        assert!(vector::length(&bls_pop) == 96, error::invalid_argument(EINVALID_BLS_POP));

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
            bls_public_key,
            bls_pop,
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
        let ValidatorConfig { validator_addr: _, stake, public_key: _, bls_public_key: _, bls_pop: _ } = config;
        
        // CRITICAL: Do NOT return stake immediately!
        // Lock it for 21 days to prevent Nothing-at-Stake attacks
        let current_time = validator_set.current_epoch * EPOCH_SECONDS;
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
        let current_time = validator_set.current_epoch * EPOCH_SECONDS;
        
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
        let current_time = validator_set.current_epoch * EPOCH_SECONDS;
        
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
        if (len == 0 || current_reward == 0) {
            return
        };
        if (validator_set.total_supply >= MAX_SUPPLY) {
            return
        };

        let epoch_budget = current_reward * (len as u128);
        if (validator_set.total_supply + epoch_budget > MAX_SUPPLY) {
            epoch_budget = MAX_SUPPLY - validator_set.total_supply;
        };
        if (epoch_budget == 0) {
            return
        };

        let total_weight = 0u128;
        let j = 0;
        while (j < len) {
            let validator = vector::borrow(&validator_set.validators, j);
            total_weight = total_weight + (coin::value(&validator.stake) / COIN_SCALE);
            j = j + 1;
        };

        if (total_weight == 0) {
            return
        };

        let i = 0;
        while (i < len) {
            let v = vector::borrow_mut(&mut validator_set.validators, i);
            let weight = coin::value(&v.stake) / COIN_SCALE;
            let reward_amount = (epoch_budget * weight) / total_weight;
            
            if (reward_amount > 0) {
                let reward_coins = coin::mint<AincoreCoin>(reward_amount);
                validator_set.total_supply = validator_set.total_supply + reward_amount;
                coin::merge(&mut v.stake, reward_coins);
            };
            i = i + 1;
        };
    }

    /// Safe Minting for Ecosystem Rewards (DePIN/Mining)
    /// Enforces MAX_SUPPLY hard cap.
    /// FIX #2: restricted to friend modules (0x1::delegation, 0x1::universal_mining)
    /// so it can never be invoked directly by a user-published module.
    public(friend) fun mint_reward(amount: u128): Coin<AincoreCoin> acquires ValidatorSet {
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        
        // Hard Cap Check
        if (validator_set.total_supply + amount > MAX_SUPPLY) {
            // Cap reached: Return 0 value coin (No reward)
            return coin::mint<AincoreCoin>(0)
        };
        
        validator_set.total_supply = validator_set.total_supply + amount;
        coin::mint<AincoreCoin>(amount)
    }

    /// Permanently burn AIN and update the canonical supply tracker.
    public fun burn_ain(coin_to_burn: Coin<AincoreCoin>) acquires ValidatorSet {
        let amount = coin::value(&coin_to_burn);
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        validator_set.total_supply =
            if (validator_set.total_supply >= amount) {
                validator_set.total_supply - amount
            } else {
                0
            };
        coin::burn(coin_to_burn);
    }

    /// Slash a validator (burn stake and remove)
    public fun slash_validator(account: &signer, validator_addr: address) acquires ValidatorSet {
        slash_validator_bps(account, validator_addr, 500)
    }

    /// Slash a validator by basis points. Only system may call this.
    /// Downtime uses 500 bps (5%). Equivocation can use 10000 bps (100%).
    public entry fun slash_validator_bps(account: &signer, validator_addr: address, slash_bps: u64) acquires ValidatorSet {
        let addr = signer::address_of(account);
        // Only 0x1 can call this (system)
        assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));
        assert!(slash_bps <= MAX_BPS, error::invalid_argument(EINVALID_SLASH_BPS));

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
            let ValidatorConfig { validator_addr, stake, public_key: _, bls_public_key: _, bls_pop: _ } = config;
            
            let total_val = coin::value(&stake);
            let slash_amount = (total_val * (slash_bps as u128)) / (MAX_BPS as u128);
            let remaining_amount = total_val - slash_amount;
            
            // Extract and burn the slash amount as a deflationary penalty.
            let slash_coins = coin::extract(&mut stake, slash_amount);
            coin::burn(slash_coins);
            validator_set.total_supply =
                if (validator_set.total_supply >= slash_amount) {
                    validator_set.total_supply - slash_amount
                } else {
                    0
                };
            
            // Burn the rest to re-mint on withdrawal (same as leave_validator_set).
            coin::burn(stake);

            if (remaining_amount > 0) {
                let current_time = validator_set.current_epoch * EPOCH_SECONDS;
                let unlock_time = current_time + UNBONDING_PERIOD;
                vector::push_back(&mut validator_set.unbonding_queue, UnbondingRequest {
                    validator_addr,
                    stake: remaining_amount,
                    unlock_time,
                });
            };
        };
    }
}
