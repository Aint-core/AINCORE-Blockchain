/// Delegation Module for AINCORE
/// Allows users to delegate stake to validators without running their own node.
/// Implements Cosmos-style delegation with commission and reward distribution.
module 0x1::delegation {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::staking::AincoreCoin;
    use 0x1::epoch;

    /// Error codes
    const EVALIDATOR_NOT_FOUND: u64 = 1;
    const EINSUFFICIENT_DELEGATION: u64 = 2;
    const ENO_DELEGATION: u64 = 3;
    const EUNBONDING_NOT_READY: u64 = 4;
    const EINVALID_COMMISSION: u64 = 5;
    const ECOMMISSION_CHANGE_TOO_SOON: u64 = 6;

    /// Minimum delegation amount: 1 AIN
    const MIN_DELEGATION: u128 = 1000000000000000000;
    
    /// Maximum commission: 30%
    const MAX_COMMISSION: u64 = 3000; // Basis points (3000 = 30%)
    
    /// Commission change notice period: 7 days
    const COMMISSION_CHANGE_DELAY: u64 = 604800;
    
    /// Unbonding period: 21 days (same as validators)
    const UNBONDING_PERIOD: u64 = 1814400;

    /// Individual delegation record
    struct Delegation has store, drop {
        delegator: address,
        amount: u128,
        reward_debt: u128, // For reward tracking (accumulated rewards already claimed)
    }

    /// Unbonding delegation (locked for 21 days)
    struct UnbondingDelegation has store, drop {
        delegator: address,
        amount: u128,
        unlock_time: u64,
    }

    /// Validator pool that accepts delegations
    struct ValidatorPool has key {
        validator_addr: address,
        commission_rate: u64,         // Basis points (100 = 1%)
        pending_commission: u64,      // New commission rate (pending)
        commission_change_time: u64,  // When commission change takes effect
        total_delegated: u128,
        delegations: vector<Delegation>,
        unbonding_queue: vector<UnbondingDelegation>,
        accumulated_rewards_per_share: u128, // Scaled by 1e18 for precision
        pending_rewards: u128,        // Rewards waiting to be distributed
        escrowed_coins: Coin<AincoreCoin>, // M2 FIX: Hold coins instead of burn/mint
    }

    /// Global delegation registry
    struct DelegationRegistry has key {
        validator_pools: vector<address>, // List of validators accepting delegations
    }

    /// Initialize the delegation module (called at genesis)
    public fun initialize(account: &signer) {
        move_to(account, DelegationRegistry {
            validator_pools: vector::empty(),
        });
    }

    /// Validator opts-in to accept delegations
    public entry fun enable_delegation(
        validator: &signer,
        commission_rate: u64
    ) acquires DelegationRegistry {
        let addr = signer::address_of(validator);
        
        // Validate commission rate
        assert!(commission_rate <= MAX_COMMISSION, error::invalid_argument(EINVALID_COMMISSION));
        
        // Create validator pool
        move_to(validator, ValidatorPool {
            validator_addr: addr,
            commission_rate,
            pending_commission: commission_rate,
            commission_change_time: 0,
            total_delegated: 0,
            delegations: vector::empty(),
            unbonding_queue: vector::empty(),
            accumulated_rewards_per_share: 0,
            pending_rewards: 0,
            escrowed_coins: coin::mint<AincoreCoin>(0), // M2 FIX: Empty escrow
        });
        
        // Register in global registry
        let registry = borrow_global_mut<DelegationRegistry>(@0x1);
        vector::push_back(&mut registry.validator_pools, addr);
    }

    /// Delegate tokens to a validator
    public entry fun delegate(
        delegator: &signer,
        validator_addr: address,
        amount: u128
    ) acquires ValidatorPool {
        let delegator_addr = signer::address_of(delegator);
        
        // Validate amount
        assert!(amount >= MIN_DELEGATION, error::invalid_argument(EINSUFFICIENT_DELEGATION));
        
        // Get validator pool
        assert!(exists<ValidatorPool>(validator_addr), error::not_found(EVALIDATOR_NOT_FOUND));
        let pool = borrow_global_mut<ValidatorPool>(validator_addr);
        
        // Withdraw coins from delegator
        let coins = coin::withdraw<AincoreCoin>(delegator, amount);
        
        // Check if delegator already has delegation to this validator
        let len = vector::length(&pool.delegations);
        let i = 0;
        let found = false;
        
        while (i < len) {
            let d = vector::borrow_mut(&mut pool.delegations, i);
            if (d.delegator == delegator_addr) {
                // Claim pending rewards first
                let pending = calculate_pending_reward(d, pool.accumulated_rewards_per_share);
                if (pending > 0) {
                    let reward_coins = 0x1::staking::mint_reward(pending);
                    if (coin::value(&reward_coins) > 0) {
                        coin::deposit<AincoreCoin>(delegator_addr, reward_coins);
                    } else {
                        coin::burn(reward_coins);
                    }
                };
                
                // Update delegation
                d.amount = d.amount + amount;
                d.reward_debt = (d.amount * pool.accumulated_rewards_per_share) / 1000000000000000000;
                found = true;
                break
            };
            i = i + 1;
        };
        
        if (!found) {
            // New delegation
            let reward_debt = (amount * pool.accumulated_rewards_per_share) / 1000000000000000000;
            vector::push_back(&mut pool.delegations, Delegation {
                delegator: delegator_addr,
                amount,
                reward_debt,
            });
        };
        
        // Update total delegated
        pool.total_delegated = pool.total_delegated + amount;
        
        // M2 FIX: Hold coins in escrow instead of burning (prevents supply bypass)
        coin::merge(&mut pool.escrowed_coins, coins);
    }

    /// Undelegate tokens (starts 21-day unbonding)
    public entry fun undelegate(
        delegator: &signer,
        validator_addr: address,
        amount: u128
    ) acquires ValidatorPool {
        let delegator_addr = signer::address_of(delegator);
        
        assert!(exists<ValidatorPool>(validator_addr), error::not_found(EVALIDATOR_NOT_FOUND));
        let pool = borrow_global_mut<ValidatorPool>(validator_addr);
        
        // Find delegation
        let len = vector::length(&pool.delegations);
        let i = 0;
        let found = false;
        let index = 0;
        
        while (i < len) {
            let d = vector::borrow(&pool.delegations, i);
            if (d.delegator == delegator_addr) {
                assert!(d.amount >= amount, error::invalid_argument(EINSUFFICIENT_DELEGATION));
                found = true;
                index = i;
                break
            };
            i = i + 1;
        };
        
        assert!(found, error::not_found(ENO_DELEGATION));
        
        // Claim pending rewards first
        let d = vector::borrow_mut(&mut pool.delegations, index);
        let pending = calculate_pending_reward(d, pool.accumulated_rewards_per_share);
        if (pending > 0) {
            let reward_coins = 0x1::staking::mint_reward(pending);
            if (coin::value(&reward_coins) > 0) {
                coin::deposit<AincoreCoin>(delegator_addr, reward_coins);
            } else {
                coin::burn(reward_coins);
            }
        };
        
        // Reduce delegation
        d.amount = d.amount - amount;
        d.reward_debt = (d.amount * pool.accumulated_rewards_per_share) / 1000000000000000000;
        
        // Remove if zero
        if (d.amount == 0) {
            vector::remove(&mut pool.delegations, index);
        };
        
        // Update total
        pool.total_delegated = pool.total_delegated - amount;
        
        // Add to unbonding queue
        let current_time = epoch::now_seconds();
        vector::push_back(&mut pool.unbonding_queue, UnbondingDelegation {
            delegator: delegator_addr,
            amount,
            unlock_time: current_time + UNBONDING_PERIOD,
        });
    }

    /// Withdraw unbonded tokens (after 21 days)
    public entry fun withdraw_unbonded(
        delegator: &signer,
        validator_addr: address
    ) acquires ValidatorPool {
        let delegator_addr = signer::address_of(delegator);
        let current_time = epoch::now_seconds();
        
        assert!(exists<ValidatorPool>(validator_addr), error::not_found(EVALIDATOR_NOT_FOUND));
        let pool = borrow_global_mut<ValidatorPool>(validator_addr);
        
        // Find and process unbonding delegations
        let len = vector::length(&pool.unbonding_queue);
        let i = 0;
        let total_withdraw = 0u128;
        let to_remove = vector::empty<u64>();
        
        while (i < len) {
            let ud = vector::borrow(&pool.unbonding_queue, i);
            if (ud.delegator == delegator_addr && current_time >= ud.unlock_time) {
                total_withdraw = total_withdraw + ud.amount;
                vector::push_back(&mut to_remove, i);
            };
            i = i + 1;
        };
        
        assert!(total_withdraw > 0, error::not_found(EUNBONDING_NOT_READY));
        
        // Remove processed entries (reverse order to maintain indices)
        let j = vector::length(&to_remove);
        while (j > 0) {
            j = j - 1;
            let idx = *vector::borrow(&to_remove, j);
            vector::remove(&mut pool.unbonding_queue, idx);
        };
        
        // M2 FIX: Return tokens from escrow instead of minting new ones
        let coins = coin::split(&mut pool.escrowed_coins, total_withdraw);
        coin::deposit<AincoreCoin>(delegator_addr, coins);
    }

    /// Claim pending rewards without undelegating
    public entry fun claim_rewards(
        delegator: &signer,
        validator_addr: address
    ) acquires ValidatorPool {
        let delegator_addr = signer::address_of(delegator);
        
        assert!(exists<ValidatorPool>(validator_addr), error::not_found(EVALIDATOR_NOT_FOUND));
        let pool = borrow_global_mut<ValidatorPool>(validator_addr);
        
        // Find delegation
        let len = vector::length(&pool.delegations);
        let i = 0;
        
        while (i < len) {
            let d = vector::borrow_mut(&mut pool.delegations, i);
            if (d.delegator == delegator_addr) {
                let pending = calculate_pending_reward(d, pool.accumulated_rewards_per_share);
                if (pending > 0) {
                    let reward_coins = 0x1::staking::mint_reward(pending);
                    if (coin::value(&reward_coins) > 0) {
                        coin::deposit<AincoreCoin>(delegator_addr, reward_coins);
                    } else {
                        coin::burn(reward_coins);
                    }
                };
                d.reward_debt = (d.amount * pool.accumulated_rewards_per_share) / 1000000000000000000;
                return
            };
            i = i + 1;
        };
        
        abort error::not_found(ENO_DELEGATION)
    }

    /// Update commission rate (requires 7-day notice)
    public entry fun update_commission(
        validator: &signer,
        new_commission: u64
    ) acquires ValidatorPool {
        let addr = signer::address_of(validator);
        
        assert!(new_commission <= MAX_COMMISSION, error::invalid_argument(EINVALID_COMMISSION));
        assert!(exists<ValidatorPool>(addr), error::not_found(EVALIDATOR_NOT_FOUND));
        
        let pool = borrow_global_mut<ValidatorPool>(addr);
        let current_time = epoch::now_seconds();
        
        // Set pending commission change
        pool.pending_commission = new_commission;
        pool.commission_change_time = current_time + COMMISSION_CHANGE_DELAY;
    }

    /// Apply pending commission change (after 7 days)
    public entry fun apply_commission_change(
        validator: &signer
    ) acquires ValidatorPool {
        let addr = signer::address_of(validator);
        let current_time = epoch::now_seconds();
        
        assert!(exists<ValidatorPool>(addr), error::not_found(EVALIDATOR_NOT_FOUND));
        let pool = borrow_global_mut<ValidatorPool>(addr);
        
        assert!(current_time >= pool.commission_change_time, error::invalid_state(ECOMMISSION_CHANGE_TOO_SOON));
        
        pool.commission_rate = pool.pending_commission;
    }

    /// Distribute rewards to delegators (called by system after block production)
    /// This updates the accumulated_rewards_per_share for the pool
    public fun distribute_delegation_rewards(
        validator_addr: address,
        total_reward: u128
    ) acquires ValidatorPool {
        if (!exists<ValidatorPool>(validator_addr)) {
            return
        };
        
        let pool = borrow_global_mut<ValidatorPool>(validator_addr);
        
        if (pool.total_delegated == 0) {
            return
        };
        
        // Calculate commission
        let commission = (total_reward * (pool.commission_rate as u128)) / 10000;
        let delegator_reward = total_reward - commission;
        
        // Commission goes to validator
        if (commission > 0) {
            let commission_coins = 0x1::staking::mint_reward(commission);
            if (coin::value(&commission_coins) > 0) {
                coin::deposit<AincoreCoin>(validator_addr, commission_coins);
            } else {
                coin::burn(commission_coins);
            }
        };
        
        // Update accumulated rewards per share (scaled by 1e18)
        let reward_per_share = (delegator_reward * 1000000000000000000) / pool.total_delegated;
        pool.accumulated_rewards_per_share = pool.accumulated_rewards_per_share + reward_per_share;
    }

    /// Helper: Calculate pending reward for a delegation
    fun calculate_pending_reward(d: &Delegation, accumulated_per_share: u128): u128 {
        let accumulated = (d.amount * accumulated_per_share) / 1000000000000000000;
        if (accumulated > d.reward_debt) {
            accumulated - d.reward_debt
        } else {
            0
        }
    }

    /// View: Get delegation info
    #[view]
    public fun get_delegation(
        delegator: address,
        validator_addr: address
    ): (u128, u128) acquires ValidatorPool {
        if (!exists<ValidatorPool>(validator_addr)) {
            return (0, 0)
        };
        
        let pool = borrow_global<ValidatorPool>(validator_addr);
        let len = vector::length(&pool.delegations);
        let i = 0;
        
        while (i < len) {
            let d = vector::borrow(&pool.delegations, i);
            if (d.delegator == delegator) {
                let pending = calculate_pending_reward(d, pool.accumulated_rewards_per_share);
                return (d.amount, pending)
            };
            i = i + 1;
        };
        
        (0, 0)
    }

    /// View: Get validator pool info
    #[view]
    public fun get_pool_info(validator_addr: address): (u128, u64, u64) acquires ValidatorPool {
        if (!exists<ValidatorPool>(validator_addr)) {
            return (0, 0, 0)
        };
        
        let pool = borrow_global<ValidatorPool>(validator_addr);
        let num_delegators = vector::length(&pool.delegations);
        
        (pool.total_delegated, pool.commission_rate, (num_delegators as u64))
    }
}
