module 0x1::staking {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};

    // FIX #2: the pool mints (mint_delegation_reward / mint_depin_reward)
    // create AIN and must only be reachable from other system (0x1) modules.
    // Declare the legitimate in-0x1 callers as friends so the public(friend)
    // mints are link-time restricted to them (enforced by the Move bytecode
    // verifier; does NOT depend on F1).
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
    /// AUDIT-#2: active validator set is full
    const EMAX_VALIDATORS: u64 = 9;

    /// Minimum stake required to join validator set (1000 AIN)
    const MIN_STAKE: u128 = 1000000000000000000000;

    /// AUDIT-#2 FIX: hard cap on the active validator set. `advance_epoch`
    /// runs O(N) reward loops under a bounded per-epoch gas budget; without a
    /// cap a growing (or sybil-flooded) set eventually OOG-aborts the epoch tx,
    /// permanently halting ALL emission + the governance driver. 1000 is far
    /// above any realistic BFT active set and well below the OOG threshold.
    const MAX_VALIDATORS: u64 = 1000;

    /// Tokenomics Constants (V3.0 FINAL)
    /// Max Supply: 150 Million AIN
    const MAX_SUPPLY: u128 = 150000000000000000000000000; 
    
    // === EMISSION v4: top-down, cap-anchored budget ===
    //
    // Design axiom: mint ONE cap-anchored number per epoch, then divide.
    // Never divide, then mint. The previous engine did the inverse
    // (BASE_REWARD x validator_count per epoch), so total emission SCALED
    // WITH VALIDATOR COUNT and blew through the 150M cap in ~10 months,
    // before the first halving could ever fire.
    //
    // Per-epoch drawdown of the REMAINING reserve:
    //   e_epoch = remaining * DRAW_NUM / DRAW_DEN
    // At a ~20s epoch cadence this emits ~11.4%/yr of the remaining
    // reserve (annual decay ~0.88, reserve half-life ~5.4y, ~95% of the
    // emission budget inside ~23.5y). Smooth geometric decay -- no halving
    // cliffs -- and independent of validator count by construction.
    // NOTE: the horizon assumes the ~20s epoch cadence; faster epoch
    // advancement compresses it (total stays cap-bounded regardless).
    const DRAW_NUM: u128 = 81;
    const DRAW_DEN: u128 = 1000000000;
    /// Bucket split (basis points of e_epoch): the delegation and DePIN
    /// mint streams accrue into cap-reserved pool budgets; validators
    /// receive the remainder.
    ///
    /// AUDIT-#4 FIX: both set to 0 until the reward-DISTRIBUTION paths are
    /// wired. Reason: `distribute_delegation_rewards` (which advances
    /// `accumulated_rewards_per_share`) currently has ZERO callers, so a
    /// non-zero delegation cut accrued into `total_supply` every epoch but
    /// could never be paid to delegators -- permanently stranding ~5% of the
    /// emission budget against the 150M cap. Routing 100% of e_epoch to
    /// validators (the one distribution path that IS wired) is cap-safe,
    /// N-independent, and loses nothing. To re-enable a stream, set its BPS
    /// AND wire its per-pool distribution into `epoch::advance_epoch`.
    const DELEGATION_BPS: u128 = 0;
    const DEPIN_BPS: u128 = 0;
    const BPS_DEN: u128 = 10000;
    /// Saturation clip (Cardano-k / Polkadot style): a validator's payout
    /// weight is capped at total_stake / SATURATION_DIVISOR. Flattens
    /// reward concentration for HONEST distributions; it is NOT
    /// sybil-proof (a whale can split identities) -- documented limitation.
    const SATURATION_DIVISOR: u128 = 50;

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

    /// EMISSION v4: accrued, cap-reserved budgets for the non-validator mint
    /// streams (delegation rewards, DePIN universal_mining). Amounts here were
    /// already counted against MAX_SUPPLY at accrual time in
    /// `distribute_rewards`, so drawing from a pool mints WITHOUT touching
    /// `total_supply` -- the cap cannot be raced by independent minters.
    /// Unused budget carries forward across epochs (empty-epoch sink).
    struct EmissionPools has key {
        delegation_budget: u128,
        depin_budget: u128,
    }

    /// AUDIT-#8 FIX (BTC mint-cap): monotonic cumulative-burn ledger. The
    /// emission anchor keys off cumulative MINTED = ValidatorSet.total_supply
    /// (which stays NET of burns, preserving the circulating==net API model)
    /// + SupplyStats.cumulative_burned. Every burn does net -= d AND
    /// cumulative_burned += d, so `minted` is invariant under burns and
    /// `remaining = MAX_SUPPLY - minted` is monotonic non-increasing -- burnt
    /// coins can NEVER be re-minted as fresh emission. This is an INDEPENDENT
    /// resource: the ValidatorSet byte layout is untouched (no BCS-mirror hard
    /// fork). It is fed by BOTH the in-VM Move burn sites here AND the Rust-
    /// native fee burn (executor `burn_supply_trackers` writes this same
    /// resource key directly). Absent => treated as 0; lazy-created like
    /// EmissionPools.
    struct SupplyStats has key {
        cumulative_burned: u128,
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

        // AUDIT-#2 FIX: bound the active set so advance_epoch's O(N) reward
        // loops can never exhaust the epoch gas budget and halt emission.
        let len = vector::length(&validator_set.validators);
        assert!((len as u64) < MAX_VALIDATORS, error::invalid_state(EMAX_VALIDATORS));

        // Check if already a validator
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
    public fun cleanup_old_unbonding(account: &signer) acquires ValidatorSet, SupplyStats {
        let addr = signer::address_of(account);
        assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));

        // AUDIT-#8: ensure the burn ledger exists before we may credit it below
        // (signer is @0x1 here). Keeps cumulative MINTED invariant under the
        // auto-burn of unclaimed stake.
        if (!exists<SupplyStats>(@0x1)) {
            move_to(account, SupplyStats { cumulative_burned: 0 });
        };

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
                
                // Auto-burn unclaimed stake (deflationary penalty for not withdrawing).
                // AUDIT-#8: reduce net total_supply AND credit the burn ledger by the
                // SAME clamped delta so cumulative MINTED (net + burned) is invariant.
                let removed = if (validator_set.total_supply >= amount) {
                    amount
                } else {
                    validator_set.total_supply
                };
                validator_set.total_supply = validator_set.total_supply - removed;
                let stats = borrow_global_mut<SupplyStats>(@0x1);
                stats.cumulative_burned = stats.cumulative_burned + removed;
                
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

    /// EMISSION v4: distribute rewards from ONE top-down, cap-anchored
    /// per-epoch budget. Replaces the old `BASE_REWARD x validator_count`
    /// engine (total emission scaled with N -- more validators literally
    /// minted more AIN and the cap blew through in ~10 months).
    ///
    /// Invariants:
    ///  * e_epoch is computed BEFORE any division and depends only on
    ///    (MAX_SUPPLY - total_supply) -- validator count and stream count
    ///    cannot inflate it.
    ///  * total_supply grows by exactly (pool accruals + actual validator
    ///    payouts) <= e_epoch <= remaining -- the cap holds at every epoch.
    ///  * Division dust is NOT minted: it stays in the remaining reserve.
    public fun distribute_rewards(account: &signer) acquires ValidatorSet, EmissionPools, SupplyStats {
        let addr = signer::address_of(account);
        // Only 0x1 can call this (system)
        assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));

        // Lazy-create the pool budgets resource (signer is @0x1 here).
        if (!exists<EmissionPools>(@0x1)) {
            move_to(account, EmissionPools { delegation_budget: 0, depin_budget: 0 });
        };
        // AUDIT-#8: lazy-create the cumulative-burn ledger (signer is @0x1 here).
        if (!exists<SupplyStats>(@0x1)) {
            move_to(account, SupplyStats { cumulative_burned: 0 });
        };
        let cumulative_burned = borrow_global<SupplyStats>(@0x1).cumulative_burned;

        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);

        // Update Epoch
        validator_set.current_epoch = validator_set.current_epoch + 1;

        // AUDIT-#8 (BTC mint-cap): anchor emission on cumulative MINTED, not net
        // supply. minted = total_supply (net of burns) + cumulative_burned. A burn
        // does net -= d and cumulative_burned += d, leaving `minted` invariant, so
        // no burn can free new issuance -- `remaining` is monotonic non-increasing.
        let minted = validator_set.total_supply + cumulative_burned;
        if (minted >= MAX_SUPPLY) {
            return
        };
        let remaining = MAX_SUPPLY - minted;

        // Master budget: geometric drawdown of the remaining reserve.
        // remaining < 1.5e26 and DRAW_NUM = 81, so remaining * DRAW_NUM
        // < 1.3e28 -- far below u128::MAX; no overflow. Cap-safe by
        // construction (DRAW_NUM << DRAW_DEN) plus a defensive clamp.
        let e_epoch = (remaining * DRAW_NUM) / DRAW_DEN;
        if (e_epoch > remaining) {
            e_epoch = remaining;
        };
        if (e_epoch == 0) {
            return
        };

        // Bucket accrual: delegation + DePIN budgets are RESERVED against
        // the cap now and drawn lazily later (mint_delegation_reward /
        // mint_depin_reward), so those streams can never race the cap.
        let delegation_cut = (e_epoch * DELEGATION_BPS) / BPS_DEN;
        let depin_cut = (e_epoch * DEPIN_BPS) / BPS_DEN;
        let val_pot = e_epoch - delegation_cut - depin_cut;

        let pools = borrow_global_mut<EmissionPools>(@0x1);
        pools.delegation_budget = pools.delegation_budget + delegation_cut;
        pools.depin_budget = pools.depin_budget + depin_cut;
        validator_set.total_supply =
            validator_set.total_supply + delegation_cut + depin_cut;

        // Validator pot: FIXED total, divided by saturation-clipped stake
        // weight. Adding validators thins the slices; it cannot enlarge
        // the pot.
        let len = vector::length(&validator_set.validators);
        if (len == 0 || val_pot == 0) {
            return
        };

        let total_stake = 0u128;
        let j = 0;
        while (j < len) {
            let validator = vector::borrow(&validator_set.validators, j);
            total_stake = total_stake + coin::value(&validator.stake);
            j = j + 1;
        };
        if (total_stake == 0) {
            return
        };

        // Saturation point: stake above z0 earns no additional weight.
        let z0 = total_stake / SATURATION_DIVISOR;
        if (z0 == 0) {
            z0 = total_stake;
        };

        // Weights in whole-AIN units so `val_pot * weight` cannot overflow
        // u128 (val_pot < 1.3e19 base units, weight < 1.5e8 whole AIN).
        let total_weight = 0u128;
        let k = 0;
        while (k < len) {
            let validator = vector::borrow(&validator_set.validators, k);
            let s = coin::value(&validator.stake);
            let clipped = if (s > z0) { z0 } else { s };
            total_weight = total_weight + (clipped / COIN_SCALE);
            k = k + 1;
        };
        if (total_weight == 0) {
            return
        };

        let i = 0;
        while (i < len) {
            let v = vector::borrow_mut(&mut validator_set.validators, i);
            let s = coin::value(&v.stake);
            let clipped = if (s > z0) { z0 } else { s };
            let weight = clipped / COIN_SCALE;
            let reward_amount = (val_pot * weight) / total_weight;

            if (reward_amount > 0) {
                let reward_coins = coin::mint<AincoreCoin>(reward_amount);
                validator_set.total_supply =
                    validator_set.total_supply + reward_amount;
                // Liquid disposition (kills AUTOMATIC compounding -- the
                // rich-get-richer feedback loop): deposit to the
                // validator's CoinStore when one is registered. Fall back
                // to merging into stake so the epoch can never abort.
                // Restaking remains possible via add_stake (opt-in).
                if (coin::has_store<AincoreCoin>(v.validator_addr)) {
                    coin::deposit<AincoreCoin>(v.validator_addr, reward_coins);
                } else {
                    coin::merge(&mut v.stake, reward_coins);
                };
            };
            i = i + 1;
        };
        // val_pot - sum of  payouts (division dust) is intentionally unminted.
    }

    /// EMISSION v4: pool-bounded mint for the DELEGATION reward stream.
    /// The pool budget was already reserved against MAX_SUPPLY at accrual
    /// time in `distribute_rewards`, so this does NOT touch total_supply
    /// and can never race the cap. Grants min(amount, pool); returns a
    /// zero-value coin when the pool is dry (caller already handles 0).
    /// FIX #2 retained: public(friend), unreachable from user modules.
    public(friend) fun mint_delegation_reward(amount: u128): Coin<AincoreCoin> acquires EmissionPools {
        if (!exists<EmissionPools>(@0x1)) {
            return coin::mint<AincoreCoin>(0)
        };
        let pools = borrow_global_mut<EmissionPools>(@0x1);
        let grant = if (amount > pools.delegation_budget) {
            pools.delegation_budget
        } else {
            amount
        };
        pools.delegation_budget = pools.delegation_budget - grant;
        coin::mint<AincoreCoin>(grant)
    }

    /// EMISSION v4: pool-bounded mint for the DePIN (universal_mining)
    /// reward stream. Same reservation semantics as
    /// `mint_delegation_reward`; per-proof draws are bounded by the accrued
    /// pool with carry-forward across empty epochs.
    public(friend) fun mint_depin_reward(amount: u128): Coin<AincoreCoin> acquires EmissionPools {
        if (!exists<EmissionPools>(@0x1)) {
            return coin::mint<AincoreCoin>(0)
        };
        let pools = borrow_global_mut<EmissionPools>(@0x1);
        let grant = if (amount > pools.depin_budget) {
            pools.depin_budget
        } else {
            amount
        };
        pools.depin_budget = pools.depin_budget - grant;
        coin::mint<AincoreCoin>(grant)
    }

    /// Permanently burn AIN and update the canonical supply tracker.
    public fun burn_ain(coin_to_burn: Coin<AincoreCoin>) acquires ValidatorSet, SupplyStats {
        let amount = coin::value(&coin_to_burn);
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        // AUDIT-#8: reduce net total_supply by the clamped delta.
        let removed = if (validator_set.total_supply >= amount) {
            amount
        } else {
            validator_set.total_supply
        };
        validator_set.total_supply = validator_set.total_supply - removed;
        // AUDIT-#8: credit the burn ledger if it exists. There is no signer here
        // to create it, but the Rust fee burn and epoch advance create it very
        // early in chain life, so it is effectively always present by the time
        // any burn_ain matters. Keeps cumulative MINTED (net + burned) invariant.
        if (exists<SupplyStats>(@0x1)) {
            let stats = borrow_global_mut<SupplyStats>(@0x1);
            stats.cumulative_burned = stats.cumulative_burned + removed;
        };
        coin::burn(coin_to_burn);
    }

    /// Slash a validator (burn stake and remove)
    public fun slash_validator(account: &signer, validator_addr: address) acquires ValidatorSet, SupplyStats {
        slash_validator_bps(account, validator_addr, 500)
    }

    /// Slash a validator by basis points. Only system may call this.
    /// Downtime uses 500 bps (5%). Equivocation can use 10000 bps (100%).
    public entry fun slash_validator_bps(account: &signer, validator_addr: address, slash_bps: u64) acquires ValidatorSet, SupplyStats {
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
            // AUDIT-#8: reduce net total_supply AND credit the burn ledger by the
            // SAME clamped delta so cumulative MINTED (net + burned) is invariant.
            let removed = if (validator_set.total_supply >= slash_amount) {
                slash_amount
            } else {
                validator_set.total_supply
            };
            validator_set.total_supply = validator_set.total_supply - removed;
            if (!exists<SupplyStats>(@0x1)) {
                move_to(account, SupplyStats { cumulative_burned: 0 });
            };
            let stats = borrow_global_mut<SupplyStats>(@0x1);
            stats.cumulative_burned = stats.cumulative_burned + removed;
            
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
