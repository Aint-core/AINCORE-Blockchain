module 0x1::staking {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::chain;

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
    /// G5 EM-2: committee members and weights of different lengths.
    const EINVALID_COMMITTEE: u64 = 10;

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
    
    // === EMISSION (G5 EM-1, amendment A1): by consensus time ===
    //
    // One cap-anchored number per payout, then divide (never divide, then
    // mint: the old engine minted per validator and blew through the cap).
    // A payout draws on the REMAINING reserve for the consensus time since
    // the last payout:
    //   e = remaining x lambda x dt,  lambda = -ln(1 - 0.019) per year
    // so the reserve decays at 1.90 %/yr of what remains, in real time, at
    // any block speed. Payouts telescope: a payout that aborts is caught up
    // at the next one, and the payout period does not change the curve.
    // Derivations: docs/research/clock_and_deadlines.md, emission_rate_decision.md.
    /// lambda in 1e-18 per second of consensus time: round(-ln(0.981) /
    /// 31,557,600 s x 1e18). Realized: 1.9000 %/yr at 133 s payouts.
    const EMISSION_RATE_E18_PER_SEC: u128 = 607866866;
    /// The most consensus time one payout may cover (1 day). It bounds the
    /// arithmetic (remaining / 1e9 x rate x dt < 8e30) and the linear form's
    /// error (lambda x dt / 2 < 2.7e-5 relative); a longer gap forgoes the
    /// excess, which stays in the reserve.
    const EMISSION_SPAN_CAP_SECS: u64 = 86400;
    /// The largest stake weight a committee member can carry, in whole AIN:
    /// all of MAX_SUPPLY. Keeps pot x weight within u128.
    const MAX_WEIGHT: u128 = 150000000;
    /// Bucket split (basis points of each payout): the delegation and DePIN
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
    const MAX_BPS: u64 = 10000;
    /// G5 UB-1 (K): matured unbonding entries paid per epoch boundary, a
    /// bounded sweep like Ethereum's withdrawals.
    const MAX_PAYOUTS_PER_BOUNDARY: u64 = 256;
    
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
    
    /// Unbonding request (G5 SL-1, SL-2). The stake stopped weighting the
    /// committee at `start_height` and unlocks at `unlock_time` in consensus
    /// time (`chain::unbonding_unlock_time`): U after the end of that
    /// committee epoch. The queue is sorted by `unlock_time`.
    struct UnbondingRequest has store, drop {
        validator_addr: address,
        stake: u128,
        start_height: u64,
        unlock_time: u64,
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

    /// AUDIT-#10: read-only epoch getter so sibling modules (universal_mining)
    /// can rate-limit per-epoch without new state or layout changes.
    public fun get_current_epoch(): u64 acquires ValidatorSet {
        if (!exists<ValidatorSet>(@0x1)) {
            return 0
        };
        borrow_global<ValidatorSet>(@0x1).current_epoch
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
        
        // CRITICAL: Do NOT return stake immediately! It stays locked (and,
        // G5 SL-1, slashable) for U after its last committee epoch.
        let stake_amount = coin::value(&stake);
        coin::burn(stake); // Burn the coin (will re-mint on withdrawal)

        let unbonding_req = UnbondingRequest {
            validator_addr: addr,
            stake: stake_amount,
            start_height: chain::height(),
            unlock_time: chain::unbonding_unlock_time(),
        };
        
        vector::push_back(&mut validator_set.unbonding_queue, unbonding_req);
    }
    /// G5 UB-1: pay matured unbonding automatically. Called by
    /// epoch::advance_epoch at every committee-epoch boundary. The queue is
    /// sorted by unlock time, so matured entries are a prefix; at most
    /// MAX_PAYOUTS_PER_BOUNDARY of them are paid per boundary and the rest wait
    /// for the next one. Nothing is ever burned. This never aborts: an owner
    /// without a CoinStore (not reachable today, since joining needs one and
    /// none is ever removed) keeps its entry at the head for its own withdrawal.
    public fun pay_matured_unbonding(account: &signer) acquires ValidatorSet {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(ENOT_VALIDATOR));
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let queue = &mut validator_set.unbonding_queue;
        let now = chain::time();
        // Work from the back of the reversed queue: its head.
        vector::reverse(queue);
        let kept = vector::empty<UnbondingRequest>();
        let seen = 0;
        while (seen < MAX_PAYOUTS_PER_BOUNDARY && !vector::is_empty(queue)) {
            let len = vector::length(queue);
            if (vector::borrow(queue, len - 1).unlock_time > now) {
                break
            };
            let req = vector::pop_back(queue);
            if (coin::has_store<AincoreCoin>(req.validator_addr)) {
                let UnbondingRequest { validator_addr, stake: amount, start_height: _, unlock_time: _ } = req;
                coin::deposit<AincoreCoin>(validator_addr, coin::mint<AincoreCoin>(amount));
            } else {
                vector::push_back(&mut kept, req);
            };
            seen = seen + 1;
        };
        // Kept entries go back to the head in their original order.
        while (!vector::is_empty(&kept)) {
            vector::push_back(queue, vector::pop_back(&mut kept));
        };
        vector::destroy_empty(kept);
        vector::reverse(queue);
    }

    /// Withdraw unbonded stake (after 21 days)
    public entry fun withdraw_unbonded(account: &signer) acquires ValidatorSet {
        let addr = signer::address_of(account);
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let now = chain::time();

        let len = vector::length(&validator_set.unbonding_queue);
        let i = 0;
        let found = false;
        let index = 0;
        
        while (i < len) {
            let req = vector::borrow(&validator_set.unbonding_queue, i);
            if (req.validator_addr == addr) {
                assert!(now >= req.unlock_time, error::invalid_state(EUNBONDING_NOT_READY));
                found = true;
                index = i;
                break
            };
            i = i + 1;
        };
        
        assert!(found, error::not_found(ENO_UNBONDING_REQUEST));
        
        let unbonding_req = vector::remove(&mut validator_set.unbonding_queue, index);
        let UnbondingRequest { validator_addr: _, stake: amount, start_height: _, unlock_time: _ } = unbonding_req;
        
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

    /// G5 EM-1: consensus time of the last payout. Created at the first
    /// payout; consensus time starts at 0, so the first payout covers the
    /// chain's time from genesis.
    struct EmissionState has key {
        last_reward_time: u64,
    }

    /// G5 EP boundary (committee epoch): count it. `universal_mining` rate-
    /// limits DePIN payouts per epoch with this counter.
    public fun advance_committee_epoch(account: &signer) acquires ValidatorSet {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(ENOT_VALIDATOR));
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        validator_set.current_epoch = validator_set.current_epoch + 1;
    }

    /// G5 EM-1, EM-2: pay the emission for the consensus time since the last
    /// payout to `members`, the committee of this block's epoch (never the
    /// live set), weighted by their committee stake `weights` in whole AIN.
    /// The executor passes them, jailed members already removed. System-only:
    /// the executor binds the genuine @0x1 signer and never lets a user
    /// forge it (FIX #1), so a user calling this entry aborts.
    ///
    /// Invariants:
    ///  * e depends only on the remaining reserve and the elapsed consensus
    ///    time, computed BEFORE any division; the member count cannot inflate it.
    ///  * total_supply grows by at most e <= remaining: the cap holds.
    ///  * Division dust, and the share of a member without a CoinStore, is not
    ///    minted: it stays in the reserve.
    public entry fun pay_rewards(
        account: &signer,
        members: vector<address>,
        weights: vector<u64>,
    ) acquires ValidatorSet, EmissionPools, SupplyStats, EmissionState {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(ENOT_VALIDATOR));
        assert!(
            vector::length(&members) == vector::length(&weights),
            error::invalid_argument(EINVALID_COMMITTEE)
        );
        if (!exists<EmissionPools>(@0x1)) {
            move_to(account, EmissionPools { delegation_budget: 0, depin_budget: 0 });
        };
        if (!exists<SupplyStats>(@0x1)) {
            move_to(account, SupplyStats { cumulative_burned: 0 });
        };
        if (!exists<EmissionState>(@0x1)) {
            move_to(account, EmissionState { last_reward_time: 0 });
        };
        let now = chain::time();
        let state = borrow_global_mut<EmissionState>(@0x1);
        if (now <= state.last_reward_time) {
            return
        };
        let elapsed = now - state.last_reward_time;
        state.last_reward_time = now;
        if (elapsed > EMISSION_SPAN_CAP_SECS) {
            elapsed = EMISSION_SPAN_CAP_SECS;
        };

        let cumulative_burned = borrow_global<SupplyStats>(@0x1).cumulative_burned;
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        // AUDIT-#8 (mint cap): anchor on cumulative MINTED (net supply plus
        // burned), so no burn can free new issuance.
        let minted = validator_set.total_supply + cumulative_burned;
        if (minted >= MAX_SUPPLY) {
            return
        };
        let remaining = MAX_SUPPLY - minted;
        let e = ((remaining / 1000000000) * EMISSION_RATE_E18_PER_SEC * (elapsed as u128))
            / 1000000000;
        if (e > remaining) {
            e = remaining;
        };
        if (e == 0) {
            return
        };

        // Bucket accrual: delegation + DePIN budgets are RESERVED against
        // the cap now and drawn lazily later (mint_delegation_reward /
        // mint_depin_reward), so those streams can never race the cap.
        let delegation_cut = (e * DELEGATION_BPS) / BPS_DEN;
        let depin_cut = (e * DEPIN_BPS) / BPS_DEN;
        let val_pot = e - delegation_cut - depin_cut;

        let pools = borrow_global_mut<EmissionPools>(@0x1);
        pools.delegation_budget = pools.delegation_budget + delegation_cut;
        pools.depin_budget = pools.depin_budget + depin_cut;
        validator_set.total_supply =
            validator_set.total_supply + delegation_cut + depin_cut;

        // Committee pot: FIXED total, divided by saturation-clipped weight.
        // Adding members thins the slices; it cannot enlarge the pot.
        let len = vector::length(&members);
        if (len == 0 || val_pot == 0) {
            return
        };
        let total = 0u128;
        let k = 0;
        while (k < len) {
            total = total + bounded_weight(*vector::borrow(&weights, k));
            k = k + 1;
        };
        if (total == 0) {
            return
        };
        // Saturation point: weight above z0 earns nothing more.
        let z0 = total / SATURATION_DIVISOR;
        if (z0 == 0) {
            z0 = total;
        };
        let clipped_total = 0u128;
        let k = 0;
        while (k < len) {
            let w = bounded_weight(*vector::borrow(&weights, k));
            clipped_total = clipped_total + (if (w > z0) { z0 } else { w });
            k = k + 1;
        };

        let i = 0;
        while (i < len) {
            let w = bounded_weight(*vector::borrow(&weights, i));
            let clipped = if (w > z0) { z0 } else { w };
            let amount = (val_pot * clipped) / clipped_total;
            let member = *vector::borrow(&members, i);
            // Liquid, never compounded automatically; restaking is opt-in.
            if (amount > 0 && coin::has_store<AincoreCoin>(member)) {
                coin::deposit<AincoreCoin>(member, coin::mint<AincoreCoin>(amount));
                validator_set.total_supply = validator_set.total_supply + amount;
            };
            i = i + 1;
        };
    }

    /// A committee weight within MAX_WEIGHT, so the pot arithmetic cannot
    /// overflow whatever the executor passes.
    fun bounded_weight(w: u64): u128 {
        let w = (w as u128);
        if (w > MAX_WEIGHT) { MAX_WEIGHT } else { w }
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
                vector::push_back(&mut validator_set.unbonding_queue, UnbondingRequest {
                    validator_addr,
                    stake: remaining_amount,
                    start_height: chain::height(),
                    unlock_time: chain::unbonding_unlock_time(),
                });
            };
        };
    }
}
