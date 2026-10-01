module 0x1::staking {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::chain;

    // FIX #2: the mints (the emission draw, mint_depin_reward) create AIN and
    // must only be reachable from other system (0x1) modules. Declare the
    // legitimate in-0x1 callers as friends so the public(friend) mints are
    // link-time restricted to them (enforced by the Move bytecode verifier;
    // does NOT depend on F1). `delegation` pays the emission (G5 DL-2);
    // `universal_mining` draws the DePIN budget.
    friend 0x1::delegation;
    friend 0x1::universal_mining;

    /// Error codes
    const ENOT_VALIDATOR: u64 = 1;
    const EALREADY_VALIDATOR: u64 = 2;
    const EINSUFFICIENT_STAKE: u64 = 3;
    const EUNBONDING_NOT_READY: u64 = 4;
    const ENO_UNBONDING_REQUEST: u64 = 5;
    const EINVALID_BLS_KEY: u64 = 7;
    const EINVALID_BLS_POP: u64 = 8;
    /// AUDIT-#2: active validator set is full
    const EMAX_VALIDATORS: u64 = 9;
    /// G5 SL-3: another active validator holds this BLS key.
    const EDUPLICATE_BLS_KEY: u64 = 10;
    /// G5 review (A3b): stake under an unsettled offense is not paid out.
    const EPAYOUT_FROZEN: u64 = 11;
    /// G5 CH-1: this epoch's allowance of new stake is used up.
    const ECHURN_LIMIT: u64 = 12;

    /// G5 CH-1 (`docs/research/churn_limit.md`): stake added to the active
    /// set within one committee epoch is at most this share of the epoch
    /// committee's stake, in basis points (10 %, Aptos mainnet's
    /// `voting_power_increase_limit` on a 2 h epoch).
    const CHURN_INCREASE_BPS: u128 = 1000;
    const BPS: u128 = 10000;

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
    /// The DePIN share of each draw (basis points), reserved against the cap
    /// into `EmissionPools.depin_budget` and drawn by `universal_mining`.
    /// AUDIT-#4: 0 until DePIN distribution is wired, so no emission is
    /// stranded. Delegators are paid from the committee payout itself
    /// (G5 DL-2, `delegation::pay_rewards`), not from a separate stream.
    const DEPIN_BPS: u128 = 0;
    const BPS_DEN: u128 = 10000;

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

    /// G5 review (A3b): validators with an offense recorded and not yet
    /// settled, at @0x1. Their unbonding entries of `from_epoch` or later are
    /// in the slash's scope and are not paid until settlement thaws them, so
    /// a settlement that is late (or keeps aborting) cannot let slashable
    /// stake leave unslashed.
    struct FrozenPayouts has key {
        scopes: vector<FrozenScope>,
    }

    struct FrozenScope has store, drop, copy {
        validator: address,
        from_epoch: u64,
    }

    /// G5 CH-1: the stake added to the active set in committee epoch `epoch`
    /// (`added`), against that epoch committee's total stake (`base`), both
    /// in quanta. Genesis writes epoch 0's and the executor rewrites it at
    /// every boundary with `added` at 0; nothing in Move creates it. A chain
    /// without it (a test fixture) has no limit.
    struct ChurnState has key {
        epoch: u64,
        base: u128,
        added: u128,
    }

    /// EMISSION v4: the accrued, cap-reserved budget of the DePIN mint
    /// stream (universal_mining). Amounts here were already counted against
    /// MAX_SUPPLY when drawn (`draw_emission`), so drawing from the budget
    /// mints WITHOUT touching `total_supply` -- the cap cannot be raced by
    /// independent minters. Unused budget carries forward.
    struct EmissionPools has key {
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

    /// Join the validator set.
    ///
    /// G5 review: `entry`, never `public`. The executor verifies the BLS
    /// proof of possession, refuses a tombstoned validator and keeps the
    /// committee's set in step only for a transaction that calls this
    /// directly; a module call would skip all three. The same holds for
    /// `leave_validator_set` and `add_stake`.
    entry fun join_validator_set(
        account: &signer,
        stake_amount: u128,
        public_key: vector<u8>,
        bls_public_key: vector<u8>,
        bls_pop: vector<u8>
    ) acquires ValidatorSet, ChurnState {
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
        // G5 review (A3b): a full set does not freeze membership. A joiner
        // with more stake than the smallest member displaces it, which starts
        // unbonding like a leaver (the committee is the top 256 by stake, so
        // the smallest of a full set is never in it).
        if ((vector::length(&validator_set.validators) as u64) >= MAX_VALIDATORS) {
            let (smallest, smallest_stake) = (0, coin::value(&vector::borrow(&validator_set.validators, 0).stake));
            let j = 1;
            while (j < vector::length(&validator_set.validators)) {
                let s = coin::value(&vector::borrow(&validator_set.validators, j).stake);
                if (s < smallest_stake) {
                    smallest = j;
                    smallest_stake = s;
                };
                j = j + 1;
            };
            assert!(stake_amount > smallest_stake, error::invalid_state(EMAX_VALIDATORS));
            let ValidatorConfig { validator_addr: gone, stake, public_key: _, bls_public_key: _, bls_pop: _ } =
                vector::remove(&mut validator_set.validators, smallest);
            let amount = coin::value(&stake);
            coin::burn(stake);
            vector::push_back(&mut validator_set.unbonding_queue, UnbondingRequest {
                validator_addr: gone,
                stake: amount,
                start_height: chain::height(),
                unlock_time: chain::unbonding_unlock_time(),
            });
        };
        let len = vector::length(&validator_set.validators);

        // Check if already a validator. G5 SL-3: and that no active
        // validator holds this BLS key, since a certificate bit names a key,
        // and evidence must name one member.
        let i = 0;
        while (i < len) {
            let v = vector::borrow(&validator_set.validators, i);
            assert!(v.validator_addr != addr, error::already_exists(EALREADY_VALIDATOR));
            assert!(
                v.bls_public_key != bls_public_key,
                error::already_exists(EDUPLICATE_BLS_KEY)
            );
            i = i + 1;
        };

        admit_increase(stake_amount);
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
    entry fun leave_validator_set(account: &signer) acquires ValidatorSet {
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
    public fun pay_matured_unbonding(account: &signer) acquires ValidatorSet, FrozenPayouts {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(ENOT_VALIDATOR));
        let frozen = frozen_scopes();
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
            if (coin::has_store<AincoreCoin>(req.validator_addr)
                && !in_frozen_scope(&frozen, req.validator_addr, req.start_height)) {
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
    public entry fun withdraw_unbonded(account: &signer) acquires ValidatorSet, FrozenPayouts {
        let addr = signer::address_of(account);
        let frozen = frozen_scopes();
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
                assert!(
                    !in_frozen_scope(&frozen, addr, req.start_height),
                    error::invalid_state(EPAYOUT_FROZEN)
                );
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
    entry fun add_stake(account: &signer, amount: u128) acquires ValidatorSet, ChurnState {
        let addr = signer::address_of(account);
        assert!(is_validator(addr), error::not_found(ENOT_VALIDATOR));
        admit_increase(amount);
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

    /// G5 CH-1: count `amount` of stake added to the active set this epoch
    /// (a join, `add_stake`, or a deposit into an open delegation pool), or
    /// abort when the epoch's total would pass `CHURN_INCREASE_BPS` of the
    /// base. Aborting rolls the count back with the rest of the transaction.
    public(friend) fun admit_increase(amount: u128) acquires ChurnState {
        if (!exists<ChurnState>(@0x1)) {
            return
        };
        let churn = borrow_global_mut<ChurnState>(@0x1);
        let added = churn.added + amount;
        assert!(
            added * BPS <= churn.base * CHURN_INCREASE_BPS,
            error::resource_exhausted(ECHURN_LIMIT)
        );
        churn.added = added;
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

    /// G5 EM-1: the emission drawn for one payout. A hot potato: it has no
    /// abilities, so the payout (`delegation::pay_rewards`, G5 DL-2) must
    /// hand every unit to a recipient (`take_emission`) or back to the
    /// reserve (`close_emission`) in the same transaction, and nothing but
    /// drawn coins can go back. The cap therefore holds by construction:
    /// nothing is paid beyond e, and no other coin is ever un-minted.
    struct Emission {
        coins: Coin<AincoreCoin>,
    }

    /// G5 EM-1: draw the emission for the consensus time since the last
    /// payout, counted in total_supply at once. Returns it with the
    /// consensus time the period began (CM-1 charges the commission in force
    /// then). A second draw at the same time draws nothing.
    ///
    /// Invariants:
    ///  * e depends only on the remaining reserve and the elapsed consensus
    ///    time, computed BEFORE any division; the member count cannot inflate it.
    ///  * total_supply grows by at most e <= remaining: the cap holds.
    public(friend) fun draw_emission(account: &signer): (Emission, u64)
        acquires ValidatorSet, EmissionPools, SupplyStats, EmissionState
    {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(ENOT_VALIDATOR));
        if (!exists<EmissionPools>(@0x1)) {
            move_to(account, EmissionPools { depin_budget: 0 });
        };
        if (!exists<SupplyStats>(@0x1)) {
            move_to(account, SupplyStats { cumulative_burned: 0 });
        };
        if (!exists<EmissionState>(@0x1)) {
            move_to(account, EmissionState { last_reward_time: 0 });
        };
        let now = chain::time();
        let state = borrow_global_mut<EmissionState>(@0x1);
        let period_start = state.last_reward_time;
        if (now <= period_start) {
            return (Emission { coins: coin::mint<AincoreCoin>(0) }, period_start)
        };
        let elapsed = now - period_start;
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
            return (Emission { coins: coin::mint<AincoreCoin>(0) }, period_start)
        };
        let remaining = MAX_SUPPLY - minted;
        let e = ((remaining / 1000000000) * EMISSION_RATE_E18_PER_SEC * (elapsed as u128))
            / 1000000000;
        if (e > remaining) {
            e = remaining;
        };
        // The DePIN budget is RESERVED against the cap now and drawn lazily
        // (mint_depin_reward), so that stream can never race the cap.
        let depin_cut = (e * DEPIN_BPS) / BPS_DEN;
        let pools = borrow_global_mut<EmissionPools>(@0x1);
        pools.depin_budget = pools.depin_budget + depin_cut;
        validator_set.total_supply = validator_set.total_supply + e;
        (Emission { coins: coin::mint<AincoreCoin>(e - depin_cut) }, period_start)
    }

    /// What is left of a drawn emission.
    public(friend) fun emission_value(emission: &Emission): u128 {
        coin::value(&emission.coins)
    }

    /// Pay `amount` of a drawn emission.
    public(friend) fun take_emission(emission: &mut Emission, amount: u128): Coin<AincoreCoin> {
        coin::extract(&mut emission.coins, amount)
    }

    /// Return what a payout did not pay (division dust, members without a
    /// coin store, pools that cannot take rewards) to the reserve: it was
    /// never minted, so it leaves total_supply and is not a burn.
    public(friend) fun close_emission(emission: Emission) acquires ValidatorSet {
        let Emission { coins } = emission;
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        validator_set.total_supply = validator_set.total_supply - coin::value(&coins);
        coin::burn(coins);
    }

    /// Consensus time of the last payout (0 before the first).
    public fun last_reward_time(): u64 acquires EmissionState {
        if (!exists<EmissionState>(@0x1)) {
            return 0
        };
        borrow_global<EmissionState>(@0x1).last_reward_time
    }

    /// True when `addr` is in the active validator set.
    public fun is_validator(addr: address): bool acquires ValidatorSet {
        if (!exists<ValidatorSet>(@0x1)) {
            return false
        };
        let validators = &borrow_global<ValidatorSet>(@0x1).validators;
        let len = vector::length(validators);
        let i = 0;
        while (i < len) {
            if (vector::borrow(validators, i).validator_addr == addr) {
                return true
            };
            i = i + 1;
        };
        false
    }

    /// EMISSION v4: pool-bounded mint for the DePIN (universal_mining)
    /// reward stream. The budget was reserved against MAX_SUPPLY when drawn,
    /// so this does NOT touch total_supply; per-proof draws are bounded by
    /// the accrued budget with carry-forward across empty epochs.
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

    /// G5 review (A3b): freeze `validator`'s unbonding entries of
    /// `from_epoch` or later until `thaw_payouts`. A second freeze keeps the
    /// earlier epoch.
    public(friend) fun freeze_payouts(sys: &signer, validator: address, from_epoch: u64) acquires FrozenPayouts {
        if (!exists<FrozenPayouts>(@0x1)) {
            move_to(sys, FrozenPayouts { scopes: vector::empty() });
        };
        let scopes = &mut borrow_global_mut<FrozenPayouts>(@0x1).scopes;
        let i = 0;
        while (i < vector::length(scopes)) {
            let scope = vector::borrow_mut(scopes, i);
            if (scope.validator == validator) {
                if (from_epoch < scope.from_epoch) {
                    scope.from_epoch = from_epoch;
                };
                return
            };
            i = i + 1;
        };
        vector::push_back(scopes, FrozenScope { validator, from_epoch });
    }

    /// Settlement is final: `validator`'s entries are paid as they mature.
    public(friend) fun thaw_payouts(validator: address) acquires FrozenPayouts {
        if (!exists<FrozenPayouts>(@0x1)) {
            return
        };
        let scopes = &mut borrow_global_mut<FrozenPayouts>(@0x1).scopes;
        let i = 0;
        while (i < vector::length(scopes)) {
            if (vector::borrow(scopes, i).validator == validator) {
                vector::remove(scopes, i);
                return
            };
            i = i + 1;
        };
    }

    fun frozen_scopes(): vector<FrozenScope> acquires FrozenPayouts {
        if (exists<FrozenPayouts>(@0x1)) {
            borrow_global<FrozenPayouts>(@0x1).scopes
        } else {
            vector::empty()
        }
    }

    /// Whether an entry of `validator` that started at `start_height` is in a
    /// frozen scope (the committee epoch it started in, as `slash_unbonding`
    /// computes it).
    fun in_frozen_scope(scopes: &vector<FrozenScope>, validator: address, start_height: u64): bool {
        let epoch = if (start_height == 0) { 0 } else { (start_height - 1) / chain::epoch_blocks() };
        let i = 0;
        while (i < vector::length(scopes)) {
            let scope = vector::borrow(scopes, i);
            if (scope.validator == validator && epoch >= scope.from_epoch) {
                return true
            };
            i = i + 1;
        };
        false
    }

    /// G5 SL-5: an accepted offender leaves the active set. Its whole stake
    /// starts unbonding like a leaver's, and all of it stays slashable
    /// (SL-1); none is burned before settlement. A no-op for an address that
    /// is not in the set (it left earlier; its entries are already queued).
    public(friend) fun remove_offender(validator_addr: address) acquires ValidatorSet {
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let len = vector::length(&validator_set.validators);
        let i = 0;
        while (i < len) {
            if (vector::borrow(&validator_set.validators, i).validator_addr == validator_addr) {
                let ValidatorConfig { validator_addr: _, stake, public_key: _, bls_public_key: _, bls_pop: _ } =
                    vector::remove(&mut validator_set.validators, i);
                let amount = coin::value(&stake);
                // Destroyed here and minted again when paid, as for a leaver;
                // it stays counted in total_supply until then.
                coin::burn(stake);
                vector::push_back(&mut validator_set.unbonding_queue, UnbondingRequest {
                    validator_addr,
                    stake: amount,
                    start_height: chain::height(),
                    unlock_time: chain::unbonding_unlock_time(),
                });
                return
            };
            i = i + 1;
        };
    }

    /// G5 SL-6: cut every unbonding entry of `validator_addr` that started in
    /// committee epoch `from_epoch` or later by `bps`, rounded up against the
    /// offender. Earlier entries left before the offense and are out of scope.
    /// The cut is never paid, so it leaves total_supply and is counted as
    /// burned (AUDIT-#8: cumulative minted is unchanged).
    public(friend) fun slash_unbonding(
        validator_addr: address,
        from_epoch: u64,
        bps: u64,
    ) acquires ValidatorSet, SupplyStats {
        if (bps == 0) {
            return
        };
        let interval = chain::epoch_blocks();
        let validator_set = borrow_global_mut<ValidatorSet>(@0x1);
        let burned = 0u128;
        let len = vector::length(&validator_set.unbonding_queue);
        let i = 0;
        while (i < len) {
            let request = vector::borrow_mut(&mut validator_set.unbonding_queue, i);
            let epoch = if (request.start_height == 0) { 0 } else { (request.start_height - 1) / interval };
            if (request.validator_addr == validator_addr && epoch >= from_epoch) {
                let cut = (request.stake * (bps as u128) + (MAX_BPS as u128) - 1) / (MAX_BPS as u128);
                if (cut > request.stake) {
                    cut = request.stake;
                };
                request.stake = request.stake - cut;
                burned = burned + cut;
            };
            i = i + 1;
        };
        if (burned == 0) {
            return
        };
        let removed = if (validator_set.total_supply >= burned) { burned } else { validator_set.total_supply };
        validator_set.total_supply = validator_set.total_supply - removed;
        if (exists<SupplyStats>(@0x1)) {
            let stats = borrow_global_mut<SupplyStats>(@0x1);
            stats.cumulative_burned = stats.cumulative_burned + removed;
        };
    }
}
