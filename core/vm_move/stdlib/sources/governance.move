module 0x1::governance {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin;
    use 0x1::chain;
    use 0x1::staking::{Self, AincoreCoin};

    /// Error codes
    const EPROPOSAL_NOT_FOUND: u64 = 1;
    const EALREADY_VOTED: u64 = 2;
    const EPROPOSAL_EXECUTED: u64 = 3;
    const EINSUFFICIENT_VOTES: u64 = 4;
    /// G5 GV-1: proposals signal; they execute no protocol change.
    const EUNSUPPORTED_ACTION: u64 = 5;
    /// B71: voting on a proposal has ended.
    const EVOTING_CLOSED: u64 = 6;
    /// B71: a proposal is resolved only once its voting has ended.
    const EVOTING_OPEN: u64 = 7;
    /// B71: an account holds at most MAX_LOCKS open votes.
    const ETOO_MANY_LOCKS: u64 = 8;
    /// B71: a description is at most MAX_DESCRIPTION_BYTES.
    const EDESCRIPTION_TOO_LONG: u64 = 9;
    /// B71: a vote locks some AIN.
    const EZERO_WEIGHT: u64 = 10;

    /// B71: voting lasts 7 days of consensus time (Aptos mainnet's
    /// `voting_duration_secs`); after it, every voter takes its coins back,
    /// whatever the outcome.
    const VOTING_PERIOD_SECS: u64 = 604800;
    /// B71: a proposal's description, at most 1 KiB (every call reads the
    /// proposals, so none may grow without bound).
    const MAX_DESCRIPTION_BYTES: u64 = 1024;
    /// B71: the open votes one account may hold at once.
    const MAX_LOCKS: u64 = 16;

    struct Proposal has store, drop {
        id: u64,
        proposer: address,
        description: vector<u8>,
        votes_for: u128, // CRITICAL FIX: Upgrade to u128 (u64 maxes out at 18.4 AIN!)
        votes_against: u128,
        executed: bool,
        action_type: u8, // 0 only: a signalling proposal (G5 GV-1)
        action_value: u64, // unused
        /// B71: consensus time voting ends at.
        voting_ends: u64,
    }

    struct GovernanceState has key {
        proposals: vector<Proposal>,
        next_proposal_id: u64,
    }

    public fun initialize(account: &signer) {
        move_to(account, GovernanceState {
            proposals: vector::empty(),
            next_proposal_id: 0,
        });
    }

    public entry fun create_proposal(
        account: &signer,
        description: vector<u8>,
        action_type: u8,
        action_value: u64
    ) acquires GovernanceState {
        let addr = signer::address_of(account);
        // G5 GV-1: no action changes the protocol (the epoch-duration action,
        // which could stretch every deadline, is gone).
        assert!(action_type == 0, error::invalid_argument(EUNSUPPORTED_ACTION));
        assert!(
            vector::length(&description) <= MAX_DESCRIPTION_BYTES,
            error::invalid_argument(EDESCRIPTION_TOO_LONG)
        );

        // --- PHASE 8 SECURITY: BURN 10,000 AIN PROPOSAL FEE ---
        // 10,000 AIN represented in 18 decimals
        let fee_amount: u128 = 10000000000000000000000;
        let fee_coins = coin::withdraw<AincoreCoin>(account, fee_amount);
        staking::burn_ain(fee_coins); // Permanently destroy fee and update canonical supply

        let state = borrow_global_mut<GovernanceState>(@0x1);

        let proposal = Proposal {
            id: state.next_proposal_id,
            proposer: addr,
            description,
            votes_for: 0,
            votes_against: 0,
            executed: false,
            action_type,
            action_value,
            voting_ends: chain::time() + VOTING_PERIOD_SECS,
        };

        vector::push_back(&mut state.proposals, proposal);
        state.next_proposal_id = state.next_proposal_id + 1;
    }

    /// B71: coins one vote locked, for one proposal.
    struct Lock has store {
        proposal_id: u64,
        coins: coin::Coin<AincoreCoin>,
    }

    /// H7: a voter's locked coins, so the same coins cannot vote twice by
    /// moving between accounts. B71: one lock per proposal, each released
    /// once its proposal's voting ends (the old single escrow released only
    /// after a proposal executed, so a failed proposal kept every voter's
    /// coins forever).
    struct VoteEscrow has key {
        locks: vector<Lock>,
    }

    /// Vote `amount` of AIN (locked until voting ends) for or against.
    public entry fun vote(
        account: &signer,
        proposal_id: u64,
        agree: bool,
        amount: u128
    ) acquires GovernanceState, VoteEscrow {
        let addr = signer::address_of(account);
        assert!(amount > 0, error::invalid_argument(EZERO_WEIGHT));
        if (!exists<VoteEscrow>(addr)) {
            move_to(account, VoteEscrow { locks: vector::empty() });
        };
        let escrow = borrow_global_mut<VoteEscrow>(addr);
        let n = vector::length(&escrow.locks);
        assert!(n < MAX_LOCKS, error::resource_exhausted(ETOO_MANY_LOCKS));
        let j = 0;
        while (j < n) {
            let lock = vector::borrow(&escrow.locks, j);
            assert!(lock.proposal_id != proposal_id, error::invalid_argument(EALREADY_VOTED));
            j = j + 1;
        };

        let state = borrow_global_mut<GovernanceState>(@0x1);
        let len = vector::length(&state.proposals);
        let i = 0;
        while (i < len) {
            let p = vector::borrow_mut(&mut state.proposals, i);
            if (p.id == proposal_id) {
                assert!(!p.executed, error::invalid_state(EPROPOSAL_EXECUTED));
                assert!(chain::time() < p.voting_ends, error::invalid_state(EVOTING_CLOSED));
                // H7: the weight is locked, so it cannot move and vote again.
                let coins = coin::withdraw<AincoreCoin>(account, amount);
                vector::push_back(&mut escrow.locks, Lock { proposal_id, coins });
                if (agree) {
                    p.votes_for = p.votes_for + amount;
                } else {
                    p.votes_against = p.votes_against + amount;
                };
                return
            };
            i = i + 1;
        };
        abort error::not_found(EPROPOSAL_NOT_FOUND)
    }

    /// B71: take back the coins of every vote whose proposal's voting has
    /// ended (or that was resolved), whatever the outcome.
    public entry fun claim_vote_tokens(account: &signer) acquires VoteEscrow, GovernanceState {
        let addr = signer::address_of(account);
        assert!(exists<VoteEscrow>(addr), error::not_found(EPROPOSAL_NOT_FOUND));
        let now = chain::time();
        let state = borrow_global<GovernanceState>(@0x1);
        let escrow = borrow_global_mut<VoteEscrow>(addr);
        let j = 0;
        while (j < vector::length(&escrow.locks)) {
            let proposal_id = vector::borrow(&escrow.locks, j).proposal_id;
            if (voting_over(state, proposal_id, now)) {
                let Lock { proposal_id: _, coins } = vector::swap_remove(&mut escrow.locks, j);
                coin::deposit<AincoreCoin>(addr, coins);
            } else {
                j = j + 1;
            };
        };
        if (vector::is_empty(&escrow.locks)) {
            let VoteEscrow { locks } = move_from<VoteEscrow>(addr);
            vector::destroy_empty(locks);
        };
    }

    /// Whether voting on `proposal_id` is over at `now`: it ended, or the
    /// proposal was resolved, or it is gone.
    fun voting_over(state: &GovernanceState, proposal_id: u64, now: u64): bool {
        let len = vector::length(&state.proposals);
        let i = 0;
        while (i < len) {
            let p = vector::borrow(&state.proposals, i);
            if (p.id == proposal_id) {
                return p.executed || now >= p.voting_ends
            };
            i = i + 1;
        };
        true
    }

    /// Resolve a proposal that passed: once its voting has ended, with the
    /// quorum and a majority for (a signal: nothing else executes).
    public entry fun execute_proposal(account: &signer, proposal_id: u64) acquires GovernanceState {
        let state = borrow_global_mut<GovernanceState>(@0x1);
        let len = vector::length(&state.proposals);
        let i = 0;
        while (i < len) {
            let p = vector::borrow_mut(&mut state.proposals, i);
            if (p.id == proposal_id) {
                assert!(!p.executed, error::invalid_state(EPROPOSAL_EXECUTED));
                assert!(chain::time() >= p.voting_ends, error::invalid_state(EVOTING_OPEN));

                // --- PHASE 8 SECURITY: ENFORCE 1M AIN MINIMUM QUORUM ---
                let min_quorum: u128 = 1000000000000000000000000; // 1,000,000 AIN
                assert!(p.votes_for + p.votes_against >= min_quorum, error::invalid_state(EINSUFFICIENT_VOTES));

                // Ensure Majority
                assert!(p.votes_for > p.votes_against, error::invalid_state(EINSUFFICIENT_VOTES));

                p.executed = true;
                return
            };
            i = i + 1;
        };
        abort error::not_found(EPROPOSAL_NOT_FOUND)
    }
}
