module 0x1::governance {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::epoch;
    use 0x1::coin;
    use 0x1::staking::AincoreCoin;

    /// Error codes
    const EPROPOSAL_NOT_FOUND: u64 = 1;
    const EALREADY_VOTED: u64 = 2;
    const EPROPOSAL_EXECUTED: u64 = 3;
    const EINSUFFICIENT_VOTES: u64 = 4;

    struct Proposal has store, drop {
        id: u64,
        proposer: address,
        description: vector<u8>,
        votes_for: u128, // CRITICAL FIX: Upgrade to u128 (u64 maxes out at 18.4 AIN!)
        votes_against: u128,
        executed: bool,
        action_type: u8, // 1 = Change Epoch Duration
        action_value: u64, // New duration
        voters: vector<address>,
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
        
        // --- PHASE 8 SECURITY: BURN 10,000 AIN PROPOSAL FEE ---
        // 10,000 AIN represented in 18 decimals
        let fee_amount: u128 = 10000000000000000000000; 
        let fee_coins = coin::withdraw<AincoreCoin>(account, fee_amount);
        coin::burn(fee_coins); // Permanently destroy the fee to prevent spam

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
            voters: vector::empty(),
        };

        vector::push_back(&mut state.proposals, proposal);
        state.next_proposal_id = state.next_proposal_id + 1;
    }

    public entry fun vote(
        account: &signer,
        proposal_id: u64,
        agree: bool
    ) acquires GovernanceState {
        let addr = signer::address_of(account);
        
        // Fetch Voter's Balance (Voting Weight)
        let weight = (coin::balance<AincoreCoin>(addr) as u128); 
        assert!(weight > 0, error::invalid_argument(EINSUFFICIENT_VOTES));

        let state = borrow_global_mut<GovernanceState>(@0x1);
        
        // Find proposal
        let len = vector::length(&state.proposals);
        let i = 0;
        while (i < len) {
            let p = vector::borrow_mut(&mut state.proposals, i);
            if (p.id == proposal_id) {
                assert!(!p.executed, error::invalid_state(EPROPOSAL_EXECUTED));
                
                // Check if already voted
                let v_len = vector::length(&p.voters);
                let j = 0;
                while (j < v_len) {
                    let v_addr = vector::borrow(&p.voters, j);
                    assert!(v_addr != &addr, error::invalid_argument(EALREADY_VOTED));
                    j = j + 1;
                };

                // Add vote weight (1 token = 1 vote representation)
                if (agree) {
                    p.votes_for = p.votes_for + weight;
                } else {
                    p.votes_against = p.votes_against + weight;
                };
                vector::push_back(&mut p.voters, addr);
                return
            };
            i = i + 1;
        };
        abort error::not_found(EPROPOSAL_NOT_FOUND)
    }

    public entry fun execute_proposal(account: &signer, proposal_id: u64) acquires GovernanceState {
        let state = borrow_global_mut<GovernanceState>(@0x1);
        let len = vector::length(&state.proposals);
        let i = 0;
        while (i < len) {
            let p = vector::borrow_mut(&mut state.proposals, i);
            if (p.id == proposal_id) {
                assert!(!p.executed, error::invalid_state(EPROPOSAL_EXECUTED));
                
                // --- PHASE 8 SECURITY: ENFORCE 1M AIN MINIMUM QUORUM ---
                let min_quorum: u128 = 1000000000000000000000000; // 1,000,000 AIN
                assert!(p.votes_for + p.votes_against >= min_quorum, error::invalid_state(EINSUFFICIENT_VOTES));
                
                // Ensure Majority
                assert!(p.votes_for > p.votes_against, error::invalid_state(EINSUFFICIENT_VOTES));

                if (p.action_type == 1) {
                    // Change Epoch Duration
                    epoch::update_epoch_duration(account, p.action_value);
                };

                p.executed = true;
                return
            };
            i = i + 1;
        };
        abort error::not_found(EPROPOSAL_NOT_FOUND)
    }
}
