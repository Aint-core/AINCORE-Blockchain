module 0x1::epoch {
    use std::signer;
    use 0x1::staking;

    /// H4 FIX: `epoch_start_time` is a MONOTONIC ACCUMULATOR of elapsed virtual
    /// seconds, advanced by the *current* `epoch_duration` on each advance_epoch.
    /// `epoch_duration` stays governance-mutable but only affects FUTURE
    /// increments, so changing it can never retroactively rescale time that has
    /// already accumulated. This keeps the absolute unlock_time /
    /// commission_change_time values stored in delegation.move valid across a
    /// duration change.
    struct Epoch has key {
        epoch_number: u64,
        epoch_start_time: u64, // accumulator: total elapsed virtual seconds
        epoch_duration: u64,   // seconds added per epoch advance (future-only)
    }

    public fun initialize(account: &signer) {
        move_to(account, Epoch {
            epoch_number: 0,
            epoch_start_time: 0,
            epoch_duration: 10, // Short duration for testing
        });
    }

    public entry fun advance_epoch(account: &signer) acquires Epoch {
        // AUDIT-HIGH: advance_epoch had NO authorization guard while
        // update_epoch_duration below it did. Any user could call this entry
        // function and ratchet the on-chain epoch clock forward, which drives the
        // 21-day unbonding deadlines and the slashing window. The inner
        // staking::* calls do assert @0x1 and abort, but before the abort-atomicity
        // fix those aborts still committed the epoch_number/epoch_start_time
        // writes made above them. Guard it here too: authorization belongs at the
        // entry point, not only in the callees.
        let addr = signer::address_of(account);
        assert!(addr == @0x1, 100);

        let epoch = borrow_global_mut<Epoch>(@0x1);
        epoch.epoch_number = epoch.epoch_number + 1;
        // H4 FIX: advance the monotonic clock by the CURRENT duration. Because we
        // add (not multiply) and only ever move forward, a later duration change
        // cannot rescale seconds already accumulated here.
        epoch.epoch_start_time = epoch.epoch_start_time + epoch.epoch_duration;

        // Clean up old unbonding requests
        staking::cleanup_old_unbonding(account);
        
        // Distribute rewards
        staking::distribute_rewards(account);
    }

    public fun update_epoch_duration(account: &signer, new_duration: u64) acquires Epoch {
        let addr = signer::address_of(account);
        // Only 0x1 (system/governance) can call
        assert!(addr == @0x1, 100); 
        
        let epoch = borrow_global_mut<Epoch>(@0x1);
        epoch.epoch_duration = new_duration;
    }

    /// Get current virtual timestamp. H4 FIX: returns the monotonic accumulator
    /// directly. It is NO LONGER a function of the live `epoch_duration`, so a
    /// governance UpdateEconomicParams that changes the duration cannot move this
    /// clock past (or behind) any previously stored absolute deadline.
    public fun now_seconds(): u64 acquires Epoch {
        let epoch = borrow_global<Epoch>(@0x1);
        epoch.epoch_start_time
    }
}
