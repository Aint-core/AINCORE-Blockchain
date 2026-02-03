module 0x1::epoch {
    use std::signer;
    use 0x1::staking;

    struct Epoch has key {
        epoch_number: u64,
        epoch_start_time: u64,
        epoch_duration: u64,
    }

    public fun initialize(account: &signer) {
        move_to(account, Epoch {
            epoch_number: 0,
            epoch_start_time: 0,
            epoch_duration: 10, // Short duration for testing
        });
    }

    public entry fun advance_epoch(account: &signer) acquires Epoch {
        let epoch = borrow_global_mut<Epoch>(@0x1);
        epoch.epoch_number = epoch.epoch_number + 1;
        
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
}
