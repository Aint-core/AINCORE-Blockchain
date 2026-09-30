module 0x1::epoch {
    use std::signer;
    use 0x1::staking;

    /// The reward-period counter. G5 CL-1: time is the block height
    /// (`0x1::chain`); the old virtual-seconds clock (`epoch_start_time`,
    /// `epoch_duration`) is gone, and with it the governance action that could
    /// stretch it.
    struct Epoch has key {
        epoch_number: u64,
    }

    public fun initialize(account: &signer) {
        move_to(account, Epoch {
            epoch_number: 0,
        });
    }

    public entry fun advance_epoch(account: &signer) acquires Epoch {
        // AUDIT-HIGH: authorization belongs at the entry point, not only in
        // the callees.
        let addr = signer::address_of(account);
        assert!(addr == @0x1, 100);

        let epoch = borrow_global_mut<Epoch>(@0x1);
        epoch.epoch_number = epoch.epoch_number + 1;

        // G5 UB-1: pay matured unbonding (never burn it).
        staking::pay_matured_unbonding(account);

        // Distribute rewards
        staking::distribute_rewards(account);
    }
}
