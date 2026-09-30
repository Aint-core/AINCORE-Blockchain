/// G5 CL-1 and P-1: the one protocol clock (the block height) and the
/// genesis-pinned parameters every deadline is counted in.
///
/// The executor writes `Clock` before any transaction of a block (CL-2), so a
/// transaction reads the height of the block that executes it; nothing in Move
/// writes it (the executor's in-order height gate is what keeps it monotonic).
/// `Params` is written by genesis and never changed: no function here, and no
/// governance action, can alter it.
module 0x1::chain {
    use std::error;
    use std::signer;

    const EUNAUTHORIZED: u64 = 1;
    const EALREADY_INITIALIZED: u64 = 2;
    const EINVALID_PARAMS: u64 = 3;

    /// The height of the block being executed.
    struct Clock has key {
        height: u64,
    }

    /// Genesis-pinned, in blocks (G5 P-1). `draw_num` is the emission draw
    /// per block on the remaining reserve, in units of 10^-12.
    struct Params has key {
        epoch_blocks: u64,
        reward_period: u64,
        unbonding_blocks: u64,
        claim_grace_blocks: u64,
        commission_delay_blocks: u64,
        draw_num: u128,
    }

    /// Genesis only (tests call it too): the system signer, once.
    public fun initialize(
        sys: &signer,
        epoch_blocks: u64,
        reward_period: u64,
        unbonding_blocks: u64,
        claim_grace_blocks: u64,
        commission_delay_blocks: u64,
        draw_num: u128,
    ) {
        assert!(signer::address_of(sys) == @0x1, error::permission_denied(EUNAUTHORIZED));
        assert!(!exists<Params>(@0x1), error::already_exists(EALREADY_INITIALIZED));
        assert!(
            valid(epoch_blocks, reward_period, unbonding_blocks, claim_grace_blocks,
                commission_delay_blocks, draw_num),
            error::invalid_argument(EINVALID_PARAMS)
        );
        move_to(sys, Params {
            epoch_blocks,
            reward_period,
            unbonding_blocks,
            claim_grace_blocks,
            commission_delay_blocks,
            draw_num,
        });
        move_to(sys, Clock { height: 0 });
    }

    /// P-1's constraints: every period positive, the reward period divides the
    /// epoch, unbonding is whole epochs, and the draw below 10^-8 per block.
    public fun valid(
        epoch_blocks: u64,
        reward_period: u64,
        unbonding_blocks: u64,
        claim_grace_blocks: u64,
        commission_delay_blocks: u64,
        draw_num: u128,
    ): bool {
        epoch_blocks > 0
            && reward_period > 0
            && epoch_blocks % reward_period == 0
            && unbonding_blocks > 0
            && unbonding_blocks % epoch_blocks == 0
            && claim_grace_blocks > 0
            && commission_delay_blocks > 0
            && draw_num > 0
            && draw_num < 10000
    }

    public fun height(): u64 acquires Clock {
        borrow_global<Clock>(@0x1).height
    }

    public fun epoch_blocks(): u64 acquires Params {
        borrow_global<Params>(@0x1).epoch_blocks
    }

    public fun reward_period(): u64 acquires Params {
        borrow_global<Params>(@0x1).reward_period
    }

    public fun unbonding_blocks(): u64 acquires Params {
        borrow_global<Params>(@0x1).unbonding_blocks
    }

    public fun claim_grace_blocks(): u64 acquires Params {
        borrow_global<Params>(@0x1).claim_grace_blocks
    }

    public fun commission_delay_blocks(): u64 acquires Params {
        borrow_global<Params>(@0x1).commission_delay_blocks
    }

    public fun draw_num(): u128 acquires Params {
        borrow_global<Params>(@0x1).draw_num
    }

    /// H_{E(h)}: the last block of the committee epoch containing h (G1 EP-1:
    /// E(h) = (h - 1) / I, and H_E = (E + 1) * I). Height 0 belongs to epoch 0.
    public fun epoch_end(h: u64): u64 acquires Params {
        let i = epoch_blocks();
        if (h == 0) {
            return i
        };
        ((h - 1) / i + 1) * i
    }

    /// G5 SL-2: when stake that stops weighting the committee at height h
    /// unlocks: U blocks after the end of h's committee epoch, since the
    /// stake still weighted the committee until then.
    public fun unlock_height(h: u64): u64 acquires Params {
        epoch_end(h) + unbonding_blocks()
    }
}
