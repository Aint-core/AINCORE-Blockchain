/// G5 CL-1, CL-2 and P-1 (amendment A1): the chain's consensus time and the
/// genesis-pinned parameters. Derivations: docs/research/clock_and_deadlines.md.
///
/// `Clock.time` is tau, consensus time in seconds. Each block adds the growth
/// of its BFT timestamp, capped at `Params.max_block_interval_secs`, so tau
/// follows real time at any block speed, and a halt ages it by at most the
/// cap. The executor writes `Clock` before any transaction of a block, so a
/// transaction reads the time of the block that executes it; nothing in Move
/// writes it. Every economic deadline counts tau. Heights stay the unit of the
/// committee epoch and the reward period. `Params` is written by genesis and
/// never changed: no function here, and no governance action, can alter it.
module 0x1::chain {
    use std::error;
    use std::signer;

    const EUNAUTHORIZED: u64 = 1;
    const EALREADY_INITIALIZED: u64 = 2;
    const EINVALID_PARAMS: u64 = 3;

    /// U: 21 days. U >= T_trust + T_mis with T_trust = 14 d (the longest halt
    /// so far was 10 days; weekly checkpoints; bridge trust is 2/3 U) and
    /// T_mis = 7 d to land evidence.
    const UNBONDING_SECS: u64 = 1814400;
    /// N: 7 days of notice before a commission increase applies.
    const COMMISSION_NOTICE_SECS: u64 = 604800;
    /// W: 7 days (G5 SL-3, amendment A2). Evidence of an offense is accepted
    /// until W after the end of its epoch: T_mis, U's misbehaviour budget.
    const EVIDENCE_MAX_AGE_SECS: u64 = 604800;
    /// D: 1 day (G5 SL-4). Offenses this close in consensus time count
    /// together in the slash fraction.
    const CORRELATION_WINDOW_SECS: u64 = 86400;

    /// The block being executed: its height, tau and its BFT timestamp.
    struct Clock has key {
        height: u64,
        time: u64,
        block_timestamp: u64,
    }

    /// Genesis-pinned (G5 P-1): I and R in blocks, and C_tau, the most one
    /// block may advance tau, in seconds (2 x the block time measured at
    /// genesis).
    struct Params has key {
        epoch_blocks: u64,
        reward_period: u64,
        max_block_interval_secs: u64,
    }

    /// Genesis only (tests call it too): the system signer, once.
    public fun initialize(
        sys: &signer,
        epoch_blocks: u64,
        reward_period: u64,
        max_block_interval_secs: u64,
    ) {
        assert!(signer::address_of(sys) == @0x1, error::permission_denied(EUNAUTHORIZED));
        assert!(!exists<Params>(@0x1), error::already_exists(EALREADY_INITIALIZED));
        assert!(
            valid(epoch_blocks, reward_period, max_block_interval_secs),
            error::invalid_argument(EINVALID_PARAMS)
        );
        move_to(sys, Params { epoch_blocks, reward_period, max_block_interval_secs });
        move_to(sys, Clock { height: 0, time: 0, block_timestamp: 0 });
    }

    /// P-1's constraints: every value positive, and the reward period divides
    /// the epoch. And (I + R) x C_tau + W + D <= U, so a slash settles before
    /// any stake it reaches can unlock (G5 SL-5): settlement comes at most
    /// D + I x C_tau + W after the offense epoch starts, plus one reward
    /// period, and in-scope stake unlocks U after it at the earliest. This
    /// also keeps `unbonding_unlock_time` from overflowing.
    public fun valid(
        epoch_blocks: u64,
        reward_period: u64,
        max_block_interval_secs: u64,
    ): bool {
        let budget = UNBONDING_SECS - EVIDENCE_MAX_AGE_SECS - CORRELATION_WINDOW_SECS;
        epoch_blocks > 0
            && reward_period > 0
            && epoch_blocks % reward_period == 0
            && max_block_interval_secs > 0
            && epoch_blocks <= budget
            && reward_period <= budget
            && epoch_blocks + reward_period <= budget / max_block_interval_secs
    }

    public fun height(): u64 acquires Clock {
        borrow_global<Clock>(@0x1).height
    }

    /// tau: consensus time in seconds.
    public fun time(): u64 acquires Clock {
        borrow_global<Clock>(@0x1).time
    }

    public fun epoch_blocks(): u64 acquires Params {
        borrow_global<Params>(@0x1).epoch_blocks
    }

    public fun reward_period(): u64 acquires Params {
        borrow_global<Params>(@0x1).reward_period
    }

    public fun max_block_interval_secs(): u64 acquires Params {
        borrow_global<Params>(@0x1).max_block_interval_secs
    }

    public fun unbonding_secs(): u64 {
        UNBONDING_SECS
    }

    public fun commission_notice_secs(): u64 {
        COMMISSION_NOTICE_SECS
    }

    public fun evidence_max_age_secs(): u64 {
        EVIDENCE_MAX_AGE_SECS
    }

    public fun correlation_window_secs(): u64 {
        CORRELATION_WINDOW_SECS
    }

    /// G5 SL-2: when stake that stops weighting the committee in this block
    /// unlocks. Its key can sign until the end of the current committee epoch,
    /// whose tau is at most now + I x C_tau, and it must stay locked for U
    /// after that. Non-decreasing over blocks, so queues stay sorted.
    public fun unbonding_unlock_time(): u64 acquires Clock, Params {
        let p = borrow_global<Params>(@0x1);
        time() + p.epoch_blocks * p.max_block_interval_secs + UNBONDING_SECS
    }
}
