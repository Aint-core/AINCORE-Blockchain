#[test_only]
/// Move unit tests for 0x1::chain, consensus time and the genesis-pinned
/// parameters (G5 CL-1, P-1, amendment A1). They run on the production VM
/// against the committed stdlib bytecode (core/vm_move/src/move_unit_tests.rs).
///
/// Abort codes are std::error categories: (category << 16) | reason.
///   0x50001 permission_denied(EUNAUTHORIZED)
///   0x80002 already_exists(EALREADY_INITIALIZED)
///   0x10003 invalid_argument(EINVALID_PARAMS)
/// The executor writes the clock, and the deadlines that read it need funded
/// accounts, which a test module cannot mint; the executor tests cover them
/// through real blocks.
module 0xcafe::chain_tests {
    use 0x1::chain;

    /// U and N, as the contract fixes them.
    const U: u64 = 1814400;
    const N: u64 = 604800;

    /// I = 20, R = 10, C_tau = 14 s.
    fun setup(system: &signer) {
        chain::initialize(system, 20, 10, 14);
    }

    #[test(system = @0x1)]
    fun genesis_values_read_back_and_the_clock_starts_at_zero(system: signer) {
        setup(&system);
        assert!(chain::epoch_blocks() == 20, 0);
        assert!(chain::reward_period() == 10, 1);
        assert!(chain::max_block_interval_secs() == 14, 2);
        assert!(chain::height() == 0, 3);
        assert!(chain::time() == 0, 4);
        assert!(chain::unbonding_secs() == U, 5);
        assert!(chain::commission_notice_secs() == N, 6);
    }

    #[test(other = @0xb0b)]
    #[expected_failure(abort_code = 0x50001, location = 0x1::chain)]
    fun only_the_system_signer_initializes(other: signer) {
        setup(&other);
    }

    #[test(system = @0x1)]
    #[expected_failure(abort_code = 0x80002, location = 0x1::chain)]
    fun the_parameters_are_written_once(system: signer) {
        setup(&system);
        chain::initialize(&system, 40, 20, 14);
    }

    #[test(system = @0x1)]
    #[expected_failure(abort_code = 0x10003, location = 0x1::chain)]
    fun an_invalid_set_is_refused(system: signer) {
        chain::initialize(&system, 20, 7, 14);
    }

    /// P-1's constraints, each broken alone, and the exact edge of I x C_tau <= U.
    #[test]
    fun valid_is_exactly_p1() {
        assert!(chain::valid(20, 20, 14), 0);
        assert!(chain::valid(20, 10, 1), 1);
        assert!(!chain::valid(0, 20, 14), 2);
        assert!(!chain::valid(20, 0, 14), 3);
        assert!(!chain::valid(20, 7, 14), 4);
        assert!(!chain::valid(20, 20, 0), 5);
        // (I + R) x C_tau <= U - W - D = 1,123,200 s (G5 SL-5): at 14 s,
        // I + R <= 80,228, so I = 80,200 fits and 80,220 does not.
        assert!(chain::valid(80200, 20, 14), 6);
        assert!(!chain::valid(80220, 20, 14), 7);
        // 1,123,200 / 1,123 = 1,000 (rounded down): I + R = 1,000 fits,
        // 1,001 does not.
        assert!(chain::valid(999, 1, 1123), 8);
        assert!(!chain::valid(1000, 1, 1123), 9);
    }

    /// G5 SL-2: stake leaving now unlocks U after the end of this committee
    /// epoch, bounded by I x C_tau: 20 x 14 = 280 s here.
    #[test(system = @0x1)]
    fun unbonding_unlocks_u_after_the_epoch_bound(system: signer) {
        setup(&system);
        assert!(chain::unbonding_unlock_time() == 280 + U, 0);
    }

    /// The launch values (I = 1,000, C_tau = 14 s): at most 3.9 h over U.
    #[test(system = @0x1)]
    fun unbonding_at_the_launch_parameters(system: signer) {
        chain::initialize(&system, 1000, 20, 14);
        assert!(chain::unbonding_unlock_time() == 14000 + U, 0);
    }
}
