#[test_only]
/// Move unit tests for 0x1::chain, the height clock and the genesis-pinned
/// parameters (G5 CL-1, P-1). They run on the production VM against the
/// committed stdlib bytecode (core/vm_move/src/move_unit_tests.rs).
///
/// Abort codes are std::error categories: (category << 16) | reason.
///   0x50001 permission_denied(EUNAUTHORIZED)
///   0x80002 already_exists(EALREADY_INITIALIZED)
///   0x10003 invalid_argument(EINVALID_PARAMS)
/// The deadlines that read this clock (unbonding, commission notice) need
/// funded accounts, which a test module cannot mint; the executor tests cover
/// them through real blocks.
module 0xcafe::chain_tests {
    use 0x1::chain;

    /// I = 20, R = 10, U = 40, G = 7, C = 5, draw 4042.
    fun setup(system: &signer) {
        chain::initialize(system, 20, 10, 40, 7, 5, 4042);
    }

    #[test(system = @0x1)]
    fun genesis_values_read_back_and_the_clock_starts_at_zero(system: signer) {
        setup(&system);
        assert!(chain::epoch_blocks() == 20, 0);
        assert!(chain::reward_period() == 10, 1);
        assert!(chain::unbonding_blocks() == 40, 2);
        assert!(chain::claim_grace_blocks() == 7, 3);
        assert!(chain::commission_delay_blocks() == 5, 4);
        assert!(chain::draw_num() == 4042, 5);
        assert!(chain::height() == 0, 6);
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
        chain::initialize(&system, 40, 20, 80, 7, 5, 4042);
    }

    #[test(system = @0x1)]
    #[expected_failure(abort_code = 0x10003, location = 0x1::chain)]
    fun an_invalid_set_is_refused(system: signer) {
        chain::initialize(&system, 20, 7, 40, 7, 5, 4042);
    }

    /// P-1's constraints, each broken alone, and their exact edges.
    #[test]
    fun valid_is_exactly_p1() {
        assert!(chain::valid(20, 20, 40, 1, 1, 1), 0);
        assert!(chain::valid(20, 10, 20, 1, 1, 9999), 1);
        assert!(!chain::valid(0, 20, 40, 1, 1, 1), 2);
        assert!(!chain::valid(20, 0, 40, 1, 1, 1), 3);
        assert!(!chain::valid(20, 7, 40, 1, 1, 1), 4);
        assert!(!chain::valid(20, 20, 0, 1, 1, 1), 5);
        assert!(!chain::valid(20, 20, 41, 1, 1, 1), 6);
        assert!(!chain::valid(20, 20, 40, 0, 1, 1), 7);
        assert!(!chain::valid(20, 20, 40, 1, 0, 1), 8);
        assert!(!chain::valid(20, 20, 40, 1, 1, 0), 9);
        assert!(!chain::valid(20, 20, 40, 1, 1, 10000), 10);
    }

    /// G1 EP-1 (E(h) = (h - 1) / I, H_E = (E + 1) * I) and G5 SL-2
    /// (unlock at H_E(h) + U), at every boundary.
    #[test(system = @0x1)]
    fun epoch_end_and_unlock_height_at_the_boundaries(system: signer) {
        setup(&system);
        assert!(chain::epoch_end(0) == 20, 0);
        assert!(chain::epoch_end(1) == 20, 1);
        assert!(chain::epoch_end(19) == 20, 2);
        assert!(chain::epoch_end(20) == 20, 3);
        assert!(chain::epoch_end(21) == 40, 4);
        assert!(chain::epoch_end(40) == 40, 5);
        assert!(chain::epoch_end(41) == 60, 6);
        assert!(chain::unlock_height(0) == 60, 7);
        assert!(chain::unlock_height(20) == 60, 8);
        assert!(chain::unlock_height(21) == 80, 9);
    }

    /// The launch values (I = 1,000, U = 273,000): a stake that stops
    /// weighting the committee anywhere in epoch 0 unlocks at 274,000.
    #[test(system = @0x1)]
    fun unlock_height_at_the_launch_parameters(system: signer) {
        chain::initialize(&system, 1000, 20, 273000, 402767, 90948, 4042);
        assert!(chain::unlock_height(1) == 274000, 0);
        assert!(chain::unlock_height(1000) == 274000, 1);
        assert!(chain::unlock_height(1001) == 275000, 2);
    }
}
