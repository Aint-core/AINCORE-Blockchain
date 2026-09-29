#[test_only]
/// Move unit tests for 0x1::universal_mining device registration. They use only
/// the module's public API and run on the production VM against the committed
/// stdlib bytecode (core/vm_move/src/move_unit_tests.rs).
///
/// Abort codes are std::error categories: (category << 16) | reason.
///   0x10005 invalid_argument(EINVALID_DEVICE_PUBKEY)
///   0x90006 resource_exhausted(EOWNER_DEVICE_LIMIT)
///   0x80002 already_exists(EDEVICE_ALREADY_REGISTERED)
///   0x60003 not_found(EDEVICE_NOT_REGISTERED)
///   0x50001 permission_denied(ENOT_AUTHORIZED)
/// The registry cap (EREGISTRY_FULL) needs more owners than a test can sign
/// for; the executor tests cover it with a seeded registry.
module 0xcafe::universal_mining_tests {
    use std::vector;
    use 0x1::universal_mining;

    const OWNER: address = @0xa11ce;
    const OTHER: address = @0xb0b;

    /// A key of `len` bytes, all equal to `seed`.
    fun key(seed: u8, len: u64): vector<u8> {
        let k = vector::empty<u8>();
        let i = 0;
        while (i < len) {
            vector::push_back(&mut k, seed);
            i = i + 1;
        };
        k
    }

    /// Registers `n` distinct 32-byte keys (seeds 0..n) for `owner`.
    fun register_n(owner: &signer, n: u64) {
        let i = 0;
        while (i < n) {
            universal_mining::register_device(owner, key((i as u8), 32), 1);
            i = i + 1;
        };
    }

    /// The registry and the oracle at @0x1, as genesis creates them, with @0x1
    /// as the only feeder and a threshold of 1.
    fun setup(system: &signer) {
        universal_mining::initialize(system);
        universal_mining::init_oracle(system);
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    fun an_honest_device_registers_is_verified_and_reaches_the_reward(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 32), 1);
        universal_mining::add_verified_device(&system, OWNER, key(1, 32));
        // Verifying the same binding again is a no-op, not an error.
        universal_mining::add_verified_device(&system, OWNER, key(1, 32));
        // Quorum is 1, so this finalizes and runs distribute_reward.
        universal_mining::submit_mining_proof(&system, key(1, 32), 90);
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x10005, location = 0x1::universal_mining)]
    fun a_33_byte_pubkey_is_refused(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 33), 1);
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x10005, location = 0x1::universal_mining)]
    fun a_31_byte_pubkey_is_refused(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 31), 1);
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x10005, location = 0x1::universal_mining)]
    fun an_empty_pubkey_is_refused(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, vector::empty(), 1);
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x10005, location = 0x1::universal_mining)]
    fun a_64_kib_pubkey_is_refused(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 65536), 1);
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    fun an_owner_may_register_up_to_the_cap(system: signer, owner: signer) {
        setup(&system);
        register_n(&owner, 32);
        // The last one is a real registration: it can be verified.
        universal_mining::add_verified_device(&system, OWNER, key(31, 32));
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x90006, location = 0x1::universal_mining)]
    fun the_33rd_device_of_one_owner_is_refused(system: signer, owner: signer) {
        setup(&system);
        register_n(&owner, 33);
    }

    #[test(system = @0x1, owner = @0xa11ce, other = @0xb0b)]
    fun the_cap_is_per_owner(system: signer, owner: signer, other: signer) {
        setup(&system);
        register_n(&owner, 32);
        universal_mining::register_device(&other, key(200, 32), 1);
        universal_mining::add_verified_device(&system, OTHER, key(200, 32));
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x80002, location = 0x1::universal_mining)]
    fun registering_the_same_device_twice_is_refused(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 32), 1);
        universal_mining::register_device(&owner, key(1, 32), 2);
    }

    /// H3: a registration under another address cannot lock the real owner out.
    #[test(system = @0x1, owner = @0xa11ce, squatter = @0xb0b)]
    fun a_squatter_cannot_lock_the_owner_out(system: signer, owner: signer, squatter: signer) {
        setup(&system);
        universal_mining::register_device(&squatter, key(1, 32), 1);
        universal_mining::register_device(&owner, key(1, 32), 1);
        universal_mining::add_verified_device(&system, OWNER, key(1, 32));
    }

    /// H3: one verified owner per pubkey.
    #[test(system = @0x1, owner = @0xa11ce, squatter = @0xb0b)]
    #[expected_failure(abort_code = 0x50001, location = 0x1::universal_mining)]
    fun a_verified_device_cannot_be_rebound(system: signer, owner: signer, squatter: signer) {
        setup(&system);
        universal_mining::register_device(&squatter, key(1, 32), 1);
        universal_mining::register_device(&owner, key(1, 32), 1);
        universal_mining::add_verified_device(&system, OWNER, key(1, 32));
        universal_mining::add_verified_device(&system, OTHER, key(1, 32));
    }

    #[test(system = @0x1)]
    #[expected_failure(abort_code = 0x60003, location = 0x1::universal_mining)]
    fun an_owner_with_no_registrations_cannot_be_verified(system: signer) {
        setup(&system);
        universal_mining::add_verified_device(&system, OWNER, key(1, 32));
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x60003, location = 0x1::universal_mining)]
    fun a_device_the_owner_did_not_register_cannot_be_verified(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 32), 1);
        universal_mining::add_verified_device(&system, OWNER, key(2, 32));
    }

    #[test(system = @0x1, owner = @0xa11ce)]
    #[expected_failure(abort_code = 0x50001, location = 0x1::universal_mining)]
    fun only_a_feeder_can_verify(system: signer, owner: signer) {
        setup(&system);
        universal_mining::register_device(&owner, key(1, 32), 1);
        universal_mining::add_verified_device(&owner, OWNER, key(1, 32));
    }
}
