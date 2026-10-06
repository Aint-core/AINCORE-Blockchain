#[test_only]
/// B99 and B100: what anyone may add to the token factory and the DEX is
/// bounded. They use only the modules' public API and run on the production
/// VM against the committed stdlib bytecode (core/vm_move/src/move_unit_tests.rs).
///
/// Abort codes are std::error categories: (category << 16) | reason.
///   0x1000a invalid_argument(token_factory::EFIELD_TOO_LONG)
///   0x10006 invalid_argument(dex::EINVALID_PAIR)
/// The token count cap needs 512 tokens' fees; the node's genesis tests
/// cover it with a seeded registry.
module 0xcafe::market_bounds_tests {
    use std::vector;
    use 0x1::dex;
    use 0x1::staking::AincoreCoin;
    use 0x1::token_factory;
    use 0x1::wbtc::WBTC;

    fun bytes(n: u64): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut v, 65);
            i = i + 1;
        };
        v
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x1000a, location = 0x1::token_factory)]
    fun a_symbol_past_its_bound_is_refused(creator: signer) {
        token_factory::create_token(&creator, bytes(8), bytes(17), 8, 1000, 0, bytes(0), bytes(0));
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x1000a, location = 0x1::token_factory)]
    fun a_url_past_its_bound_is_refused(creator: signer) {
        token_factory::create_token(&creator, bytes(8), bytes(4), 8, 1000, 0, bytes(257), bytes(0));
    }

    #[test(system = @0x1, creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x10006, location = 0x1::dex)]
    fun a_pool_of_other_types_is_refused(system: signer, creator: signer) {
        dex::initialize(&system);
        dex::create_pool<u64, u8>(&creator);
    }

    #[test(system = @0x1, creator = @0xa11ce)]
    fun the_ain_wbtc_pool_is_created(system: signer, creator: signer) {
        dex::initialize(&system);
        dex::create_pool<AincoreCoin, WBTC>(&creator);
    }
}
