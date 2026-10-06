#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use crate::{EntryFunctionCall, TransactionPayload};
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::{ModuleId, StructTag, TypeTag};

    fn system_address() -> AccountAddress {
        AccountAddress::from_hex_literal("0x1").unwrap()
    }

    fn parse_addr(hex_addr: &str) -> AccountAddress {
        AccountAddress::from_hex_literal(&format!("0x{}", hex_addr)).unwrap()
    }

    fn aincore_coin_type() -> TypeTag {
        TypeTag::Struct(Box::new(StructTag {
            address: system_address(),
            module: Identifier::new("staking").unwrap(),
            name: Identifier::new("AincoreCoin").unwrap(),
            type_params: vec![],
        }))
    }

    /// Golden BCS vectors for the canonical transaction payloads. Updated for
    /// #35: AINCORE addresses are 32 bytes (`address32`), so every embedded
    /// AccountAddress now serializes as 32 raw bytes (and address-typed `args`
    /// carry a 0x20 length prefix). The JS SDK must be regenerated to match.
    #[test]
    fn test_bcs_payload_golden_vectors_match_js_sdk() {
        let sender = "fe812c12f3ab4ce6ac5db69ac352f906";
        let recipient = "5c29b78f10a35a49a6231d08ee840a04";

        let transfer = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("coin").unwrap()),
            function: "transfer".to_string(),
            ty_args: vec![aincore_coin_type()],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes(&parse_addr(recipient)).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&transfer).unwrap()),
            "01000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e7366657201070000000000000000000000000000000000000000000000000000000000000001077374616b696e670b41696e636f7265436f696e00032000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f90620000000000000000000000000000000005c29b78f10a35a49a6231d08ee840a041064000000000000000000000000000000"
        );

        let publish = TransactionPayload::PublishModule(vec![vec![0xca, 0xfe, 0xba, 0xbe]]);
        assert_eq!(
            hex::encode(bcs::to_bytes(&publish).unwrap()),
            "020104cafebabe"
        );

        let register_validator = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("staking").unwrap()),
            function: "join_validator_set".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes(&123456789u128).unwrap(),
                bcs::to_bytes(
                    &hex::decode(
                        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
                    )
                    .unwrap(),
                )
                .unwrap(),
                bcs::to_bytes(&vec![0x11u8; 48]).unwrap(),
                bcs::to_bytes(&vec![0x22u8; 96]).unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&register_validator).unwrap()),
            "010000000000000000000000000000000000000000000000000000000000000001077374616b696e67126a6f696e5f76616c696461746f725f73657400052000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f9061015cd5b070000000000000000000000002120ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c31301111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111116160222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
        );

        let create_token = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("token_factory").unwrap()),
            function: "create_token".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes("Ain Token").unwrap(),
                bcs::to_bytes("AINX").unwrap(),
                bcs::to_bytes(&8u8).unwrap(),
                bcs::to_bytes(&1_000_000_000_000u128).unwrap(),
                bcs::to_bytes(&12_345u128).unwrap(),
                bcs::to_bytes("ipfs://icon").unwrap(),
                bcs::to_bytes("https://aincore.test").unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&create_token).unwrap()),
            "0100000000000000000000000000000000000000000000000000000000000000010d746f6b656e5f666163746f72790c6372656174655f746f6b656e00082000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f9060a0941696e20546f6b656e050441494e580108100010a5d4e8000000000000000000000010393000000000000000000000000000000c0b697066733a2f2f69636f6e151468747470733a2f2f61696e636f72652e74657374"
        );

        let delegate = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("delegation").unwrap()),
            function: "delegate".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes(&parse_addr(recipient)).unwrap(),
                bcs::to_bytes(&555u128).unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&delegate).unwrap()),
            "0100000000000000000000000000000000000000000000000000000000000000010a64656c65676174696f6e0864656c656761746500032000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f90620000000000000000000000000000000005c29b78f10a35a49a6231d08ee840a04102b020000000000000000000000000000"
        );
    }

    #[test]
    fn test_account_address_is_32_bytes() {
        assert_eq!(AccountAddress::LENGTH, 32);

        // A full 64-hex literal must parse to a 32-byte address.
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let addr = AccountAddress::from_hex_literal(&format!("0x{}", hex64))
            .expect("64-hex literal must parse with address32");
        assert_eq!(addr.to_vec().len(), 32);
        assert_eq!(addr.to_string(), hex64);

        // System address 0x1 left-pads to 32 bytes.
        let one = AccountAddress::from_hex_literal("0x1").unwrap();
        assert_eq!(one, AccountAddress::ONE);
        assert_eq!(one.to_vec().len(), 32);
    }

    /// B69: the VM runs with Aptos's production module limits, not move's
    /// unbounded defaults. B93: and no dependency depth of its own (it
    /// depended on the module cache); the executor bounds it from storage.
    #[test]
    fn the_vm_runs_with_the_production_verifier_limits() {
        let config = crate::AINCOREVM::vm_config().verifier;
        assert_eq!(config.max_dependency_depth, None);
        assert_eq!(config.max_loop_depth, Some(5));
        assert_eq!(config.max_generic_instantiation_length, Some(32));
        assert_eq!(config.max_function_parameters, Some(128));
        assert_eq!(config.max_basic_blocks, Some(1024));
        assert_eq!(config.max_type_nodes, Some(256));
        assert_eq!(config.max_push_size, Some(10_000));
        assert_eq!(config.max_struct_definitions, Some(200));
        assert_eq!(config.max_fields_in_struct, Some(64));
        assert_eq!(config.max_function_definitions, Some(1000));
        assert!(
            config.max_per_mod_meter_units.is_some(),
            "verification is metered"
        );
    }
}
