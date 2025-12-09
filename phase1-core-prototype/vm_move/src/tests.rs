#[cfg(test)]
mod tests {
    use crate::AINCOREVM;
    use move_core_types::account_address::AccountAddress;
    use std::sync::Arc;
    use storage::StateDB;

    // Helper to get a unique DB path for each test
    fn get_test_db_path(suffix: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("aincore_test_db_{}_{}", std::process::id(), suffix));
        let _ = std::fs::remove_dir_all(&path); // Clean start
        path.to_string_lossy().to_string()
    }

    #[test]
    fn test_pqc_dilithium_detection() {
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

        // 1. Setup VM
        let path = get_test_db_path("pqc");
        let db = Arc::new(StateDB::open(&path).expect("Failed to open DB"));
        let vm = AINCOREVM::new(Arc::clone(&db));
        let sender = AccountAddress::random();

        // 2. Generate Real Dilithium5 Keypair
        let (pk, sk) = pqcrypto_dilithium::dilithium5::keypair();
        
        // 3. Store Public Key in DB (simulating on-chain registration)
        let pk_key = format!("pqc_pubkey_{}", sender);
        let _ = db.put(&pk_key, &hex::encode(pk.as_bytes()));

        // 4. Sign a message
        let payload = b"Hello Quantum World";
        let sig = pqcrypto_dilithium::dilithium5::detached_sign(payload, &sk);

        // 5. Execute Transaction
        let result = vm.execute_transaction(sender, sig.as_bytes(), payload);

        // 6. Verify Success
        assert!(result.is_ok());
        assert!(result.unwrap(), "PQC Signature Verification Failed!");
        
        // 7. Verify Failure with Wrong Message
        let wrong_payload = b"Hacked Message";
        let result_fail = vm.execute_transaction(sender, sig.as_bytes(), wrong_payload);
        assert!(result_fail.is_ok());
        assert!(!result_fail.unwrap(), "PQC Verification should fail for wrong payload");

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_standard_ed25519_detection() {
        // 1. Setup VM
        let path = get_test_db_path("ed25519");
        let db = Arc::new(StateDB::open(&path).expect("Failed to open DB"));
        let vm = AINCOREVM::new(db);
        let sender = AccountAddress::random();

        // 2. Create Dummy Ed25519 Signature (Length 64)
        let dummy_sig = vec![0u8; 64];
        let payload = vec![];

        // 3. Execute
        let result = vm.execute_transaction(sender, &dummy_sig, &payload);

        // 4. Verify
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_invalid_signature_scheme() {
        // 1. Setup VM
        let path = get_test_db_path("invalid");
        let db = Arc::new(StateDB::open(&path).expect("Failed to open DB"));
        let vm = AINCOREVM::new(db);
        let sender = AccountAddress::random();

        // 2. Create Invalid Signature (Length 100 - unknown)
        let dummy_sig = vec![0u8; 100];
        let payload = vec![];

        // 3. Execute
        let result = vm.execute_transaction(sender, &dummy_sig, &payload);

        // 4. Verify - Should return Ok(false)
        assert!(result.is_ok());
        assert!(!result.unwrap());
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }
}
