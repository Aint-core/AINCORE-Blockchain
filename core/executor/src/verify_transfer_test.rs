#[cfg(test)]
mod tests {
    use crate::{Executor, Transaction};
    use std::sync::Arc;
    use storage::StateDB;
    use aa::AccountData;
    use storage::object::{Object, ObjectID, Owner};
    use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
    use std::fs;

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = format!("/tmp/aincore_executor_db_{}", name);
        let _ = fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("Failed to open DB"))
    }

    #[test]
    #[ignore]
    fn test_transfer_success_real_sig() {
        let db = temp_db("transfer");
        // Initialize federation key to satisfy genesis lock check
        db.set_federation_key("dummy_federation_key").unwrap();
        
        let executor = Executor::new(db.clone());
        
        // 1. Hardcoded valid keys for sender
        let secret_bytes: [u8; 32] = [1; 32];
        let sender_keypair = SigningKey::from_bytes(&secret_bytes);
        let sender_pubkey = VerifyingKey::from(&sender_keypair);
        let sender_pubkey_hex = hex::encode(sender_pubkey.as_bytes());
        let sender_addr = sender_pubkey_hex[0..32].to_string(); // Sender ID is first 32 chars of pubkey
        
        // 2. Set up Sender account with balance
        let sender_obj = Object {
            id: ObjectID::new(sender_addr.clone()),
            owner: Owner::Address(sender_addr.clone()),
            data: serde_json::to_vec(&AccountData {
                balance: 1000,
                sequence_number: 0,
                btc_balance: 0,
                public_key: sender_pubkey_hex.clone(),
            }).unwrap(),
            type_struct: "0x1::account::Account".to_string(),
            version: 0,
        };
        db.put_object(&sender_obj).unwrap();
        
        let recipient_addr = "recipient_12345678901234567890".to_string();
        let payload = format!("transfer:{}:100", recipient_addr);
        
        // 3. Construct message to sign
        // lib.rs uses: format!("{}:{}:{}:{}", tx.chain_id, tx.sender, tx.payload, tx.sequence_number)
        let chain_id = "AINCORE-TESTNET-1";
        std::env::set_var("AINCORE_CHAIN_ID", chain_id); // Ensure correct chain ID
        let message = format!("{}:{}:{}:{}", chain_id, sender_addr, payload, 0);
        
        // 4. Sign message
        let signature = sender_keypair.sign(message.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        
        // 5. Construct Transaction
        let tx = Transaction {
            chain_id: chain_id.to_string(),
            sender: sender_addr.clone(),
            input_objects: vec![],
            payload,
            args: vec![],
            gas_limit: 10,
            gas_price: 1,
            sequence_number: 0,
            public_key: sender_pubkey_hex.clone(),
            signature: signature_hex,
            paymaster: None,
            paymaster_signature: None,
            zkp_proof: None,
        };
        
        let tx_json = serde_json::to_string(&tx).unwrap();
        
        // 6. Execute (we use execute_transaction which returns DB updates for verification)
        let result = executor.execute_transaction(&tx_json);
        assert!(result.is_some(), "Execution failed: signature or validation rejected");
        
        let (updates, gas_used) = result.unwrap();
        assert_eq!(gas_used, 10); // 10 gas_limit * 1 gas_price
        
        // Manually apply updates to DB to verify resulting state
        for (key, val_opt) in updates {
            if let Some(val) = val_opt {
                if key.starts_with("obj:") {
                    let _obj_id = key.strip_prefix("obj:").unwrap();
                    let obj: Object = serde_json::from_str(&val).unwrap();
                    db.put_object(&obj).unwrap();
                }
            }
        }
        
        // 7. Verify Balances
        let final_sender = db.get_object(&sender_addr).unwrap();
        let final_sender_data: AccountData = serde_json::from_slice(&final_sender.data).unwrap();
        
        let final_recipient = db.get_object(&recipient_addr).unwrap();
        let final_recipient_data: AccountData = serde_json::from_slice(&final_recipient.data).unwrap();
        
        // Initial 1000 - 100 (transfer) - 10 (gas) = 890
        assert_eq!(final_sender_data.balance, 890);
        assert_eq!(final_sender_data.sequence_number, 1); // Sequence should increment
        
        // Initial 0 + 100 (transfer) = 100
        assert_eq!(final_recipient_data.balance, 100);
    }
}
