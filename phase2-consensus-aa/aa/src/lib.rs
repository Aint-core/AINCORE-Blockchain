use serde::{Deserialize, Serialize};
use storage::object::{Object, Owner};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AccountData {
    pub sequence_number: u64,
    pub balance: u64,
    #[serde(default)]
    pub btc_balance: u64, // Wrapped Bitcoin Balance (Sats)
    pub public_key: String,
}

pub struct AccountManager;

impl AccountManager {
    /// Create a new Account Object
    pub fn create_account(address: String, public_key: String) -> Object {
        let data = AccountData {
            public_key,
            sequence_number: 0,
            balance: 0,
            btc_balance: 0,
        };
        let data_bytes = serde_json::to_vec(&data)
            .expect("AA: Failed to serialize AccountData");
        
        Object::new(
            address.clone(),
            Owner::Address(address),
            data_bytes,
            "0x1::account::Account".to_string(),
        )
    }

    /// Verify a transaction signature against the Account Object
    /// This simulates the "validate" phase of AA
    pub fn validate_transaction(account_obj: &Object, tx_payload: &[u8], signature_hex: &str) -> bool {
        // 1. Parse Account Data
        let account_data: AccountData = match serde_json::from_slice(&account_obj.data) {
            Ok(d) => d,
            Err(_) => return false,
        };

        // 2. Decode Public Key
        let pub_key_bytes_vec = match hex::decode(&account_data.public_key) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // CRITICAL FIX: Safe Ed25519 signature verification (VULN-CRYPTO-001)
        let pub_key_array: [u8; 32] = match pub_key_bytes_vec.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                eprintln!("❌ [AA] Invalid Ed25519 public key length");
                return false;
            }
        };
        
        let verifying_key = match VerifyingKey::from_bytes(&pub_key_array) {
            Ok(k) => k,
            Err(_) => {
                eprintln!("❌ [AA] Invalid Ed25519 public key format");
                return false;
            }
        };

        // 3. Decode Signature
        let sig_bytes_vec = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        
        let sig_array: [u8; 64] = match sig_bytes_vec.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                eprintln!("❌ [AA] Invalid Ed25519 signature length");
                return false;
            }
        };
        
        let signature = Signature::from_bytes(&sig_array);


        // 4. Verify
        verifying_key.verify(tx_payload, &signature).is_ok()
    }
}
