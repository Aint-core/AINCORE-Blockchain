use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use rand::rngs::OsRng;

pub struct FederationSigner {
    signing_key: SigningKey,
}

impl FederationSigner {
    pub fn new(priv_key_hex: &str) -> Self {
        let bytes = hex::decode(priv_key_hex).expect("Invalid private key hex");
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes[..32]);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Self { signing_key }
    }

    pub fn get_public_key_hex(&self) -> String {
        let vk: VerifyingKey = self.signing_key.verifying_key();
        hex::encode(vk.as_bytes())
    }

    /// Sign the payload + sequence number (Standard AINCORE Transaction Signature)
    pub fn sign_transaction(&self, payload: &str, sequence_number: u64) -> String {
        let message = format!("{}:{}", payload, sequence_number);
        println!("✍️ Signing Message: '{}'", message);
        let signature = self.signing_key.sign(message.as_bytes());
        hex::encode(signature.to_bytes())
    }
}
