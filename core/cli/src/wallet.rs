use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

pub struct Wallet {
    pub key_pair: SigningKey,
}

impl Wallet {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let key_pair = SigningKey::generate(&mut csprng);
        Self { key_pair }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = fs::read(path).context("Failed to read keyfile")?;
            
            // Try to decode as hex string first (trim whitespace)
            let key_bytes = if let Ok(s) = String::from_utf8(bytes.clone()) {
                 let s = s.trim();
                 if let Ok(decoded) = hex::decode(s) {
                     decoded
                 } else {
                     bytes
                 }
            } else {
                bytes
            };

            let key_pair = SigningKey::from_bytes(key_bytes.as_slice().try_into().context("Invalid key length")?);
            Ok(Self { key_pair })
        } else {
            let wallet = Self::new();
            fs::write(path, wallet.key_pair.to_bytes()).context("Failed to write keyfile")?;
            Ok(wallet)
        }
    }

    pub fn address(&self) -> String {
        let full_hex = hex::encode(self.key_pair.verifying_key().to_bytes());
        full_hex[0..32].to_string()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key_pair.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.key_pair.sign(message);
        hex::encode(signature.to_bytes())
    }
}
