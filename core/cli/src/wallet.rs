use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

/// A spending key: Ed25519, or ML-DSA-65 (FIPS 204, B8) kept as its seed.
pub enum Key {
    Ed25519(Box<SigningKey>),
    MlDsa65(Box<crypto::MlDsa65Key>),
}

pub struct Wallet {
    pub key: Key,
}

impl Wallet {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let key_pair = SigningKey::generate(&mut csprng);
        Self {
            key: Key::Ed25519(Box::new(key_pair)),
        }
    }

    /// An ML-DSA-65 wallet from a 32-byte seed file (hex), as `pqc-keygen`
    /// writes it.
    pub fn load_ml_dsa_65(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).context("Failed to read the ML-DSA-65 seed file")?;
        let seed: [u8; 32] = hex::decode(text.trim())
            .context("the ML-DSA-65 seed is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the ML-DSA-65 seed is not 32 bytes"))?;
        Ok(Self {
            key: Key::MlDsa65(Box::new(crypto::MlDsa65Key::from_seed(&seed))),
        })
    }

    /// The Ed25519 secret, which a validator's BLS identity is derived from.
    /// Validators sign with Ed25519; an ML-DSA-65 wallet cannot register one.
    pub fn ed25519_secret(&self) -> Result<[u8; 32]> {
        match &self.key {
            Key::Ed25519(k) => Ok(k.to_bytes()),
            Key::MlDsa65(_) => {
                anyhow::bail!("validators sign with Ed25519; this wallet is ML-DSA-65")
            }
        }
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

            let key_pair = SigningKey::from_bytes(
                key_bytes
                    .as_slice()
                    .try_into()
                    .context("Invalid key length")?,
            );
            Ok(Self {
                key: Key::Ed25519(Box::new(key_pair)),
            })
        } else {
            let allow_plain = std::env::var("AINCORE_ALLOW_PLAINTEXT_WALLET")
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false);
            if !allow_plain {
                anyhow::bail!(
                    "Plaintext wallet.key auto-create disabled in secure mode. Use `aincore-cli keys generate --out-dir <dir>` or set AINCORE_ALLOW_PLAINTEXT_WALLET=1 for local dev."
                );
            }
            let wallet = Self::new();
            // SECURITY (audit M-6): wallet.key holds the plaintext spending key — write
            // it owner-only (0600), matching the node.key hardening; never leave the
            // secret world-readable (default 0644).
            #[cfg(unix)]
            {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)
                    .context("Failed to create keyfile")?;
                f.write_all(hex::encode(wallet.ed25519_secret()?).as_bytes())
                    .context("Failed to write keyfile")?;
            }
            #[cfg(not(unix))]
            {
                fs::write(path, hex::encode(wallet.ed25519_secret()?))
                    .context("Failed to write keyfile")?;
            }
            Ok(wallet)
        }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        match &self.key {
            Key::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
            Key::MlDsa65(k) => k.public_key(),
        }
    }

    pub fn address(&self) -> String {
        crypto::derive_address(&self.public_key_bytes())
            .expect("wallet public key must derive a valid AINCORE address")
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> String {
        match &self.key {
            Key::Ed25519(k) => hex::encode(k.sign(message).to_bytes()),
            Key::MlDsa65(k) => hex::encode(k.sign(message)),
        }
    }
}
