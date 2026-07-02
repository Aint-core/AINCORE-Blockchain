use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

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

            let key_pair = SigningKey::from_bytes(
                key_bytes
                    .as_slice()
                    .try_into()
                    .context("Invalid key length")?,
            );
            Ok(Self { key_pair })
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
                f.write_all(hex::encode(wallet.key_pair.to_bytes()).as_bytes())
                    .context("Failed to write keyfile")?;
            }
            #[cfg(not(unix))]
            {
                fs::write(path, hex::encode(wallet.key_pair.to_bytes()))
                    .context("Failed to write keyfile")?;
            }
            Ok(wallet)
        }
    }

    pub fn address(&self) -> String {
        crypto::derive_address(self.key_pair.verifying_key().as_bytes())
            .expect("wallet public key must derive a valid AINCORE address")
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key_pair.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.key_pair.sign(message);
        hex::encode(signature.to_bytes())
    }
}
