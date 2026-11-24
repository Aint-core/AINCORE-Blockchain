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

    /// B350: an Ed25519 wallet from its secret in hex (a decrypted keystore).
    pub fn from_ed25519_hex(secret: &str) -> Result<Self> {
        let bytes: [u8; 32] = hex::decode(secret.trim())
            .context("the keystore's key is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the keystore's key is not 32 bytes"))?;
        Ok(Self {
            key: Key::Ed25519(Box::new(SigningKey::from_bytes(&bytes))),
        })
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        let allow_plain = std::env::var("AINCORE_ALLOW_PLAINTEXT_WALLET")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        Self::load_keyfile(path, allow_plain)
    }

    fn load_keyfile(path: &Path, allow_creation: bool) -> Result<Self> {
        use std::io::ErrorKind;
        let key = match crypto::key_file::read_ed25519(path) {
            Ok(key) => key,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if !allow_creation {
                    anyhow::bail!(
                        "no key file at {} (plaintext keys are not made in secure mode): make an encrypted keystore with `aincore-cli keys generate` and sign with `--keystore <file>`, or set AINCORE_ALLOW_PLAINTEXT_WALLET=1 for local dev",
                        path.display()
                    );
                }
                let candidate = Self::new();
                let hex_key = hex::encode(candidate.ed25519_secret()?);
                match crypto::key_file::publish_new(path, hex_key.as_bytes()) {
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e).context("Failed to create keyfile"),
                }
                crypto::key_file::read_ed25519(path).context("Failed to read installed keyfile")?
            }
            Err(e) => return Err(e).context("Failed to read keyfile"),
        };
        Ok(Self {
            key: Key::Ed25519(Box::new(key)),
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn concurrent_plaintext_wallet_creators_use_the_same_key() {
        let dir =
            std::env::temp_dir().join(format!("aincore-wallet-{:032x}", rand::random::<u128>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("wallet.key");
        let start = Barrier::new(2);
        let initialize = || {
            start.wait();
            Wallet::load_keyfile(&path, true).unwrap().public_key()
        };
        let (a, b) = std::thread::scope(|scope| {
            let first = scope.spawn(initialize);
            let second = initialize();
            (first.join().unwrap(), second)
        });
        assert_eq!(a, b);
        assert_eq!(a, Wallet::load_keyfile(&path, false).unwrap().public_key());
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.len(), 64);
        assert!(text.bytes().all(|b| b.is_ascii_hexdigit()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_raw_and_hex_wallets_open_with_creation_disabled() {
        let dir =
            std::env::temp_dir().join(format!("aincore-formats-{:032x}", rand::random::<u128>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("wallet.key");
        assert!(Wallet::load_keyfile(&path, false).is_err());
        assert!(!path.exists());
        let key = SigningKey::generate(&mut OsRng);
        let public = hex::encode(key.verifying_key().as_bytes());
        for content in [
            key.to_bytes().to_vec(),
            format!("  {}\n", hex::encode_upper(key.to_bytes())).into_bytes(),
        ] {
            crypto::key_file::publish_new(&path, &content).unwrap();
            assert_eq!(
                Wallet::load_keyfile(&path, false).unwrap().public_key(),
                public
            );
            fs::remove_file(&path).unwrap();
        }
        fs::remove_dir(dir).unwrap();
    }
}
