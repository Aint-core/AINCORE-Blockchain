use eth_keystore::KeystoreError;
use std::path::Path;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Keystore error: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid key")]
    InvalidKey,
}

pub struct KeyManager;

impl KeyManager {
    /// Create a new encrypted keystore file
    pub fn create<P: AsRef<Path>>(dir: P, password: &str) -> Result<(String, String), Error> {
        use rand::rngs::OsRng;
        use zeroize::Zeroize;

        let mut rng = OsRng;
        // eth-keystore generates a random key and encrypts it
        let (mut private_key, uuid) = eth_keystore::new(&dir, &mut rng, password, None)?;

        let hex_key = hex::encode(&private_key);

        // WIPE PRIVATE KEY FROM MEMORY
        private_key.zeroize();

        // Return private key (hex) and filename (uuid)
        Ok((hex_key, uuid))
    }

    /// Decrypt a private key from a keystore file
    pub fn decrypt<P: AsRef<Path>>(path: P, password: &str) -> Result<String, Error> {
        use zeroize::Zeroize;
        let mut key = eth_keystore::decrypt_key(path, password)?;
        let hex_key = hex::encode(&key);

        // WIPE RAW BYTES
        key.zeroize();

        Ok(hex_key)
    }

    /// Import an existing private key into a new keystore file
    pub fn import<P: AsRef<Path>>(
        dir: P,
        private_key: &str,
        password: &str,
    ) -> Result<String, Error> {
        use rand::rngs::OsRng;
        use zeroize::Zeroize;

        let mut rng = OsRng;
        let mut key_bytes = hex::decode(private_key).map_err(|_| Error::InvalidKey)?;
        let uuid = eth_keystore::encrypt_key(&dir, &mut rng, &key_bytes, password, None)?;

        // WIPE INTERMEDIATE BYTES
        key_bytes.zeroize();

        Ok(uuid)
    }
}
