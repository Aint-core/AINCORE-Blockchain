use secp256k1::{All, Error as Secp256k1Error, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// ECDSA cryptography using secp256k1 (Bitcoin-compatible)
///
/// This module provides Bitcoin/Ethereum-compatible ECDSA signatures
/// using the secp256k1 elliptic curve (y² = x³ + 7).
///
/// Security: Discrete Logarithm Problem (DLP)
/// Time to crack: ~10^27 years with current computers
/// Quantum vulnerability: Yes (Shor's algorithm)

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ECDSAError {
    InvalidSecretKey(String),
    InvalidPublicKey(String),
    InvalidSignature(String),
    InvalidMessage(String),
    SigningFailed(String),
    VerificationFailed(String),
}

impl fmt::Display for ECDSAError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ECDSAError::InvalidSecretKey(msg) => write!(f, "Invalid secret key: {}", msg),
            ECDSAError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            ECDSAError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            ECDSAError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            ECDSAError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            ECDSAError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
        }
    }
}

impl std::error::Error for ECDSAError {}

impl From<Secp256k1Error> for ECDSAError {
    fn from(err: Secp256k1Error) -> Self {
        ECDSAError::InvalidPublicKey(err.to_string())
    }
}

/// ECDSA cryptographic engine
pub struct ECDSACrypto {
    secp: Secp256k1<All>,
}

impl ECDSACrypto {
    /// Create new ECDSA crypto instance
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Generate new keypair (Bitcoin-compatible)
    ///
    /// Returns (SecretKey, PublicKey)
    /// SecretKey: 32 bytes (256-bit random number)
    /// PublicKey: 33 bytes (compressed) or 65 bytes (uncompressed)
    pub fn generate_keypair(&self) -> Result<(SecretKey, PublicKey), ECDSAError> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        Ok(self.secp.generate_keypair(&mut rng))
    }

    /// Sign message using ECDSA
    ///
    /// # Arguments
    /// * `secret_key` - 32-byte secret key
    /// * `message` - Message to sign (will be hashed with SHA-256)
    ///
    /// # Returns
    /// * Compact signature (64 bytes: 32-byte r + 32-byte s)
    pub fn sign(&self, secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, ECDSAError> {
        // Hash message with SHA-256
        let msg_hash = Sha256::digest(message);

        // Create Message from hash
        let msg = Message::from_digest_slice(&msg_hash)
            .map_err(|e| ECDSAError::InvalidMessage(e.to_string()))?;

        // Sign using ECDSA
        let signature = self.secp.sign_ecdsa(&msg, secret_key);

        // Return compact signature (64 bytes)
        Ok(signature.serialize_compact().to_vec())
    }

    /// Verify ECDSA signature
    ///
    /// # Arguments
    /// * `public_key` - Public key to verify against
    /// * `message` - Original message
    /// * `signature` - 64-byte compact signature
    ///
    /// # Returns
    /// * `Ok(true)` if signature is valid
    /// * `Ok(false)` if signature is invalid
    /// * `Err` if inputs are malformed
    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ECDSAError> {
        // Validate signature length
        if signature.len() != 64 {
            return Err(ECDSAError::InvalidSignature(format!(
                "Expected 64 bytes, got {}",
                signature.len()
            )));
        }

        // Hash message with SHA-256
        let msg_hash = Sha256::digest(message);

        // Create Message from hash
        let msg = Message::from_digest_slice(&msg_hash)
            .map_err(|e| ECDSAError::InvalidMessage(e.to_string()))?;

        // Parse signature
        let sig = secp256k1::ecdsa::Signature::from_compact(signature)
            .map_err(|e| ECDSAError::InvalidSignature(e.to_string()))?;

        // Verify signature
        match self.secp.verify_ecdsa(&msg, &sig, public_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Derive Bitcoin-style address from public key
    ///
    /// Address = hex(first 20 bytes of SHA256(public_key))
    ///
    /// # Arguments
    /// * `public_key` - secp256k1 public key
    ///
    /// # Returns
    /// * 40-character hex string (20 bytes)
    pub fn derive_address(&self, public_key: &PublicKey) -> String {
        let pubkey_bytes = public_key.serialize();
        let hash = Sha256::digest(pubkey_bytes);
        hex::encode(&hash[0..20])
    }

    /// Parse secret key from bytes
    pub fn secret_key_from_bytes(&self, bytes: &[u8]) -> Result<SecretKey, ECDSAError> {
        if bytes.len() != 32 {
            return Err(ECDSAError::InvalidSecretKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        SecretKey::from_slice(bytes).map_err(|e| ECDSAError::InvalidSecretKey(e.to_string()))
    }

    /// Parse public key from bytes
    pub fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<PublicKey, ECDSAError> {
        PublicKey::from_slice(bytes).map_err(|e| ECDSAError::InvalidPublicKey(e.to_string()))
    }

    /// Serialize secret key to bytes
    pub fn secret_key_to_bytes(&self, sk: &SecretKey) -> [u8; 32] {
        sk.secret_bytes()
    }

    /// Serialize public key to bytes (compressed)
    pub fn public_key_to_bytes(&self, pk: &PublicKey) -> Vec<u8> {
        pk.serialize().to_vec()
    }
}

impl Default for ECDSACrypto {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let crypto = ECDSACrypto::new();
        let (sk, pk) = crypto.generate_keypair().unwrap();

        // Secret key should be 32 bytes
        assert_eq!(crypto.secret_key_to_bytes(&sk).len(), 32);

        // Public key should be 33 bytes (compressed)
        assert_eq!(crypto.public_key_to_bytes(&pk).len(), 33);
    }

    #[test]
    fn test_sign_and_verify() {
        let crypto = ECDSACrypto::new();
        let (sk, pk) = crypto.generate_keypair().unwrap();

        let message = b"Hello, Bitcoin!";

        // Sign
        let signature = crypto.sign(&sk, message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify (should succeed)
        assert!(crypto.verify(&pk, message, &signature).unwrap());

        // Verify with wrong message (should fail)
        let wrong_message = b"Wrong message";
        assert!(!crypto.verify(&pk, wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_verify_with_different_keypair() {
        let crypto = ECDSACrypto::new();
        let (sk1, _pk1) = crypto.generate_keypair().unwrap();
        let (_sk2, pk2) = crypto.generate_keypair().unwrap();

        let message = b"Test message";
        let signature = crypto.sign(&sk1, message).unwrap();

        // Verify with different public key (should fail)
        assert!(!crypto.verify(&pk2, message, &signature).unwrap());
    }

    #[test]
    fn test_derive_address() {
        let crypto = ECDSACrypto::new();
        let (_sk, pk) = crypto.generate_keypair().unwrap();

        let address = crypto.derive_address(&pk);

        // Address should be 40 hex characters (20 bytes)
        assert_eq!(address.len(), 40);

        // Should be valid hex
        assert!(hex::decode(&address).is_ok());
    }

    #[test]
    fn test_deterministic_address() {
        let crypto = ECDSACrypto::new();
        let (_sk, pk) = crypto.generate_keypair().unwrap();

        let address1 = crypto.derive_address(&pk);
        let address2 = crypto.derive_address(&pk);

        // Same public key should give same address
        assert_eq!(address1, address2);
    }

    #[test]
    fn test_invalid_signature_length() {
        let crypto = ECDSACrypto::new();
        let (_sk, pk) = crypto.generate_keypair().unwrap();

        let message = b"Test";
        let invalid_sig = vec![0u8; 32]; // Wrong length

        let result = crypto.verify(&pk, message, &invalid_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_serialization() {
        let crypto = ECDSACrypto::new();
        let (sk, _pk) = crypto.generate_keypair().unwrap();

        // Serialize
        let bytes = crypto.secret_key_to_bytes(&sk);

        // Deserialize
        let sk2 = crypto.secret_key_from_bytes(&bytes).unwrap();

        // Should be equal
        assert_eq!(
            crypto.secret_key_to_bytes(&sk),
            crypto.secret_key_to_bytes(&sk2)
        );
    }

    #[test]
    fn test_public_key_serialization() {
        let crypto = ECDSACrypto::new();
        let (_sk, pk) = crypto.generate_keypair().unwrap();

        // Serialize
        let bytes = crypto.public_key_to_bytes(&pk);

        // Deserialize
        let pk2 = crypto.public_key_from_bytes(&bytes).unwrap();

        // Should be equal
        assert_eq!(
            crypto.public_key_to_bytes(&pk),
            crypto.public_key_to_bytes(&pk2)
        );
    }
}
