use sha2::{Sha256, Digest};
// Re-export specific Ed25519 types for consumers (like consensus)
pub use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey, SigningKey};
use std::fmt;

// Core cryptographic primitives
pub mod ecdsa;
pub mod poseidon;

// Zero-Knowledge Proofs
pub mod zkp;

// Advanced cryptography
pub mod bls;
pub mod threshold;
pub mod accumulator;
pub mod mpc;

pub mod vdf;
pub mod multi_sig;
pub mod transport;

// Blockchain features
pub mod account_abstraction;
pub mod bridges;

pub mod rollup;
pub mod recursive;

// Re-exports for convenient access
pub use ecdsa::{ECDSACrypto, ECDSAError};
pub use multi_sig::{MultiSigVerifier, SignatureScheme, MultiSigError};
pub use zkp::{SNARKProver, SNARKError, STARKProver, STARKError, HashPreimageCircuit};
pub use vdf::{VDFEngine, VDFError};

pub use mpc::{MPCProtocol, MPCError};
pub use threshold::threshold_bls::{ThresholdBLS, ThresholdKeyShare, PartialSignature, BlsSigner, aggregate_bls};
pub use bls::{BLSEngine, BLSError};
pub use accumulator::{Accumulator, AccumulatorError};


/// Cryptographic primitives for AINCORE Blockchain
/// 
/// This module provides centralized, verified implementations of:
/// - Hashing (SHA-256)
/// - Signature verification (Ed25519)
/// - Address derivation
/// 
/// All functions use industry-standard libraries and include proper error handling.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey(String),
    InvalidSignature(String),
    InvalidInput(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            CryptoError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            CryptoError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Hash arbitrary data using SHA-256
/// 
/// # Arguments
/// * `data` - Byte slice to hash
/// 
/// # Returns
/// * 32-byte hash as `Vec<u8>`
/// 
/// # Example
/// ```
/// let data = b"Hello, AINCORE!";
/// let hash = crypto::hash(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash and return as hex string
pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash(data))
}

/// Verify Ed25519 signature
/// 
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// * `message` - Message that was signed
/// * `signature` - 64-byte Ed25519 signature
/// 
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err(CryptoError)` if inputs are malformed
/// 
/// # Example
/// ```
/// use crypto::{Signer, SigningKey}; // re-exported
/// use rand::rngs::OsRng; // assuming rand is avail, or just mock bytes
/// // Use dummy bytes for example to avoid complex setup
/// let pubkey = [0u8; 32];
/// let message = b"transaction data";
/// let signature = [0u8; 64];
/// 
/// // This will return Ok(false) or Err because sig is invalid, but it compiles/runs
/// let _ = crypto::verify_signature(&pubkey, message, &signature);
/// ```
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8]
) -> Result<bool, CryptoError> {
    // Validate input lengths
    if public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKey(
            format!("Expected 32 bytes, got {}", public_key.len())
        ));
    }
    
    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature(
            format!("Expected 64 bytes, got {}", signature.len())
        ));
    }
    
    // Parse public key
    let pubkey = VerifyingKey::from_bytes(
        public_key.try_into()
            .map_err(|_| CryptoError::InvalidPublicKey("Failed to convert bytes".to_string()))?
    ).map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
    
    // Parse signature
    let sig = Signature::from_bytes(
        signature.try_into()
            .map_err(|_| CryptoError::InvalidSignature("Failed to convert bytes".to_string()))?
    );
    
    // Verify
    match pubkey.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Derive AINCORE address from public key
/// 
/// Address = hex(first 16 bytes of SHA256(public_key))
/// 
/// # Arguments
/// * `public_key` - 32-byte Ed25519 public key
/// 
/// # Returns
/// * 32-character hex string (16 bytes)
/// 
/// # Example
/// ```
/// let pubkey = [0u8; 32];
/// let address = crypto::derive_address(&pubkey).unwrap();
/// assert_eq!(address.len(), 32); // 16 bytes = 32 hex chars
/// ```
pub fn derive_address(public_key: &[u8]) -> Result<String, CryptoError> {
    if public_key.is_empty() {
        return Err(CryptoError::InvalidInput("Public key cannot be empty".to_string()));
    }
    
    let hash = hash(public_key);
    Ok(hex::encode(&hash[0..16]))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash() {
        let data = b"Hello, AINCORE!";
        let hash_result = hash(data);
        assert_eq!(hash_result.len(), 32);
        
        // Hash should be deterministic
        let hash2 = hash(data);
        assert_eq!(hash_result, hash2);
    }
    
    #[test]
    fn test_hash_hex() {
        let data = b"test";
        let hex_hash = hash_hex(data);
        assert_eq!(hex_hash.len(), 64); // 32 bytes = 64 hex chars
    }
    
    #[test]
    fn test_derive_address() {
        let pubkey = vec![0u8; 32]; // Dummy pubkey
        let address = derive_address(&pubkey).unwrap();
        assert_eq!(address.len(), 32); // 16 bytes = 32 hex chars
    }
    
    #[test]
    fn test_derive_address_empty() {
        let result = derive_address(&[]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_verify_signature_invalid_pubkey_length() {
        let result = verify_signature(&[0u8; 16], b"msg", &[0u8; 64]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_verify_signature_invalid_sig_length() {
        let result = verify_signature(&[0u8; 32], b"msg", &[0u8; 32]);
        assert!(result.is_err());
    }
}
