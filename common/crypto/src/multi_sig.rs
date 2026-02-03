use crate::ecdsa::ECDSACrypto;
use crate::verify_signature as verify_ed25519;
use std::fmt;

/// Signature scheme selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Ed25519 (fast, existing)
    /// - Signature size: 64 bytes
    /// - Public key size: 32 bytes
    /// - Speed: VERY FAST
    /// - Quantum-safe: NO
    Ed25519 = 0,
    
    /// CRYSTALS-Dilithium5 (post-quantum)
    /// - Signature size: 4627 bytes
    /// - Public key size: 2592 bytes
    /// - Speed: MEDIUM
    /// - Quantum-safe: YES
    Dilithium5 = 1,
    
    /// secp256k1 ECDSA (Bitcoin-compatible)
    /// - Signature size: 64 bytes
    /// - Public key size: 33 bytes (compressed)
    /// - Speed: FAST
    /// - Quantum-safe: NO
    Secp256k1 = 2,
}

impl SignatureScheme {
    /// Parse scheme from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SignatureScheme::Ed25519),
            1 => Some(SignatureScheme::Dilithium5),
            2 => Some(SignatureScheme::Secp256k1),
            _ => None,
        }
    }
    
    /// Convert scheme to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiSigError {
    UnsupportedScheme(u8),
    Ed25519Error(String),
    Dilithium5Error(String),
    Secp256k1Error(String),
    InvalidPublicKeyLength(usize, usize), // expected, got
    InvalidSignatureLength(usize, usize), // expected, got
}

impl fmt::Display for MultiSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MultiSigError::UnsupportedScheme(s) => write!(f, "Unsupported signature scheme: {}", s),
            MultiSigError::Ed25519Error(e) => write!(f, "Ed25519 error: {}", e),
            MultiSigError::Dilithium5Error(e) => write!(f, "Dilithium5 error: {}", e),
            MultiSigError::Secp256k1Error(e) => write!(f, "secp256k1 error: {}", e),
            MultiSigError::InvalidPublicKeyLength(exp, got) => {
                write!(f, "Invalid public key length: expected {}, got {}", exp, got)
            }
            MultiSigError::InvalidSignatureLength(exp, got) => {
                write!(f, "Invalid signature length: expected {}, got {}", exp, got)
            }
        }
    }
}

impl std::error::Error for MultiSigError {}

/// Multi-signature verifier supporting multiple schemes
pub struct MultiSigVerifier {
    ecdsa_crypto: ECDSACrypto,
}

impl MultiSigVerifier {
    pub fn new() -> Self {
        Self {
            ecdsa_crypto: ECDSACrypto::new(),
        }
    }
    
    /// Verify signature with specified scheme
    /// 
    /// # Arguments
    /// * `scheme` - Signature scheme to use
    /// * `public_key` - Public key bytes
    /// * `message` - Message that was signed
    /// * `signature` - Signature bytes
    /// 
    /// # Returns
    /// * `Ok(true)` if signature is valid
    /// * `Ok(false)` if signature is invalid
    /// * `Err` if inputs are malformed
    pub fn verify(
        &self,
        scheme: SignatureScheme,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, MultiSigError> {
        match scheme {
            SignatureScheme::Ed25519 => {
                self.verify_ed25519(public_key, message, signature)
            }
            SignatureScheme::Dilithium5 => {
                self.verify_dilithium5(public_key, message, signature)
            }
            SignatureScheme::Secp256k1 => {
                self.verify_secp256k1(public_key, message, signature)
            }
        }
    }
    
    /// Verify Ed25519 signature
    fn verify_ed25519(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, MultiSigError> {
        // Validate lengths
        if public_key.len() != 32 {
            return Err(MultiSigError::InvalidPublicKeyLength(32, public_key.len()));
        }
        if signature.len() != 64 {
            return Err(MultiSigError::InvalidSignatureLength(64, signature.len()));
        }
        
        // Use existing Ed25519 verification
        verify_ed25519(public_key, message, signature)
            .map_err(|e| MultiSigError::Ed25519Error(e.to_string()))
    }
    
    /// Verify Dilithium5 signature (Post-Quantum)
    fn verify_dilithium5(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, MultiSigError> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
        
        // Validate lengths
        if public_key.len() != 2592 {
            return Err(MultiSigError::InvalidPublicKeyLength(2592, public_key.len()));
        }
        if signature.len() != 4627 {
            return Err(MultiSigError::InvalidSignatureLength(4627, signature.len()));
        }
        
        // Parse public key
        let pk = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|_| MultiSigError::Dilithium5Error("Invalid public key format".to_string()))?;
        
        // Parse signature
        let sig = dilithium5::DetachedSignature::from_bytes(signature)
            .map_err(|_| MultiSigError::Dilithium5Error("Invalid signature format".to_string()))?;
        
        // Verify signature
        match dilithium5::verify_detached_signature(&sig, message, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Verify secp256k1 ECDSA signature
    fn verify_secp256k1(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, MultiSigError> {
        // Validate signature length
        if signature.len() != 64 {
            return Err(MultiSigError::InvalidSignatureLength(64, signature.len()));
        }
        
        // Parse public key
        let pk = self.ecdsa_crypto.public_key_from_bytes(public_key)
            .map_err(|e| MultiSigError::Secp256k1Error(e.to_string()))?;
        
        // Verify signature
        self.ecdsa_crypto.verify(&pk, message, signature)
            .map_err(|e| MultiSigError::Secp256k1Error(e.to_string()))
    }
    
    /// Auto-detect signature scheme from signature length
    /// 
    /// This is a convenience method that attempts to determine the scheme
    /// based on signature size. Use with caution as it's not foolproof.
    pub fn auto_detect_scheme(&self, signature: &[u8]) -> Option<SignatureScheme> {
        match signature.len() {
            64 => Some(SignatureScheme::Ed25519), // Could also be secp256k1
            4627 => Some(SignatureScheme::Dilithium5),
            _ => None,
        }
    }
}

impl Default for MultiSigVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scheme_conversion() {
        assert_eq!(SignatureScheme::from_u8(0), Some(SignatureScheme::Ed25519));
        assert_eq!(SignatureScheme::from_u8(1), Some(SignatureScheme::Dilithium5));
        assert_eq!(SignatureScheme::from_u8(2), Some(SignatureScheme::Secp256k1));
        assert_eq!(SignatureScheme::from_u8(99), None);
        
        assert_eq!(SignatureScheme::Ed25519.to_u8(), 0);
        assert_eq!(SignatureScheme::Dilithium5.to_u8(), 1);
        assert_eq!(SignatureScheme::Secp256k1.to_u8(), 2);
    }
    
    #[test]
    fn test_secp256k1_verification() {
        let verifier = MultiSigVerifier::new();
        let ecdsa = ECDSACrypto::new();
        
        // Generate keypair
        let (sk, pk) = ecdsa.generate_keypair().unwrap();
        let pk_bytes = ecdsa.public_key_to_bytes(&pk);
        
        // Sign message
        let message = b"Test message for secp256k1";
        let signature = ecdsa.sign(&sk, message).unwrap();
        
        // Verify with multi-sig verifier
        let result = verifier.verify(
            SignatureScheme::Secp256k1,
            &pk_bytes,
            message,
            &signature,
        );
        
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_secp256k1_invalid_signature() {
        let verifier = MultiSigVerifier::new();
        let ecdsa = ECDSACrypto::new();
        
        let (sk, pk) = ecdsa.generate_keypair().unwrap();
        let pk_bytes = ecdsa.public_key_to_bytes(&pk);
        
        let message = b"Original message";
        let signature = ecdsa.sign(&sk, message).unwrap();
        
        // Verify with different message
        let wrong_message = b"Wrong message";
        let result = verifier.verify(
            SignatureScheme::Secp256k1,
            &pk_bytes,
            wrong_message,
            &signature,
        );
        
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    
    #[test]
    fn test_invalid_signature_length() {
        let verifier = MultiSigVerifier::new();
        let ecdsa = ECDSACrypto::new();
        
        let (_sk, pk) = ecdsa.generate_keypair().unwrap();
        let pk_bytes = ecdsa.public_key_to_bytes(&pk);
        
        let message = b"Test";
        let invalid_sig = vec![0u8; 32]; // Wrong length
        
        let result = verifier.verify(
            SignatureScheme::Secp256k1,
            &pk_bytes,
            message,
            &invalid_sig,
        );
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_auto_detect_scheme() {
        let verifier = MultiSigVerifier::new();
        
        // Ed25519/secp256k1 signature (both 64 bytes)
        let sig_64 = vec![0u8; 64];
        assert_eq!(verifier.auto_detect_scheme(&sig_64), Some(SignatureScheme::Ed25519));
        
        // Dilithium5 signature
        let sig_4627 = vec![0u8; 4627];
        assert_eq!(verifier.auto_detect_scheme(&sig_4627), Some(SignatureScheme::Dilithium5));
        
        // Unknown
        let sig_unknown = vec![0u8; 100];
        assert_eq!(verifier.auto_detect_scheme(&sig_unknown), None);
    }
}
