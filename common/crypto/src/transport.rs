use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use chacha20poly1305::aead::Aead; // Added Aead trait
use sha2::{Sha256, Digest};

/// Transport Encryption Engine
/// 
/// Handles Transport Layer Security using:
/// - X25519 for Key Exchange (Diffie-Hellman)
/// - ChaCha20Poly1305 for Authenticated Encryption
pub struct TransportEngine;

impl TransportEngine {
    /// Generate an ephemeral keypair for a session
    pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Compute Shared Secret via ECDH
    /// Returns a 32-byte key derived from the shared secret (ready for ChaCha20)
    pub fn diffie_hellman(secret: EphemeralSecret, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_pub = PublicKey::from(*peer_public);
        let shared_secret = secret.diffie_hellman(&peer_pub);
        
        // KDF: Hash the shared secret to get a uniform key
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let result = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Encrypt data using ChaCha20Poly1305
    /// 
    /// # Arguments
    /// * `key` - 32-byte shared session key
    /// * `nonce` - 12-byte unique nonce (must increment per message)
    /// * `plaintext` - Message to encrypt
    pub fn encrypt(key_bytes: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = Key::from_slice(key_bytes); // Warning suppressed / dealt with by compiler usually
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes); 

        cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failure: {}", e))
    }

    /// Decrypt data using ChaCha20Poly1305
    pub fn decrypt(key_bytes: &[u8; 32], nonce_bytes: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failure (Auth Tag Mismatch)".to_string())
    }
}
