use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use chacha20poly1305::aead::Aead; // Added Aead trait
use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================
// SECURITY: Global atomic nonce counter
// ============================================================
// ChaCha20-Poly1305 requires unique nonces per (key, message) pair.
// Reusing a nonce with the same key leaks plaintext via XOR of 
// ciphertexts and invalidates the Poly1305 authentication tag.
//
// This counter guarantees monotonically increasing nonce values
// across all threads. Combined with 4 random bytes as salt,
// the 12-byte nonce format is:
//   [counter: 8 bytes (big-endian)] [random_salt: 4 bytes]
//
// The random salt prevents cross-process/restart collisions.
// Even if the counter resets to 0 on node restart, the 4 random
// bytes make a nonce collision astronomically unlikely (~2^-32 per
// counter value, and the counter itself is unique per session).
// ============================================================
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Transport Encryption Engine
/// 
/// Handles Transport Layer Security using:
/// - X25519 for Key Exchange (Diffie-Hellman)
/// - ChaCha20Poly1305 for Authenticated Encryption
/// - Atomic nonce counter for guaranteed nonce uniqueness
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

    /// Generate a unique 12-byte nonce using atomic counter + random salt.
    ///
    /// Format: [counter (8 bytes BE)][random_salt (4 bytes)]
    ///
    /// This is safe to call from multiple threads concurrently.
    /// The counter is monotonically increasing and never repeats within
    /// a process lifetime. The 4-byte random salt prevents collisions
    /// across process restarts.
    pub fn generate_nonce() -> [u8; 12] {
        let counter = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let counter_bytes = counter.to_be_bytes(); // 8 bytes
        
        let mut salt = [0u8; 4];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
        
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter_bytes);
        nonce[8..].copy_from_slice(&salt);
        nonce
    }

    /// Encrypt data using ChaCha20Poly1305 with an automatically generated
    /// unique nonce. Returns (nonce, ciphertext).
    ///
    /// This is the **recommended** encryption method. It guarantees nonce
    /// uniqueness via an internal atomic counter, eliminating the risk of
    /// nonce reuse.
    ///
    /// # Arguments
    /// * `key` - 32-byte shared session key
    /// * `plaintext` - Message to encrypt
    ///
    /// # Returns
    /// * `Ok((nonce, ciphertext))` - The nonce must be transmitted alongside
    ///   the ciphertext so the receiver can decrypt.
    pub fn encrypt_safe(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), String> {
        let nonce_bytes = Self::generate_nonce();
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failure: {}", e))?;
        
        Ok((nonce_bytes, ciphertext))
    }

    /// Encrypt data using ChaCha20Poly1305
    /// 
    /// # Arguments
    /// * `key` - 32-byte shared session key
    /// * `nonce` - 12-byte unique nonce (must increment per message)
    /// * `plaintext` - Message to encrypt
    ///
    /// # Safety Warning
    /// Callers MUST ensure nonce uniqueness per key. Prefer `encrypt_safe()`
    /// which handles nonce generation automatically.
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
