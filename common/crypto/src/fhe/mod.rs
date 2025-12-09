use tfhe::prelude::*;
use tfhe::{ConfigBuilder, ServerKey, ClientKey, FheUint64, set_server_key};

// Global Server Key for Validators (Simulated for Prototype)
// In production, this would be loaded from extensive setup
pub struct FheEngine {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
}

impl FheEngine {
    /// Initialize FHE Environment (Expensive!)
    pub fn new() -> Self {
        let config = ConfigBuilder::default().build();
        let client_key = ClientKey::generate(config);
        let server_key = ServerKey::new(&client_key);
        Self { client_key, server_key }
    }

    /// Encrypt a u64 balance
    pub fn encrypt(&self, value: u64) -> FheUint64 {
        FheUint64::encrypt(value, &self.client_key)
    }

    /// Decrypt a u64 balance
    pub fn decrypt(&self, cipher: &FheUint64) -> u64 {
        cipher.decrypt(&self.client_key)
    }

    /// Add two encrypted balances (Homomorphic Addition)
    /// This happens on Valiadtor WITHOUT Client Key
    pub fn add(&self, a: &FheUint64, b: &FheUint64) -> FheUint64 {
        // In real usage, we would set_server_key(self.server_key.clone())
        // But here we just use the reference if API supports it, or set global
        set_server_key(self.server_key.clone());
        a + b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_homomorphic_addition() {
        // 1. Setup
        let engine = FheEngine::new();
        set_server_key(engine.server_key.clone());

        // 2. Encrypt Inputs (Client Side)
        let a = 10u64;
        let b = 20u64;
        
        // TFHE encryption
        let ct_a = engine.encrypt(a);
        let ct_b = engine.encrypt(b);

        // 3. Compute (Server Side - Validator)
        // Validator DOES NOT KNOW 'a' or 'b', only sees ciphertexts.
        let ct_result = engine.add(&ct_a, &ct_b);

        // 4. Decrypt Result (Client Side)
        let result = engine.decrypt(&ct_result);

        // 5. Verify
        assert_eq!(result, 30);
        println!("✅ FHE Verified: Enc({}) + Enc({}) = Enc({}) -> Decrypted {}", a, b, 30, result);
    }
}
