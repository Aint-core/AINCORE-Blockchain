use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, PreparedVerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK; // Import SNARK trait
use ark_std::rand::RngCore;
use std::fmt;

/// zk-SNARK errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SNARKError {
    SetupFailed(String),
    ProvingFailed(String),
    VerificationFailed(String),
    InvalidProof(String),
    InvalidPublicInputs(String),
    SerializationFailed(String),
}

impl fmt::Display for SNARKError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SNARKError::SetupFailed(msg) => write!(f, "Setup failed: {}", msg),
            SNARKError::ProvingFailed(msg) => write!(f, "Proving failed: {}", msg),
            SNARKError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            SNARKError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            SNARKError::InvalidPublicInputs(msg) => write!(f, "Invalid public inputs: {}", msg),
            SNARKError::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
        }
    }
}

impl std::error::Error for SNARKError {}

/// zk-SNARK prover using Groth16
/// 
/// Groth16 is a zero-knowledge proof system that produces:
/// - Constant-size proofs (~200 bytes)
/// - Fast verification (~5ms)
/// - Requires trusted setup
/// 
/// Security: Based on elliptic curve pairings (BN254)
/// Quantum-safe: NO (uses elliptic curves)
pub struct SNARKProver {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
    prepared_vk: PreparedVerifyingKey<Bn254>,
}

impl SNARKProver {
    /// Setup zk-SNARK with a circuit
    /// 
    /// WARNING: This performs a trusted setup. In production, use a
    /// multi-party computation (MPC) ceremony for the setup phase.
    /// 
    /// # Arguments
    /// * `circuit` - The circuit to create proofs for
    /// * `rng` - Random number generator
    pub fn setup<C, R>(circuit: C, rng: &mut R) -> Result<Self, SNARKError>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + rand::CryptoRng,
    {
        // Perform trusted setup
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
            .map_err(|e| SNARKError::SetupFailed(format!("{:?}", e)))?;
        
        // Prepare verifying key for faster verification
        let prepared_vk = PreparedVerifyingKey::from(vk.clone());
        
        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_vk,
        })
    }
    
    /// Generate a zk-SNARK proof
    /// 
    /// # Arguments
    /// * `circuit` - Circuit with witness values
    /// * `rng` - Random number generator
    /// 
    /// # Returns
    /// * Groth16 proof (~200 bytes)
    pub fn prove<C, R>(&self, circuit: C, rng: &mut R) -> Result<Proof<Bn254>, SNARKError>
    where
        C: ConstraintSynthesizer<Fr>,
        R: RngCore + rand::CryptoRng,
    {
        Groth16::<Bn254>::prove(&self.proving_key, circuit, rng)
            .map_err(|e| SNARKError::ProvingFailed(format!("{:?}", e)))
    }
    
    /// Verify a zk-SNARK proof
    /// 
    /// # Arguments
    /// * `public_inputs` - Public inputs to the circuit
    /// * `proof` - The proof to verify
    /// 
    /// # Returns
    /// * `Ok(true)` if proof is valid
    /// * `Ok(false)` if proof is invalid
    pub fn verify(
        &self,
        public_inputs: &[Fr],
        proof: &Proof<Bn254>,
    ) -> Result<bool, SNARKError> {
        Groth16::<Bn254>::verify_with_processed_vk(&self.prepared_vk, public_inputs, proof)
            .map_err(|e| SNARKError::VerificationFailed(format!("{:?}", e)))
    }
    
    /// Get verifying key (for sharing with verifiers)
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }
}

/// Example circuit: Prove knowledge of a value that hashes to a given output
/// 
/// Public inputs: hash_output
/// Private inputs: preimage
/// 
/// Circuit proves: hash(preimage) == hash_output
#[derive(Clone)]
pub struct HashPreimageCircuit {
    pub preimage: Option<Fr>,
    pub hash_output: Fr,
}

impl ConstraintSynthesizer<Fr> for HashPreimageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_r1cs_std::prelude::*;
        use ark_r1cs_std::fields::fp::FpVar;
        
        // Allocate private input (witness)
        let preimage_var = FpVar::new_witness(cs.clone(), || {
            self.preimage.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate public input
        let hash_output_var = FpVar::new_input(cs.clone(), || Ok(self.hash_output))?;
        
        // Simple hash: square the preimage
        // In production, use a proper hash function like Poseidon
        let computed_hash = &preimage_var * &preimage_var;
        
        // Enforce constraint: computed_hash == hash_output
        computed_hash.enforce_equal(&hash_output_var)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_snark_setup() {
        let mut rng = thread_rng();
        
        // Create dummy circuit for setup
        let circuit = HashPreimageCircuit {
            preimage: None,
            hash_output: Fr::from(0u64),
        };
        
        // Setup should succeed
        let prover = SNARKProver::setup(circuit, &mut rng);
        assert!(prover.is_ok());
    }
    
    #[test]
    fn test_snark_prove_and_verify() {
        let mut rng = thread_rng();
        
        // Setup with dummy circuit
        let setup_circuit = HashPreimageCircuit {
            preimage: None,
            hash_output: Fr::from(0u64),
        };
        let prover = SNARKProver::setup(setup_circuit, &mut rng).unwrap();
        
        // Create proof with actual values
        let preimage = Fr::from(5u64);
        let hash_output = preimage * preimage; // 25
        
        let prove_circuit = HashPreimageCircuit {
            preimage: Some(preimage),
            hash_output,
        };
        
        // Generate proof
        let proof = prover.prove(prove_circuit, &mut rng).unwrap();
        
        // Verify proof (should succeed)
        let public_inputs = vec![hash_output];
        let is_valid = prover.verify(&public_inputs, &proof).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_snark_invalid_proof() {
        let mut rng = thread_rng();
        
        // Setup
        let setup_circuit = HashPreimageCircuit {
            preimage: None,
            hash_output: Fr::from(0u64),
        };
        let prover = SNARKProver::setup(setup_circuit, &mut rng).unwrap();
        
        // Create proof with correct values
        let preimage = Fr::from(5u64);
        let hash_output = preimage * preimage; // 25
        
        let prove_circuit = HashPreimageCircuit {
            preimage: Some(preimage),
            hash_output,
        };
        
        let proof = prover.prove(prove_circuit, &mut rng).unwrap();
        
        // Try to verify with wrong public input
        let wrong_public_inputs = vec![Fr::from(100u64)];
        let is_valid = prover.verify(&wrong_public_inputs, &proof).unwrap();
        assert!(!is_valid);
    }
    
    #[test]
    fn test_multiple_proofs() {
        let mut rng = thread_rng();
        
        // Setup once
        let setup_circuit = HashPreimageCircuit {
            preimage: None,
            hash_output: Fr::from(0u64),
        };
        let prover = SNARKProver::setup(setup_circuit, &mut rng).unwrap();
        
        // Generate multiple proofs
        for i in 1..10 {
            let preimage = Fr::from(i);
            let hash_output = preimage * preimage;
            
            let circuit = HashPreimageCircuit {
                preimage: Some(preimage),
                hash_output,
            };
            
            let proof = prover.prove(circuit, &mut rng).unwrap();
            let is_valid = prover.verify(&vec![hash_output], &proof).unwrap();
            assert!(is_valid, "Proof {} should be valid", i);
        }
    }
}
