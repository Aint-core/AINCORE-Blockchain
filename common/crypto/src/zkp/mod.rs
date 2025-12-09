/// Zero-Knowledge Proof modules
pub mod snark;
pub mod stark;

// STARK AIR circuits (Phase 2)
pub mod fibonacci_air;
pub mod fibonacci_trace;  // Week 5: Trace generation
pub mod fibonacci_prover; // Week 5 Phase 2: Prover integration
pub mod stark_proof;      // Phase 3-5: Proof generation & verification
pub mod minimal_air;
pub mod merkle_air;  // Week 1: Merkle Tree Circuit
pub mod merkle_trace;  // Week 2: Merkle Trace Generation
pub mod merkle_prover;  // Week 2: Merkle Prover
pub mod batch_prover;  // Week 3: Batch Proving

// Poseidon-based Merkle (Advanced cryptographic security)
pub mod poseidon_merkle_air;
pub mod poseidon_merkle_trace;

// Advanced features moved to separate modules
// See: src/poseidon, src/rollup, src/account_abstraction, etc.

// Re-exports
pub use snark::{SNARKProver, SNARKError, HashPreimageCircuit};
pub use stark::{STARKProver, STARKVerifier, STARKError, STARKProofData};
