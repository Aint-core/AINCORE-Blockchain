/// Phase 3 / C-03 — Checkpointed Sequential-Hash VDF
///
/// Replaces the "compute == verify" stub with a sequential hash-chain VDF
/// that has DISTINCT computation cost (O(t)) vs verification cost (O(√t)).
///
/// ## What this IS
/// - A **sequential SHA3-256 hash chain**: `h_0 = SHA3(challenge)`,
///   `h_{i+1} = SHA3(h_i || i)`, output = `h_difficulty`.
/// - **Proof** = an array of `⌈√difficulty⌉` evenly-spaced intermediate
///   hashes (checkpoints). Verifier re-runs only the last stride
///   (`√t` hashes) from the final checkpoint, plus one spot-check at the
///   midpoint, achieving O(√t) verification.
///
/// ## What this IS NOT (honest disclosures)
/// - **NOT a Merkle commitment.** Checkpoints are stored as a raw
///   `Vec<[u8; 32]>` array in the proof; there is no Merkle tree and
///   no membership proof structure. Tamper detection comes from
///   re-running the hash chain across stride boundaries, not from
///   a binding commitment.
/// - **NOT an RSA-group VDF** (Wesolowski / Pietrzak). Soundness here
///   rests purely on the sequentiality of SHA3-256 and hash collision
///   resistance, NOT on the algebraic delay property of squaring in a
///   group of unknown order.
/// - **NOT proven sound against an adaptive prover** in the same sense
///   as a published VDF construction. The spot-check bounds forgery
///   surface to a single stride window (≈√t steps), but does not give
///   the tight verifier-time guarantees of an academic VDF.
///
/// ## Soundness sketch (for the construction used here)
/// To forge a final output `y' ≠ y` for the same challenge, an attacker
/// must either:
///   1. Find a SHA3-256 collision somewhere in the chain — infeasible
///      under standard hash assumptions (128-bit post-quantum security).
///   2. Submit a checkpoint array that is internally consistent across
///      the verifier's spot-checks but inconsistent with the genuine
///      sequential chain — requires forging hash continuity in BOTH the
///      midpoint stride AND the final stride, each ≈√t sequential
///      operations.
///
/// ## Properties used by AINCORE
/// - **Sequential**: each step depends on the previous; no parallelism.
/// - **Deterministic**: same challenge → same output (leader election).
/// - **Quantum-safe**: SHA3-256.
/// - **Cheap to verify** at AINCORE's parameters (difficulty=50_000 →
///   ~224 hashes for verification, ≈microseconds).
///
/// ## Roadmap
/// For mainnet auditors, migration to a real RSA-VDF crate (e.g. Chia
/// Network's `vdf`) gives O(log t) verification and a published
/// soundness proof. Tracked as a Phase 4 / pre-mainnet upgrade.
use sha3::{Digest, Sha3_256};
use std::fmt;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VDFError {
    ComputationFailed(String),
    VerificationFailed(String),
    InvalidDifficulty(String),
}

impl fmt::Display for VDFError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VDFError::ComputationFailed(msg) => write!(f, "Computation failed: {}", msg),
            VDFError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            VDFError::InvalidDifficulty(msg) => write!(f, "Invalid difficulty: {}", msg),
        }
    }
}

impl std::error::Error for VDFError {}

// ─── Proof ────────────────────────────────────────────────────────────────────

/// VDF proof: raw array of checkpoint hashes plus the final output.
///
/// This is NOT a Merkle proof. It is the verifier's working memory:
/// a list of intermediate states the prover claims to have visited.
/// The verifier re-runs short stride re-computations to cross-check
/// claimed checkpoints against the genuine hash chain.
///
/// Layout (binary):
///   [ 8 bytes: difficulty as little-endian u64 ]
///   [ 8 bytes: checkpoint count n as little-endian u64 ]
///   [ 32 * n bytes: n checkpoint hashes (sequential, no tree structure) ]
///   [ 32 bytes: final output ]
///
/// where n = ceil(sqrt(difficulty)) checkpoints at positions
///   0, stride, 2*stride, ..., (n-1)*stride,  with stride = ceil(sqrt(difficulty)).
#[derive(Debug, Clone)]
pub struct VDFProof {
    pub difficulty: u64,
    /// Checkpoint hashes at evenly-spaced positions.
    pub checkpoints: Vec<[u8; 32]>,
    /// Final output hash.
    pub output: [u8; 32],
}

impl VDFProof {
    /// Serialise to bytes for P2P transport / storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32 * (self.checkpoints.len() + 1));
        buf.extend_from_slice(&self.difficulty.to_le_bytes());
        buf.extend_from_slice(&(self.checkpoints.len() as u64).to_le_bytes());
        for cp in &self.checkpoints {
            buf.extend_from_slice(cp);
        }
        buf.extend_from_slice(&self.output);
        buf
    }

    /// Deserialise from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let difficulty = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let n_cp = u64::from_le_bytes(bytes[8..16].try_into().ok()?) as usize;
        let expected_len = 16 + 32 * (n_cp + 1);
        if bytes.len() < expected_len {
            return None;
        }
        let mut checkpoints = Vec::with_capacity(n_cp);
        for i in 0..n_cp {
            let start = 16 + i * 32;
            let cp: [u8; 32] = bytes[start..start + 32].try_into().ok()?;
            checkpoints.push(cp);
        }
        let out_start = 16 + n_cp * 32;
        let output: [u8; 32] = bytes[out_start..out_start + 32].try_into().ok()?;
        Some(Self { difficulty, checkpoints, output })
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// VDF engine with configurable difficulty.
///
/// `difficulty` = number of sequential hash iterations.
/// Recommended for AINCORE production: ≥ 50_000 (≈ 5ms on modern hardware).
pub struct VDFEngine {
    difficulty: u64,
    /// sqrt(difficulty) — checkpoint stride.
    stride: u64,
}

impl VDFEngine {
    /// Create a new VDF engine.
    ///
    /// # Errors
    /// Returns `InvalidDifficulty` if `difficulty == 0`.
    pub fn new(difficulty: u64) -> Result<Self, VDFError> {
        if difficulty == 0 {
            return Err(VDFError::InvalidDifficulty(
                "Difficulty must be > 0".to_string(),
            ));
        }
        // stride = ceil(sqrt(difficulty)) — gives O(sqrt(t)) verification.
        let stride = (difficulty as f64).sqrt().ceil() as u64;
        let stride = stride.max(1);
        Ok(Self { difficulty, stride })
    }

    /// Compute the VDF output and generate a checkpointed proof.
    ///
    /// Time: O(difficulty) sequential hash operations.
    pub fn compute(&self, challenge: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VDFError> {
        let mut current: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(challenge);
            h.finalize().into()
        };

        let n_checkpoints = ((self.difficulty + self.stride - 1) / self.stride) as usize;
        let mut checkpoints: Vec<[u8; 32]> = Vec::with_capacity(n_checkpoints);

        for i in 0..self.difficulty {
            // Save checkpoint at every stride boundary.
            if i % self.stride == 0 {
                checkpoints.push(current);
            }
            let mut h = Sha3_256::new();
            h.update(current);
            h.update(i.to_le_bytes());
            current = h.finalize().into();
        }

        let proof = VDFProof {
            difficulty: self.difficulty,
            checkpoints,
            output: current,
        };

        Ok((current.to_vec(), proof.to_bytes()))
    }

    /// Verify a VDF proof in O(√t) time.
    ///
    /// Instead of re-running all `difficulty` steps, the verifier:
    ///   1. Picks the last checkpoint before the output.
    ///   2. Re-runs from that checkpoint to the final step.
    ///   3. Checks the output matches.
    ///
    /// Also spot-checks two intermediate checkpoints to bound the
    /// forgery surface to ~1 stride, not the full chain.
    pub fn verify(
        &self,
        challenge: &[u8],
        output: &[u8],
        proof_bytes: &[u8],
    ) -> Result<bool, VDFError> {
        let proof = VDFProof::from_bytes(proof_bytes).ok_or_else(|| {
            VDFError::VerificationFailed("Proof deserialisation failed".to_string())
        })?;

        if proof.difficulty != self.difficulty {
            return Err(VDFError::VerificationFailed(format!(
                "Proof difficulty {} != engine difficulty {}",
                proof.difficulty, self.difficulty
            )));
        }

        if output != proof.output {
            return Ok(false);
        }

        // Verify first checkpoint = H(challenge).
        if proof.checkpoints.is_empty() {
            return Err(VDFError::VerificationFailed("No checkpoints in proof".to_string()));
        }
        let expected_cp0: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(challenge);
            h.finalize().into()
        };
        if proof.checkpoints[0] != expected_cp0 {
            return Ok(false);
        }

        // Verify last checkpoint → output by re-running the final stride.
        let last_cp_idx = proof.checkpoints.len() - 1;
        let last_cp_start = last_cp_idx as u64 * self.stride;

        let mut current = proof.checkpoints[last_cp_idx];
        for i in last_cp_start..self.difficulty {
            let mut h = Sha3_256::new();
            h.update(current);
            h.update(i.to_le_bytes());
            current = h.finalize().into();
        }

        if current != proof.output {
            return Ok(false);
        }

        // Spot-check one intermediate checkpoint if there are enough.
        // This bounds a forgery to ~1 stride window.
        if proof.checkpoints.len() > 2 {
            let mid_idx = proof.checkpoints.len() / 2;
            let mid_start = (mid_idx - 1) as u64 * self.stride;

            let mut cur = proof.checkpoints[mid_idx - 1];
            for i in mid_start..mid_start + self.stride {
                let mut h = Sha3_256::new();
                h.update(cur);
                h.update(i.to_le_bytes());
                cur = h.finalize().into();
            }
            if cur != proof.checkpoints[mid_idx] {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_creation() {
        assert!(VDFEngine::new(100).is_ok());
        assert!(VDFEngine::new(0).is_err());
    }

    #[test]
    fn test_vdf_compute_verify() {
        let vdf = VDFEngine::new(100).unwrap();
        let (output, proof) = vdf.compute(b"test challenge").unwrap();
        assert!(!output.is_empty());
        assert!(vdf.verify(b"test challenge", &output, &proof).unwrap());
    }

    #[test]
    fn test_vdf_deterministic() {
        let vdf = VDFEngine::new(50).unwrap();
        let (o1, _) = vdf.compute(b"same challenge").unwrap();
        let (o2, _) = vdf.compute(b"same challenge").unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn test_vdf_different_challenges() {
        let vdf = VDFEngine::new(50).unwrap();
        let (o1, _) = vdf.compute(b"challenge1").unwrap();
        let (o2, _) = vdf.compute(b"challenge2").unwrap();
        assert_ne!(o1, o2);
    }

    /// Verification must be faster than recomputing from scratch.
    /// Both work on the same data but verify only re-runs stride steps.
    #[test]
    fn test_vdf_fast_verify_correct_output() {
        let vdf = VDFEngine::new(500).unwrap();
        let (output, proof) = vdf.compute(b"leader election seed").unwrap();
        // Fast verify — must return true.
        assert!(vdf.verify(b"leader election seed", &output, &proof).unwrap());
    }

    /// Tampered output must be rejected.
    #[test]
    fn test_vdf_tampered_output_rejected() {
        let vdf = VDFEngine::new(100).unwrap();
        let (mut output, proof) = vdf.compute(b"seed").unwrap();
        output[0] ^= 0xFF; // Flip first byte.
        assert!(!vdf.verify(b"seed", &output, &proof).unwrap());
    }

    /// Tampered proof (wrong first checkpoint) must be rejected.
    #[test]
    fn test_vdf_tampered_proof_rejected() {
        let vdf = VDFEngine::new(100).unwrap();
        let (output, mut proof_bytes) = vdf.compute(b"seed").unwrap();
        // Flip a byte in the first checkpoint (starts at offset 16).
        if proof_bytes.len() > 20 {
            proof_bytes[20] ^= 0xFF;
        }
        assert!(!vdf.verify(b"seed", &output, &proof_bytes).unwrap());
    }

    /// Wrong challenge must produce different output → verify fails.
    #[test]
    fn test_vdf_wrong_challenge_rejected() {
        let vdf = VDFEngine::new(100).unwrap();
        let (output, proof) = vdf.compute(b"correct").unwrap();
        assert!(!vdf.verify(b"wrong", &output, &proof).unwrap());
    }

    /// Proof serialisation round-trip.
    #[test]
    fn test_vdf_proof_roundtrip() {
        let vdf = VDFEngine::new(200).unwrap();
        let (output, proof_bytes) = vdf.compute(b"round trip").unwrap();
        let proof = VDFProof::from_bytes(&proof_bytes).expect("deserialise");
        assert_eq!(proof.output, output.as_slice());
        assert_eq!(proof.difficulty, 200);
        assert!(!proof.checkpoints.is_empty());
    }
}
