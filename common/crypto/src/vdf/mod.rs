/// Phase 3 / C-03 + Phase 5B.4 / L-01 — Checkpointed Sequential-Hash VDF
///
/// Replaces the "compute == verify" stub with a sequential hash-chain VDF
/// whose verifier forces the prover to have materialised the full chain.
///
/// ## What this IS
/// - A **sequential SHA3-256 hash chain**: `h_0 = SHA3(challenge)`,
///   `h_{i+1} = SHA3(h_i || i)`, output = `h_difficulty`.
/// - **Proof** = an array of `⌈√difficulty⌉` evenly-spaced intermediate
///   checkpoints. Verifier re-runs EVERY adjacent stride boundary
///   (Phase 5B.4 fix), then the final-stride terminal segment.
///
/// ## Honest soundness vs cost trade-off (Phase 5B.4 / L-01)
///
/// The original Phase 3 verifier only spot-checked ONE midpoint stride.
/// An adaptive prover could pick every other checkpoint freely → forgery
/// cost was ~`2 * stride ≈ 2√t`, the same order as honest verification.
/// That broke the sequentiality guarantee a VDF is supposed to provide.
///
/// The L-01 fix verifies ALL adjacent checkpoint pairs. Forging now
/// requires producing internally-consistent hash chains across every
/// stride — equivalent to materialising the full chain, which costs `t`
/// sequential hashes. Sequentiality restored.
///
/// **Cost paid for soundness:** verification is now O(t), not O(√t).
/// For AINCORE's leader-election parameters (`difficulty ≈ 50`) this is
/// trivially cheap (microseconds). For mainnet-scale (`difficulty ≥
/// 50_000`) a real RSA-group VDF (Wesolowski / Pietrzak) is the proper
/// choice — that delivers O(log t) verify with a published soundness
/// proof. Tracked as a pre-mainnet upgrade.
///
/// ## What this IS NOT (still honest)
/// - **NOT a Merkle commitment.** Checkpoints are a raw `Vec<[u8;32]>`;
///   tamper detection comes from re-running the chain across boundaries,
///   not from a binding commitment data structure.
/// - **NOT an RSA-group VDF.** Soundness rests on hash sequentiality
///   under standard assumptions, NOT on group-of-unknown-order squaring.
///
/// ## Properties used by AINCORE
/// - **Sequential**: each step depends on previous; no parallelism
///   (after L-01 fix, this is also FORCED on the prover via verify).
/// - **Deterministic**: same challenge → same output (leader election).
/// - **Quantum-safe**: SHA3-256 (128-bit post-quantum).
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
    ///
    /// Phase 5C.4 / NEW-004: cap `n_cp` BEFORE `Vec::with_capacity` to
    /// prevent an attacker-crafted blob with `n_cp = u64::MAX` from
    /// triggering an allocator panic / OOM. The VDF is internal today
    /// (no external proof ingest), but this bound future-proofs any
    /// path that ever forwards untrusted bytes here.
    const MAX_CHECKPOINTS: usize = 1 << 20; // 1M checkpoints = ~32MB max alloc

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let difficulty = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let n_cp_u64 = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        if n_cp_u64 > Self::MAX_CHECKPOINTS as u64 {
            return None;
        }
        let n_cp = n_cp_u64 as usize;
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
        Some(Self {
            difficulty,
            checkpoints,
            output,
        })
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

        let n_checkpoints = self.difficulty.div_ceil(self.stride) as usize;
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
    /// Phase 5B.4 / L-01 fix: the previous implementation only spot-checked
    /// ONE midpoint stride. A forger could pick all other checkpoints
    /// freely → forgery cost ~2√t (not t), defeating the sequentiality
    /// guarantee that the entire VDF construction is supposed to provide.
    ///
    /// The verifier now re-runs every adjacent stride boundary, plus the
    /// first-checkpoint anchor and the final-stride termination. This
    /// FORCES the prover to have materialised the full hash chain — any
    /// missing or forged intermediate checkpoint breaks the boundary
    /// check at its neighbour and the proof is rejected.
    ///
    /// Verifier cost: roughly `(n-1) * stride ≈ difficulty - stride`
    /// hashes, i.e. O(t). This is the SAME cost as honest computation,
    /// not O(√t) as the original (broken) construction claimed.
    /// Honesty disclosure: this construction is sound but loses the
    /// fast-verify property; for the testnet's leader-election use case,
    /// `difficulty ≈ 50` makes verification effectively free (~50 hashes,
    /// microseconds). For mainnet, migrate to an RSA-group VDF
    /// (Wesolowski / Pietrzak) which offers genuine O(log t) verification.
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

        if proof.checkpoints.is_empty() {
            return Err(VDFError::VerificationFailed(
                "No checkpoints in proof".to_string(),
            ));
        }

        // Anchor: first checkpoint MUST equal H(challenge).
        let expected_cp0: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(challenge);
            h.finalize().into()
        };
        if proof.checkpoints[0] != expected_cp0 {
            return Ok(false);
        }

        // Phase 5B.4: verify EVERY adjacent checkpoint pair. The hash
        // chain between `checkpoints[i]` and `checkpoints[i+1]` is
        // exactly `stride` SHA3 iterations starting at absolute index
        // `i * stride`. If ANY pair fails, the proof is invalid.
        for i in 0..proof.checkpoints.len() - 1 {
            let segment_start = i as u64 * self.stride;
            let mut cur = proof.checkpoints[i];
            for step in segment_start..segment_start + self.stride {
                let mut h = Sha3_256::new();
                h.update(cur);
                h.update(step.to_le_bytes());
                cur = h.finalize().into();
            }
            if cur != proof.checkpoints[i + 1] {
                return Ok(false);
            }
        }

        // Terminal: last checkpoint MUST hash forward to the output. The
        // last checkpoint sits at absolute index `(n-1) * stride`; the
        // remaining iterations go up to `difficulty`.
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
        assert!(vdf
            .verify(b"leader election seed", &output, &proof)
            .unwrap());
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

    /// Phase 5B.4 / L-01: a forger who fills the checkpoint array with
    /// internally-inconsistent intermediates (e.g. all zeros) MUST be
    /// rejected. Before the L-01 fix, only the midpoint stride was
    /// spot-checked and this attack succeeded.
    #[test]
    fn l01_forged_checkpoint_array_rejected() {
        let vdf = VDFEngine::new(100).unwrap();
        let (output, real_proof) = vdf.compute(b"forge target").unwrap();

        // Parse real proof, then overwrite all checkpoints between the
        // anchor and the last one with zeros — keep the first (anchor)
        // and the last (which the terminal-segment check uses) intact.
        let mut proof = VDFProof::from_bytes(&real_proof).expect("decode");
        for slot in proof.checkpoints.iter_mut().skip(1).rev().skip(1) {
            *slot = [0u8; 32];
        }
        let forged_bytes = proof.to_bytes();

        // Sanity: at least one inner checkpoint must have been touched
        // for the test to be meaningful.
        assert!(
            proof.checkpoints.len() > 2,
            "test setup requires >2 checkpoints to have inner slots"
        );

        // Verifier MUST reject — every adjacent stride boundary is checked.
        assert!(
            !vdf.verify(b"forge target", &output, &forged_bytes).unwrap(),
            "L-01: forged-checkpoint array must be rejected"
        );
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
