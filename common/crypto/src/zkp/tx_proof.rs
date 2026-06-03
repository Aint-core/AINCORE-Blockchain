//! Transaction-attached STARK proof verifier (Phase 2.2 / H-04 wiring).
//!
//! Background
//! ----------
//! AINCORE transactions carry an optional `zkp_proof: Option<String>`
//! field. Before Phase 1 the executor logged the proof's presence and
//! then continued execution as if it had been verified — pure security
//! theatre. Phase 1 closed the gate (mempool + executor reject any
//! non-empty `zkp_proof`).
//!
//! Phase 2.2 promotes that to a real dispatcher:
//!
//!   1. Decode the hex blob.
//!   2. Parse the bytes as a [`STARKProofData`] (catches obvious
//!      garbage at the structural layer — anyone who can't even
//!      produce a well-formed proof envelope is rejected without
//!      bothering the verifier).
//!   3. Bind the proof to *this specific transaction* by requiring
//!      `proof.public_inputs() == sha256(canonical_tx_message)`. This
//!      stops proof-replay across transactions: a valid proof for
//!      tx A cannot be detached and re-attached to tx B because their
//!      canonical messages differ.
//!   4. Invoke [`STARKVerifier::verify`] with that public input.
//!
//! The current [`STARKVerifier::verify`] is a Phase-2 placeholder that
//! returns `STARKError::LibraryError` until the AIR circuits are
//! finalized. We deliberately treat that error as a *verification
//! failure*, not a soft pass — there is no path where an unverified
//! proof is accepted. When the verifier is wired to a real AIR, this
//! exact code path begins accepting valid proofs without changes
//! elsewhere in the stack.
//!
//! This is the honest "wire it" upgrade over Phase 1's fail-closed
//! gate: garbage is rejected earlier, the rejection reason carries
//! more information, and we now have a single place to swap in real
//! verification as it becomes available.

use crate::zkp::{STARKError, STARKProofData, STARKVerifier};
use sha2::{Digest, Sha256};

/// Result of attempting to verify a transaction-attached STARK proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachedProofError {
    /// The hex envelope did not decode.
    InvalidHex(String),
    /// The decoded bytes did not parse as a [`STARKProofData`].
    InvalidStructure(String),
    /// The proof was structurally valid but its embedded public inputs
    /// do not match the SHA-256 of this transaction's canonical
    /// message. The proof is either for a different transaction or
    /// has been tampered with.
    PublicInputMismatch,
    /// The verifier itself rejected the proof (either returned
    /// `Ok(false)` or an error). The string captures the verifier's
    /// own message for diagnostics.
    VerificationFailed(String),
}

impl std::fmt::Display for AttachedProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachedProofError::InvalidHex(e) => {
                write!(f, "zkp_proof is not valid hex: {}", e)
            }
            AttachedProofError::InvalidStructure(e) => {
                write!(f, "zkp_proof is not a valid STARKProofData envelope: {}", e)
            }
            AttachedProofError::PublicInputMismatch => write!(
                f,
                "zkp_proof public inputs do not bind to this transaction \
                 (sha256(canonical_msg) mismatch — possible proof replay or \
                 message tampering)"
            ),
            AttachedProofError::VerificationFailed(e) => {
                write!(f, "zkp_proof verifier rejected the proof: {}", e)
            }
        }
    }
}

impl std::error::Error for AttachedProofError {}

/// Verify a transaction-attached STARK proof.
///
/// `proof_hex` is the raw hex string from `Transaction::zkp_proof`.
/// `canonical_msg` is the bytes the transaction binds the proof to —
/// callers should use the same canonical message that wallets sign
/// over (`"{chain_id}:{sender}:{payload}:{seq}"`).
///
/// Returns `Ok(())` only if all four layers (hex, structure, binding,
/// verifier) accept the proof. Any failure returns a specific
/// [`AttachedProofError`] variant so callers can log meaningful errors.
pub fn verify_tx_attached_proof(
    proof_hex: &str,
    canonical_msg: &[u8],
) -> Result<(), AttachedProofError> {
    // 1. Hex decode.
    let proof_bytes =
        hex::decode(proof_hex).map_err(|e| AttachedProofError::InvalidHex(e.to_string()))?;

    // 2. Structural parse.
    let proof = STARKProofData::from_bytes(&proof_bytes)
        .map_err(|e: STARKError| AttachedProofError::InvalidStructure(e.to_string()))?;

    // 3. Public-input binding: the proof must commit to the SHA-256
    //    digest of this transaction's canonical message. This makes
    //    a valid proof non-transferable across transactions.
    let expected = Sha256::digest(canonical_msg);
    if proof.public_inputs() != &expected[..] {
        return Err(AttachedProofError::PublicInputMismatch);
    }

    // 4. Verifier. STARKVerifier::verify is currently a Phase-2
    //    placeholder that returns Err until AIR circuits are
    //    finalized — we treat that as verification failure (no soft
    //    pass). When the verifier is wired to a real AIR, accepted
    //    proofs flow through here unchanged.
    let verifier = STARKVerifier::new();
    match verifier.verify(&proof, &expected[..]) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AttachedProofError::VerificationFailed(
            "verifier returned Ok(false)".to_string(),
        )),
        Err(e) => Err(AttachedProofError::VerificationFailed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn well_formed_proof_bytes(public_inputs: Vec<u8>) -> Vec<u8> {
        // Make a STARKProofData with the requested public inputs and
        // some opaque proof bytes. The verifier will reject it at the
        // crypto layer because the underlying STARKVerifier is a
        // placeholder, but the envelope is structurally correct.
        let proof = STARKProofData::new(vec![0xCA, 0xFE, 0xBA, 0xBE], public_inputs);
        proof.to_bytes()
    }

    #[test]
    fn invalid_hex_is_rejected() {
        let err = verify_tx_attached_proof("zzznothex", b"any-msg").unwrap_err();
        matches!(err, AttachedProofError::InvalidHex(_));
    }

    #[test]
    fn malformed_envelope_is_rejected() {
        // Valid hex but does not parse as STARKProofData.
        let bad = hex::encode([0u8; 3]);
        let err = verify_tx_attached_proof(&bad, b"any-msg").unwrap_err();
        matches!(err, AttachedProofError::InvalidStructure(_));
    }

    #[test]
    fn public_input_must_bind_to_canonical_message() {
        // Proof commits to one message, caller claims a different one.
        let msg_a = b"tx-A-canonical";
        let msg_b = b"tx-B-canonical";
        let proof_bytes = well_formed_proof_bytes(Sha256::digest(msg_a).to_vec());
        let proof_hex = hex::encode(&proof_bytes);

        let err = verify_tx_attached_proof(&proof_hex, msg_b).unwrap_err();
        assert_eq!(err, AttachedProofError::PublicInputMismatch);
    }

    #[test]
    fn well_bound_proof_falls_through_to_verifier_failure() {
        // Envelope correct, binding correct — but STARKVerifier is a
        // placeholder and rejects. We assert the failure surfaces as
        // VerificationFailed (not InvalidStructure or
        // PublicInputMismatch), proving the binding check passed and
        // the verifier itself made the decision.
        let msg = b"some-canonical-tx";
        let proof_bytes = well_formed_proof_bytes(Sha256::digest(msg).to_vec());
        let proof_hex = hex::encode(&proof_bytes);

        let err = verify_tx_attached_proof(&proof_hex, msg).unwrap_err();
        match err {
            AttachedProofError::VerificationFailed(_) => {}
            other => panic!(
                "binding passed; expected VerificationFailed from \
                 placeholder verifier, got {:?}",
                other
            ),
        }
    }
}
