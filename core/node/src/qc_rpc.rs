//! Certificate checks against this node's retained, locally trusted metadata.
//! This does not replay execution, prove state, or authenticate epoch transitions.

use consensus::{qc, qc_producer};
use storage::StateDB;

pub const VERIFICATION_SCOPE: &str = "local_committee_and_epoch";

#[derive(Debug)]
pub enum VerificationError {
    Unavailable(&'static str),
    Invalid(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => f.write_str(message),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

/// Read-only checks; the separate metadata reads are not a database snapshot.
/// `indexed_height` binds a stored result to the height requested by the caller.
pub fn verify(
    storage: &StateDB,
    certificate: &qc::QuorumCertificate,
    indexed_height: Option<u64>,
) -> Result<(), VerificationError> {
    if indexed_height.is_some_and(|height| height != certificate.block_height) {
        return Err(VerificationError::Invalid(
            "QC block height differs from requested storage index".into(),
        ));
    }
    if certificate.block_height == 0 {
        return Err(VerificationError::Invalid("QC block height is zero".into()));
    }
    let epoch = qc_producer::epoch_for_block_height(storage, certificate.block_height).ok_or(
        VerificationError::Unavailable("epoch activation history unavailable"),
    )?;
    if epoch != certificate.epoch {
        return Err(VerificationError::Invalid(
            "QC epoch does not match the block's retained activation interval".into(),
        ));
    }
    let validators = qc_producer::load_validator_set_for_epoch(storage, certificate.epoch)
        .ok_or(VerificationError::Unavailable("validator set unavailable"))?;
    qc::verify_qc(certificate, &validators, &qc::expected_chain_id())
        .map_err(|error| VerificationError::Invalid(error.to_string()))
}
