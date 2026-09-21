//! Proposed genesis commitment to a single, immutable block-format activation.
//! No storage/environment fallback and no live activation writer is provided.

use super::{domain_hash, BlockIdentityV2, CodecError, Digest, MAX_CHAIN_ID_BYTES, VERSION};
use serde::{Deserialize, Serialize};

const POLICY_VERSION: u16 = 1;
const POLICY_DOMAIN: &[u8] = b"AINCORE_BLOCK_FORMAT_GENESIS_V1\0";
pub const MAX_POLICY_BYTES: usize = 512;

/// Untrusted proof input. `base_genesis_identity` commits the pre-policy genesis
/// fields; the final, externally pinned identity also commits this policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisFormatProof {
    pub base_genesis_identity: Digest,
    pub chain_id: String,
    pub v2_from_height: u64,
}

impl GenesisFormatProof {
    fn validate(&self) -> Result<(), CodecError> {
        if self.chain_id.is_empty() || self.chain_id.len() > MAX_CHAIN_ID_BYTES {
            return Err(CodecError::Invalid("policy chain ID length outside bounds"));
        }
        if self.v2_from_height == 0 {
            return Err(CodecError::Invalid(
                "format activation height must be positive",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        bcs::to_bytes(&(POLICY_VERSION, self)).map_err(|e| CodecError::Encoding(e.to_string()))
    }

    /// Computes a candidate chain identity, NOT a source of trust. Distribute or
    /// accept this pin only through the separately authorized bootstrap process.
    pub fn proposed_genesis_identity(&self) -> Result<Digest, CodecError> {
        Ok(domain_hash(POLICY_DOMAIN, &self.encode()?))
    }
}

/// Constructible only after checking against a caller-supplied trusted pin.
/// Do not obtain that pin from the same untrusted proof or peer response.
#[derive(Debug, Clone)]
pub struct VerifiedFormatPolicy {
    genesis_identity: Digest,
    proof: GenesisFormatProof,
}

impl VerifiedFormatPolicy {
    pub fn verify_against_pin(trusted_pin: Digest, bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(CodecError::Invalid("format policy exceeds byte bound"));
        }
        let (version, proof): (u16, GenesisFormatProof) =
            bcs::from_bytes(bytes).map_err(|e| CodecError::Encoding(e.to_string()))?;
        if version != POLICY_VERSION {
            return Err(CodecError::Invalid(
                "unsupported format policy proof version",
            ));
        }
        proof.validate()?;
        if proof.proposed_genesis_identity()? != trusted_pin {
            return Err(CodecError::Invalid(
                "format policy does not match trusted genesis pin",
            ));
        }
        Ok(Self {
            genesis_identity: trusted_pin,
            proof,
        })
    }

    pub fn genesis_identity(&self) -> Digest {
        self.genesis_identity
    }

    pub fn chain_id(&self) -> &str {
        &self.proof.chain_id
    }

    pub fn required_version(&self, height: u64) -> Result<u16, CodecError> {
        if height == 0 {
            return Err(CodecError::Invalid("block height must be positive"));
        }
        Ok(if height < self.proof.v2_from_height {
            1
        } else {
            VERSION
        })
    }

    pub fn check_version(&self, height: u64, version: u16) -> Result<(), CodecError> {
        if version != self.required_version(height)? {
            return Err(CodecError::Invalid(
                "block format is not authorized at this height",
            ));
        }
        Ok(())
    }

    /// Authenticates format and chain context, NOT epoch membership, execution,
    /// finality-digest derivation, or an upgrade decision after this genesis.
    pub fn validate_identity(&self, identity: &BlockIdentityV2) -> Result<(), CodecError> {
        self.check_version(identity.height, VERSION)?;
        if identity.chain_id != self.proof.chain_id
            || identity.genesis_hash != self.genesis_identity
        {
            return Err(CodecError::Invalid(
                "block identity belongs to a different pinned chain",
            ));
        }
        identity.validate()
    }

    pub fn signing_bytes(&self, identity: &BlockIdentityV2) -> Result<Vec<u8>, CodecError> {
        self.validate_identity(identity)?;
        identity.signing_bytes()
    }
}

#[cfg(test)]
mod tests;
