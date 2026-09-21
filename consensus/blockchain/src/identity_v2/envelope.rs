//! V2 content/signature contract, with a bounded codec in `wire`.
//! Not an execution acceptance gate: production Block/ChainSync do not yet
//! consume this type or its wire codec.

pub mod wire;

use super::{
    byte_items_framed_size, evidence_root, policy::VerifiedFormatPolicy, transactions_root,
    vertices_root, BlockIdentityV2, CodecError, Digest, Parent, MAX_BODY_BYTES, MAX_ITEMS,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyV2 {
    pub transactions: Vec<Vec<u8>>,
    pub committed_vertices: Vec<Digest>,
    pub evidence: Vec<Vec<u8>>,
}

impl BodyV2 {
    fn validate(&self, identity: &BlockIdentityV2) -> Result<(), CodecError> {
        if self.committed_vertices.len() > MAX_ITEMS {
            return Err(CodecError::Invalid("too many vertices"));
        }
        let framed_size = byte_items_framed_size(&self.transactions)?
            .checked_add(byte_items_framed_size(&self.evidence)?)
            .and_then(|n| n.checked_add(7 + self.committed_vertices.len() * 32))
            .ok_or(CodecError::Invalid("combined body size overflow"))?;
        if framed_size > MAX_BODY_BYTES {
            return Err(CodecError::Invalid("combined body exceeds byte bound"));
        }
        if transactions_root(&self.transactions)? != identity.transactions_root
            || vertices_root(&self.committed_vertices)? != identity.vertices_root
            || evidence_root(&self.evidence)? != identity.evidence_root
        {
            return Err(CodecError::Invalid(
                "body does not match signed commitments",
            ));
        }
        Ok(())
    }
}

/// Caller-supplied trusted inputs, NOT authenticated by this struct. Obtain the
/// epoch/height/parent and positive-stake eligible keys from the same trusted
/// acceptance snapshot; never construct them from this block's peer metadata.
pub struct EnvelopeContext<'a> {
    pub policy: &'a VerifiedFormatPolicy,
    pub expected_epoch: u64,
    pub expected_height: u64,
    pub expected_parent: &'a Parent,
    pub eligible_keys: &'a BTreeMap<Digest, Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlockV2 {
    pub identity: BlockIdentityV2,
    pub body: BodyV2,
    pub signer: Digest,
    pub signature: Vec<u8>,
}

/// An immutable borrow prevents mutation between this check and consumption.
/// This authenticates content, not execution roots, ordering/QC authority, the
/// cumulative finality digest, or transaction/evidence semantics.
/// It borrows the block only, NOT a database snapshot. Recheck authority/parent
/// inside the eventual acceptance transaction; do not cache this as permission.
pub struct AuthenticatedEnvelope<'a> {
    block: &'a SignedBlockV2,
    hash: Digest,
}

impl AuthenticatedEnvelope<'_> {
    pub fn block(&self) -> &SignedBlockV2 {
        self.block
    }

    pub fn hash(&self) -> Digest {
        self.hash
    }
}

fn address(key: &Digest) -> Digest {
    // Same address derivation as crypto::derive_address, without hex conversion.
    crypto::hash(key)
        .try_into()
        .expect("SHA-256 outputs 32 bytes")
}

fn eligible_key(context: &EnvelopeContext<'_>, account: &Digest) -> Result<Digest, CodecError> {
    let key = context
        .eligible_keys
        .get(account)
        .ok_or(CodecError::Invalid(
            "block author is not eligible in trusted epoch",
        ))?;
    if address(key) != *account {
        return Err(CodecError::Invalid(
            "committee key does not match author address",
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(key)
        .map_err(|_| CodecError::Invalid("invalid committee public key"))?;
    if verifying_key.is_weak() {
        return Err(CodecError::Invalid("weak committee public key"));
    }
    Ok(*key)
}

impl SignedBlockV2 {
    fn check_context(&self, context: &EnvelopeContext<'_>) -> Result<Digest, CodecError> {
        context.policy.validate_identity(&self.identity)?;
        if self.identity.epoch != context.expected_epoch
            || self.identity.height != context.expected_height
            || self.identity.parent != *context.expected_parent
        {
            return Err(CodecError::Invalid(
                "block does not extend trusted acceptance context",
            ));
        }
        eligible_key(context, &self.identity.proposer)?;
        eligible_key(context, &self.signer)
    }

    /// Checks content and eligibility before signing. Does not derive execution
    /// roots or order/finality metadata for the producer.
    pub fn sign(
        identity: BlockIdentityV2,
        body: BodyV2,
        key: &SigningKey,
        context: &EnvelopeContext<'_>,
    ) -> Result<Self, CodecError> {
        let signer = address(&key.verifying_key().to_bytes());
        let mut block = Self {
            identity,
            body,
            signer,
            signature: vec![],
        };
        let expected_key = block.check_context(context)?;
        if expected_key != key.verifying_key().to_bytes() {
            return Err(CodecError::Invalid(
                "signing key is not the eligible committee key",
            ));
        }
        block.body.validate(&block.identity)?;
        block.signature = key
            .sign(&block.identity.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(block)
    }

    pub fn authenticate(
        &self,
        context: &EnvelopeContext<'_>,
    ) -> Result<AuthenticatedEnvelope<'_>, CodecError> {
        self.authenticate_header(context)?;
        // An unauthenticated peer must not force large-body hashing merely by
        // naming an eligible signer. Verify the small signed identity first.
        self.body.validate(&self.identity)?;
        Ok(AuthenticatedEnvelope {
            block: self,
            hash: self.identity.hash()?,
        })
    }

    fn authenticate_header(&self, context: &EnvelopeContext<'_>) -> Result<(), CodecError> {
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| CodecError::Invalid("invalid block signature length"))?;
        let key = self.check_context(context)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| CodecError::Invalid("invalid committee public key"))?
            .verify_strict(&self.identity.signing_bytes()?, &signature)
            .map_err(|_| CodecError::Invalid("invalid block signature"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
