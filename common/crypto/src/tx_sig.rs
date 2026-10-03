//! Transaction signatures (bug ledger B8).
//!
//! A transaction carries its public key and its signature, and the scheme
//! follows from their sizes, which no two schemes share:
//!
//! | scheme    | public key | signature | standard                                   |
//! |-----------|------------|-----------|--------------------------------------------|
//! | Ed25519   | 32 B       | 64 B      | RFC 8032, strict verification              |
//! | ML-DSA-65 | 1952 B     | 3309 B    | FIPS 204 (final), pure ML-DSA, empty context |
//!
//! The sizes of ML-DSA-65 are FIPS 204, Table 2. The address of either key is
//! `SHA-256(public key)` ([`crate::derive_address`]); the two key lengths
//! differ, so one address belongs to keys of two schemes only through a
//! SHA-256 collision.
//!
//! Ed25519 is verified strictly (`verify_strict`): plain verification accepts
//! a small-order public key, for which `(R, s) = (identity, 0)` verifies for
//! every message, so anyone could spend from that key's address.
//!
//! ML-DSA-65 is a choice: FIPS 204's category 3 set, between ML-DSA-44
//! (category 2, 2420-byte signatures) and ML-DSA-87 (category 5, 4627 bytes).
//! It is verified with aws-lc-rs, pinned to one version: its ML-DSA is the
//! C-only mldsa-native code on every CPU, so x86 without AVX2 (the NAS) and
//! aarch64 (the Pi) run the same path. A version bump of aws-lc-rs is a
//! consensus change; the cross-implementation tests below must pass on both
//! architectures before one ships.

use crate::CryptoError;
use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_65, ML_DSA_65_SIGNING,
};
use ed25519_dalek::{Signature, VerifyingKey};

/// ML-DSA-65 public key bytes (FIPS 204, Table 2).
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 signature bytes (FIPS 204, Table 2).
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;
/// The seed `ξ` of ML-DSA.KeyGen_internal (FIPS 204, Algorithm 6).
pub const ML_DSA_SEED_BYTES: usize = 32;

/// A transaction signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxScheme {
    Ed25519,
    MlDsa65,
}

impl TxScheme {
    /// The scheme whose key and signature have these sizes, if any.
    pub fn of(public_key_len: usize, signature_len: usize) -> Option<Self> {
        match (public_key_len, signature_len) {
            (32, 64) => Some(Self::Ed25519),
            (ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES) => Some(Self::MlDsa65),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::MlDsa65 => "ML-DSA-65",
        }
    }
}

/// Verify a transaction signature over `message` under `public_key`. Total:
/// any malformed key or signature is an error, never a panic.
pub fn verify_tx_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<TxScheme, CryptoError> {
    let scheme = TxScheme::of(public_key.len(), signature.len()).ok_or_else(|| {
        CryptoError::InvalidInput(format!(
            "no scheme has a {}-byte public key and a {}-byte signature",
            public_key.len(),
            signature.len()
        ))
    })?;
    match scheme {
        TxScheme::Ed25519 => {
            let key: [u8; 32] = public_key.try_into().expect("length checked above");
            let sig: [u8; 64] = signature.try_into().expect("length checked above");
            let key = VerifyingKey::from_bytes(&key)
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            key.verify_strict(message, &Signature::from_bytes(&sig))
                .map_err(|_| CryptoError::InvalidSignature("Ed25519 does not verify".into()))?;
        }
        TxScheme::MlDsa65 => {
            UnparsedPublicKey::new(&ML_DSA_65, public_key)
                .verify(message, signature)
                .map_err(|_| CryptoError::InvalidSignature("ML-DSA-65 does not verify".into()))?;
        }
    }
    Ok(scheme)
}

/// An ML-DSA-65 key pair, kept as its 32-byte seed.
pub struct MlDsa65Key {
    pair: PqdsaKeyPair,
}

impl MlDsa65Key {
    /// ML-DSA.KeyGen_internal(ξ): the same seed gives the same key pair.
    pub fn from_seed(seed: &[u8; ML_DSA_SEED_BYTES]) -> Self {
        let pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)
            .expect("a 32-byte seed is a valid ML-DSA-65 seed");
        Self { pair }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; ML_DSA_65_SIGNATURE_BYTES];
        let written = self
            .pair
            .sign(message, &mut signature)
            .expect("the buffer holds an ML-DSA-65 signature");
        debug_assert_eq!(written, ML_DSA_65_SIGNATURE_BYTES);
        signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    const MSG: &[u8] = b"AINCORE-TESTNET-V5:sender:payload:0:100000:1:";

    #[test]
    fn ml_dsa_65_sizes_are_fips_204_table_2() {
        let key = MlDsa65Key::from_seed(&[7; 32]);
        assert_eq!(key.public_key().len(), 1952);
        assert_eq!(key.sign(MSG).len(), 3309);
    }

    #[test]
    fn each_scheme_verifies_its_own_signature() {
        let ed = SigningKey::from_bytes(&[9; 32]);
        let sig = ed.sign(MSG).to_bytes();
        assert_eq!(
            verify_tx_signature(ed.verifying_key().as_bytes(), MSG, &sig),
            Ok(TxScheme::Ed25519)
        );
        let ml = MlDsa65Key::from_seed(&[7; 32]);
        assert_eq!(
            verify_tx_signature(&ml.public_key(), MSG, &ml.sign(MSG)),
            Ok(TxScheme::MlDsa65)
        );
    }

    #[test]
    fn a_changed_message_signature_or_key_is_refused() {
        let ml = MlDsa65Key::from_seed(&[7; 32]);
        let other = MlDsa65Key::from_seed(&[8; 32]);
        let sig = ml.sign(MSG);
        assert!(verify_tx_signature(&ml.public_key(), b"another message", &sig).is_err());
        assert!(verify_tx_signature(&other.public_key(), MSG, &sig).is_err());
        for i in [0, 1000, 3308] {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert!(
                verify_tx_signature(&ml.public_key(), MSG, &bad).is_err(),
                "byte {i}"
            );
        }

        let ed = SigningKey::from_bytes(&[9; 32]);
        let mut sig = ed.sign(MSG).to_bytes();
        sig[5] ^= 1;
        assert!(verify_tx_signature(ed.verifying_key().as_bytes(), MSG, &sig).is_err());
    }

    /// A key of one scheme with a signature of the other, and every size no
    /// scheme has, are refused before any verification.
    #[test]
    fn sizes_no_scheme_has_are_refused() {
        let ml = MlDsa65Key::from_seed(&[7; 32]);
        let ed = SigningKey::from_bytes(&[9; 32]);
        let ed_sig = ed.sign(MSG).to_bytes();
        let ed_key = ed.verifying_key().to_bytes();
        let ml_key = ml.public_key();
        let ml_sig = ml.sign(MSG);
        let cases: [(&[u8], &[u8]); 6] = [
            (&ml_key, &ed_sig),
            (&ed_key, &ml_sig),
            (&[], &[]),
            (&[0; 33], &[0; 64]),
            (&[0; 1952], &[0; 3308]),
            (&[0; 2592], &[0; 4627]), // ML-DSA-87 sizes: not accepted
        ];
        for (key, sig) in cases {
            assert!(
                matches!(
                    verify_tx_signature(key, MSG, sig),
                    Err(CryptoError::InvalidInput(_))
                ),
                "{} / {}",
                key.len(),
                sig.len()
            );
        }
    }

    #[test]
    fn malformed_keys_and_signatures_are_refused_without_a_panic() {
        let ml = MlDsa65Key::from_seed(&[7; 32]);
        let sig = ml.sign(MSG);
        assert!(verify_tx_signature(&[0; 1952], MSG, &sig).is_err());
        assert!(verify_tx_signature(&[0xff; 1952], MSG, &sig).is_err());
        assert!(verify_tx_signature(&ml.public_key(), MSG, &[0; 3309]).is_err());
        assert!(verify_tx_signature(&ml.public_key(), MSG, &[0xff; 3309]).is_err());
        assert!(verify_tx_signature(&[0xff; 32], MSG, &[0; 64]).is_err());
    }

    /// The small-order public key (the identity point) with the signature
    /// (R = identity, s = 0) passes non-strict Ed25519 verification for every
    /// message. Strict verification refuses it.
    #[test]
    fn a_small_order_ed25519_key_cannot_sign_for_everyone() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(
            ed25519_dalek::Verifier::verify(&key, MSG, &Signature::from_bytes(&sig)).is_ok(),
            "control: plain verification accepts the forgery"
        );
        assert!(verify_tx_signature(&identity, MSG, &sig).is_err());
        assert!(verify_tx_signature(&identity, b"any other message", &sig).is_err());
    }

    /// Pins KeyGen: a library change that alters keys fails here. The value
    /// also equals the RustCrypto `ml-dsa` key for the same seed (next test).
    #[test]
    fn golden_ml_dsa_65_public_key_for_a_fixed_seed() {
        let pk = MlDsa65Key::from_seed(&[7; 32]).public_key();
        assert_eq!(
            hex::encode(Sha256::digest(&pk)),
            ML_DSA_65_GOLDEN_PK_SHA256_SEED_7
        );
    }

    /// Two independent implementations agree: RustCrypto `ml-dsa` (pure Rust)
    /// derives the same public key from the same seed, verifies aws-lc's
    /// signatures, and aws-lc verifies its signatures.
    #[test]
    fn rustcrypto_ml_dsa_agrees_with_aws_lc() {
        use ml_dsa::{Keypair, MlDsa65, SigningKey as RcKey};
        for s in [0u8, 7, 0xa5, 0xff] {
            let seed = [s; 32];
            let ours = MlDsa65Key::from_seed(&seed);
            let rc = RcKey::<MlDsa65>::from_seed(&seed.into());
            let rc_vk = rc.verifying_key();
            assert_eq!(
                ours.public_key().as_slice(),
                rc_vk.encode().as_slice(),
                "seed {s}"
            );

            let sig = ours.sign(MSG);
            let enc: &ml_dsa::EncodedSignature<MlDsa65> = sig.as_slice().try_into().unwrap();
            let decoded = ml_dsa::Signature::<MlDsa65>::decode(enc).expect("decodes");
            assert!(rc_vk.verify_with_context(MSG, &[], &decoded), "seed {s}");

            let theirs = rc
                .expanded_key()
                .sign_deterministic(MSG, &[])
                .unwrap()
                .encode();
            assert_eq!(
                verify_tx_signature(&ours.public_key(), MSG, theirs.as_slice()),
                Ok(TxScheme::MlDsa65),
                "seed {s}"
            );
        }
    }

    const ML_DSA_65_GOLDEN_PK_SHA256_SEED_7: &str =
        "d3a1e51ecf491b79ca7691bd269271f8d8e8d94313a6abcc6c8ae8bc34b5f9aa";
}
