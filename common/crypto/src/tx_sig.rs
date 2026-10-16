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
//! B321: it is verified with RustCrypto `ml-dsa` (pinned; pure Rust, no
//! assembly and no CPU-specific code), so every node runs one code path.
//! aws-lc-rs verified it before: aws-lc-sys 0.45 builds mldsa-native's AVX2
//! and NEON assembly, which replaces the steps that decode and bound a
//! signature, so the NAS (no AVX2: C), an AVX2 host and the Pi (NEON) ran
//! three paths over attacker-chosen signatures. aws-lc-rs still makes keys
//! and signs (signing is not consensus). Either crate's bump is a consensus
//! change; the cross-implementation tests below must pass first.
//!
//! B454: one code path holds for ML-DSA only. Ed25519 and BLS checks of
//! attacker-chosen bytes still run CPU-specific arithmetic: curve25519-dalek
//! multiplies with AVX2 code where the CPU has it and serial code elsewhere
//! (its decoding, canonical-s and small-order checks and the final
//! comparison are one serial path), and blst's field arithmetic is mulx or
//! mulq assembly on x86 (chosen when the node starts: blst is built
//! `portable`) and armv8 assembly on the Pi. Unlike B321's case, no path
//! decodes or bounds by its own rules: each computes a group element or a
//! field value that has one correct value, so two nodes disagree only
//! through an arithmetic bug in one path (none is known; Ethereum's
//! consensus clients run blst on all three). Accepted, with a gate:
//! `ed25519_verdicts_on_edge_inputs_are_pinned_for_every_cpu` (below) and
//! `bls::tests::bls_verdicts_on_edge_inputs_are_pinned_for_every_cpu` pin the
//! verdicts on honest, flipped, unreduced, small-order, mixed-order and
//! infinity inputs, and a release runs them on each CPU class of the fleet.
//! curve25519-dalek's serial backend is not forced: only rustflags select it
//! (a RUSTFLAGS variable silently replaces a config file's), so no setting
//! here could hold it, and it would change which path computes a verdict,
//! not the verdict.

use crate::CryptoError;
use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_65_SIGNING};
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
            use ml_dsa::{EncodedVerifyingKey, MlDsa65};
            let key: &EncodedVerifyingKey<MlDsa65> = public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidPublicKey("not an ML-DSA-65 key".into()))?;
            // sigDecode refuses a hint out of order or past ω, and z at or
            // past γ1 − β (FIPS 204, Algorithms 21 and 27, and 3's step 13).
            let signature = ml_dsa::Signature::<MlDsa65>::try_from(signature).map_err(|_| {
                CryptoError::InvalidSignature("ML-DSA-65 signature does not decode".into())
            })?;
            if !ml_dsa::VerifyingKey::<MlDsa65>::decode(key).verify_with_context(
                message,
                &[],
                &signature,
            ) {
                return Err(CryptoError::InvalidSignature(
                    "ML-DSA-65 does not verify".into(),
                ));
            }
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
    use sha2::{Digest, Sha256, Sha512};

    const MSG: &[u8] = b"AINCORE-TESTNET-V5:sender:payload:0:100000:1:";

    /// A scalar of the type `like` has: curve25519-dalek's `Scalar`, which
    /// this crate does not depend on by name.
    fn scalar_like<S: From<u128>>(_like: &S, value: u128) -> S {
        S::from(value)
    }

    /// B454 gate: one verdict on every CPU. curve25519-dalek's double-scalar
    /// multiply runs AVX2 code on a host that has it and serial code
    /// elsewhere (the NAS, the Pi); decoding, the canonical-s and small-order
    /// checks and the final comparison are one serial path. The verdicts are
    /// pinned (the mixed-order ones by the group law) for both consensus
    /// entry points, and a release runs this test on each CPU class.
    #[test]
    fn ed25519_verdicts_on_edge_inputs_are_pinned_for_every_cpu() {
        let verdict = |key: &[u8], msg: &[u8], sig: &[u8]| {
            let tx = verify_tx_signature(key, msg, sig).is_ok();
            let block = crate::verify_signature(key, msg, sig).unwrap_or(false);
            assert_eq!(tx, block, "the two entry points disagree");
            tx
        };
        // Honest signatures over many keys verify: the refusals below are
        // not vacuous.
        for seed in 0u8..32 {
            let key = SigningKey::from_bytes(&[seed; 32]);
            for len in [0usize, 1, 64, 1000] {
                let msg = vec![seed ^ 0x5a; len];
                let sig = key.sign(&msg).to_bytes();
                let public = key.verifying_key().to_bytes();
                assert!(verdict(&public, &msg, &sig), "seed {seed}, {len} bytes");
            }
        }
        let key = SigningKey::from_bytes(&[9; 32]);
        let public = key.verifying_key().to_bytes();
        let sig = key.sign(MSG).to_bytes();
        // Every bit of the signature and of the key, flipped.
        for bit in 0..512 {
            let mut bad = sig;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(!verdict(&public, MSG, &bad), "signature bit {bit}");
        }
        for bit in 0..256 {
            let mut bad = public;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(!verdict(&bad, MSG, &sig), "key bit {bit}");
        }

        // The group order L, little-endian (RFC 8032, 5.1).
        let low = 0x14def9dea2f79cd65812631a5cf5d3edu128.to_le_bytes();
        let mut order = [0u8; 32];
        order[..16].copy_from_slice(&low);
        order[31] = 0x10;
        let a = key.to_scalar();
        let two_64 = scalar_like(&a, 1u128 << 64);
        let two_128 = two_64 * two_64;
        // A little-endian integer mod L, as `Scalar::from_hash` reduces.
        let reduce = |bytes: &[u8]| {
            bytes
                .chunks(16)
                .rev()
                .fold(scalar_like(&a, 0), |acc, chunk| {
                    let limb = u128::from_le_bytes(chunk.try_into().expect("16 bytes"));
                    acc * two_128 + scalar_like(&a, limb)
                })
        };
        let l_mod_l = reduce(&order[..]).to_bytes();
        assert_eq!(l_mod_l, [0; 32], "L is the group order");

        // s + L: the same [s]B, refused as not reduced.
        let mut unreduced = sig;
        let mut carry = 0u16;
        for (i, l) in order.iter().enumerate() {
            let sum = u16::from(unreduced[32 + i]) + u16::from(*l) + carry;
            unreduced[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verdict(&public, MSG, &unreduced), "s + L");

        // Small-order keys (the identity; (0, -1) of order 2; (±√-1, 0) of
        // order 4; y = p and y = p + 1, non-canonical), under (R = identity,
        // s = 0) and under an honest signature.
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut minus_root = [0u8; 32];
        minus_root[31] = 0x80;
        let (mut y_p, mut y_p_plus_1) = (minus_one, minus_one);
        y_p[0] = 0xed;
        y_p_plus_1[0] = 0xee;
        let mut forged = [0u8; 64];
        forged[0] = 1;
        for small in [identity, minus_one, [0; 32], minus_root, y_p, y_p_plus_1] {
            assert!(!verdict(&small, MSG, &forged), "{}", hex::encode(small));
            assert!(!verdict(&small, MSG, &sig), "{}", hex::encode(small));
        }

        // Mixed-order keys A + T, T of order 2 and of order 4, signed for
        // that key with A's scalar a: R = [r]B, s = r + k·a, k = H(R, A + T,
        // M). Then [s]B - [k](A + T) = R - [k]T: the signature verifies
        // exactly when the order of T divides k.
        let torsion = |bytes: [u8; 32]| VerifyingKey::from_bytes(&bytes).unwrap().to_edwards();
        let a_point = key.verifying_key().to_edwards();
        let nonce = SigningKey::from_bytes(&[0x33; 32]);
        let (r, r_bytes) = (nonce.to_scalar(), nonce.verifying_key().to_bytes());
        for (t, t_order) in [(torsion(minus_one), 2u8), (torsion([0; 32]), 4)] {
            assert!(VerifyingKey::from(t).is_weak(), "T has small order");
            let mixed_key = VerifyingKey::from(a_point + t);
            assert!(!mixed_key.is_weak(), "A + T does not");
            let mixed = mixed_key.to_bytes();
            let mut verified = 0;
            for n in 0u8..64 {
                let msg = [n; 8];
                let wide = Sha512::new()
                    .chain_update(r_bytes)
                    .chain_update(mixed)
                    .chain_update(msg)
                    .finalize();
                let k = reduce(&wide[..]);
                let s = r + k * a;
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&r_bytes);
                sig[32..].copy_from_slice(&s.to_bytes());
                let expected = k.to_bytes()[0] % t_order == 0;
                assert_eq!(
                    verdict(&mixed, &msg, &sig),
                    expected,
                    "order {t_order}, message {n}"
                );
                verified += usize::from(expected);
            }
            assert!(
                verified > 0 && verified < 64,
                "order {t_order}: {verified} of 64 verify"
            );
        }
    }

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
        use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_65};
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
            assert!(
                UnparsedPublicKey::new(&ML_DSA_65, ours.public_key())
                    .verify(MSG, theirs.as_slice())
                    .is_ok(),
                "seed {s}"
            );
        }
    }

    /// B321 witness: the consensus verifier (RustCrypto) and aws-lc give one
    /// verdict on malformed signatures too: an honest signature with bytes
    /// flipped across it, and its hint section (the last ω + k = 61 bytes)
    /// set to every edge value (indices out of order, counts past ω).
    #[test]
    fn rustcrypto_and_aws_lc_agree_on_malformed_ml_dsa_signatures() {
        use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_65};
        let ml = MlDsa65Key::from_seed(&[7; 32]);
        let pk = ml.public_key();
        let sig = ml.sign(MSG);
        let mut cases = Vec::new();
        for i in (0..sig.len()).step_by(7) {
            let mut bad = sig.clone();
            bad[i] ^= 0x80;
            cases.push(bad);
        }
        for i in sig.len() - 61..sig.len() {
            for v in [0u8, 1, 0x36, 0x37, 0x7f, 0xff] {
                let mut bad = sig.clone();
                bad[i] = v;
                cases.push(bad);
            }
        }
        let mut accepted = 0;
        for (n, case) in cases.iter().enumerate() {
            let ours = verify_tx_signature(&pk, MSG, case).is_ok();
            let theirs = UnparsedPublicKey::new(&ML_DSA_65, &pk)
                .verify(MSG, case)
                .is_ok();
            assert_eq!(ours, theirs, "case {n}");
            accepted += usize::from(ours);
        }
        assert!(
            accepted < cases.len(),
            "vacuous: every malformed signature verified"
        );
    }

    const ML_DSA_65_GOLDEN_PK_SHA256_SEED_7: &str =
        "d3a1e51ecf491b79ca7691bd269271f8d8e8d94313a6abcc6c8ae8bc34b5f9aa";
}
