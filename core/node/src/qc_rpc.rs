//! Certificate checks against this node's retained, locally trusted metadata.
//! This does not replay execution, prove state, or authenticate epoch transitions.

use consensus::{qc, qc_producer};
use storage::StateDB;

pub const VERIFICATION_SCOPE: &str = "local_committee_and_epoch";

#[derive(Debug)]
pub enum VerificationError {
    Unavailable(&'static str),
    Invalid(String),
    /// B175: not remembered, and no verification slot was free.
    Busy,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => f.write_str(message),
            Self::Invalid(message) => f.write_str(message),
            Self::Busy => f.write_str("verifications are busy; retry"),
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
    verify_with(storage, certificate, indexed_height, || Some(()))
}

/// `verify` for a client: a certificate not remembered costs a pairing, on
/// a `slot` (`None`: busy). B175: `getQuorumCert` took none, so a client
/// asking for more stored heights than are remembered paid a pairing a call.
pub fn verify_with<G>(
    storage: &StateDB,
    certificate: &qc::QuorumCertificate,
    indexed_height: Option<u64>,
    slot: impl FnOnce() -> Option<G>,
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
    // B182: only a stored certificate's outcome is remembered: a client's
    // own (`indexed_height` none), junk at a dry-run slot each, pushed the
    // stored ones out of the table. B234: the epoch's committee as the
    // engine remembers it (parsed once per record, with its hash). B254:
    // read only on a miss, on the slot.
    verify_qc_once(
        certificate,
        storage.db.instance(),
        &qc::expected_chain_id(),
        slot,
        || {
            #[cfg(test)]
            COMMITTEE_READS.with(|n| n.set(n.get() + 1));
            qc_producer::epoch_committee(storage, certificate.epoch).map(|c| c.set.clone())
        },
        indexed_height.is_some(),
    )
}

#[cfg(test)]
thread_local! {
    /// B167 witness support: the certificates `verify_qc_once` verified on
    /// this thread (not the remembered ones).
    pub(crate) static QC_VERIFIES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// B254 witness support: the committees `verify_with` read on this
    /// thread.
    pub(crate) static COMMITTEE_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Outcomes `verify_qc_once` remembers (a choice).
const REMEMBERED_OUTCOMES: usize = 1_024;

/// B167: `verify_qc`'s outcome for one certificate under one committee and
/// chain id, remembered: every call of the QC RPCs paid a pairing, 100 calls
/// a second per IP. B254: keyed by the certificate, the chain id and the
/// store (`StateDB`'s instance) whose committee for the certificate's epoch
/// it is checked against: a store's committee records never change once
/// written, so a hit is exact, and it is found before the `committee` is
/// read (B234 keyed it by the committee's hash, so every call read the
/// committee first: four are kept, and certificates of past epochs asked in
/// turn parsed one, ~130 KB at 256 members, on every call). A miss reads
/// the committee and verifies on a `slot` (B175: `Busy` when none was
/// free); its outcome is kept when `remember_it` (B182: a stored
/// certificate's).
fn verify_qc_once<G, V: std::ops::Deref<Target = [qc::ValidatorInfo]>>(
    certificate: &qc::QuorumCertificate,
    store: u64,
    chain_id: &str,
    slot: impl FnOnce() -> Option<G>,
    committee: impl FnOnce() -> Option<V>,
    remember_it: bool,
) -> Result<(), VerificationError> {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    type Outcomes = HashMap<Vec<u8>, Result<(), String>>;
    static OUTCOMES: LazyLock<Mutex<Outcomes>> = LazyLock::new(Default::default);
    let Ok(bytes) = serde_json::to_vec(&(certificate, store, chain_id)) else {
        return Err(VerificationError::Invalid(
            "the certificate does not serialize".into(),
        ));
    };
    let key = crypto::hash(&bytes);
    if let Some(known) = OUTCOMES.lock().ok().and_then(|o| o.get(&key).cloned()) {
        return known.map_err(VerificationError::Invalid);
    }
    let _slot = slot().ok_or(VerificationError::Busy)?;
    let validators =
        committee().ok_or(VerificationError::Unavailable("validator set unavailable"))?;
    #[cfg(test)]
    QC_VERIFIES.with(|n| n.set(n.get() + 1));
    let outcome = qc::verify_qc(certificate, &validators, chain_id).map_err(|e| e.to_string());
    if remember_it {
        if let Ok(mut outcomes) = OUTCOMES.lock() {
            remember(&mut outcomes, key, outcome.clone());
        }
    }
    outcome.map_err(VerificationError::Invalid)
}

/// B175: one outcome makes room for another when the table is full: it
/// used to be cleared, so a client cycling past `REMEMBERED_OUTCOMES`
/// certificates missed on every call.
fn remember<V>(outcomes: &mut std::collections::HashMap<Vec<u8>, V>, key: Vec<u8>, value: V) {
    if outcomes.len() >= REMEMBERED_OUTCOMES && !outcomes.contains_key(&key) {
        if let Some(evicted) = outcomes.keys().next().cloned() {
            outcomes.remove(&evicted);
        }
    }
    outcomes.insert(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B167 witness: a certificate verified once under its committee is not
    /// verified again (each QC RPC call paid a pairing).
    #[test]
    fn a_certificate_is_verified_once() {
        let bls = crypto::bls::BLSEngine::consensus();
        let seed = qc::derive_validator_bls_seed(&[7; 32]);
        let validators = vec![qc::ValidatorInfo {
            address: "ab".repeat(32),
            stake: 100,
            ed25519_public_key: "cd".repeat(32),
            bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&seed, &[0xcd; 32])),
        }];
        let vote = qc::FinalityVote {
            chain_id: qc::expected_chain_id(),
            epoch: 0,
            finalized_round: 4,
            anchor_round: 2,
            anchor_hash: "aa".repeat(32),
            block_height: 1,
            block_hash: "bb".repeat(32),
            state_root: "cc".repeat(32),
            receipts_root: "dd".repeat(32),
            finality_digest: "ee".repeat(32),
            validator_set_hash: qc::validator_set_hash(&validators),
            next_validator_set_hash: String::new(),
        };
        let signature = bls.sign_raw(&vote.to_signing_bytes(), &seed);
        let cert = qc::build_qc(&vote, &validators, &[0], &[signature]).expect("a QC");
        let verifies = || QC_VERIFIES.with(|n| n.get());
        let chain = qc::expected_chain_id();
        let committee = || Some(validators.clone());
        let before = verifies();
        let first = verify_qc_once(&cert, 7, &chain, || Some(()), committee, true);
        assert!(first.is_ok(), "vacuous: {first:?}");
        // B175: remembered, it needs no slot; one not remembered does.
        let second = verify_qc_once(&cert, 7, &chain, || None::<()>, committee, true);
        assert!(
            second.is_ok(),
            "a remembered outcome took a slot: {second:?}"
        );
        assert_eq!(verifies() - before, 1, "a certificate was verified twice");
        let mut other = vote.clone();
        other.block_height = 2;
        let signature = bls.sign_raw(&other.to_signing_bytes(), &seed);
        let other = qc::build_qc(&other, &validators, &[0], &[signature]).expect("a QC");
        assert!(
            matches!(
                verify_qc_once(&other, 7, &chain, || None::<()>, committee, true),
                Err(VerificationError::Busy)
            ),
            "a miss was verified without a slot"
        );
        assert_eq!(verifies() - before, 1);
        // B182: a client's certificate is checked, never remembered, so
        // junk cannot push a stored one out.
        let ask = || verify_qc_once(&other, 7, &chain, || Some(()), committee, false);
        assert!(ask().is_ok());
        assert!(ask().is_ok());
        assert_eq!(
            verifies() - before,
            3,
            "a client's certificate was remembered"
        );
    }

    /// B254 witness: a stored certificate's remembered outcome is answered
    /// before its epoch's committee is read, and with no slot: the committee
    /// was read first (four kept), so certificates of past epochs asked in
    /// turn parsed one, ~130 KB at 256 members, on every call.
    #[test]
    fn a_remembered_outcome_reads_no_committee() {
        let dir = storage::test_dir::process_dir().join(format!(
            "qc-b254-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = StateDB::open(dir.to_str().unwrap()).unwrap();
        let bls = crypto::bls::BLSEngine::consensus();
        let seed = [7u8; 32];
        let set = vec![qc::ValidatorInfo {
            address: "local".into(),
            stake: 100,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&seed, &[0u8; 32])),
        }];
        {
            let _seed = db.seeding();
            let json = serde_json::to_string(&set).unwrap();
            db.put("genesis:validator_set:v1", &json).unwrap();
            db.put("sys:validator_set:epoch:1", &json).unwrap();
            db.put("consensus:epoch", "1").unwrap();
            db.put("consensus:epoch_start_height:1", "21").unwrap();
        }
        let vote = qc::FinalityVote {
            chain_id: qc::expected_chain_id(),
            epoch: 0,
            finalized_round: 6,
            anchor_round: 6,
            anchor_hash: "01".repeat(32),
            block_height: 5,
            block_hash: "02".repeat(32),
            state_root: "03".repeat(32),
            receipts_root: "04".repeat(32),
            finality_digest: "05".repeat(32),
            validator_set_hash: qc::validator_set_hash(&set),
            next_validator_set_hash: String::new(),
        };
        let signature = bls.sign_raw(&vote.to_signing_bytes(), &seed);
        let cert = qc::build_qc(&vote, &set, &[0], &[signature]).expect("a QC");
        let reads = || COMMITTEE_READS.with(|n| n.get());
        verify_with(&db, &cert, Some(5), || Some(())).expect("vacuous: it verifies");
        let before = reads();
        verify_with(&db, &cert, Some(5), || None::<()>).expect("a remembered outcome took a slot");
        assert_eq!(reads(), before, "a remembered outcome read the committee");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// B175 witness: a full table makes room for one outcome by dropping
    /// one; it used to be cleared, so a client cycling past it missed on
    /// every call.
    #[test]
    fn a_full_table_drops_one_outcome() {
        let mut outcomes = std::collections::HashMap::new();
        for i in 0..=REMEMBERED_OUTCOMES as u32 {
            remember(&mut outcomes, i.to_be_bytes().to_vec(), i);
        }
        assert_eq!(outcomes.len(), REMEMBERED_OUTCOMES, "the table was cleared");
        let newest = (REMEMBERED_OUTCOMES as u32).to_be_bytes().to_vec();
        assert_eq!(outcomes.get(&newest), Some(&(REMEMBERED_OUTCOMES as u32)));
        remember(&mut outcomes, newest.clone(), 7);
        assert_eq!(outcomes.len(), REMEMBERED_OUTCOMES, "a known key made room");
    }
}
