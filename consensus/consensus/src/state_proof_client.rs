//! G3 PF-2: what a client must check before it believes an
//! `aincore_getStateProof` answer. Any failure means the answer is refused.
//!
//! 1. The QC verifies under the committee the client trusts for its epoch.
//! 2. `qc.epoch` is the epoch the client expects for `qc.block_height`. The
//!    client selects the committee by height from a committee chain it
//!    trusts (TA). Until the committee record lands (S5), the caller
//!    supplies both.
//! 3. `qc.block_height` is the answer's height.
//! 4. The proof verifies against `qc.state_root`, never a field the server
//!    chose.
//! 5. The key hash is derived here from the requested key (inside
//!    `state_proof::verify`).
//! 6. Freshness: the height is at least `min_height`, the client's known
//!    finalized height or the height it asked for.

use crate::qc::{verify_qc, QuorumCertificate, ValidatorInfo};
use serde::{Deserialize, Serialize};

/// The parts of an `aincore_getStateProof` answer a client relies on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProofAnswer {
    pub key: String,
    pub value: Option<String>,
    pub height: u64,
    pub proof: state_proof::WireProof,
    pub quorum_certificate: Option<QuorumCertificate>,
}

/// What the client trusts, independently of the server.
pub struct Trust<'a> {
    pub chain_id: &'a str,
    /// The committee of the epoch the client expects at the answer's height.
    pub committee: &'a [ValidatorInfo],
    pub expected_epoch: u64,
    /// The lowest height the client will accept (PF-2.6).
    pub min_height: u64,
}

/// Check an answer for `key`. `Ok(Some(value))` or `Ok(None)` (absent) only
/// when every PF-2 check passes.
pub fn verify_answer(
    key: &str,
    answer: &StateProofAnswer,
    trust: &Trust<'_>,
) -> Result<Option<String>, String> {
    if answer.key != key {
        return Err(format!("the answer is for {}, not {key}", answer.key));
    }
    let qc = answer
        .quorum_certificate
        .as_ref()
        .ok_or("no quorum certificate for this height yet")?;
    verify_qc(qc, trust.committee, trust.chain_id).map_err(|e| format!("QC: {e}"))?;
    if qc.epoch != trust.expected_epoch {
        return Err(format!(
            "QC epoch {} is not the expected epoch {}",
            qc.epoch, trust.expected_epoch
        ));
    }
    if qc.block_height != answer.height {
        return Err(format!(
            "QC height {} is not the answer's height {}",
            qc.block_height, answer.height
        ));
    }
    if answer.height < trust.min_height {
        return Err(format!(
            "height {} is older than the {} the client requires",
            answer.height, trust.min_height
        ));
    }
    let root = state_proof::parse_hash(&qc.state_root).map_err(|e| e.to_string())?;
    state_proof::verify(
        &root,
        key,
        answer.value.as_deref().map(str::as_bytes),
        &answer.proof,
    )
    .map_err(|e| e.to_string())?;
    Ok(answer.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qc::{build_qc, validator_set_hash, FinalityVote};
    use crypto::bls::BLSEngine;
    use std::sync::Arc;
    use storage::StateDB;

    fn committee(seeds: &[u8]) -> (Vec<ValidatorInfo>, Vec<[u8; 32]>) {
        let bls = BLSEngine::consensus();
        let mut infos = Vec::new();
        let mut secrets = Vec::new();
        for &seed in seeds {
            let ikm = [seed; 32];
            infos.push(ValidatorInfo {
                address: format!("{:064x}", seed),
                stake: 100,
                ed25519_public_key: "00".repeat(32),
                bls_public_key: hex::encode(bls.pubkey_raw(&ikm)),
                bls_pop: hex::encode(bls.prove_possession_raw(&ikm)),
            });
            secrets.push(ikm);
        }
        (infos, secrets)
    }

    /// A QC over `state_root` at `height`, signed by the whole committee.
    fn qc(
        infos: &[ValidatorInfo],
        secrets: &[[u8; 32]],
        height: u64,
        epoch: u64,
        state_root: &str,
    ) -> QuorumCertificate {
        let vote = FinalityVote {
            chain_id: "AINCORE-TEST-PF".into(),
            epoch,
            finalized_round: height * 2,
            anchor_round: height * 2,
            anchor_hash: "aa".repeat(32),
            block_height: height,
            block_hash: "bb".repeat(32),
            state_root: state_root.into(),
            receipts_root: "dd".repeat(32),
            finality_digest: "ee".repeat(32),
            validator_set_hash: validator_set_hash(infos),
        };
        let bls = BLSEngine::consensus();
        let order = crate::qc::canonical_order(infos);
        let sigs: Vec<Vec<u8>> = order
            .iter()
            .map(|v| {
                let i = infos.iter().position(|x| x.address == v.address).unwrap();
                bls.sign_raw(&vote.to_signing_bytes(), &secrets[i])
            })
            .collect();
        build_qc(&vote, infos, &(0..order.len()).collect::<Vec<_>>(), &sigs).unwrap()
    }

    /// A real tree at version 1, the answer the RPC would give for `key`,
    /// and a QC over that version's root.
    fn obj(i: u64) -> String {
        format!("obj:{i:064x}")
    }

    fn answer_for(test: &str, key: &str, epoch: u64) -> (StateProofAnswer, Vec<ValidatorInfo>) {
        let path =
            std::env::temp_dir().join(format!("pf_client_{test}_{epoch}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let db = Arc::new(StateDB::open(path.to_str().unwrap()).unwrap());
        let mut v0: Vec<(String, Option<Vec<u8>>)> = (0..20)
            .map(|i| (obj(i), Some(format!("v{i}").into_bytes())))
            .collect();
        v0.push(("sys:chain_id".into(), Some(b"AINCORE-TEST-PF".to_vec())));
        let a = state_commit::apply(&db, 0, v0).unwrap();
        db.write_batch(a.batch).unwrap();
        let a = state_commit::apply(&db, 1, vec![(obj(1), Some(b"updated".to_vec()))]).unwrap();
        db.write_batch(a.batch).unwrap();
        let (value, proof) = state_commit::wire_proof(&db, key, 1).unwrap();
        let root = hex::encode(state_commit::root(&db, 1).unwrap().0);
        let (infos, secrets) = committee(&[1, 2, 3]);
        let answer = StateProofAnswer {
            key: key.into(),
            value: value.map(|v| String::from_utf8(v).unwrap()),
            height: 1,
            proof,
            quorum_certificate: Some(qc(&infos, &secrets, 1, epoch, &root)),
        };
        (answer, infos)
    }

    fn trust(committee: &[ValidatorInfo]) -> Trust<'_> {
        Trust {
            chain_id: "AINCORE-TEST-PF",
            committee,
            expected_epoch: 0,
            min_height: 1,
        }
    }

    #[test]
    fn a_proven_value_and_a_proven_absence_are_accepted() {
        let (answer, infos) = answer_for("present", &obj(1), 0);
        assert_eq!(
            verify_answer(&obj(1), &answer, &trust(&infos)),
            Ok(Some("updated".into()))
        );
        let (answer, infos) = answer_for("absent", &obj(999), 0);
        assert_eq!(verify_answer(&obj(999), &answer, &trust(&infos)), Ok(None));
    }

    /// Every PF-2 check refuses on its own.
    #[test]
    fn every_pf2_check_refuses() {
        let key = obj(1);
        let key = key.as_str();
        let (good, infos) = answer_for("refusals", key, 0);
        let t = trust(&infos);
        let refuses = |name: &str, key: &str, a: &StateProofAnswer, t: &Trust| {
            assert!(verify_answer(key, a, t).is_err(), "{name}");
        };
        refuses("another key", &obj(2), &good, &t);
        let mut a = good.clone();
        a.value = Some("forged".into());
        refuses("a forged value", key, &a, &t);
        let mut a = good.clone();
        a.quorum_certificate = None;
        refuses("no QC", key, &a, &t);
        let (other_committee, _) = committee(&[7, 8, 9]);
        refuses("another committee", key, &good, &trust(&other_committee));
        let wrong_chain = Trust {
            chain_id: "AINCORE-OTHER",
            ..trust(&infos)
        };
        refuses("another chain", key, &good, &wrong_chain);
        let (other_epoch, infos2) = answer_for("refusals_epoch", key, 3);
        refuses(
            "a QC from another epoch",
            key,
            &other_epoch,
            &trust(&infos2),
        );
        let mut a = good.clone();
        a.height = 2;
        refuses("a QC for another height", key, &a, &t);
        let stale = Trust {
            min_height: 2,
            ..trust(&infos)
        };
        refuses("a stale height", key, &good, &stale);
        let mut a = good.clone();
        let mut forged = a.quorum_certificate.clone().unwrap();
        forged.state_root = "00".repeat(32);
        a.quorum_certificate = Some(forged);
        refuses("a QC whose root was rewritten", key, &a, &t);
    }
}
