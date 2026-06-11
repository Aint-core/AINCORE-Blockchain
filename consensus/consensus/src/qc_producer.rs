//! QC Phase 2 — live quorum-certificate production (side-effect-only).
//!
//! This module wires the keystone (`crate::qc`) into the live commit path. After
//! a block is committed AND executed (state root known), the node:
//!   1. reads the active validator set (`sys:validator_set:v1`, written at genesis
//!      by B1, carrying each validator's BLS public key + PoP),
//!   2. derives ITS OWN BLS secret from the persistent node identity (the SAME
//!      derivation genesis used — `SHA256(VALIDATOR_BLS_DOMAIN || node_key)`),
//!   3. signs the canonical `FinalityVote` for the committed block,
//!   4. if this node's stake alone meets the strict >2/3 quorum (the live
//!      single-validator / supermajority-holder topology), aggregates a complete
//!      1-of-1 QC, self-verifies it, and stores it; otherwise records the node's
//!      partial vote for future multi-party aggregation (Phase 3).
//!
//! ## SAFETY INVARIANT — additive only
//! QC production is NOT a precondition for commit or finality. Every fallible
//! step returns `None` / logs and the commit path continues unchanged. A bug
//! here can at worst fail to produce an attestation; it can never fork, halt, or
//! alter consensus. QC keys (`consensus:qc:*`) are consensus metadata, written
//! with the same direct-`put` pattern as DAG checkpoints — they are not Move
//! state and do not enter the state root.
//!
//! Multi-validator aggregation (collecting other validators' votes over the
//! network) is Phase 3 — this module only ever contributes THIS node's signature.

use crate::qc::{self, build_qc, verify_qc, FinalityVote, QuorumCertificate, ValidatorInfo};
use storage::StateDB;

pub use crate::qc::derive_validator_bls_seed;

/// Load and parse the active validator set written by B1 at genesis.
pub fn load_validator_set_v1(storage: &StateDB) -> Option<Vec<ValidatorInfo>> {
    let raw = storage.get("sys:validator_set:v1").ok()??;
    let set: Vec<ValidatorInfo> = serde_json::from_str(&raw).ok()?;
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

/// Commit context captured at the point a block is finalized + executed.
pub struct CommitContext {
    pub chain_id: String,
    pub epoch: u64,
    pub finalized_round: u64,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    /// The canonical finality digest computed by the ordering engine for this
    /// committed anchor (reused so the QC binds to the exact digest consensus
    /// finalized over, not a separately-recomputed one).
    pub finality_digest: String,
}

/// Produce (and store) a quorum certificate for a committed block, contributing
/// THIS node's BLS signature. Returns the QC iff a complete >2/3-stake quorum was
/// achievable from this node alone (the live single-validator / supermajority
/// case). Side-effect-only; never affects the commit path.
pub fn produce_and_store_qc(
    storage: &StateDB,
    node_key: &[u8; 32],
    node_address: &str,
    ctx: &CommitContext,
) -> Option<QuorumCertificate> {
    let validators = load_validator_set_v1(storage)?;
    let ordered = qc::canonical_order(&validators);

    // Position of this node in the canonical set, by validator address.
    let my_idx = ordered.iter().position(|v| v.address == node_address)?;

    let vote = FinalityVote {
        chain_id: ctx.chain_id.clone(),
        epoch: ctx.epoch,
        finalized_round: ctx.finalized_round,
        anchor_round: ctx.anchor_round,
        anchor_hash: ctx.anchor_hash.clone(),
        block_height: ctx.block_height,
        block_hash: ctx.block_hash.clone(),
        state_root: ctx.state_root.clone(),
        receipts_root: ctx.receipts_root.clone(),
        finality_digest: ctx.finality_digest.clone(),
        validator_set_hash: qc::validator_set_hash(&validators),
    };

    let seed = derive_validator_bls_seed(node_key);
    let bls = crypto::bls::BLSEngine::consensus();

    // Derived pubkey MUST equal the genesis-registered key for our address; if it
    // does not, derivation drift / misconfig — abort (a QC that can never verify
    // must not be produced).
    let our_pk = hex::encode(bls.pubkey_raw(&seed));
    if our_pk != ordered[my_idx].bls_public_key {
        eprintln!(
            "🚨 [QC] derived BLS pubkey != genesis-registered key for {node_address} — skipping QC production"
        );
        return None;
    }

    let sig = bls.sign_raw(&vote.to_signing_bytes(), &seed);

    // Does our stake alone meet the strict >2/3 quorum (single-validator or
    // supermajority holder)? If not, record the partial vote for Phase 3
    // aggregation and produce no complete QC.
    let my_stake = ordered[my_idx].stake as u128;
    let total_stake: u128 = ordered.iter().map(|v| v.stake as u128).sum();
    if !qc::stake_quorum_met(my_stake, total_stake) {
        let key = format!("consensus:qc_vote:{}:{}", ctx.anchor_round, node_address);
        let _ = storage.put(&key, &hex::encode(&sig));
        return None;
    }

    let qc = match build_qc(&vote, &validators, &[my_idx], std::slice::from_ref(&sig)) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("🚨 [QC] build_qc failed: {e} — skipping");
            return None;
        }
    };

    // Self-verify before storing: an unverifiable QC must never be persisted.
    if let Err(e) = verify_qc(&qc, &validators) {
        eprintln!("🚨 [QC] self-verify failed: {e} — not storing");
        return None;
    }

    match serde_json::to_string(&qc) {
        Ok(json) => {
            let _ = storage.put(&format!("consensus:qc:{}", ctx.block_height), &json);
            let _ = storage.put(&format!("consensus:qc_by_round:{}", ctx.anchor_round), &json);
            let _ = storage.put("consensus:qc:latest", &json);
            let _ = storage.put(
                "consensus:qc:latest_height",
                &ctx.block_height.to_string(),
            );
            let _ = storage.put(
                "consensus:qc:latest_round",
                &ctx.anchor_round.to_string(),
            );
            println!(
                "🔏 [QC] stored quorum cert for block #{} (signed_stake={}/{} > 2/3)",
                ctx.block_height, qc.signed_stake, qc.total_stake
            );
        }
        Err(e) => {
            eprintln!("🚨 [QC] serialize failed: {e} — not storing");
            return None;
        }
    }

    Some(qc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qc::ValidatorInfo;

    fn validator_for(node_key: &[u8; 32], stake: u64, address: &str) -> ValidatorInfo {
        let bls = crypto::bls::BLSEngine::consensus();
        let seed = derive_validator_bls_seed(node_key);
        ValidatorInfo {
            address: address.to_string(),
            stake,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&seed)),
        }
    }

    fn ctx_for(height: u64) -> CommitContext {
        CommitContext {
            chain_id: "AINCORE-TEST-1".into(),
            epoch: 0,
            finalized_round: height + 2,
            anchor_round: height,
            anchor_hash: "ab".repeat(32),
            block_height: height,
            block_hash: "cd".repeat(32),
            state_root: "ef".repeat(32),
            receipts_root: "12".repeat(32),
            finality_digest: "34".repeat(32),
        }
    }

    #[test]
    fn single_validator_produces_verifiable_qc() {
        let dir = std::env::temp_dir().join(format!("qc_prod_single_{}", std::process::id()));
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();
        let node_key = [7u8; 32];
        let addr = "deadbeef";
        let v = validator_for(&node_key, 1_000_000, addr);
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&vec![v.clone()]).unwrap())
            .unwrap();

        let qc = produce_and_store_qc(&storage, &node_key, addr, &ctx_for(42))
            .expect("single validator must produce a complete QC");
        // The produced QC verifies against the trusted set.
        assert!(verify_qc(&qc, &[v]).is_ok());
        // And it was stored at the height key.
        assert!(storage.get("consensus:qc:42").unwrap().is_some());
        assert_eq!(
            storage.get("consensus:qc:latest_height").unwrap().as_deref(),
            Some("42")
        );
        assert_eq!(
            storage.get("consensus:qc:latest_round").unwrap().as_deref(),
            Some("42")
        );
        assert!(storage.get("consensus:qc:latest").unwrap().is_some());
        assert!(storage.get("consensus:qc_by_round:42").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn observer_node_not_in_set_produces_nothing() {
        let dir = std::env::temp_dir().join(format!("qc_prod_obs_{}", std::process::id()));
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();
        // Set contains a DIFFERENT validator; our node_key is not registered.
        let other = validator_for(&[9u8; 32], 1_000_000, "aaaa");
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&vec![other]).unwrap())
            .unwrap();

        let got = produce_and_store_qc(&storage, &[7u8; 32], "deadbeef", &ctx_for(7));
        assert!(got.is_none(), "node not in validator set must produce no QC");
        assert!(storage.get("consensus:qc:7").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn minority_stake_records_partial_vote_no_qc() {
        let dir = std::env::temp_dir().join(format!("qc_prod_minor_{}", std::process::id()));
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();
        let my_key = [7u8; 32];
        // Our node holds 10 of 100 total stake — far below >2/3.
        let me = validator_for(&my_key, 10, "bbbb");
        let big = validator_for(&[9u8; 32], 90, "aaaa");
        storage
            .put(
                "sys:validator_set:v1",
                &serde_json::to_string(&vec![me, big]).unwrap(),
            )
            .unwrap();

        let got = produce_and_store_qc(&storage, &my_key, "bbbb", &ctx_for(5));
        assert!(got.is_none(), "minority stake must not yield a complete QC");
        // No complete QC stored, but a partial vote was recorded for Phase 3.
        assert!(storage.get("consensus:qc:5").unwrap().is_none());
        assert!(
            storage.get("consensus:qc_vote:5:bbbb").unwrap().is_some(),
            "partial vote must be recorded under anchor_round"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validator_set_hash_is_order_independent() {
        let a = validator_for(&[1u8; 32], 10, "zzzz");
        let b = validator_for(&[2u8; 32], 20, "aaaa");
        let h1 = qc::validator_set_hash(&[a.clone(), b.clone()]);
        let h2 = qc::validator_set_hash(&[b, a]);
        assert_eq!(h1, h2, "set hash must be canonical-order invariant");
    }
}
