//! The committee of an epoch: one definition for consensus and the executor.
//!
//! G1 EP-2 derives each epoch's committee from the post-state of the previous
//! boundary block. G5 EM-2 pays that same committee. Both call the functions
//! here, so they can never disagree on who the committee is.

use crypto::bls::BLSEngine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Per-validator finality identity. `bls_public_key` / `bls_pop` are hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub stake: u64,
    pub ed25519_public_key: String,
    pub bls_public_key: String,
    /// Proof-of-possession over `bls_public_key` (MANDATORY at registration).
    pub bls_pop: String,
}

/// The canonical order of a committee: by address.
pub fn canonical_order(validators: &[ValidatorInfo]) -> Vec<ValidatorInfo> {
    let mut v = validators.to_vec();
    v.sort_by(|a, b| a.address.cmp(&b.address));
    v
}

/// Canonical hash of the validator set whose order defines QC bitmap indices.
/// This is included in every FinalityVote so a QC cannot be replayed against a
/// different epoch/set with the same address ordering.
pub fn validator_set_hash(validators: &[ValidatorInfo]) -> String {
    let canonical = canonical_order(validators);
    let bytes = bcs::to_bytes(&canonical).expect("ValidatorInfo is BCS-serializable");
    hex::encode(crypto::hash(&bytes))
}

/// G1 EP-2: a proposed committee is valid when its positive-stake members are
/// 1 to 256 distinct validators whose Ed25519 keys derive their addresses and
/// whose BLS proofs of possession verify. Returns it in canonical order.
///
/// G5 SL-3: no two members share a BLS key. A certificate bit proves that a
/// registered key signed, so a shared key would make evidence name the wrong
/// member.
pub fn validate_committee(proposed: &[ValidatorInfo]) -> Result<Vec<ValidatorInfo>, String> {
    let members: Vec<ValidatorInfo> = proposed.iter().filter(|m| m.stake > 0).cloned().collect();
    if members.is_empty() {
        return Err("an empty committee".into());
    }
    if members.len() > 256 {
        return Err(format!("{} members, over 256", members.len()));
    }
    let mut seen = HashSet::new();
    let mut keys = HashSet::new();
    let bls = BLSEngine::consensus();
    for m in &members {
        if !seen.insert(m.address.as_str()) {
            return Err(format!("member {} twice", m.address));
        }
        if !keys.insert(m.bls_public_key.to_ascii_lowercase()) {
            return Err(format!(
                "member {}: its BLS key is another member's",
                m.address
            ));
        }
        let derives = hex::decode(&m.ed25519_public_key)
            .ok()
            .and_then(|pk| crypto::derive_address(&pk).ok())
            .is_some_and(|a| a == m.address);
        if !derives {
            return Err(format!("member {}: its key does not derive it", m.address));
        }
        let pop_ok = match (hex::decode(&m.bls_public_key), hex::decode(&m.bls_pop)) {
            (Ok(pk), Ok(pop)) => bls.verify_possession(&pk, &pop).unwrap_or(false),
            _ => false,
        };
        if !pop_ok {
            return Err(format!(
                "member {}: its BLS proof of possession fails",
                m.address
            ));
        }
    }
    Ok(canonical_order(&members))
}

/// G1 EP-2: the committee of epoch E+1 from the live set proposed at the
/// boundary H_E: the proposal if it is valid, C_E otherwise (the reason is
/// returned so the caller can raise its alarm).
pub fn next_committee(
    current: &[ValidatorInfo],
    proposed: &[ValidatorInfo],
) -> (Vec<ValidatorInfo>, Option<String>) {
    match validate_committee(proposed) {
        Ok(c) => (c, None),
        Err(why) => (canonical_order(current), Some(why)),
    }
}
