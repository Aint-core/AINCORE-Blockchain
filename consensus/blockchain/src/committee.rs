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

/// At most this many members sign for an epoch (G1 EP-2).
pub const MAX_COMMITTEE: usize = 256;

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
    if members.len() > MAX_COMMITTEE {
        return Err(format!("{} members, over {MAX_COMMITTEE}", members.len()));
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

/// The leader of `round`: a stake-weighted draw seeded by the round and the
/// committee (`validators` in canonical order, whole-AIN stakes). Consensus
/// elects anchors with it; the executor measures bootstrap operators against
/// it (G5 BW-6), so both use this one definition.
pub fn leader_for_round(round: u64, validators: &[(String, u64)], attempt: u32) -> String {
    if validators.is_empty() {
        return String::new();
    }
    let mut preimage = b"AINCORE_LEADER_V2".to_vec();
    preimage.extend_from_slice(&round.to_le_bytes());
    preimage.extend_from_slice(&(attempt as u64).to_le_bytes());
    for (addr, stake) in validators {
        preimage.extend_from_slice(addr.as_bytes());
        preimage.extend_from_slice(&stake.to_le_bytes());
    }
    let digest = crypto::hash(&preimage);
    let seed = u64::from_le_bytes(digest[..8].try_into().expect("a SHA-256 digest"));
    let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
    if total_stake == 0 {
        // No stake information: uniform, so the chain never divides by zero.
        return validators[(seed % validators.len() as u64) as usize]
            .0
            .clone();
    }
    let draw = (seed as u128) % total_stake;
    let mut cumulative: u128 = 0;
    for (addr, stake) in validators {
        cumulative += *stake as u128;
        if draw < cumulative {
            return addr.clone();
        }
    }
    validators[validators.len() - 1].0.clone()
}

/// The `MAX_COMMITTEE` positive-stake members of `proposed` with the most
/// stake, ties by address (G5 review: the active set is chosen by stake, as
/// Cosmos chooses it by power under `MaxValidators`). More validators may be
/// bonded; only these sign and are paid for the epoch.
pub fn top_by_stake(proposed: &[ValidatorInfo]) -> Vec<ValidatorInfo> {
    let mut members: Vec<ValidatorInfo> =
        proposed.iter().filter(|m| m.stake > 0).cloned().collect();
    members.sort_by(|a, b| {
        b.stake
            .cmp(&a.stake)
            .then_with(|| a.address.cmp(&b.address))
    });
    members.truncate(MAX_COMMITTEE);
    members
}

/// G1 EP-2: the committee of epoch E+1 from the live set proposed at the
/// boundary H_E: its top `MAX_COMMITTEE` by stake if they are valid.
/// Otherwise C_E, without the members the live set no longer holds (G5
/// review: a kept committee must not keep a member whose stake left), or
/// all of C_E if that is not valid either. The reason is returned so the
/// caller can raise its alarm.
pub fn next_committee(
    current: &[ValidatorInfo],
    proposed: &[ValidatorInfo],
) -> (Vec<ValidatorInfo>, Option<String>) {
    match validate_committee(&top_by_stake(proposed)) {
        Ok(c) => (c, None),
        Err(why) => {
            let live: HashSet<&str> = proposed
                .iter()
                .filter(|m| m.stake > 0)
                .map(|m| m.address.as_str())
                .collect();
            let kept: Vec<ValidatorInfo> = current
                .iter()
                .filter(|m| live.contains(m.address.as_str()))
                .cloned()
                .collect();
            match validate_committee(&kept) {
                Ok(c) => (c, Some(why)),
                Err(_) => (canonical_order(current), Some(why)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(seed: u32, stake: u64) -> ValidatorInfo {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&seed.to_le_bytes());
        key[31] = 1;
        let ed = crypto::SigningKey::from_bytes(&key)
            .verifying_key()
            .to_bytes();
        let bls = BLSEngine::consensus();
        let bls_seed: [u8; 32] = crypto::hash(&key).try_into().unwrap();
        ValidatorInfo {
            address: crypto::derive_address(&ed).unwrap(),
            stake,
            ed25519_public_key: hex::encode(ed),
            bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
        }
    }

    /// G5 review: 257 or more bonded validators no longer make the live set
    /// invalid (which kept C_E, leavers included, for good): the committee is
    /// the top 256 by stake, ties by address, whatever their order.
    #[test]
    fn more_than_256_validators_elect_the_top_256_by_stake() {
        let mut live: Vec<ValidatorInfo> = (0..300).map(|i| member(i, 1_000)).collect();
        live[7].stake = 5_000;
        live[299].stake = 4_000;
        live[3].stake = 0;
        let mut reversed = live.clone();
        reversed.reverse();
        let (next, invalid) = next_committee(&live[..4], &live);
        assert_eq!(invalid, None);
        assert_eq!(next.len(), MAX_COMMITTEE);
        assert_eq!(next_committee(&live[..4], &reversed).0, next);
        let addresses: HashSet<&str> = next.iter().map(|m| m.address.as_str()).collect();
        assert!(addresses.contains(live[7].address.as_str()));
        assert!(addresses.contains(live[299].address.as_str()));
        assert!(
            !addresses.contains(live[3].address.as_str()),
            "no zero stake"
        );
        // The 1,000-stake seats go to the lowest addresses.
        let mut equal: Vec<&ValidatorInfo> = live.iter().filter(|m| m.stake == 1_000).collect();
        equal.sort_by(|a, b| a.address.cmp(&b.address));
        let (inside, outside) = equal.split_at(MAX_COMMITTEE - 2);
        assert!(inside
            .iter()
            .all(|m| addresses.contains(m.address.as_str())));
        assert!(outside
            .iter()
            .all(|m| !addresses.contains(m.address.as_str())));
    }

    /// G5 review: when the proposal is invalid, the kept committee drops the
    /// members the live set no longer holds; with none left valid, C_E stays.
    #[test]
    fn a_kept_committee_drops_members_whose_stake_left() {
        let (a, b, c) = (member(1, 100), member(2, 100), member(3, 100));
        let mut bad = b.clone();
        bad.bls_pop = a.bls_pop.clone();
        let (next, invalid) = next_committee(&[a.clone(), b.clone(), c.clone()], &[a.clone(), bad]);
        assert!(invalid.is_some());
        assert_eq!(
            next,
            canonical_order(&[a.clone(), b.clone()]),
            "C left, B kept as it was"
        );
        let (next, invalid) = next_committee(&[a.clone(), b.clone()], &[]);
        assert!(invalid.is_some());
        assert_eq!(
            next,
            canonical_order(&[a, b]),
            "nothing valid is left: C_E stays"
        );
    }

    /// G5 BW-6: the executor's leader schedule is consensus's. Pinned to the
    /// first five blocks of the live AINCORE-TESTNET-V4 chain (2026-10-02):
    /// four validators of 4,625,000 AIN, anchors on rounds 2, 4, 6, 8, 10.
    #[test]
    fn the_leader_schedule_matches_live_testnet_blocks() {
        let validators: Vec<(String, u64)> = [
            "b89a4bfd24ae7ecd69130215ab1009994887dd68286595eced85ce99c32ed772",
            "c4ab03c269bcea7031e467ddcc04e970f2e22e419bf7bc1cbcca142914c8a433",
            "d3ac8b5d68464ad24692653fb27f01bde5261dcfb3854064e0ecdbce8fab76d7",
            "dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42",
        ]
        .iter()
        .map(|a| (a.to_string(), 4_625_000))
        .collect();
        let proposers = [
            (2, "d3ac8b5d6846"),
            (4, "c4ab03c269bc"),
            (6, "b89a4bfd24ae"),
            (8, "b89a4bfd24ae"),
            (10, "c4ab03c269bc"),
        ];
        for (round, proposer) in proposers {
            assert!(
                leader_for_round(round, &validators, 0).starts_with(proposer),
                "round {round}"
            );
        }
        assert_eq!(leader_for_round(1, &[], 0), "");
    }
}
