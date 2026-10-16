//! G1 CE-3 recovery, step 5 of `docs/CERT_CONFLICT_RECOVERY_RUNBOOK.md`: on a
//! stopped validator, pin the slot's canonical certificate and clear the
//! halt. The operators pick the certificate by the runbook's rule (step 4);
//! every node then applies the same one.
//!
//! Pinning replaces the slot's certificate row, takes the certified role
//! from every other digest of the slot and deletes the slot's alarm, in one
//! transaction. The evidence row (`sys:equiv_cert_v4:*`) stays, so the
//! offenders are still convicted. A node that ordered another digest of the
//! slot is refused: its committed sequence already holds the other vertex,
//! and pinning cannot undo that. It is restored by state sync instead.

use super::evidence;
use crate::qc::ValidatorInfo;
use crate::staging::{self, Role, SlotEntry};
use crate::vcert::{self, VertexCertificate};
use std::collections::BTreeSet;
use storage::StateDB;

/// The key of a slot's CE-3 halt alarm.
pub fn alarm_key(epoch: u64, round: u64, author: &str) -> String {
    format!("alarm:vcert_conflict:{epoch:020}:{round:020}:{author}")
}

/// One slot's state on this node, for the runbook's steps 2 and 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotState {
    pub epoch: u64,
    pub round: u64,
    pub author: String,
    /// The digest of the slot's certificate row, if one is held.
    pub cert_digest: Option<String>,
    /// The two digests of the slot's alarm, if one is held, in digest order.
    pub alarm_digests: Option<(String, String)>,
    /// Every digest this node knows for the slot.
    pub digests: BTreeSet<String>,
    /// The digests of the slot this node ordered (in its committed sequence).
    pub ordered: BTreeSet<String>,
}

/// Every slot this node holds a CE-3 alarm for. B456: the alarms are read
/// whole or not at all (`try_scan_prefix`): a read error ended the scan,
/// and the slots past it went unreported (`inspect`, and after a pin "no
/// alarm is left").
pub fn alarmed_slots(storage: &StateDB) -> Result<Vec<SlotState>, String> {
    let mut out = Vec::new();
    let alarms = storage
        .try_scan_prefix("alarm:vcert_conflict:")
        .map_err(|e| e.to_string())?;
    for (key, _) in alarms {
        let mut parts = key["alarm:vcert_conflict:".len()..].splitn(3, ':');
        let (Some(e), Some(r), Some(author)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!("an alarm key of an unknown shape: {key}"));
        };
        let (Ok(epoch), Ok(round)) = (e.parse::<u64>(), r.parse::<u64>()) else {
            return Err(format!("an alarm key of an unknown shape: {key}"));
        };
        out.push(slot_state(storage, epoch, round, author)?);
    }
    Ok(out)
}

fn read_cert(storage: &StateDB, key: &str) -> Result<Option<VertexCertificate>, String> {
    match storage.try_get(key).map_err(|e| e.to_string())? {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| format!("a corrupt certificate row {key}: {e}")),
    }
}

/// What this node holds for slot (epoch, round, author). B456: every row is
/// read fail-closed: one that cannot be read, or does not parse, is an
/// error, never "absent". Read so, the CE-3 pin check could miss the other
/// twin (in a committed-sequence row, the certificate or slot row, or the
/// alarm's pair), pin over it and clear the halt, and `inspect` reported
/// the slot without it.
pub fn slot_state(
    storage: &StateDB,
    epoch: u64,
    round: u64,
    author: &str,
) -> Result<SlotState, String> {
    let cert_digest =
        read_cert(storage, &staging::vcert_key(epoch, round, author))?.map(|c| c.body.digest);
    let alarm_digests = match storage
        .try_get(&alarm_key(epoch, round, author))
        .map_err(|e| e.to_string())?
    {
        None => None,
        Some(raw) => {
            let pair: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| format!("a corrupt alarm row: {e}"))?;
            let digest = |field: &str| -> Result<String, String> {
                serde_json::from_value::<VertexCertificate>(pair[field].clone())
                    .map(|c| c.body.digest)
                    .map_err(|e| format!("a corrupt alarm row ({field}): {e}"))
            };
            let (a, b) = (digest("held")?, digest("other")?);
            Some(if a <= b { (a, b) } else { (b, a) })
        }
    };
    let mut digests: BTreeSet<String> = staging::slot_digests(storage, epoch, round, author)?
        .into_iter()
        .collect();
    digests.extend(cert_digest.iter().cloned());
    if let Some((a, b)) = &alarm_digests {
        digests.insert(a.clone());
        digests.insert(b.clone());
    }
    let ordered = ordered_among(storage, &digests)?;
    Ok(SlotState {
        epoch,
        round,
        author: author.to_string(),
        cert_digest,
        alarm_digests,
        digests,
        ordered,
    })
}

/// The members of `digests` in this node's committed sequence (every
/// `consensus:cseq:` row it still holds). B456: a row that cannot be read
/// (a read error, or a row that is not UTF-8: read lossily, a digest with
/// one byte rotted named another) or does not parse is an error. Skipped,
/// the row that held the other twin read as "not ordered here", and the
/// pin went through on a node whose committed sequence held that twin.
fn ordered_among(
    storage: &StateDB,
    digests: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    let rows = storage
        .try_scan_prefix("consensus:cseq:")
        .map_err(|e| e.to_string())?;
    for (key, raw) in rows {
        let Ok(hashes) = serde_json::from_str::<Vec<String>>(&raw) else {
            return Err(format!("{key} does not parse"));
        };
        out.extend(hashes.into_iter().filter(|h| digests.contains(h)));
    }
    Ok(out)
}

/// What pinning changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// The certificate row's digest before, if there was one.
    pub replaced: Option<String>,
    /// Digests whose certified role was taken.
    pub demoted: Vec<String>,
    /// Whether the slot's alarm was deleted.
    pub alarm_cleared: bool,
}

/// Pin `cert` as its slot's certificate on this (stopped) node. `committee`
/// is the slot's epoch committee C_E. Nothing is written unless every check
/// passes:
/// - the certificate verifies under C_E, this chain and this genesis;
/// - the node did not order another digest of the slot.
pub fn pin_canonical(
    storage: &StateDB,
    cert: &VertexCertificate,
    committee: &[ValidatorInfo],
    chain_id: &str,
    genesis_identity: &str,
) -> Result<Pinned, String> {
    let body = &cert.body;
    vcert::verify_vertex_cert(cert, committee, chain_id, genesis_identity, body.epoch)
        .map_err(|e| format!("the certificate does not verify: {e:?}"))?;
    let state = slot_state(storage, body.epoch, body.round, &body.author)?;
    if let Some(other) = state.ordered.iter().find(|d| **d != body.digest) {
        return Err(format!(
            "this node ordered {other}, not the canonical {}: its committed sequence \
             cannot be changed here. Restore it by state sync from a checkpoint at or \
             below the last block with a QC",
            body.digest
        ));
    }
    let cert_key = staging::vcert_key(body.epoch, body.round, &body.author);
    let slot_key = staging::vslot_key(body.epoch, body.round, &body.author);
    let bytes_key = staging::vbytes_key(body.epoch, &body.author);
    let alarm = alarm_key(body.epoch, body.round, &body.author);
    let json = serde_json::to_string(cert).map_err(|e| e.to_string())?;
    storage
        .transaction(|view| {
            let err = |e: String| storage::StorageError::DatabaseOperation(e);
            view.put(&cert_key, &json)?;
            // Another digest keeps its body (an honest attester must still
            // serve what it attested), but not the certified role: it would
            // block the canonical body from the slot (ST-2).
            let mut demoted = Vec::new();
            if let Some(raw) = view.get(&slot_key).map_err(|e| err(e.to_string()))? {
                let mut slot: Vec<SlotEntry> = serde_json::from_str(&raw)
                    .map_err(|e| err(format!("a corrupt slot row: {e}")))?;
                let mut plain = view
                    .get(&bytes_key)
                    .map_err(|e| err(e.to_string()))?
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                for entry in slot.iter_mut() {
                    if entry.digest != body.digest && entry.role == Role::Certified {
                        entry.role = Role::Staged;
                        plain = plain.saturating_add(entry.bytes);
                        demoted.push(entry.digest.clone());
                    }
                }
                if !demoted.is_empty() {
                    let raw = serde_json::to_string(&slot).map_err(|e| err(e.to_string()))?;
                    view.put(&slot_key, &raw)?;
                    view.put(&bytes_key, &plain.to_string())?;
                }
            }
            let alarm_cleared = view.get(&alarm).map_err(|e| err(e.to_string()))?.is_some();
            if alarm_cleared {
                view.delete(&alarm)?;
            }
            Ok(Pinned {
                replaced: state.cert_digest.clone().filter(|d| *d != body.digest),
                demoted,
                alarm_cleared,
            })
        })
        .map_err(|e| e.to_string())
}

/// The runbook's step 4 rule for one slot, from what every node reported:
/// the digest some node ordered, else the lower digest of the pair. Two
/// different ordered digests mean the nodes' orders already diverged: no
/// certificate can be pinned (step 3, social recovery).
pub fn choose_canonical<'a>(
    pair: (&'a str, &'a str),
    ordered: impl IntoIterator<Item = &'a str>,
) -> Result<&'a str, String> {
    let ordered: BTreeSet<&str> = ordered.into_iter().collect();
    match ordered.len() {
        0 => Ok(pair.0.min(pair.1)),
        1 => {
            let d = *ordered.iter().next().unwrap_or(&pair.0);
            if d == pair.0 || d == pair.1 {
                Ok(d)
            } else {
                Err(format!("{d} is not a digest of the pair"))
            }
        }
        _ => Err(format!(
            "nodes ordered different digests of one slot ({ordered:?}): the orders \
             diverged; this needs social recovery (runbook step 3)"
        )),
    }
}

/// The evidence row of the slot, which pinning keeps.
pub fn evidence_row(storage: &StateDB, epoch: u64, round: u64, author: &str) -> Option<String> {
    storage
        .get(&evidence::cert_seen_key(author, epoch, round))
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_digest_is_the_ordered_one_else_the_lower() {
        let (a, b) = ("aa", "bb");
        assert_eq!(choose_canonical((b, a), []), Ok("aa"));
        assert_eq!(choose_canonical((a, b), ["bb", "bb"]), Ok("bb"));
        assert!(choose_canonical((a, b), ["aa", "bb"])
            .unwrap_err()
            .contains("social recovery"));
        assert!(choose_canonical((a, b), ["cc"]).is_err());
    }

    #[test]
    fn an_alarm_key_names_its_slot() {
        assert_eq!(
            alarm_key(3, 153_030, "ab"),
            "alarm:vcert_conflict:00000000000000000003:00000000000000153030:ab"
        );
    }

    /// B456 witness: what this node holds for a slot is read fail-closed: a
    /// row that is not UTF-8 or does not parse is an error, not "absent".
    /// Read so, the CE-3 pin check could miss the other twin (in a
    /// committed-sequence row, the certificate or slot row, or the alarm's
    /// pair) and pin over it, and `inspect` reported the slot without it.
    #[test]
    fn a_slot_row_that_cannot_be_read_is_an_error_not_absent() {
        let db = StateDB::open(&storage::test_dir_str("b456_slot_state")).unwrap();
        let _seed = db.seeding();
        let raw = |key: &str, bytes: &[u8]| {
            let mut batch = storage::rocksdb::WriteBatch::default();
            batch.put(key.as_bytes(), bytes);
            db.write_batch(batch).unwrap();
        };
        let author = "ab";
        let clean = slot_state(&db, 0, 1, author).unwrap();
        assert!(clean.digests.is_empty() && clean.ordered.is_empty());
        let rotted = [0xff_u8, 0xfe].to_vec();
        let corrupt = [
            (alarm_key(0, 1, author), rotted.clone()),
            (staging::vcert_key(0, 1, author), rotted),
            (staging::vslot_key(0, 1, author), b"not a slot".to_vec()),
            ("consensus:cseq:7".to_string(), b"not a sequence".to_vec()),
            // One byte of a digest rotted: read lossily, it parsed as
            // another digest.
            ("consensus:cseq:7".to_string(), b"[\"aa\xff\"]".to_vec()),
        ];
        for (key, bytes) in corrupt {
            raw(&key, &bytes);
            assert!(
                slot_state(&db, 0, 1, author).is_err(),
                "{key} was read as absent"
            );
            db.delete(&key).unwrap();
            assert!(slot_state(&db, 0, 1, author).is_ok(), "control: {key}");
        }
        // An alarm key with one byte of its author rotted: read lossily, the
        // slot was reported under another author, as if it held nothing.
        let mut key = alarm_key(0, 2, author).into_bytes();
        key.push(0xff);
        let mut batch = storage::rocksdb::WriteBatch::default();
        batch.put(&key, b"{}");
        db.write_batch(batch).unwrap();
        assert!(
            alarmed_slots(&db).is_err(),
            "inspect reported a slot whose alarm it could not read"
        );
    }
}
