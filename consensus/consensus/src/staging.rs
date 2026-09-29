//! G1 S3: the staging store (ST-1..ST-3 of `docs/G1_CONSENSUS_CONTRACT.md`)
//! and its boot load (RC-1 steps 2 and 3). Unwired: S5 puts it on the path.
//!
//! Staging holds validly signed V4 bodies; it never orders them (ST-4). A
//! slot (epoch, round, author) keeps at most two bodies, so twins are staged
//! equally whatever order they arrive in, and a certified digest always finds
//! room.

use crate::ingress_v4::{self, EpochRecord};
use crate::vcert::{self, VertexCertificate};
use blockchain::Vertex;
use serde::{Deserialize, Serialize};
use storage::StateDB;

/// At most this many bodies per slot, the certified reservation included.
pub const MAX_STAGED_PER_SLOT: usize = 2;
/// The bytes of plain bodies (neither certified nor self-attested) staged per
/// author and epoch (ST-3). Callers pass it; tests use smaller budgets.
pub const B_AUTH: u64 = 64 * 1024 * 1024;
/// Boot loads only rounds above `g − RETAIN_SLACK` (GC-3).
pub const RETAIN_SLACK: u64 = 50;
pub const PENDING_MAX_PER_AUTHOR: usize = 16;

/// Why a body is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Staged,
    /// This node attested it (AT-2, in the same transaction).
    SelfAttested,
    /// The slot's certified digest.
    Certified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEntry {
    pub digest: String,
    pub role: Role,
    /// Serialized size, counted against `B_AUTH` while the role is `Staged`.
    pub bytes: u64,
}

pub fn vslot_key(epoch: u64, round: u64, author: &str) -> String {
    format!("consensus:vslot:v1:{epoch:020}:{round:020}:{author}")
}

pub fn vcert_key(epoch: u64, round: u64, author: &str) -> String {
    format!("consensus:vcert:v1:{epoch:020}:{round:020}:{author}")
}

pub fn vbytes_key(epoch: u64, author: &str) -> String {
    format!("consensus:vbytes:v1:{epoch:020}:{author}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// Already held; a higher role, if given, was recorded.
    Held,
    /// Stored as a new member of its slot.
    Staged,
    /// Stored as the slot's certified digest, evicting this plain member.
    Evicted(String),
    /// Not stored: evidence only.
    EvidenceOnly(&'static str),
}

fn read_slot(view: &StateDB, key: &str) -> Result<Vec<SlotEntry>, String> {
    match view.db.get(key).map_err(|e| e.to_string())? {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_slice(&raw).map_err(|e| format!("a corrupt slot row: {e}")),
    }
}

fn read_bytes(view: &StateDB, key: &str) -> Result<u64, String> {
    Ok(view
        .get(key)
        .map_err(|e| e.to_string())?
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0))
}

fn put_json<T: Serialize>(view: &StateDB, key: &str, value: &T) -> Result<(), String> {
    let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
    view.put(key, &json).map_err(|e| e.to_string())
}

/// ST-1..ST-3 for `v`, which passed IN-1, inside the caller's transaction
/// `view` (RC-2: staging commits with the node's own attestation guard).
/// `role` is `SelfAttested` when this node attests `v` in that transaction;
/// `certified` is the slot's certified digest, if one is known; `budget` is
/// the plain-body allowance per author and epoch (`B_AUTH`).
pub fn stage_in(
    view: &StateDB,
    v: &Vertex,
    role: Role,
    certified: Option<&str>,
    budget: u64,
) -> Result<StageOutcome, String> {
    let role = if certified == Some(v.hash.as_str()) {
        role.max(Role::Certified)
    } else {
        role
    };
    let slot_key = vslot_key(v.epoch, v.round, &v.author);
    let bytes_key = vbytes_key(v.epoch, &v.author);
    let mut slot = read_slot(view, &slot_key)?;
    let mut plain = read_bytes(view, &bytes_key)?;
    if let Some(held) = slot.iter_mut().find(|e| e.digest == v.hash) {
        if role > held.role {
            if held.role == Role::Staged {
                plain = plain.saturating_sub(held.bytes);
            }
            held.role = role;
            put_json(view, &slot_key, &slot)?;
            view.put(&bytes_key, &plain.to_string())
                .map_err(|e| e.to_string())?;
        }
        return Ok(StageOutcome::Held);
    }
    // The canonical body: transport fields stripped, so whichever copy
    // arrived first, the stored and served bytes are the same. Certificates
    // live in their own rows.
    let body = ingress_v4::canonical_body(v)?;
    let bytes = body.len() as u64;
    let mut outcome = StageOutcome::Staged;
    if slot.len() >= MAX_STAGED_PER_SLOT {
        // ST-2: only the slot's certified digest may displace a member. A
        // body this node attests must be held (AT-3), so attesting one that
        // cannot be is an error that aborts the caller's transaction.
        if role == Role::SelfAttested {
            return Err("attesting a third digest for a full slot".into());
        }
        if role != Role::Certified {
            return Ok(StageOutcome::EvidenceOnly("a third digest for a full slot"));
        }
        if slot.iter().any(|e| e.role == Role::Certified) {
            return Ok(StageOutcome::EvidenceOnly(
                "a second certified digest for the slot",
            ));
        }
        // Neither self-attested nor certified. At most one member is
        // self-attested (AT-2), so one is always evictable; of two plain
        // members the greater digest goes, the same on every restart.
        let Some(at) = slot
            .iter()
            .enumerate()
            .filter(|(_, e)| e.role == Role::Staged)
            .max_by(|a, b| a.1.digest.cmp(&b.1.digest))
            .map(|(i, _)| i)
        else {
            return Err("a full slot with no plain member to evict".into());
        };
        let evicted = slot.remove(at);
        view.delete(&format!("vertex:{}", evicted.digest))
            .map_err(|e| e.to_string())?;
        #[cfg(test)]
        if FAULT_AFTER_EVICT.with(|f| f.get()) {
            return Err("an injected write fault".into());
        }
        plain = plain.saturating_sub(evicted.bytes);
        outcome = StageOutcome::Evicted(evicted.digest);
    }
    if role == Role::Staged {
        if plain.saturating_add(bytes) > budget {
            return Ok(StageOutcome::EvidenceOnly("the author's plain-body budget"));
        }
        plain += bytes;
    }
    view.put(&format!("vertex:{}", v.hash), &body)
        .map_err(|e| e.to_string())?;
    slot.push(SlotEntry {
        digest: v.hash.clone(),
        role,
        bytes,
    });
    put_json(view, &slot_key, &slot)?;
    view.put(&bytes_key, &plain.to_string())
        .map_err(|e| e.to_string())?;
    #[cfg(test)]
    staging_crash_boundary();
    Ok(outcome)
}

/// `stage_in` in a transaction of its own; an error writes nothing.
pub fn stage(
    storage: &StateDB,
    v: &Vertex,
    role: Role,
    certified: Option<&str>,
    budget: u64,
) -> Result<StageOutcome, String> {
    storage
        .transaction(|view| {
            stage_in(&view, v, role, certified, budget)
                .map_err(storage::StorageError::DatabaseOperation)
        })
        .map_err(|e| e.to_string())
}

/// What boot reloads for the active epoch (RC-1 steps 2 and 3).
#[derive(Debug, Default)]
pub struct Loaded {
    /// Every staged body that still passes Layer S, both twins of a slot
    /// included: there is no load-order dedup.
    pub bodies: Vec<(Role, Vertex)>,
    /// Slot entries whose body is missing or no longer passes Layer S.
    pub refused: Vec<String>,
    /// The certificates of the epoch that verify under its committee.
    pub certs: Vec<VertexCertificate>,
}

/// RC-1 steps 2 and 3 for `record`'s epoch: the staged bodies of rounds above
/// `gc_floor − RETAIN_SLACK`, each re-checked with Layer S and the size bound,
/// and the epoch's certificates, each verified. Step 4 (O_E through OR-1) is
/// S5.
pub fn load(
    storage: &StateDB,
    record: &EpochRecord<'_>,
    chain_id: &str,
    genesis_identity: &str,
    gc_floor: u64,
) -> Result<Loaded, String> {
    let mut out = Loaded::default();
    // Rounds above g − RETAIN_SLACK: all of them while that is negative.
    let from = gc_floor.checked_sub(RETAIN_SLACK).map_or(0, |r| r + 1);
    let prefix = format!("consensus:vslot:v1:{:020}:", record.epoch);
    let start = format!("{prefix}{from:020}:");
    for row in storage.db.iterator(storage::rocksdb::IteratorMode::From(
        start.as_bytes(),
        storage::rocksdb::Direction::Forward,
    )) {
        let (key, raw) = row.map_err(|e| e.to_string())?;
        if !key.starts_with(prefix.as_bytes()) {
            break;
        }
        let slot: Vec<SlotEntry> =
            serde_json::from_slice(&raw).map_err(|e| format!("a corrupt slot row: {e}"))?;
        for entry in slot {
            let body = storage
                .get(&format!("vertex:{}", entry.digest))
                .map_err(|e| e.to_string())?
                // Bounds the parse; Layer S re-checks these same bytes.
                .filter(|json| json.len() <= crate::dag::MAX_VERTEX_BYTES)
                .and_then(|json| serde_json::from_str::<Vertex>(&json).ok());
            match body {
                Some(v)
                    if v.hash == entry.digest
                        && v.epoch == record.epoch
                        && ingress_v4::layer_s(&v, record, chain_id, genesis_identity).is_ok() =>
                {
                    out.bodies.push((entry.role, v))
                }
                _ => out.refused.push(entry.digest),
            }
        }
    }
    let prefix = format!("consensus:vcert:v1:{:020}:", record.epoch);
    for row in storage.db.prefix_iterator(prefix.as_bytes()) {
        let (key, raw) = row.map_err(|e| e.to_string())?;
        if !key.starts_with(prefix.as_bytes()) {
            break;
        }
        if let Ok(cert) = serde_json::from_slice::<VertexCertificate>(&raw) {
            if vcert::verify_vertex_cert(
                &cert,
                record.committee,
                chain_id,
                genesis_identity,
                record.epoch,
            )
            .is_ok()
            {
                out.certs.push(cert);
            }
        }
    }
    Ok(out)
}

/// The PENDING buffer (ST-3): vertices that passed Layer S and wait for an
/// epoch or for parent certificates, at most `PENDING_MAX_PER_AUTHOR` per
/// author, the highest round evicted first.
#[derive(Debug, Default)]
pub struct PendingBuffer {
    per_author:
        std::collections::HashMap<String, std::collections::BTreeMap<(u64, String), Vertex>>,
}

impl PendingBuffer {
    /// Keep `v`; returns the vertex evicted to make room, if any (possibly
    /// `v` itself, when it is the highest round).
    pub fn push(&mut self, v: Vertex) -> Option<Vertex> {
        let held = self.per_author.entry(v.author.clone()).or_default();
        held.insert((v.round, v.hash.clone()), v);
        if held.len() > PENDING_MAX_PER_AUTHOR {
            let highest = *held.keys().next_back().map(|(r, _)| r)?;
            let key = held.keys().rev().find(|(r, _)| *r == highest)?.clone();
            return held.remove(&key);
        }
        None
    }

    /// Whether a vertex with this digest is held (bounded: at most
    /// `PENDING_MAX_PER_AUTHOR` per author).
    pub fn contains(&self, digest: &str) -> bool {
        self.per_author
            .values()
            .any(|held| held.keys().any(|(_, d)| d == digest))
    }

    pub fn remove(&mut self, author: &str, round: u64, digest: &str) -> Option<Vertex> {
        self.per_author
            .get_mut(author)?
            .remove(&(round, digest.to_string()))
    }

    /// Every held vertex, lowest round first per author, leaving the buffer
    /// empty: what a trigger re-evaluates (a new certificate or epoch).
    pub fn take_all(&mut self) -> Vec<Vertex> {
        let mut out: Vec<Vertex> = self
            .per_author
            .drain()
            .flat_map(|(_, held)| held.into_values())
            .collect();
        out.sort_by(|a, b| (a.round, &a.author, &a.hash).cmp(&(b.round, &b.author, &b.hash)));
        out
    }

    pub fn len(&self) -> usize {
        self.per_author.values().map(|m| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
thread_local! {
    /// Fails `stage_in` after its first write, to show `stage` rolls back.
    static FAULT_AFTER_EVICT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn staging_crash_boundary() {
    if std::env::var("AINCORE_TEST_STAGING_CRASH").is_ok() {
        std::process::exit(77);
    }
}

#[cfg(test)]
mod tests;
