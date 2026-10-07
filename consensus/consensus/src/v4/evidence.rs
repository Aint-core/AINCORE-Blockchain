//! G1 EQ-1, CE-3 and G5 SL-3: equivocation evidence on a V4 chain.
//!
//! Proposer twins: a slot (E, round, author) that reaches a node with a second
//! digest is an equivocation by its author. A certificate conflict: two
//! certificates of one slot on different digests; every attester in both
//! signed both digests. The node keeps the pair in a durable,
//! epoch-keyed row before GC can drop either body, and carries it through
//! the DAG (`SLASH_EVIDENCE:`) until a block holds it. Every node then checks
//! the pair against C_E, never the live set (executor
//! `verify_slash_evidence`). The rows are node-local bookkeeping, never state.

use blockchain::attest::VertexCertificate;
use blockchain::Vertex;
use storage::StateDB;

/// The evidence kind of a V4 proposer-twin pair.
pub const KIND: &str = "equivocation_v4";

/// The durable row holding the evidence item for a slot.
pub fn seen_key(author: &str, epoch: u64, round: u64) -> String {
    format!("sys:equiv_seen_v4:{author}:{epoch}:{round}")
}

/// Written once a block this node carried the item into holds it.
pub fn carried_key(author: &str, epoch: u64, round: u64) -> String {
    format!("sys:equiv_carried_v4:{author}:{epoch}:{round}")
}

/// The key of the in-flight and dedup maps shared with V3 items: V3 keys by
/// (offender, round), V4 by (offender:epoch, round), so the two never meet.
pub fn flight_key(author: &str, epoch: u64, round: u64) -> (String, u64) {
    (format!("{author}:{epoch}"), round)
}

/// The evidence item for two bodies of one slot: the compact V4 proofs
/// (payload-free, hashing to the vertices' own `hash_v4`) in hash order, so
/// every node builds the same item. None unless they are twins.
pub fn twin_item(a: &Vertex, b: &Vertex) -> Option<String> {
    if a.author != b.author || a.epoch != b.epoch || a.round != b.round || a.hash == b.hash {
        return None;
    }
    let (first, second) = if a.hash < b.hash { (a, b) } else { (b, a) };
    twin_json(&first.to_compact_proof_v4(), &second.to_compact_proof_v4())
}

/// B210: an evidence item's one encoding, its fields in this order whatever
/// serde_json's features (a `json!` object's key order follows
/// `preserve_order`, and Layer S compares items byte for byte, B192).
#[derive(serde::Serialize)]
struct TwinEncoding<'a> {
    kind: &'static str,
    offender: &'a str,
    epoch: u64,
    round: u64,
    vertex_a: &'a Vertex,
    vertex_b: &'a Vertex,
}

#[derive(serde::Serialize)]
struct ConflictEncoding<'a> {
    kind: &'static str,
    offender: &'a str,
    epoch: u64,
    round: u64,
    cert_a: &'a VertexCertificate,
    cert_b: &'a VertexCertificate,
}

/// The twin item of two compact proofs, `first` the lower hash.
pub(crate) fn twin_json(first: &Vertex, second: &Vertex) -> Option<String> {
    serde_json::to_string(&TwinEncoding {
        kind: KIND,
        offender: &first.author,
        epoch: first.epoch,
        round: first.round,
        vertex_a: first,
        vertex_b: second,
    })
    .ok()
}

/// Record the pair once, unless its author is already jailed (one offense
/// per validator, SL-3).
pub fn record_twin(storage: &StateDB, a: &Vertex, b: &Vertex) {
    // B155: the rows first, the item (two bodies cloned, their payloads
    // hashed) only for a pair not recorded yet.
    let key = seen_key(&a.author, a.epoch, a.round);
    let recorded = matches!(storage.get(&key), Ok(Some(_)));
    let jailed = matches!(
        storage.get(&format!("validator:jailed:{}", a.author)),
        Ok(Some(_))
    );
    if recorded || jailed {
        return;
    }
    let Some(item) = twin_item(a, b) else {
        return;
    };
    eprintln!(
        "🚨 [EQUIVOCATION] {} proposed twins at epoch {} round {}",
        a.author, a.epoch, a.round
    );
    let _ = storage.put(&key, &item);
}

/// The bodies this node holds for `v`'s slot under another digest.
pub fn other_bodies(storage: &StateDB, v: &Vertex) -> Vec<Vertex> {
    crate::staging::slot_digests(storage, v.epoch, v.round, &v.author)
        .into_iter()
        .filter(|digest| *digest != v.hash)
        .filter_map(|digest| {
            let raw = storage.get(&format!("vertex:{digest}")).ok().flatten()?;
            serde_json::from_str::<Vertex>(&raw).ok()
        })
        .collect()
}

/// The evidence kind of a certificate conflict (G1 CE-3).
pub const CERT_KIND: &str = "certificate_conflict";

/// The durable row holding a certificate-conflict item for a slot.
pub fn cert_seen_key(author: &str, epoch: u64, round: u64) -> String {
    format!("sys:equiv_cert_v4:{author}:{epoch}:{round}")
}

/// Written once a block this node carried the certificate item into holds it.
pub fn cert_carried_key(author: &str, epoch: u64, round: u64) -> String {
    format!("sys:equiv_cert_carried_v4:{author}:{epoch}:{round}")
}

/// The in-flight and dedup key of a certificate conflict: its own
/// namespace, so a twin item of the same slot is never deduplicated against it.
pub fn cert_flight_key(author: &str, epoch: u64, round: u64) -> (String, u64) {
    (format!("cert:{author}:{epoch}"), round)
}

/// The item for two certificates of one slot on different digests, in digest
/// order. None unless they conflict.
pub fn cert_conflict_item(a: &VertexCertificate, b: &VertexCertificate) -> Option<String> {
    if !a.body.same_slot(&b.body) || a.body.digest == b.body.digest {
        return None;
    }
    let (first, second) = if a.body.digest < b.body.digest {
        (a, b)
    } else {
        (b, a)
    };
    serde_json::to_string(&ConflictEncoding {
        kind: CERT_KIND,
        offender: &first.body.author,
        epoch: first.body.epoch,
        round: first.body.round,
        cert_a: first,
        cert_b: second,
    })
    .ok()
}

/// B192: an item's bytes past the chain id and genesis identity its
/// certificates repeat. The largest an honest node builds is a certificate
/// conflict on a full committee: two certificates of 1,017 bytes
/// (`MAX_COMMITTEE` bits, a 96-byte aggregate, 39-digit stakes, 20-digit
/// epoch and round, three 64-character digests) in a 187-byte envelope,
/// 2,221 in all; a twin pair is at most 1,426. Rounded up to 4 KiB (a choice).
pub const ITEM_FIXED_BYTES: usize = 4 * 1024;

/// B192: the most bytes an evidence item takes on this chain: each
/// certificate of a conflict carries the chain id and genesis identity once.
pub fn max_item_bytes(chain_id: &str, genesis_identity: &str) -> usize {
    let quoted = |s: &str| serde_json::to_string(s).map_or(usize::MAX, |j| j.len());
    ITEM_FIXED_BYTES
        .saturating_add(quoted(chain_id).saturating_mul(2))
        .saturating_add(quoted(genesis_identity).saturating_mul(2))
}

/// B192: Layer S's predicate for an evidence item (past its prefix): at most
/// `max_item_bytes`, and byte for byte the item an honest node builds from
/// what it parses to -- compact, payload-free proofs of one slot in hash
/// order, or two certificates of one slot on different digests in digest
/// order. Whether it convicts anyone is the executor's to decide; this bounds
/// what a block carries and verifies (an item used to pass on its kind, at
/// any size, with its payload).
pub fn admissible_item(item: &str, chain_id: &str, genesis_identity: &str) -> Result<(), String> {
    let most = max_item_bytes(chain_id, genesis_identity);
    if item.len() > most {
        return Err(format!("{} bytes, over {most}", item.len()));
    }
    let ev: serde_json::Value = serde_json::from_str(item).map_err(|e| e.to_string())?;
    let field = |name: &str| ev.get(name).cloned().unwrap_or_default();
    let rebuilt = match ev.get("kind").and_then(|k| k.as_str()) {
        Some(KIND) => {
            let proof = |name: &str| -> Result<Vertex, String> {
                serde_json::from_value(field(name)).map_err(|e| format!("{name}: {e}"))
            };
            let (a, b) = (proof("vertex_a")?, proof("vertex_b")?);
            if !(is_compact(&a) && is_compact(&b)) {
                return Err("a proof is not in compact form".into());
            }
            twin_item(&a, &b)
        }
        Some(CERT_KIND) => {
            let cert = |name: &str| -> Result<VertexCertificate, String> {
                serde_json::from_value(field(name)).map_err(|e| format!("{name}: {e}"))
            };
            cert_conflict_item(&cert("cert_a")?, &cert("cert_b")?)
        }
        _ => return Err("evidence of no ordered kind".into()),
    };
    if rebuilt.as_deref() != Some(item) {
        return Err("not the item its parts build".into());
    }
    Ok(())
}

/// A compact V4 proof as `twin_item` carries one: no payload, no parents,
/// both roots, and no aggregate (Layer S refuses one on a live vertex).
fn is_compact(v: &Vertex) -> bool {
    v.payload.is_empty()
        && v.parents.is_empty()
        && v.parent_refs.is_empty()
        && v.payload_root.is_some()
        && v.parents_root.is_some()
        && v.aggregated_signature.is_none()
}

/// Record a certificate conflict once.
pub fn record_cert_conflict(storage: &StateDB, a: &VertexCertificate, b: &VertexCertificate) {
    let Some(item) = cert_conflict_item(a, b) else {
        return;
    };
    let key = cert_seen_key(&a.body.author, a.body.epoch, a.body.round);
    if matches!(storage.get(&key), Ok(Some(_))) {
        return;
    }
    let _ = storage.put(&key, &item);
}
