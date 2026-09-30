//! G1 EQ-1 and G5 SL-3: proposer-twin evidence on a V4 chain.
//!
//! A slot (E, round, author) that reaches a node with a second digest is an
//! equivocation by its author. The node keeps the pair in a durable,
//! epoch-keyed row before GC can drop either body, and carries it through
//! the DAG (`SLASH_EVIDENCE:`) until a block holds it. Every node then checks
//! the pair against C_E, never the live set (executor
//! `verify_slash_evidence`). The rows are node-local bookkeeping, never state.

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
    Some(
        serde_json::json!({
            "kind": KIND,
            "offender": first.author,
            "epoch": first.epoch,
            "round": first.round,
            "vertex_a": first.to_compact_proof_v4(),
            "vertex_b": second.to_compact_proof_v4(),
        })
        .to_string(),
    )
}

/// Record the pair once, unless its author is already jailed (one offense
/// per validator, SL-3).
pub fn record_twin(storage: &StateDB, a: &Vertex, b: &Vertex) {
    let Some(item) = twin_item(a, b) else {
        return;
    };
    let key = seen_key(&a.author, a.epoch, a.round);
    let recorded = matches!(storage.get(&key), Ok(Some(_)));
    let jailed = matches!(
        storage.get(&format!("validator:jailed:{}", a.author)),
        Ok(Some(_))
    );
    if recorded || jailed {
        return;
    }
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
