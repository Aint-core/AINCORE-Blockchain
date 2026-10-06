//! B21: transactions reach the committee from any node.
//!
//! Only committee members put transactions into vertices. A node outside
//! the committee (an observer, an RPC node) used to keep what its RPC
//! accepted in its own mempool for good. It now forwards: every
//! `FORWARD_EVERY` it loans its pending transactions (as a vertex would)
//! and sends them in `TX_SUBMIT:` batches over the sync protocol to one
//! connected member, the first in an order the sender's address fixes, so
//! one sender's transactions reach one member in nonce order (Aptos public
//! fullnodes forward their mempool upstream the same way). The member
//! answers each transaction with its mempool's verdict. An accepted one
//! stays on loan until a synced block settles it (`mark_executed`), or
//! returns to the queue after 30 s and is forwarded again, starting at the
//! next member (B53; bounded by the mempool's requeue cap); a refused one
//! goes to the next member and is
//! dropped once `REFUSALS_TO_DROP` members refused it (B39); an unanswered
//! batch goes to the next member, and back to the queue when none answers.
//!
//! B122: "enough members" is stake, not a count: a transaction is dropped
//! once members holding more than a third of the committee's stake refused
//! it (and at least `REFUSALS_TO_DROP` of them), so the Byzantine minority
//! cannot drop it however it sits in the rotation. The groups of a pass are
//! sent at once, and a member that did not answer is skipped for
//! `SILENT_FOR` (one silent member used to cost every batch its timeout).

use mempool::Mempool;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A batch of raw transactions, a JSON array of strings.
pub const TX_SUBMIT: &str = "TX_SUBMIT:";
/// The verdicts, a JSON array in the batch's order.
pub const TX_RESULT: &str = "TX_RESULT:";
/// Transactions per batch (a choice: 64 transfers are ~32 KB; the request
/// cap cuts batches of large transactions sooner).
pub const FORWARD_BATCH: usize = 64;
/// How often a node outside the committee forwards.
pub const FORWARD_EVERY: Duration = Duration::from_millis(250);
/// How long a member may take to answer a batch.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);
/// A forwarded transaction no block settled is forwarded again after this
/// long (consensus re-queues its own loans after the same 30 s).
const FORWARD_RETRY_SECS: u64 = 30;
/// B122: how long a member that did not answer is skipped (a choice: the
/// retry period above).
pub const SILENT_FOR: Duration = Duration::from_secs(FORWARD_RETRY_SECS);

/// B122: the current committee's stake by member address (the PeerBook's),
/// and the members that did not answer, skipped until the time kept.
#[derive(Debug, Default)]
pub struct ForwardState {
    pub stakes: HashMap<String, u64>,
    silent: Mutex<HashMap<String, Instant>>,
}

impl ForwardState {
    pub fn with_stakes(stakes: HashMap<String, u64>) -> Self {
        Self {
            stakes,
            silent: Mutex::new(HashMap::new()),
        }
    }

    fn total_stake(&self) -> u128 {
        self.stakes.values().map(|s| u128::from(*s)).sum()
    }

    fn stake_of(&self, member: &str) -> u128 {
        self.stakes.get(member).map_or(0, |s| u128::from(*s))
    }

    fn silent(&self, peer: &str, now: Instant) -> bool {
        self.silent
            .lock()
            .map(|s| s.get(peer).is_some_and(|until| now < *until))
            .unwrap_or(false)
    }

    fn strike(&self, peer: &str, now: Instant) {
        if let Ok(mut s) = self.silent.lock() {
            s.retain(|_, until| now < *until);
            s.insert(peer.to_string(), now + SILENT_FOR);
        }
    }
}

/// One transaction's verdict from the member's mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accepted(String),
    Refused(String),
}

/// Member side: the batch's verdicts from this node's mempool. `None`
/// (refused whole) for a malformed batch, an empty one, or one longer than
/// `FORWARD_BATCH`.
pub fn serve_tx_submit(mempool: &Mutex<Mempool>, wire: &str) -> Option<String> {
    let txs: Vec<String> = serde_json::from_str(wire.strip_prefix(TX_SUBMIT)?).ok()?;
    if txs.is_empty() || txs.len() > FORWARD_BATCH {
        return None;
    }
    // B31: the stateless checks (signatures included) run before the
    // mempool lock, which the consensus ticker needs; only what passes is
    // admitted under it, without being verified again.
    let checked: Vec<Result<(String, executor::admission::CheckedTx), String>> = txs
        .into_iter()
        .map(|tx| Mempool::check_admissible(&tx).map(|checked| (tx, checked)))
        .collect();
    let mut mp = mempool.lock().ok()?;
    let verdicts: Vec<Verdict> = checked
        .into_iter()
        .map(|tx| tx.and_then(|(tx, checked)| mp.add_checked(tx, checked)))
        .map(|admitted| match admitted {
            Ok(hash) => Verdict::Accepted(hash),
            Err(reason) => Verdict::Refused(reason),
        })
        .collect();
    drop(mp);
    Some(format!(
        "{TX_RESULT}{}",
        serde_json::to_string(&verdicts).ok()?
    ))
}

/// The sender a raw transaction names ("" when it names none).
fn sender_of(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("sender")?.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The member sessions to try for `sender`, in order: the connected members
/// sorted by PeerId, rotated to start at the sender's hash.
pub fn members_for(sender: &str, sessions: &[network::SessionPeer]) -> Vec<String> {
    let mut peers: Vec<String> = sessions
        .iter()
        .filter(|s| s.member.is_some())
        .map(|s| s.peer.clone())
        .collect();
    peers.sort();
    peers.dedup();
    if peers.is_empty() {
        return peers;
    }
    let digest = crypto::hash(sender.as_bytes());
    let start =
        u64::from_be_bytes(digest[..8].try_into().unwrap_or_default()) as usize % peers.len();
    peers.rotate_left(start);
    peers
}

/// Batches of at most `FORWARD_BATCH` transactions whose `TX_SUBMIT:` wire
/// fits `cap` bytes, in order. A transaction that alone does not fit is
/// its own batch (the member's frame limit refuses it, and it returns).
fn batches(txs: Vec<String>, cap: usize) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut size = 0usize;
    for tx in txs {
        let cost = serde_json::to_string(&tx).map_or(tx.len(), |s| s.len()) + 1;
        let full = out
            .last()
            .is_none_or(|b| b.len() >= FORWARD_BATCH || size + cost > cap);
        if full {
            out.push(Vec::new());
            size = TX_SUBMIT.len() + 2;
        }
        size += cost;
        out.last_mut().expect("pushed above").push(tx);
    }
    out
}

/// One forwarding pass: loan what the mempool holds, send it, settle the
/// answers. Returns how many transactions a member accepted.
pub async fn forward_once(
    mempool: &Arc<Mutex<Mempool>>,
    client: &network::SessionClient,
    state: &ForwardState,
) -> usize {
    let loaned: Vec<(String, u8)> = match mempool.lock() {
        Ok(mut mp) => {
            let now = wall_secs();
            mp.requeue_stale_at(FORWARD_RETRY_SECS, now);
            mp.get_pending_transactions_at(FORWARD_BATCH * 4, now)
                .into_iter()
                .map(|tx| {
                    let attempts = mp.loan_attempts(&tx);
                    (tx, attempts)
                })
                .collect()
        }
        Err(_) => return 0,
    };
    if loaned.is_empty() {
        return 0;
    }
    let sessions = client.sessions();
    // Group by the first member each sender maps to, keeping order.
    let mut groups: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    for (tx, attempts) in loaned {
        // B53: a transaction loaned again (no block settled it within
        // FORWARD_RETRY_SECS) starts at the next member: one that answered
        // Accepted and dropped it cannot hold every one of its sender's.
        let mut order = members_for(&sender_of(&tx), &sessions);
        if !order.is_empty() {
            let shift = usize::from(attempts) % order.len();
            order.rotate_left(shift);
        }
        match groups.iter_mut().find(|(o, _)| *o == order) {
            Some((_, txs)) => txs.push(tx),
            None => groups.push((order, vec![tx])),
        }
    }
    // B122: the groups at once (each starts at another member), their
    // batches in order within a group.
    let member_of: HashMap<String, String> = sessions
        .iter()
        .filter_map(|s| Some((s.peer.clone(), s.member.clone()?)))
        .collect();
    let passes = groups.into_iter().map(|(order, txs)| {
        let member_of = &member_of;
        async move {
            let mut accepted = 0;
            for batch in batches(txs, crate::sessions::SYNC_REQUEST_CAP) {
                accepted += send_batch(mempool, client, state, member_of, &order, batch).await;
            }
            accepted
        }
    });
    futures::future::join_all(passes).await.into_iter().sum()
}

/// B39: a transaction is dropped only once at least this many members
/// refused it (one member alone never drops it), and (B122) only once those
/// members hold more than a third of the stake.
pub const REFUSALS_TO_DROP: usize = 2;

async fn send_batch(
    mempool: &Arc<Mutex<Mempool>>,
    client: &network::SessionClient,
    state: &ForwardState,
    member_of: &HashMap<String, String>,
    order: &[String],
    batch: Vec<String>,
) -> usize {
    let mut pending = batch;
    let mut refusals: HashMap<String, (usize, u128)> = HashMap::new();
    let mut dropped = Vec::new();
    let mut accepted = 0;
    // A committee whose stakes this node does not know counts each member
    // as one.
    let total = match state.total_stake() {
        0 => member_of.len() as u128,
        stake => stake,
    };
    for peer in order {
        if pending.is_empty() {
            break;
        }
        if state.silent(peer, Instant::now()) {
            continue;
        }
        let Ok(wire) = serde_json::to_string(&pending).map(|json| format!("{TX_SUBMIT}{json}"))
        else {
            break;
        };
        let Ok(reply) = client.ask(peer, &wire, FORWARD_TIMEOUT).await else {
            state.strike(peer, Instant::now());
            continue;
        };
        let stake = match state.total_stake() {
            0 => 1,
            _ => member_of.get(peer).map_or(0, |m| state.stake_of(m)),
        };
        let Some(verdicts) = reply
            .strip_prefix(TX_RESULT)
            .and_then(|json| serde_json::from_str::<Vec<Verdict>>(json).ok())
            .filter(|v| v.len() == pending.len())
        else {
            continue;
        };
        let mut next = Vec::new();
        for (tx, verdict) in pending.into_iter().zip(verdicts) {
            match verdict {
                Verdict::Accepted(_) => accepted += 1,
                Verdict::Refused(_) => {
                    let (count, refused) = refusals.entry(tx.clone()).or_insert((0, 0));
                    *count += 1;
                    *refused += stake;
                    if *count >= REFUSALS_TO_DROP && *refused * 3 > total {
                        dropped.push(tx);
                    } else {
                        next.push(tx);
                    }
                }
            }
        }
        pending = next;
    }
    if let Ok(mut mp) = mempool.lock() {
        // Refused by enough members: dropped here too (a used nonce, a payer
        // that cannot pay, a transaction they already hold).
        mp.mark_executed(&dropped);
        // Not settled: back to the front of the queue, in order. Once any
        // member answered, every one left was refused by too few members:
        // a failed attempt, so one refused in every pass is dropped after
        // the mempool's requeue cap (review of B39). None answered: the
        // network's failure, not the transaction's.
        let reversed: Vec<String> = pending.into_iter().rev().collect();
        if refusals.is_empty() {
            mp.return_unshipped(&reversed);
        } else {
            mp.return_refused(&reversed);
        }
    }
    accepted
}

fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The forwarding task: a pass every `FORWARD_EVERY` while this node is
/// outside the current committee.
pub async fn run_forwarder(
    mempool: Arc<Mutex<Mempool>>,
    client: network::SessionClient,
    book: Arc<std::sync::RwLock<crate::sessions::PeerBook>>,
    in_committee: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) {
    let mut tick = tokio::time::interval(FORWARD_EVERY);
    let mut state = ForwardState::default();
    while !shutdown.load(Ordering::SeqCst) {
        tick.tick().await;
        if !in_committee.load(Ordering::SeqCst) {
            if let Ok(b) = book.read() {
                if *b.stakes() != state.stakes {
                    state.stakes = b.stakes().clone();
                }
            }
            forward_once(&mempool, &client, &state).await;
        }
    }
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
