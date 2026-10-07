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
//! B122/B133/B134: "enough members" is stake, not a count, and it is
//! counted across passes and loans: a transaction is dropped once members
//! holding more than a third of the committee's stake refused it (and at
//! least `REFUSALS_TO_DROP` of them), or once it is `FORWARD_TTL_SECS` old,
//! never by how many passes it took, so the Byzantine minority cannot drop
//! it however it sits in the rotation. Each pass and each re-forward asks
//! the members that have not answered for it first (three adjacent
//! accept-and-drop members held every re-forward). A busy member says so
//! (`TX_BUSY`) and was not asked; only one that let the timeout run is
//! skipped for `SILENT_FOR`; one ask is in flight to a member at a time.

use mempool::Mempool;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A batch of raw transactions, a JSON array of strings.
pub const TX_SUBMIT: &str = "TX_SUBMIT:";
/// The verdicts, a JSON array in the batch's order.
pub const TX_RESULT: &str = "TX_RESULT:";
/// B133: a member too busy to take a batch now (its serving permits or its
/// budget for the asker are spent): the batch was not looked at.
pub const TX_BUSY: &str = "TX_BUSY:";
/// Transactions per batch (a choice: 64 transfers are ~32 KB; the request
/// cap cuts batches of large transactions sooner).
pub const FORWARD_BATCH: usize = 64;
/// How often a node outside the committee forwards.
pub const FORWARD_EVERY: Duration = Duration::from_millis(250);
/// How long a member may take to answer a batch (below the sync protocol's
/// own 10 s request timeout, so the forwarder's fires first and is told
/// apart from a refusal).
const FORWARD_TIMEOUT: Duration = Duration::from_secs(8);
/// B133: a forwarded transaction no member took into a block is dropped
/// this long after its first forward (a choice: Aptos's mempool timeout,
/// B98's parked TTL).
pub const FORWARD_TTL_SECS: u64 = 600;
/// B133: transactions the forwarder remembers at most (twice the mempool).
const MAX_FORWARD_RECORDS: usize = 10_000;
/// A forwarded transaction no block settled is forwarded again after this
/// long (consensus re-queues its own loans after the same 30 s).
pub const FORWARD_RETRY_SECS: u64 = 30;
/// B122: how long a member that did not answer is skipped (a choice: the
/// retry period above).
pub const SILENT_FOR: Duration = Duration::from_secs(FORWARD_RETRY_SECS);
/// B151: passes forwarding at once. A pass waits for its slowest batch, and
/// each pass waited for the one before, so a member answering just inside
/// the timeout held them all (a pass loans at most `4 x FORWARD_BATCH`):
/// about 32 transactions a second. Passes run apart now; a member has one
/// ask in flight at most (`begin_ask`), so a slow one holds only the batch
/// it was asked. The timeout over the pass period (a choice): a pass held
/// for a whole timeout still leaves room for one a period.
pub const PASSES_AT_ONCE: usize =
    (FORWARD_TIMEOUT.as_millis() / FORWARD_EVERY.as_millis()) as usize;

/// B247: member sessions a forwarder names in its records at once (a
/// choice, four times the largest committee; B251: an id no record names any
/// more is given again).
const MAX_MEMBER_IDS: usize = 1024;

/// B247: a set of member sessions, as bits of the ids `ForwardState`
/// gives them: the records held sets of PeerIds, up to n each under
/// congestion (10,000 records, 256 members), cloned twice a transaction a
/// pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Members([u64; MAX_MEMBER_IDS / 64]);

impl Members {
    fn insert(&mut self, id: usize) {
        self.0[id / 64] |= 1 << (id % 64);
    }

    fn remove(&mut self, id: usize) {
        self.0[id / 64] &= !(1 << (id % 64));
    }

    fn contains(&self, id: usize) -> bool {
        self.0[id / 64] & (1 << (id % 64)) != 0
    }

    fn len(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    fn union(&mut self, other: &Members) {
        for (w, o) in self.0.iter_mut().zip(other.0.iter()) {
            *w |= o;
        }
    }

    /// The lowest id not in the set.
    fn first_free(&self) -> Option<usize> {
        self.0
            .iter()
            .enumerate()
            .find(|(_, w)| **w != u64::MAX)
            .map(|(i, w)| i * 64 + w.trailing_ones() as usize)
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }
}

/// B133: what one forwarded transaction met: when it was first forwarded,
/// and the members (sessions) that took it or refused it, over every pass.
#[derive(Debug, Default, Clone, Copy)]
struct Forwarded {
    first_secs: u64,
    /// B154: the last pass that loaned it.
    last_secs: u64,
    accepted: Members,
    refused: Members,
    /// B232: the members that refused it for now (`Verdict::Later`), and
    /// (B247) when the last of them did.
    later: Members,
    later_secs: u64,
}

/// B122/B133: the current committee's stake by member address (the
/// PeerBook's), the members that let a timeout run (skipped until the time
/// kept), the members with an ask in flight, and what each transaction met.
#[derive(Debug)]
pub struct ForwardState {
    stakes: std::sync::RwLock<HashMap<String, u64>>,
    timeout: Duration,
    silent: Mutex<HashMap<String, Instant>>,
    /// B156: members that said they were busy, resting until the second
    /// kept (of the pass clock): each was asked again every pass, 250 ms on,
    /// and every ask spent the forwarder's quota at the member.
    busy: Mutex<HashMap<String, u64>>,
    asking: Mutex<HashSet<String>>,
    forwarded: Mutex<Records>,
}

/// What each forwarded transaction met (by its `raw_tx_hash`), and (B247)
/// the ids its member sets use. B251: under one lock, so an id is given,
/// set in a record and freed at once: given on first use and never freed,
/// the ids ran out after `MAX_MEMBER_IDS` members over a node's life, and
/// from then on a new member's verdicts were recorded nowhere (never a
/// refusal toward a drop, always untried).
#[derive(Debug, Default)]
struct Records {
    by_tx: HashMap<String, Forwarded>,
    ids: HashMap<String, usize>,
    /// The ids `ids` gives.
    given: Members,
}

impl Records {
    /// `peer`'s id, given on first use; with every id given, those no record
    /// names any more are freed first (`None` only when every one is named).
    fn id(&mut self, peer: &str) -> Option<usize> {
        if let Some(&id) = self.ids.get(peer) {
            return Some(id);
        }
        if self.ids.len() >= MAX_MEMBER_IDS {
            let mut named = Members::default();
            for r in self.by_tx.values() {
                named.union(&r.accepted);
                named.union(&r.refused);
                named.union(&r.later);
            }
            self.ids.retain(|_, id| named.contains(*id));
            self.given = named;
        }
        let id = self.given.first_free()?;
        self.given.insert(id);
        self.ids.insert(peer.to_string(), id);
        Some(id)
    }
}

impl Default for ForwardState {
    fn default() -> Self {
        Self::with_stakes(HashMap::new())
    }
}

impl ForwardState {
    pub fn with_stakes(stakes: HashMap<String, u64>) -> Self {
        Self {
            stakes: std::sync::RwLock::new(stakes),
            timeout: FORWARD_TIMEOUT,
            silent: Mutex::new(HashMap::new()),
            busy: Mutex::new(HashMap::new()),
            asking: Mutex::new(HashSet::new()),
            forwarded: Mutex::new(Records::default()),
        }
    }

    /// Whether `set` names `peer` (a member with no id is in no set).
    fn names(&self, set: &Members, peer: &str) -> bool {
        self.forwarded
            .lock()
            .ok()
            .and_then(|f| f.ids.get(peer).copied())
            .is_some_and(|id| set.contains(id))
    }

    /// Tests: a shorter wait for an answer.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The current committee's stakes, when they changed.
    pub fn set_stakes(&self, stakes: &HashMap<String, u64>) {
        if let Ok(mut held) = self.stakes.write() {
            if *held != *stakes {
                *held = stakes.clone();
            }
        }
    }

    fn total_stake(&self) -> u128 {
        self.stakes
            .read()
            .map(|s| s.values().map(|s| u128::from(*s)).sum())
            .unwrap_or(0)
    }

    fn stake_of(&self, member: &str) -> u128 {
        self.stakes
            .read()
            .map(|s| s.get(member).map_or(0, |s| u128::from(*s)))
            .unwrap_or(0)
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

    /// B156: whether `peer` said it was busy less than a second ago.
    fn resting(&self, peer: &str, now_secs: u64) -> bool {
        self.busy
            .lock()
            .map(|b| b.get(peer).is_some_and(|until| now_secs < *until))
            .unwrap_or(false)
    }

    fn rest(&self, peer: &str, now_secs: u64) {
        if let Ok(mut b) = self.busy.lock() {
            b.retain(|_, until| now_secs < *until);
            b.insert(peer.to_string(), now_secs + 1);
        }
    }

    /// B133: claim `peer` for one ask; false while another is in flight.
    fn begin_ask(&self, peer: &str) -> bool {
        self.asking
            .lock()
            .map(|mut a| a.insert(peer.to_string()))
            .unwrap_or(false)
    }

    fn end_ask(&self, peer: &str) {
        if let Ok(mut a) = self.asking.lock() {
            a.remove(peer);
        }
    }

    /// `tx`'s record, made at its first forward (`now_secs`); records older
    /// than the TTL leave, and the table stays bounded.
    fn record(&self, tx: &str, now_secs: u64) -> Forwarded {
        let key = storage::StateDB::raw_tx_hash(tx);
        let Ok(mut f) = self.forwarded.lock() else {
            return Forwarded {
                first_secs: now_secs,
                ..Forwarded::default()
            };
        };
        // A backstop: `make_room` keeps the table below its cap while the
        // mempool holds fewer transactions than it.
        if !f.by_tx.contains_key(&key) && f.by_tx.len() >= MAX_FORWARD_RECORDS {
            if let Some(idlest) = f
                .by_tx
                .iter()
                .min_by_key(|(k, r)| (r.last_secs, (*k).clone()))
                .map(|(k, _)| k.clone())
            {
                f.by_tx.remove(&idlest);
            }
        }
        let r = f.by_tx.entry(key).or_insert_with(|| Forwarded {
            first_secs: now_secs,
            ..Forwarded::default()
        });
        r.last_secs = now_secs;
        *r
    }

    /// `peer` took (`true`) or refused `tx`; the members that took it and
    /// those that refused it so far.
    fn note(&self, tx: &str, peer: &str, took: bool) -> (Members, Members) {
        let key = storage::StateDB::raw_tx_hash(tx);
        let Ok(mut f) = self.forwarded.lock() else {
            return Default::default();
        };
        if !f.by_tx.contains_key(&key) {
            return Default::default();
        }
        let Some(id) = f.id(peer) else {
            return Default::default();
        };
        let Some(r) = f.by_tx.get_mut(&key) else {
            return Default::default();
        };
        if took {
            r.later.remove(id);
            r.accepted.insert(id);
        } else {
            r.refused.insert(id);
        }
        (r.accepted, r.refused)
    }

    /// B232: `peer` refused `tx` for now, at `now_secs`.
    fn note_later(&self, tx: &str, peer: &str, now_secs: u64) {
        let key = storage::StateDB::raw_tx_hash(tx);
        let Ok(mut f) = self.forwarded.lock() else {
            return;
        };
        if !f.by_tx.contains_key(&key) {
            return;
        }
        let Some(id) = f.id(peer) else {
            return;
        };
        if let Some(r) = f.by_tx.get_mut(&key) {
            r.later.insert(id);
            r.later_secs = now_secs;
        }
    }

    /// B154: room for `incoming` new records. When the table would pass its
    /// cap, the records of transactions the mempool no longer holds (`held`:
    /// their `raw_tx_hash`es) go: a record lives exactly as long as its
    /// transaction is held. A full table used to evict the longest-pending
    /// live record, and an idle bound forgot a held one across a long gap
    /// between its loans; either restarted its TTL and its members.
    fn make_room(&self, incoming: usize, held: impl FnOnce() -> HashSet<String>) {
        let full = self
            .forwarded
            .lock()
            .is_ok_and(|f| f.by_tx.len().saturating_add(incoming) > MAX_FORWARD_RECORDS);
        if full {
            // Read before this table is locked: passes run at once, and none
            // may hold the two locks together.
            let held = held();
            if let Ok(mut f) = self.forwarded.lock() {
                f.by_tx.retain(|key, _| held.contains(key));
            }
        }
    }

    fn forget(&self, txs: &[String]) {
        if let Ok(mut f) = self.forwarded.lock() {
            for tx in txs {
                f.by_tx.remove(&storage::StateDB::raw_tx_hash(tx));
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// B173 witness support: the transactions `check_from_outside` checked
    /// (signatures included) on this thread.
    pub(crate) static OUTSIDE_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The stateless checks of transactions from outside (a forwarded batch, an
/// RPC call), in order. B31: run before the mempool lock, which the
/// consensus ticker needs; only what passes is admitted under it
/// (`add_checked`), without being verified again. B173: a copy of a
/// transaction the mempool has seen, or of one earlier in `txs`, is refused
/// before any signature is checked: each copy was checked in full (64
/// copies of one signed transaction, 64 checks, refused only afterwards).
pub fn check_from_outside(
    mempool: &Mutex<Mempool>,
    txs: Vec<String>,
) -> Vec<Result<(String, executor::admission::CheckedTx), String>> {
    let keys: Vec<Option<String>> = txs.iter().map(|tx| Mempool::dedup_key(tx)).collect();
    let held: Vec<bool> = match mempool.lock() {
        Ok(mp) => keys
            .iter()
            .map(|key| key.as_deref().is_some_and(|key| mp.has_seen(key)))
            .collect(),
        Err(_) => vec![false; keys.len()],
    };
    let mut first = HashSet::new();
    txs.into_iter()
        .zip(keys)
        .zip(held)
        .map(|((tx, key), held)| {
            if held || key.as_ref().is_some_and(|key| !first.insert(key.clone())) {
                return Err(format!(
                    "Duplicate transaction: {}",
                    key.unwrap_or_default()
                ));
            }
            #[cfg(test)]
            OUTSIDE_CHECKS.with(|n| n.set(n.get() + 1));
            Mempool::check_admissible(&tx).map(|checked| (tx, checked))
        })
        .collect()
}

/// One transaction's verdict from the member's mempool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accepted(String),
    Refused(String),
    /// B201: refused for now (`mempool::Refusal::for_now`): kept, asked
    /// again, never counted toward a drop.
    Later(String),
}

/// Member side: the batch's verdicts from this node's mempool. `None`
/// (refused whole) for a malformed batch, an empty one, or one longer than
/// `FORWARD_BATCH`.
pub fn serve_tx_submit(mempool: &Mutex<Mempool>, wire: &str) -> Option<String> {
    let txs: Vec<String> = serde_json::from_str(wire.strip_prefix(TX_SUBMIT)?).ok()?;
    if txs.is_empty() || txs.len() > FORWARD_BATCH {
        return None;
    }
    let checked = check_from_outside(mempool, txs);
    // B239: the mempool's lock taken for one transaction at a time, so a
    // proposal waiting on it waits for one admission, not a batch of 64;
    // B259: and each admission lets a waiting consensus thread go first.
    let mut verdicts: Vec<Verdict> = Vec::with_capacity(checked.len());
    for tx in checked {
        let admitted = match tx {
            Err(e) => Err(mempool::Refusal::from(e)),
            Ok((tx, checked)) => {
                mempool::yield_to_consensus();
                mempool.lock().ok()?.add_checked(tx, checked)
            }
        };
        verdicts.push(match admitted {
            Ok(hash) => Verdict::Accepted(hash),
            Err(refusal) if refusal.for_now => Verdict::Later(refusal.reason),
            Err(refusal) => Verdict::Refused(refusal.reason),
        });
    }
    Some(format!(
        "{TX_RESULT}{}",
        serde_json::to_string(&verdicts).ok()?
    ))
}

/// B172/B183: the fewest bytes a `TX_SUBMIT` batch carries per signature a
/// member checks. The smallest transaction `check_admissible` reads up to its
/// signatures (a one-byte chain id, an empty module bundle as the payload,
/// the sequence number left out, a 32-byte key and a 64-byte signature in
/// hex, the gas limit just covering its bytes) is 413 bytes as a batch
/// element (its quotes escaped, a comma) for one check; sponsored, with the
/// paymaster's key and signature, 653 for two, 326.5 a check (the witness
/// builds both). 324 is the figure with a one-digit gas limit (a choice, on
/// the safe side). B183: the bound was per transaction, so a sponsored one
/// bought its second check free. Real ones are longer (the chain id), so a
/// submit priced at its length pays at least a token a check
/// (`sessions::SubmitBudget`).
pub const MIN_WIRE_PER_CHECK: usize = 324;

/// B133: what a busy node answers `wire` with: `TX_BUSY` for a batch (it
/// was dropped unanswered, which the forwarder could not tell from a
/// silent member), a snapshot part's busy answer, nothing for the rest.
pub fn busy_reply(wire: &str) -> Option<String> {
    if wire.starts_with(TX_SUBMIT) {
        Some(TX_BUSY.to_string())
    } else {
        chain_sync::state_sync::busy_reply(wire)
    }
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
    forward_once_at(mempool, client, state, wall_secs()).await
}

/// `forward_once` at `now_secs` (the clock loans and the TTL are kept in).
pub async fn forward_once_at(
    mempool: &Arc<Mutex<Mempool>>,
    client: &network::SessionClient,
    state: &ForwardState,
    now_secs: u64,
) -> usize {
    let loaned: Vec<String> = match mempool.lock() {
        Ok(mut mp) => {
            mp.requeue_stale_uncapped_at(FORWARD_RETRY_SECS, now_secs);
            mp.get_pending_transactions_at(FORWARD_BATCH * 4, now_secs)
        }
        Err(_) => return 0,
    };
    if loaned.is_empty() {
        return 0;
    }
    state.make_room(loaned.len(), || match mempool.lock() {
        Ok(mp) => mp.held_raw_hashes(),
        Err(_) => HashSet::new(),
    });
    // B133: what no member took into a block within the TTL leaves.
    let (expired, loaned): (Vec<String>, Vec<String>) = loaned.into_iter().partition(|tx| {
        now_secs.saturating_sub(state.record(tx, now_secs).first_secs) >= FORWARD_TTL_SECS
    });
    if !expired.is_empty() {
        if let Ok(mut mp) = mempool.lock() {
            mp.mark_executed(&expired);
        }
        state.forget(&expired);
    }
    let sessions = client.sessions();
    // Group by the order of members each transaction is sent to, keeping
    // order.
    let mut groups: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    for tx in loaned {
        // B53/B134: the sender's members, those that have not answered for
        // this transaction first, then (B232) those that refused it for now,
        // then those that took it (it was loaned again: no block settled
        // it), then those that refused it. B247: one that refused it for
        // now within the loan period is not asked again yet.
        let record = state.record(&tx, now_secs);
        let recent = !record.later.is_empty()
            && now_secs.saturating_sub(record.later_secs) < FORWARD_RETRY_SECS;
        let mut order = members_for(&sender_of(&tx), &sessions);
        order.retain(|peer| !(recent && state.names(&record.later, peer)));
        if order.is_empty() && recent {
            // Refused for now by every member it can be asked of: it stays
            // on loan, asked again once the loan is stale.
            continue;
        }
        order.sort_by_key(|peer| {
            if state.names(&record.refused, peer) {
                3
            } else if state.names(&record.accepted, peer) {
                2
            } else if state.names(&record.later, peer) {
                1
            } else {
                0
            }
        });
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
                accepted +=
                    send_batch(mempool, client, state, member_of, &order, batch, now_secs).await;
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
    now_secs: u64,
) -> usize {
    let mut pending = batch;
    let mut dropped = Vec::new();
    let mut accepted = 0;
    // B232: refused for now by a member this pass; B247: and how many of
    // the order answered each transaction this pass.
    let mut later: HashSet<String> = HashSet::new();
    let mut answered: HashMap<String, usize> = HashMap::new();
    // A committee whose stakes this node does not know counts each member
    // as one.
    let total = match state.total_stake() {
        0 => member_of.len() as u128,
        stake => stake,
    };
    let stake_of = |peer: &String| match state.total_stake() {
        0 => 1,
        _ => member_of.get(peer).map_or(0, |m| state.stake_of(m)),
    };
    // B247: the stake of the members of this order that `set` names.
    let stake_in = |set: &Members| -> u128 {
        order
            .iter()
            .filter(|p| state.names(set, p))
            .map(stake_of)
            .sum()
    };
    for peer in order {
        if pending.is_empty() {
            break;
        }
        // B133: a member that let a timeout run is skipped for a while; one
        // with an ask in flight is busy for this batch; B156: one that said
        // it was busy rests a second.
        if state.silent(peer, Instant::now())
            || state.resting(peer, now_secs)
            || !state.begin_ask(peer)
        {
            continue;
        }
        let Ok(wire) = serde_json::to_string(&pending).map(|json| format!("{TX_SUBMIT}{json}"))
        else {
            state.end_ask(peer);
            break;
        };
        let reply = client.ask_timed(peer, &wire, state.timeout).await;
        state.end_ask(peer);
        let reply = match reply {
            Ok(reply) => reply,
            Err(network::AskError::Timeout) => {
                state.strike(peer, Instant::now());
                continue;
            }
            // Refused at once (busy, gone): not a strike, not an answer.
            Err(network::AskError::Failed(_)) => continue,
        };
        if reply.starts_with(TX_BUSY) {
            state.rest(peer, now_secs);
            continue;
        }
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
                Verdict::Accepted(_) => {
                    let (took, refused) = state.note(&tx, peer, true);
                    // B154: taken before and not settled (it came back):
                    // on to the members not tried yet, until those that
                    // took it hold more than a third of the stake, so an
                    // honest one holds it. One member a re-forward let a run
                    // of Byzantine members, adjacent in the rotation, hold
                    // it past its TTL.
                    let stake = stake_in(&took);
                    let after = order
                        .iter()
                        .position(|p| p == peer)
                        .map_or(&order[..0], |i| &order[i + 1..]);
                    let untried = after
                        .iter()
                        .any(|p| !state.names(&took, p) && !state.names(&refused, p));
                    if took.len() > 1 && stake * 3 <= total && untried {
                        *answered.entry(tx.clone()).or_default() += 1;
                        next.push(tx);
                    } else {
                        accepted += 1;
                    }
                }
                // B201: kept to its TTL whoever says so (the fee, the
                // pool's room, a nonce gap, the payer's balance). B232: and
                // asked of the next member in this pass: B216 left it on
                // loan at the first, so a member first in a sender's order
                // that always said so censored its senders for free. Once
                // the pass is done it stays on loan (B216), asked again when
                // the loan is stale, not every pass.
                Verdict::Later(_) => {
                    state.note_later(&tx, peer, now_secs);
                    later.insert(tx.clone());
                    *answered.entry(tx.clone()).or_default() += 1;
                    next.push(tx);
                }
                Verdict::Refused(_) => {
                    let (_, refused) = state.note(&tx, peer, false);
                    let stake = stake_in(&refused);
                    if refused.len() >= REFUSALS_TO_DROP && stake * 3 > total {
                        dropped.push(tx);
                    } else {
                        *answered.entry(tx.clone()).or_default() += 1;
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
        // Not settled: back to the front of the queue, in order. B133: no
        // pass counts against a transaction (busy or silent members, a
        // refusing minority); what bounds it is its TTL. B216/B232: one a
        // member refused for now this pass stays on loan, asked again once
        // the loan is stale; B247: only if every member of its order
        // answered (one member's refusal for now, the others busy or
        // silent, held it 30 s; back in the queue, it is asked of those
        // that did not answer, not again of those that refused it for now).
        let reversed: Vec<String> = pending
            .into_iter()
            .rev()
            .filter(|tx| {
                !(later.contains(tx) && answered.get(tx).copied().unwrap_or(0) >= order.len())
            })
            .collect();
        mp.return_unshipped(&reversed);
    }
    state.forget(&dropped);
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
    let state = Arc::new(ForwardState::default());
    let passes = Arc::new(tokio::sync::Semaphore::new(PASSES_AT_ONCE));
    while !shutdown.load(Ordering::SeqCst) {
        tick.tick().await;
        if in_committee.load(Ordering::SeqCst) {
            continue;
        }
        if let Ok(b) = book.read() {
            state.set_stakes(b.stakes());
        }
        // B151: each pass runs apart, so a slow member holds no other.
        let Ok(permit) = Arc::clone(&passes).try_acquire_owned() else {
            continue;
        };
        let (mempool, client, state) = (Arc::clone(&mempool), client.clone(), Arc::clone(&state));
        tokio::spawn(async move {
            forward_once(&mempool, &client, &state).await;
            drop(permit);
        });
    }
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
