use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use storage::StateDB;

/// B1 (best-effort): early-reject a `0x1::staking::join_validator_set` whose BLS
/// proof-of-possession does not verify, before it enters the mempool. The
/// executor pre-dispatch gate is authoritative; this mirrors it for early reject.
/// `join_validator_set(account: &signer, stake_amount: u128, public_key,
/// bls_public_key, bls_pop)` -> args[2]=public_key, args[3]=bls_public_key,
/// args[4]=bls_pop.
fn verify_join_validator_pop_mempool(
    call: &vm_move::EntryFunctionCall,
    tx_public_key_hex: &str,
) -> Result<(), String> {
    // 0x1 system address renders as 31 zero bytes + 01 in hex (no direct
    // move_core_types dep in mempool, so compare via the canonical Display form).
    let is_system = format!("{}", call.module.address())
        .trim_start_matches("0x")
        .trim_start_matches('0')
        == "1";
    if !is_system
        || call.module.name().as_str() != "staking"
        || call.function != "join_validator_set"
    {
        return Ok(());
    }
    if call.args.len() < 5 {
        return Err(format!(
            "join_validator_set: expected 5 args, got {}",
            call.args.len()
        ));
    }
    let public_key: Vec<u8> = bcs::from_bytes(&call.args[2])
        .map_err(|e| format!("join_validator_set: malformed public_key arg: {}", e))?;
    let bls_public_key: Vec<u8> = bcs::from_bytes(&call.args[3])
        .map_err(|e| format!("join_validator_set: malformed bls_public_key arg: {}", e))?;
    let bls_pop: Vec<u8> = bcs::from_bytes(&call.args[4])
        .map_err(|e| format!("join_validator_set: malformed bls_pop arg: {}", e))?;
    let tx_public_key = hex::decode(tx_public_key_hex.trim_start_matches("0x"))
        .map_err(|e| format!("join_validator_set: malformed tx public_key hex: {}", e))?;
    if public_key.len() != 32 {
        return Err(format!(
            "join_validator_set: public_key must be 32 bytes, got {}",
            public_key.len()
        ));
    }
    if public_key != tx_public_key {
        return Err("join_validator_set: public_key arg must equal tx.public_key".into());
    }
    if bls_public_key.len() != 48 {
        return Err(format!(
            "join_validator_set: bls_public_key must be 48 bytes, got {}",
            bls_public_key.len()
        ));
    }
    if bls_pop.len() != 96 {
        return Err(format!(
            "join_validator_set: bls_pop must be 96 bytes, got {}",
            bls_pop.len()
        ));
    }
    match crypto::bls::BLSEngine::consensus().verify_possession(&bls_public_key, &bls_pop) {
        Ok(true) => Ok(()),
        Ok(false) => Err("join_validator_set: BLS proof-of-possession failed verification".into()),
        Err(e) => Err(format!(
            "join_validator_set: BLS PoP verification error: {:?}",
            e
        )),
    }
}

const MAX_PENDING_TXS: usize = 5000;
/// How many times a loaned transaction may return to the queue before it is
/// dropped for good (orphaned payloads need one; a permanently failing tx must
/// not loop forever).
const MAX_REQUEUE_ATTEMPTS: u8 = 3;
const MAX_SEEN_TXS: usize = 50000;

/// Seconds since the Unix epoch, for callers without a clock of their own.
fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub struct Mempool {
    pending_txs: VecDeque<String>,
    seen_txs: HashSet<String>,       // Deduplication
    seen_order: VecDeque<String>,    // Bounded cache tracking
    pending_nonces: HashSet<String>, // sender:sequence_number in the pending queue
    /// LOANED, NOT GONE (orphan-loss fix): transactions handed to consensus by
    /// `get_pending_transactions` move HERE instead of vanishing. They leave for
    /// good only when `mark_executed` reports them executed in a committed
    /// block; anything still here after `requeue_stale`'s age limit goes back to
    /// `pending_txs`. Before this, a vertex that never committed (a node
    /// briefly behind the network orphans its own vertex) silently destroyed
    /// its whole payload — the sender's nonce sequence then had a permanent
    /// hole, every later transaction died with "Invalid Sequence", and the
    /// account was wedged forever. Keyed by the RAW transaction string; value is
    /// (loaned at, in the caller's clock's seconds; attempts). The clock is the
    /// caller's (consensus passes its injectable `now_secs`), so a simulated
    /// cluster never re-queues by the wall clock (BUG_LEDGER B9).
    inflight: std::collections::HashMap<String, (u64, u8)>,
    /// RE-AUDIT MEDIUM (perf): parsed (sender, sequence_number, gas_price) per
    /// raw tx, filled once at admission so selection never re-parses every
    /// pending transaction under the mempool lock on every tick.
    meta: std::collections::HashMap<String, (String, u64, u128)>,
    /// Attempt counter carried from `requeue_stale` back into the next pull.
    requeue_attempts: std::collections::HashMap<String, u8>,
    /// Optional storage handle for the admission balance gate (the payer's
    /// committed AIN). Production callers pass it via
    /// [`Mempool::with_storage`]; without it the gate is skipped.
    storage: Option<Arc<StateDB>>,
}

impl Mempool {
    /// Construct a mempool without storage: no balance gate. For unit tests.
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            inflight: std::collections::HashMap::new(),
            meta: std::collections::HashMap::new(),
            requeue_attempts: std::collections::HashMap::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
            storage: None,
        }
    }

    /// Construct a mempool with storage access: the constructor production
    /// node code uses, so the balance gate runs.
    pub fn with_storage(storage: Arc<StateDB>) -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            inflight: std::collections::HashMap::new(),
            meta: std::collections::HashMap::new(),
            requeue_attempts: std::collections::HashMap::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
            storage: Some(storage),
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    /// Phase 5B.11 / PWN-007 PROPER fix: canonical TX identity.
    ///
    /// The dedup key MUST be derived from the same canonical form the
    /// signature is bound to (`chain_id:sender:payload:seq`), NOT from
    /// raw JSON bytes. Otherwise an attacker can replay a signed TX by
    /// reordering JSON keys or tweaking whitespace — different raw bytes,
    /// same signature, same semantic intent — and bypass `seen_txs`.
    ///
    /// Hashing canonical fields at this layer also closes ALL upstream
    /// entry points in one place: api_local.rs, api.rs, P2P TX inbound,
    /// and any future RPC method. None of them can submit a "different"
    /// version of a TX that has already been seen.
    fn canonical_tx_hash(tx: &executor::Transaction) -> String {
        // F4: dedup identity must match the signed canonical form, which now
        // also binds gas_limit, gas_price, and input_objects.
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            tx.chain_id,
            tx.sender,
            tx.payload,
            tx.sequence_number,
            tx.gas_limit,
            tx.gas_price,
            tx.input_objects.join(",")
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn add_transaction(&mut self, tx: String) -> Result<String, String> {
        // === M-04: SIZE GUARD FIRST (cheapest reject path) ===
        if tx.len() > executor::admission::MAX_TX_BYTES {
            return Err(format!(
                "Transaction too large ({} bytes). limit {}KB.",
                tx.len(),
                executor::admission::MAX_TX_BYTES / 1024
            ));
        }

        // Phase 5B.11 / PWN-004 + PWN-007: reject a replay, byte-identical or
        // re-encoded, before any signature work. The dedup key is the canonical
        // form the signature binds, so a re-encoding of the JSON is the same tx.
        let parsed_tx = serde_json::from_str::<executor::Transaction>(&tx)
            .map_err(|_| "Invalid JSON format".to_string())?;
        let tx_hash = Self::canonical_tx_hash(&parsed_tx);
        if self.seen_txs.contains(&tx_hash) {
            return Err(format!("Duplicate transaction: {}", tx_hash));
        }

        // B8/B12/B13: the stateless half of validity (chain id from
        // `sys:chain_id`, gas bounds, payload kind with scripts disabled, ZK
        // proof, the sender's signature in Ed25519 or ML-DSA-65, and the
        // paymaster's) is the one predicate vertex ingress and the executor
        // run too. `payer` is whoever pays the gas.
        let checked = executor::admission::check_stateless(&tx, &blockchain::chain_id())?;

        // B1 (best-effort early reject): a join_validator_set call's BLS
        // proof-of-possession is checked here so a rogue-key join never enters
        // the mempool. The executor's pre-dispatch gate is the authoritative one.
        let payload_bytes = hex::decode(parsed_tx.payload.trim_start_matches("0x"))
            .map_err(|_| "Invalid payload hex: expected BCS TransactionPayload".to_string())?;
        if let Ok(vm_move::TransactionPayload::EntryFunction(call)) =
            bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes)
        {
            verify_join_validator_pop_mempool(&call, &parsed_tx.public_key)?;
        }

        // Economic gate, after authentication so a bad signature is reported as
        // such. The executor reserves the full gas_limit * gas_price from the
        // payer up front, so a payer who cannot cover it only wastes block
        // space. It fails CLOSED (RE-AUDIT HIGH): a payer with no CoinStore can
        // never pay gas, and admitting it would buy an attacker free block
        // space with unlimited fresh keypairs. The paymaster is held to it too
        // (B13): its signature is verified now, so its balance is the one that
        // pays. Without storage (unit tests) the gate is skipped.
        if let Some(storage) = &self.storage {
            // B15: below the committed base fee the executor would refuse it.
            let base_fee = executor::committed_base_fee(storage);
            if parsed_tx.gas_price < base_fee {
                return Err(format!(
                    "Gas price {} is below the base fee {}",
                    parsed_tx.gas_price, base_fee
                ));
            }
            if let Some(gas_cost) = (parsed_tx.gas_limit as u128).checked_mul(parsed_tx.gas_price) {
                match executor::committed_ain_balance(storage, &checked.payer) {
                    Some(balance) if balance < gas_cost => {
                        return Err(format!(
                            "Insufficient balance for gas: have {}, need {} (gas_limit {} × gas_price {})",
                            balance, gas_cost, parsed_tx.gas_limit, parsed_tx.gas_price
                        ));
                    }
                    Some(_) => {}
                    None => {
                        return Err(format!(
                            "Gas payer {} has no AIN balance to pay gas (no CoinStore)",
                            checked.payer
                        ));
                    }
                }
            }
        }

        // RE-AUDIT HIGH: the cap must count LOANED transactions too, or a pull
        // simply moves 500 into `inflight` and frees 500 slots for the attacker.
        if self.pending_txs.len() + self.inflight.len() >= MAX_PENDING_TXS {
            return Err(format!(
                "Mempool full ({}+{} inflight / {})",
                self.pending_txs.len(),
                self.inflight.len(),
                MAX_PENDING_TXS
            ));
        }

        let nonce_key = format!("{}:{}", parsed_tx.sender, parsed_tx.sequence_number);
        if self.pending_nonces.contains(&nonce_key) {
            return Err(format!(
                "Duplicate pending nonce for sender {} sequence {}",
                parsed_tx.sender, parsed_tx.sequence_number
            ));
        }

        // Bounded LRU-style eviction
        if self.seen_txs.len() >= MAX_SEEN_TXS {
            if let Some(old_tx) = self.seen_order.pop_front() {
                self.seen_txs.remove(&old_tx);
            }
        }

        self.seen_txs.insert(tx_hash.clone());
        self.seen_order.push_back(tx_hash.clone());
        self.pending_nonces.insert(nonce_key);
        self.meta.insert(
            tx.clone(),
            (parsed_tx.sender.clone(), parsed_tx.sequence_number, parsed_tx.gas_price),
        );
        self.pending_txs.push_back(tx.clone());

        println!(
            "📥 Added transaction to mempool: {}",
            self.pending_txs.len()
        );
        Ok(tx_hash)
    }

    /// Whether any transaction still waiting satisfies `matches`: queued, or
    /// loaned to a vertex that has not committed yet. Read-only — unlike
    /// `get_pending_transactions`, it never loans anything out.
    ///
    /// The RPC answers "pending" with this instead of "is the mempool
    /// non-empty", which reported every unknown hash as pending whenever
    /// anyone else had a transaction waiting.
    pub fn any_pending(&self, matches: impl Fn(&str) -> bool) -> bool {
        self.pending_txs.iter().any(|tx| matches(tx)) || self.inflight.keys().any(|tx| matches(tx))
    }

    /// `get_pending_transactions_at` with the wall clock.
    pub fn get_pending_transactions(&mut self, limit: usize) -> Vec<String> {
        self.get_pending_transactions_at(limit, wall_secs())
    }

    /// Select up to `limit` transactions and loan them, stamped `now_secs`.
    pub fn get_pending_transactions_at(&mut self, limit: usize, now_secs: u64) -> Vec<String> {
        if limit == 0 || self.pending_txs.is_empty() {
            return Vec::new();
        }

        // SEC-#27 (fee market): select up to `limit` txs preferring higher
        // gas_price, while preserving each sender's nonce (sequence_number)
        // order — a sender's seq N MUST be chosen before seq N+1 or the executor
        // rejects the gap. This is the geth-style "best head per sender" merge:
        // repeatedly take the highest-gas_price *front* tx (lowest unselected
        // nonce) across senders. Selection order is deterministic (gas_price desc,
        // then original FIFO index) — the leader's block ordering only needs to be
        // self-consistent; every node executes the block in the order it ships.
        use std::collections::BTreeMap;

        let raws: Vec<String> = self.pending_txs.iter().cloned().collect();

        // sender -> [(sequence_number, gas_price, original_index)], nonce-ordered.
        let mut by_sender: BTreeMap<String, Vec<(u64, u128, usize)>> = BTreeMap::new();
        for (idx, raw) in raws.iter().enumerate() {
            // Metadata was parsed once at admission (see `meta`); a raw without
            // it (should not happen) is simply never selected rather than dropped.
            if let Some((sender, seq, gp)) = self.meta.get(raw) {
                by_sender
                    .entry(sender.clone())
                    .or_default()
                    .push((*seq, *gp, idx));
            }
        }
        for q in by_sender.values_mut() {
            q.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
        }

        // Per-sender cursor into its nonce-ordered queue.
        let mut cursor: BTreeMap<String, usize> =
            by_sender.keys().map(|s| (s.clone(), 0usize)).collect();

        let mut selected: Vec<usize> = Vec::with_capacity(limit.min(raws.len()));
        while selected.len() < limit {
            // Highest-gas_price eligible head; tie-break by FIFO index.
            let mut best: Option<(u128, usize, String)> = None;
            for (sender, q) in by_sender.iter() {
                let c = cursor[sender];
                if c < q.len() {
                    let (_, gp, idx) = q[c];
                    let take = match &best {
                        None => true,
                        Some((bgp, bidx, _)) => gp > *bgp || (gp == *bgp && idx < *bidx),
                    };
                    if take {
                        best = Some((gp, idx, sender.clone()));
                    }
                }
            }
            match best {
                Some((_, idx, sender)) => {
                    selected.push(idx);
                    // advance the chosen sender's cursor
                    if let Some(c) = cursor.get_mut(&sender) {
                        *c += 1;
                    }
                }
                None => break, // all sender queues exhausted
            }
        }

        let selected_set: HashSet<usize> = selected.iter().copied().collect();
        let result: Vec<String> = selected.iter().map(|&i| raws[i].clone()).collect();
        let now = now_secs;
        for raw in &result {
            self.remove_pending_nonce(raw);
            // Loaned, not gone: see the `inflight` field doc. Attempts carry
            // over across re-queues so a permanently failing tx is bounded.
            let attempts = self.requeue_attempts.remove(raw).unwrap_or(0);
            self.inflight.insert(raw.clone(), (now, attempts));
        }
        // Keep unselected txs in their original FIFO order for the next round.
        self.pending_txs = raws
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !selected_set.contains(i))
            .map(|(_, r)| r)
            .collect();

        result
    }

    pub fn is_empty(&self) -> bool {
        self.pending_txs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending_txs.len()
    }

    pub fn get_all_pending(&self) -> &VecDeque<String> {
        &self.pending_txs
    }

    /// Orphan-loss fix: consensus reports the raw transactions that actually
    /// EXECUTED in a committed block; only those leave the loan ledger for good.
    /// Deferred/failed ones stay inflight and come back via `requeue_stale`.
    pub fn mark_executed(&mut self, raws: &[String]) {
        if raws.is_empty() {
            return;
        }
        let done: std::collections::HashSet<&str> = raws.iter().map(|s| s.as_str()).collect();
        for raw in raws {
            self.inflight.remove(raw);
            // Also clear the nonce guard: an executed tx must not keep blocking
            // a resubmission of the same sender:sequence.
            self.remove_pending_nonce(raw);
            self.meta.remove(raw);
            self.requeue_attempts.remove(raw);
        }
        // An executed tx can also be sitting in pending_txs (returned by
        // return_unshipped or requeue_stale, then executed via another
        // validator's vertex). Without meta it can never be selected again, so
        // leaving it there pins it forever and it counts against MAX_PENDING_TXS.
        self.pending_txs.retain(|r| !done.contains(r.as_str()));
    }

    /// Return loaned transactions that never executed within `max_age` to the
    /// pending queue. Heals both failure shapes the live cluster hit: a vertex
    /// that never committed (orphaned payload), and a transaction that reached a
    /// block ahead of its nonce and was refused by the executor. Re-queued
    /// entries re-register their `sender:sequence` guard so a duplicate
    /// submission is still refused at admission; `seen_txs` is intentionally
    /// left alone (the tx has genuinely been seen — resubmission stays deduped).
    /// Returns how many were re-queued.
    /// Return transactions that were LOANED by `get_pending_transactions` but
    /// never shipped in a vertex (the block-builder trimmed them to fit the
    /// vertex byte budget). They are put back at the FRONT of the queue in
    /// their original order and their nonce guard is re-registered.
    ///
    /// Does not INCREMENT `requeue_attempts` (a byte-budget trim is not a failed
    /// execution) but does PRESERVE any count carried in the loan: the loan
    /// stashes the counter inside the inflight tuple, so simply dropping it
    /// would reset a repeatedly-failing transaction's history to zero and defeat
    /// MAX_REQUEUE_ATTEMPTS.
    ///
    /// `raws` arrives in reverse-payload order (the trimmer pops from the tail),
    /// so pushing to the front in THAT order restores the original sequence.
    pub fn return_unshipped(&mut self, raws: &[String]) {
        for raw in raws.iter() {
            let Some((_, attempts)) = self.inflight.remove(raw) else {
                // Not on loan (already executed or re-queued elsewhere): ignore.
                continue;
            };
            if attempts > 0 {
                self.requeue_attempts.insert(raw.clone(), attempts);
            }
            // A raw with no live `meta` is unselectable: get_pending_transactions
            // builds its per-sender queues only from raws that have one, and
            // mark_executed removes meta when the tx lands via another
            // validator's vertex. Re-queuing it would pin it in pending_txs
            // forever, so drop it instead.
            let Some((sender, seq, _)) = self.meta.get(raw).cloned() else {
                self.requeue_attempts.remove(raw);
                continue;
            };
            self.pending_nonces.insert(format!("{}:{}", sender, seq));
            self.pending_txs.push_front(raw.clone());
        }
    }

    /// `requeue_stale_at` with the wall clock.
    pub fn requeue_stale(&mut self, max_age: std::time::Duration) -> usize {
        self.requeue_stale_at(max_age.as_secs(), wall_secs())
    }

    /// Re-queue loans at least `max_age_secs` old at `now_secs`, in the same
    /// clock the loans were stamped with.
    pub fn requeue_stale_at(&mut self, max_age_secs: u64, now_secs: u64) -> usize {
        let stale: Vec<(String, u8)> = self
            .inflight
            .iter()
            .filter(|(_, (at, _))| now_secs.saturating_sub(*at) >= max_age_secs)
            .map(|(raw, (_, n))| (raw.clone(), *n))
            .collect();
        let mut requeued = 0usize;
        let mut dropped = 0usize;
        for (raw, attempts) in &stale {
            self.inflight.remove(raw);
            // RE-AUDIT HIGH: bounded. A tx that keeps failing (bad nonce forever,
            // unpayable gas) must not become an immortal 30s loop that burns
            // every validator's CPU and block space.
            if *attempts + 1 >= MAX_REQUEUE_ATTEMPTS {
                self.meta.remove(raw);
                self.requeue_attempts.remove(raw);
                dropped += 1;
                continue;
            }
            self.requeue_attempts.insert(raw.clone(), attempts + 1);
            if let Some((sender, seq, _)) = self.meta.get(raw) {
                self.pending_nonces.insert(format!("{}:{}", sender, seq));
            }
            self.pending_txs.push_back(raw.clone());
            requeued += 1;
        }
        if requeued > 0 || dropped > 0 {
            println!(
                "♻️  Mempool re-queued {} stale inflight tx(s), dropped {} after {} attempts",
                requeued, dropped, MAX_REQUEUE_ATTEMPTS
            );
        }
        requeued
    }

    fn remove_pending_nonce(&mut self, tx: &str) {
        if let Ok(parsed_tx) = serde_json::from_str::<executor::Transaction>(tx) {
            self.pending_nonces.remove(&format!(
                "{}:{}",
                parsed_tx.sender, parsed_tx.sequence_number
            ));
        }
    }
}

// Fungsi main bisa dihapus jika crate ini adalah library
// fn main() {
//     println!("Hello, world!");
// }
#[cfg(test)]
mod tests;
