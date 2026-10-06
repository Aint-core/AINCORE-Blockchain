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

/// B16: how far above the sender's committed sequence number a transaction
/// may be admitted, so at most this many of one sender's transactions wait.
/// A choice: Aptos's mempool holds at most 100 per account
/// (`MempoolConfig::capacity_per_user`).
pub const MAX_NONCE_AHEAD: u64 = 100;

/// B98: how long a transaction may wait parked (behind a nonce gap, or under
/// the base fee) before it leaves the pool. A choice: Aptos's mempool drops a
/// transaction after `system_transaction_timeout_secs` (600).
pub const PARKED_TTL_SECS: u64 = 600;

/// B98: a waiting transaction may be replaced by one with the same sender
/// and sequence number whose price is at least this many percent higher
/// (geth's txpool `PriceBump`, 10).
pub const REPLACE_PRICE_BUMP_PERCENT: u128 = 10;

/// B94: what a block would do with a ready transaction.
enum Payable {
    /// Charged: offer it.
    Yes,
    /// Skipped for good (its pre-charge does not fit): it leaves the pool.
    Never,
    /// Its payer cannot cover it now: its sender's run stops here.
    NotNow,
}

/// What admission parsed out of a waiting transaction, kept so selection never
/// re-parses it and the payer's waiting total is a sum, not a scan of JSON.
#[derive(Debug, Clone)]
struct TxMeta {
    sender: String,
    seq: u64,
    gas_price: u128,
    /// Whoever pays its gas: the paymaster's address or the sender (B13).
    payer: String,
    /// The most it can charge: `gas_limit * gas_price`.
    cost: u128,
    /// B54: `StateDB::raw_tx_hash` of the raw string, the key RPC lookups
    /// use, hashed once here and never again under the lock.
    raw_hash: String,
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
    /// RE-AUDIT MEDIUM (perf): parsed metadata per raw tx, filled once at
    /// admission so selection never re-parses every pending transaction under
    /// the mempool lock on every tick. Queued and loaned transactions both
    /// have an entry until they execute or are dropped.
    meta: std::collections::HashMap<String, TxMeta>,
    /// Attempt counter carried from `requeue_stale` back into the next pull.
    requeue_attempts: std::collections::HashMap<String, u8>,
    /// Optional storage handle for the admission balance gate (the payer's
    /// committed AIN). Production callers pass it via
    /// [`Mempool::with_storage`]; without it the gate is skipped.
    storage: Option<Arc<StateDB>>,
    /// B98: each sender's committed next sequence number, read once per
    /// committed height (`seq_cache_at`), not once per sender per pass under
    /// the mempool and consensus locks.
    seq_cache: std::collections::HashMap<String, u64>,
    seq_cache_at: Option<String>,
    /// B98: when each parked transaction was first seen parked (the caller's
    /// clock); past `PARKED_TTL_SECS` it leaves.
    parked_since: std::collections::HashMap<String, u64>,
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
            seq_cache: std::collections::HashMap::new(),
            seq_cache_at: None,
            parked_since: std::collections::HashMap::new(),
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
            seq_cache: std::collections::HashMap::new(),
            seq_cache_at: None,
            parked_since: std::collections::HashMap::new(),
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
        // also binds gas_limit, gas_price, and input_objects (B73: and the
        // paymaster).
        let canonical = executor::admission::signing_message(tx);
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

        let checked = Self::check_admissible(&tx)?;
        self.add_checked(tx, checked)
    }

    /// The stateless half of admission, which needs no mempool state: run it
    /// before taking the mempool's lock (B31), then `add_checked`.
    ///
    /// B8/B12/B13: the stateless half of validity (chain id from
    /// `sys:chain_id`, gas bounds, payload kind with scripts disabled, ZK
    /// proof, the sender's signature in Ed25519 or ML-DSA-65, and the
    /// paymaster's) is the one predicate vertex ingress and the executor run
    /// too. `payer` is whoever pays the gas. B1 (best-effort early reject): a
    /// join_validator_set call's BLS proof-of-possession is checked here so a
    /// rogue-key join never enters the mempool; the executor's pre-dispatch
    /// gate is the authoritative one.
    ///
    /// B73: what it checks is `tx` in its canonical encoding, the one the
    /// mempool keeps (`add_checked`).
    pub fn check_admissible(tx: &str) -> Result<executor::admission::CheckedTx, String> {
        let canonical = executor::admission::canonicalize(tx)?;
        let checked = executor::admission::check_stateless(&canonical, &blockchain::chain_id())?;
        let payload_bytes = hex::decode(checked.tx.payload.trim_start_matches("0x"))
            .map_err(|_| "Invalid payload hex: expected BCS TransactionPayload".to_string())?;
        if let Ok(vm_move::TransactionPayload::EntryFunction(call)) =
            bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes)
        {
            verify_join_validator_pop_mempool(&call, &checked.tx.public_key)?;
        }
        Ok(checked)
    }

    /// Admit `tx`, whose `check_admissible` already passed as `checked`: the
    /// replay, economic and capacity gates, which read the mempool and the
    /// committed state. Nothing here verifies a signature again (B31: a
    /// batch of validly signed transactions from unfunded keys used to be
    /// verified a second time under the lock).
    pub fn add_checked(
        &mut self,
        _arrived_as: String,
        checked: executor::admission::CheckedTx,
    ) -> Result<String, String> {
        // B73: kept, offered and forwarded in its canonical encoding only,
        // whatever encoding it arrived in (vertex ingress takes no other).
        let tx = executor::admission::canonical_json(&checked.tx);
        let parsed_tx = &checked.tx;
        let tx_hash = Self::canonical_tx_hash(parsed_tx);
        if self.seen_txs.contains(&tx_hash) {
            return Err(format!("Duplicate transaction: {}", tx_hash));
        }
        // B98: a sender:sequence already waiting is refused before anything
        // else (it used to evict a parked transaction first, for free), or
        // replaced when the new price is REPLACE_PRICE_BUMP_PERCENT higher
        // and the old one is still queued (not on loan to a vertex).
        let nonce_key = format!("{}:{}", parsed_tx.sender, parsed_tx.sequence_number);
        let replacing = if self.pending_nonces.contains(&nonce_key) {
            let old = self
                .pending_txs
                .iter()
                .find(|raw| {
                    self.meta.get(*raw).is_some_and(|m| {
                        m.sender == parsed_tx.sender && m.seq == parsed_tx.sequence_number
                    })
                })
                .cloned();
            match old {
                Some(old)
                    if self.meta.get(&old).is_some_and(|m| {
                        parsed_tx.gas_price.saturating_mul(100)
                            >= m.gas_price.saturating_mul(100 + REPLACE_PRICE_BUMP_PERCENT)
                    }) =>
                {
                    Some(old)
                }
                _ => {
                    return Err(format!(
                        "Duplicate pending nonce for sender {} sequence {} (a replacement \
                         must pay {REPLACE_PRICE_BUMP_PERCENT}% more)",
                        parsed_tx.sender, parsed_tx.sequence_number
                    ));
                }
            }
        } else {
            None
        };

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
            // B16: a transaction the executor refuses for its nonce pays
            // nothing, so it is not admitted. Below the committed sequence
            // number it can never execute; far above it, it waits on a gap.
            let next_seq = executor::committed_sequence_number(storage, &parsed_tx.sender);
            if parsed_tx.sequence_number < next_seq {
                return Err(format!(
                    "Sequence number {} is already used: the sender's next is {}",
                    parsed_tx.sequence_number, next_seq
                ));
            }
            if parsed_tx.sequence_number - next_seq >= MAX_NONCE_AHEAD {
                return Err(format!(
                    "Sequence number {} is {} or more above the sender's next, {}",
                    parsed_tx.sequence_number, MAX_NONCE_AHEAD, next_seq
                ));
            }
            // B16: the payer must cover every transaction of its still
            // waiting, not each one alone, or a balance for one buys many
            // that cannot all pay.
            let gas_cost = (parsed_tx.gas_limit as u128)
                .checked_mul(parsed_tx.gas_price)
                .ok_or_else(|| "Gas limit times gas price overflows".to_string())?;
            let waiting: u128 = self
                .meta
                .iter()
                .filter(|(raw, m)| m.payer == checked.payer && Some(*raw) != replacing.as_ref())
                .map(|(_, m)| m.cost)
                .fold(0u128, u128::saturating_add);
            let need = waiting.saturating_add(gas_cost);
            match executor::committed_ain_balance(storage, &checked.payer) {
                Some(balance) if balance < need => {
                    return Err(format!(
                        "Insufficient balance for gas: have {}, need {} (gas_limit {} × gas_price {}, plus {} for the payer's waiting transactions)",
                        balance, need, parsed_tx.gas_limit, parsed_tx.gas_price, waiting
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
            // B94: what a block charges before anything runs (object loads,
            // the account writes) must fit the execution gas, or every block
            // skips the transaction for nothing.
            let execution = parsed_tx
                .gas_limit
                .saturating_sub(executor::admission::intrinsic_gas(tx.len()));
            match executor::precharge_gas(storage, parsed_tx) {
                Some(owed) if owed <= execution => {}
                Some(owed) => {
                    return Err(format!(
                        "the gas limit leaves {execution} execution gas, under the {owed} \
                         owed before execution (object loads and account writes)"
                    ));
                }
                None => return Err("an account record does not parse".to_string()),
            }
        }

        // RE-AUDIT HIGH: the cap must count LOANED transactions too, or a pull
        // simply moves 500 into `inflight` and frees 500 slots for the attacker.
        // B70: a full pool makes room for a READY transaction by evicting a
        // parked one (behind a nonce gap, or priced under the base fee):
        // parked transactions are never offered to a block and pay nothing,
        // so they cannot hold the pool against transactions that can run.
        if replacing.is_none() && self.pending_txs.len() + self.inflight.len() >= MAX_PENDING_TXS {
            let evicted = match self.storage.clone() {
                Some(storage)
                    if self.is_ready(
                        &storage,
                        &parsed_tx.sender,
                        parsed_tx.sequence_number,
                        parsed_tx.gas_price,
                    ) =>
                {
                    self.evict_parked(&storage)
                }
                _ => false,
            };
            if !evicted {
                return Err(format!(
                    "Mempool full ({}+{} inflight / {})",
                    self.pending_txs.len(),
                    self.inflight.len(),
                    MAX_PENDING_TXS
                ));
            }
        }

        if let Some(old) = replacing {
            self.drop_waiting(&old);
            println!("🔁 Mempool: replaced a waiting transaction at a higher price");
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
            TxMeta {
                sender: parsed_tx.sender.clone(),
                seq: parsed_tx.sequence_number,
                gas_price: parsed_tx.gas_price,
                cost: (parsed_tx.gas_limit as u128).saturating_mul(parsed_tx.gas_price),
                payer: checked.payer,
                raw_hash: StateDB::raw_tx_hash(&tx),
            },
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

    /// B54: the raw transaction queued or on loan whose `StateDB::raw_tx_hash`
    /// is `hash`, without hashing anything under the lock.
    pub fn pending_with_raw_hash(&self, hash: &str) -> Option<&str> {
        self.meta
            .iter()
            .find(|(_, m)| m.raw_hash == hash)
            .map(|(raw, _)| raw.as_str())
    }

    /// How many times a loaned transaction was handed back to the queue and
    /// loaned again (0 for its first loan). B53: an observer forwards each
    /// new loan of a transaction to the next member.
    pub fn loan_attempts(&self, raw: &str) -> u8 {
        self.inflight.get(raw).map_or(0, |(_, attempts)| *attempts)
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
            if let Some(m) = self.meta.get(raw) {
                by_sender
                    .entry(m.sender.clone())
                    .or_default()
                    .push((m.seq, m.gas_price, idx));
            }
        }
        for q in by_sender.values_mut() {
            q.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
        }

        // B70: only READY transactions are offered: from the sender's
        // committed sequence number, contiguous over what is waiting and what
        // is loaned, each at least the base fee. One behind a gap (or under
        // the fee) would be skipped by every block and pay nothing, so it is
        // parked here instead of riding in vertices for free.
        // A transaction whose sequence number is already used can never run:
        // it leaves the pool.
        let mut dead: Vec<String> = Vec::new();
        let storage = self.storage.clone();
        if let Some(storage) = &storage {
            let loaned = self.loaned_seqs();
            let base_fee = executor::committed_base_fee(storage);
            for (sender, q) in by_sender.iter_mut() {
                let committed = self.committed_next(storage, sender);
                let mut expected = committed;
                let mut ready = Vec::with_capacity(q.len());
                let mut parked_from = q.len();
                for (at, &(seq, gas_price, idx)) in q.iter().enumerate() {
                    if seq < committed {
                        dead.push(raws[idx].clone());
                        continue;
                    }
                    while loaned.get(sender).is_some_and(|s| s.contains(&expected)) {
                        expected += 1;
                    }
                    if seq != expected || gas_price < base_fee {
                        parked_from = at;
                        break;
                    }
                    ready.push((seq, gas_price, idx));
                    expected += 1;
                }
                // B98: a parked transaction leaves after PARKED_TTL_SECS.
                for &(_, _, idx) in &q[parked_from..] {
                    let raw = &raws[idx];
                    let since = *self.parked_since.entry(raw.clone()).or_insert(now_secs);
                    if now_secs.saturating_sub(since) >= PARKED_TTL_SECS {
                        dead.push(raw.clone());
                    }
                }
                for &(_, _, idx) in &ready {
                    self.parked_since.remove(&raws[idx]);
                }
                *q = ready;
            }
        }
        // B94: what a block would skip for nothing is not offered: one whose
        // pre-charge no longer fits (the state byte gas rose) leaves; a payer
        // whose committed balance does not cover its run so far stops its
        // senders' runs there.
        let mut payer_left: std::collections::HashMap<String, u128> =
            std::collections::HashMap::new();

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
                    let payable = match &storage {
                        Some(storage) => self.payable(storage, &raws[idx], &mut payer_left),
                        None => Payable::Yes,
                    };
                    match payable {
                        Payable::Yes => {
                            selected.push(idx);
                            if let Some(c) = cursor.get_mut(&sender) {
                                *c += 1;
                            }
                        }
                        Payable::Never => {
                            dead.push(raws[idx].clone());
                            if let Some(c) = cursor.get_mut(&sender) {
                                *c = usize::MAX;
                            }
                        }
                        Payable::NotNow => {
                            if let Some(c) = cursor.get_mut(&sender) {
                                *c = usize::MAX;
                            }
                        }
                    }
                }
                None => break, // all sender queues exhausted
            }
        }

        let selected_set: HashSet<usize> = selected.iter().copied().collect();
        let result: Vec<String> = selected.iter().map(|&i| raws[i].clone()).collect();
        for raw in &dead {
            self.remove_pending_nonce(raw);
            self.meta.remove(raw);
            self.requeue_attempts.remove(raw);
            self.parked_since.remove(raw);
            if let Ok(parsed) = serde_json::from_str::<executor::Transaction>(raw) {
                self.seen_txs.remove(&Self::canonical_tx_hash(&parsed));
            }
        }
        self.parked_since
            .retain(|raw, _| self.meta.contains_key(raw));
        let dead: HashSet<String> = dead.into_iter().collect();
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
            .filter(|(i, r)| !selected_set.contains(i) && !dead.contains(r))
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
            let Some(m) = self.meta.get(raw) else {
                self.requeue_attempts.remove(raw);
                continue;
            };
            self.pending_nonces
                .insert(format!("{}:{}", m.sender, m.seq));
            self.pending_txs.push_front(raw.clone());
        }
    }

    /// B39: forwarded transactions a member refused, though too few members
    /// to drop them yet: back to the front of the queue as a failed attempt.
    /// One that is refused in every pass (its other members silent) is
    /// dropped after `MAX_REQUEUE_ATTEMPTS` instead of forwarded every pass
    /// forever. `raws` in reverse order, as `return_unshipped` takes them.
    pub fn return_refused(&mut self, raws: &[String]) {
        for raw in raws.iter() {
            let Some((_, attempts)) = self.inflight.remove(raw) else {
                continue;
            };
            let Some(m) = self.meta.get(raw) else {
                self.requeue_attempts.remove(raw);
                continue;
            };
            if attempts + 1 >= MAX_REQUEUE_ATTEMPTS {
                self.meta.remove(raw);
                self.requeue_attempts.remove(raw);
                continue;
            }
            self.pending_nonces
                .insert(format!("{}:{}", m.sender, m.seq));
            self.requeue_attempts.insert(raw.clone(), attempts + 1);
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
            if let Some(m) = self.meta.get(raw) {
                self.pending_nonces
                    .insert(format!("{}:{}", m.sender, m.seq));
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

    /// B70: each sender's sequence numbers loaned to vertices.
    fn loaned_seqs(&self) -> std::collections::HashMap<String, HashSet<u64>> {
        let mut out: std::collections::HashMap<String, HashSet<u64>> =
            std::collections::HashMap::new();
        for raw in self.inflight.keys() {
            if let Some(m) = self.meta.get(raw) {
                out.entry(m.sender.clone()).or_default().insert(m.seq);
            }
        }
        out
    }

    /// B94: whether the block would charge `raw` (its pre-charge fits its
    /// execution gas, and its payer's committed balance covers it with what
    /// this pass already offered of the payer's). `payer_left` holds each
    /// payer's balance left in this pass.
    fn payable(
        &self,
        storage: &StateDB,
        raw: &str,
        payer_left: &mut std::collections::HashMap<String, u128>,
    ) -> Payable {
        let (Some(m), Ok(tx)) = (
            self.meta.get(raw),
            serde_json::from_str::<executor::Transaction>(raw),
        ) else {
            return Payable::Never;
        };
        let execution = tx
            .gas_limit
            .saturating_sub(executor::admission::intrinsic_gas(raw.len()));
        match executor::precharge_gas(storage, &tx) {
            Some(owed) if owed <= execution => {}
            _ => return Payable::Never,
        }
        let left = payer_left
            .entry(m.payer.clone())
            .or_insert_with(|| executor::committed_ain_balance(storage, &m.payer).unwrap_or(0));
        if *left < m.cost {
            return Payable::NotNow;
        }
        *left -= m.cost;
        Payable::Yes
    }

    /// B70: whether `sender`'s transaction `seq` at `gas_price` is ready: at
    /// least the base fee, and its sequence number the committed next or
    /// right after a run of the sender's waiting and loaned transactions that
    /// starts there.
    fn is_ready(&mut self, storage: &StateDB, sender: &str, seq: u64, gas_price: u128) -> bool {
        if gas_price < executor::committed_base_fee(storage) {
            return false;
        }
        let held: HashSet<u64> = self
            .meta
            .values()
            .filter(|m| m.sender == sender)
            .map(|m| m.seq)
            .collect();
        let mut expected = self.committed_next(storage, sender);
        while expected < seq && held.contains(&expected) {
            expected += 1;
        }
        expected == seq
    }

    /// B70: evict one parked transaction (not ready, still waiting): the one
    /// furthest above its sender's next sequence number, ties by its raw
    /// string, so the choice is deterministic. Its sender may submit it again.
    /// One pass: each sender's ready run is found once.
    fn evict_parked(&mut self, storage: &StateDB) -> bool {
        let base_fee = executor::committed_base_fee(storage);
        let senders: HashSet<String> = self.meta.values().map(|m| m.sender.clone()).collect();
        let committed_of: std::collections::HashMap<String, u64> = senders
            .into_iter()
            .map(|s| {
                let next = self.committed_next(storage, &s);
                (s, next)
            })
            .collect();
        let mut held: std::collections::HashMap<&str, HashSet<u64>> =
            std::collections::HashMap::new();
        for m in self.meta.values() {
            held.entry(m.sender.as_str()).or_default().insert(m.seq);
        }
        // Per sender: its committed next and the end of its ready run.
        let mut runs: std::collections::HashMap<&str, (u64, u64)> =
            std::collections::HashMap::new();
        for (sender, seqs) in &held {
            let committed = committed_of[*sender];
            let mut end = committed;
            while seqs.contains(&end) {
                end += 1;
            }
            runs.insert(sender, (committed, end));
        }
        let mut victim: Option<(u64, &str)> = None;
        for raw in &self.pending_txs {
            let Some(m) = self.meta.get(raw) else {
                continue;
            };
            let Some(&(committed, end)) = runs.get(m.sender.as_str()) else {
                continue;
            };
            let parked = m.gas_price < base_fee || m.seq >= end;
            let ahead = m.seq.saturating_sub(committed);
            if parked && victim.is_none_or(|(a, r)| (ahead, raw.as_str()) > (a, r)) {
                victim = Some((ahead, raw.as_str()));
            }
        }
        let Some((_, raw)) = victim else {
            return false;
        };
        let raw = raw.to_string();
        self.drop_waiting(&raw);
        println!("🧹 Mempool full: evicted a parked transaction for a ready one");
        true
    }

    /// Remove a queued transaction for good (evicted, replaced, expired);
    /// its sender may submit it again.
    fn drop_waiting(&mut self, raw: &str) {
        self.pending_txs.retain(|r| r != raw);
        self.remove_pending_nonce(raw);
        self.meta.remove(raw);
        self.requeue_attempts.remove(raw);
        self.parked_since.remove(raw);
        if let Ok(parsed) = serde_json::from_str::<executor::Transaction>(raw) {
            self.seen_txs.remove(&Self::canonical_tx_hash(&parsed));
        }
    }

    /// B98: the sender's committed next sequence number, read once per
    /// committed height.
    fn committed_next(&mut self, storage: &StateDB, sender: &str) -> u64 {
        let height = storage.get("latest_height").ok().flatten();
        if self.seq_cache_at != height {
            self.seq_cache.clear();
            self.seq_cache_at = height;
        }
        if let Some(next) = self.seq_cache.get(sender) {
            return *next;
        }
        let next = executor::committed_sequence_number(storage, sender);
        if self.seq_cache.len() < 2 * MAX_PENDING_TXS {
            self.seq_cache.insert(sender.to_string(), next);
        }
        next
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
