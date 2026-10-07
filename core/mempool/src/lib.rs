use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use storage::StateDB;

/// B259: the consensus thread's waits for a pool's lock. A submitter lets
/// each go first (`yield_to_consensus`): `std::sync::Mutex` is not fair, and
/// a submit batch's loop took the lock again ~100 ns after giving it back,
/// so the proposal, waiting under the consensus lock, waited for the batch.
static CONSENSUS_WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// B259: the consensus thread waiting for a pool's lock, while held.
pub struct ConsensusWaiting(());

impl ConsensusWaiting {
    pub fn begin() -> Self {
        CONSENSUS_WAITING.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(())
    }
}

impl Drop for ConsensusWaiting {
    fn drop(&mut self) {
        CONSENSUS_WAITING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// B259: the consensus thread's lock of `pool`: submitters let it go first.
pub fn lock_for_consensus(
    pool: &std::sync::Mutex<Mempool>,
) -> std::sync::LockResult<std::sync::MutexGuard<'_, Mempool>> {
    let _waiting = ConsensusWaiting::begin();
    pool.lock()
}

/// B259: a submitter's turn: it waits while the consensus thread waits for
/// a pool's lock. Never called holding a pool's lock.
pub fn yield_to_consensus() {
    while CONSENSUS_WAITING.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        std::thread::yield_now();
    }
}

/// B259 witness support: the consensus thread's waits counted now.
#[cfg(test)]
fn consensus_waits() -> usize {
    CONSENSUS_WAITING.load(std::sync::atomic::Ordering::SeqCst)
}

pub const MAX_PENDING_TXS: usize = 5000;
/// B215: the raw bytes the pool holds, queued and on loan (a choice: the
/// count cap's 5,000 at ~1.7 KB each, where a transfer is ~0.7 KB). Every
/// pass of the selection hashes each held transaction a few times under the
/// consensus lock (its maps are keyed by the transaction), and 5,000 of up
/// to 100 KiB could be held: several hundred MB hashed a pass.
pub const MAX_PENDING_BYTES: usize = 8 << 20;

/// B231: parked transactions one admission may evict at most: a maximal
/// transaction (`MAX_TX_BYTES`, 100 KiB) fits after 251 of the smallest
/// (408 bytes, B183), so 256 bound the work without refusing a fit.
pub const MAX_EVICTIONS_PER_ADMISSION: usize = 256;
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

#[cfg(test)]
thread_local! {
    /// B206 witness: transactions `payable` priced on this thread.
    static PRICINGS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// B231 witness: the scans for parked transactions to evict.
    static EVICTION_SCANS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// B239 witness: the bytes of transaction text hashed to find held ones.
    static TEXT_HASHED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// `StateDB::raw_tx_hash`, counted for the B239 witness.
fn raw_hash_of(raw: &str) -> String {
    #[cfg(test)]
    TEXT_HASHED.with(|n| n.set(n.get() + raw.len() as u64));
    StateDB::raw_tx_hash(raw)
}

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
    /// B188: what `payable` prices, kept at admission: the transaction
    /// without its payload and args (the pre-charge reads neither), and the
    /// raw length (its intrinsic gas). Each pass parsed every stuck sender's
    /// head again, up to 100 KB each, under the consensus lock.
    charge: executor::Transaction,
    raw_len: usize,
    /// B239: its `canonical_tx_hash` (the dedup identity), kept so it can
    /// leave `seen_txs` without parsing the transaction again.
    dedup: String,
}

/// B239: a held transaction's id: every map and the queue are keyed by it.
/// They were keyed by the raw transaction (up to 100 KiB), so every lookup
/// under the lock hashed the whole transaction, and a scan of the pool
/// (a replacement's lookup, an eviction, a selection pass) hashed up to
/// `MAX_PENDING_BYTES`.
type TxId = u64;

/// B239: an eviction scan's outcome: the parked transactions in eviction
/// order (`(ahead, raw hash, bytes, id)`), valid while nothing changed.
struct ParkedScan {
    version: u64,
    height: Option<String>,
    base_fee: u128,
    parked: Vec<(u64, String, usize, TxId)>,
}

/// B239: one transaction the pool holds, queued or on loan, with all it
/// keeps of it.
struct Held {
    raw: String,
    meta: TxMeta,
    /// B98: when it was first seen parked (the caller's clock); past
    /// `PARKED_TTL_SECS` it leaves.
    parked_since: Option<u64>,
    /// B188: when its payer first did not cover it (the caller's clock):
    /// past `PARKED_TTL_SECS` it leaves, and a full pool evicts it for a
    /// ready one.
    unpaid_since: Option<u64>,
    /// The attempts carried from a requeue into its next loan.
    requeue_attempts: u8,
    /// On loan to a vertex: (loaned at, in the caller's clock; attempts).
    loan: Option<(u64, u8)>,
}

/// B201: why `add_checked` did not admit a transaction, and whether only
/// for now (the fee, the pool's room, a nonce gap, the payer's balance, the
/// pre-charge at today's byte gas). A forwarder keeps a transaction refused
/// for now until its TTL: two such refusals dropped it for good, after the
/// RPC had answered "sent".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub for_now: bool,
}

impl Refusal {
    fn for_now(reason: String) -> Self {
        Self {
            reason,
            for_now: true,
        }
    }
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Self {
            reason,
            for_now: false,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

pub struct Mempool {
    /// The queue, in order: the transactions not on loan (B239: by id).
    pending_txs: VecDeque<TxId>,
    seen_txs: HashSet<String>,    // Deduplication
    seen_order: VecDeque<String>, // Bounded cache tracking
    /// sender:sequence_number → the queued transaction (B239: so a
    /// replacement finds the one it replaces by a point lookup; it walked
    /// the queue).
    pending_nonces: std::collections::HashMap<String, TxId>,
    /// B239: every transaction held, queued or on loan, by id. LOANED, NOT
    /// GONE (orphan-loss fix): transactions handed to consensus by
    /// `get_pending_transactions` stay here, on loan, instead of vanishing.
    /// They leave for good only when `mark_executed` reports them executed
    /// in a committed block; one still on loan after `requeue_stale`'s age
    /// limit goes back to the queue. Before this, a vertex that never
    /// committed (a node briefly behind the network orphans its own vertex)
    /// silently destroyed its whole payload — the sender's nonce sequence
    /// then had a permanent hole, every later transaction died with
    /// "Invalid Sequence", and the account was wedged forever. The loan's
    /// clock is the caller's (consensus passes its injectable `now_secs`),
    /// so a simulated cluster never re-queues by the wall clock (B9).
    held: std::collections::HashMap<TxId, Held>,
    /// B239: `StateDB::raw_tx_hash` → id, how callers name a transaction.
    by_hash: std::collections::HashMap<String, TxId>,
    next_id: TxId,
    /// B239: each sender's held transactions by sequence number, the
    /// payers' waiting costs and the bytes held, kept as transactions come
    /// and go: an admission refused for now read each of them by a scan of
    /// the pool, for free and again on every copy.
    by_sender: std::collections::HashMap<String, std::collections::BTreeMap<u64, Vec<TxId>>>,
    payer_waiting: std::collections::HashMap<String, u128>,
    bytes_held: usize,
    /// B239: bumped by every change to what the pool holds, so the parked
    /// transactions found by the last eviction scan are found again only
    /// when something changed (`parked_scan`).
    version: u64,
    /// B239: the last eviction scan's parked transactions, eviction order
    /// first, with the version, height and base fee it was made at.
    parked_scan: Option<ParkedScan>,
    /// Optional storage handle for the admission balance gate (the payer's
    /// committed AIN). Production callers pass it via
    /// [`Mempool::with_storage`]; without it the gate is skipped.
    storage: Option<Arc<StateDB>>,
    /// B98: each sender's committed next sequence number, read once per
    /// committed height (`seq_cache_at`), not once per sender per pass under
    /// the mempool and consensus locks.
    seq_cache: std::collections::HashMap<String, u64>,
    seq_cache_at: Option<String>,
}

impl Mempool {
    /// Construct a mempool without storage: no balance gate. For unit tests.
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            seen_order: VecDeque::new(),
            pending_nonces: std::collections::HashMap::new(),
            held: std::collections::HashMap::new(),
            by_hash: std::collections::HashMap::new(),
            next_id: 0,
            by_sender: std::collections::HashMap::new(),
            payer_waiting: std::collections::HashMap::new(),
            bytes_held: 0,
            version: 0,
            parked_scan: None,
            storage: None,
            seq_cache: std::collections::HashMap::new(),
            seq_cache_at: None,
        }
    }

    /// Construct a mempool with storage access: the constructor production
    /// node code uses, so the balance gate runs.
    pub fn with_storage(storage: Arc<StateDB>) -> Self {
        Self {
            storage: Some(storage),
            ..Self::new()
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
    /// B173: the identity `raw` is deduplicated by (`canonical_tx_hash`),
    /// read without checking any signature; `None` when it does not parse
    /// or is too large (its check refuses it as cheaply).
    pub fn dedup_key(raw: &str) -> Option<String> {
        if raw.len() > executor::admission::MAX_TX_BYTES {
            return None;
        }
        serde_json::from_str::<executor::Transaction>(raw)
            .ok()
            .map(|tx| Self::canonical_tx_hash(&tx))
    }

    /// B173: whether this mempool has seen a transaction of identity `key`
    /// (`dedup_key`).
    pub fn has_seen(&self, key: &str) -> bool {
        self.seen_txs.contains(key)
    }

    /// B154: the `StateDB::raw_tx_hash` of each transaction this mempool
    /// holds, waiting or on loan (the forwarder keeps a record per held one).
    pub fn held_raw_hashes(&self) -> HashSet<String> {
        self.by_hash.keys().cloned().collect()
    }

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
        self.add_checked(tx, checked).map_err(|r| r.reason)
    }

    /// The stateless half of admission, which needs no mempool state: run it
    /// before taking the mempool's lock (B31), then `add_checked`.
    ///
    /// B8/B12/B13: the stateless half of validity (chain id from
    /// `sys:chain_id`, gas bounds, payload kind with scripts disabled, ZK
    /// proof, the sender's signature in Ed25519 or ML-DSA-65, and the
    /// paymaster's) is the one predicate vertex ingress and the executor run
    /// too. `payer` is whoever pays the gas. B173: a join_validator_set
    /// call's BLS proof-of-possession is not checked here: the executor's
    /// pre-dispatch gate refuses a bad one, charged (B1), while here it cost
    /// a pairing for every copy and was refused for free.
    ///
    /// B73: what it checks is `tx` in its canonical encoding, the one the
    /// mempool keeps (`add_checked`).
    pub fn check_admissible(tx: &str) -> Result<executor::admission::CheckedTx, String> {
        let canonical = executor::admission::canonicalize(tx)?;
        executor::admission::check_stateless(&canonical, &blockchain::chain_id())
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
    ) -> Result<String, Refusal> {
        // B73: kept, offered and forwarded in its canonical encoding only,
        // whatever encoding it arrived in (vertex ingress takes no other).
        let tx = executor::admission::canonical_json(&checked.tx);
        let parsed_tx = &checked.tx;
        let tx_hash = Self::canonical_tx_hash(parsed_tx);
        if self.seen_txs.contains(&tx_hash) {
            return Err(format!("Duplicate transaction: {}", tx_hash).into());
        }
        // B239: held already under this exact text (its identity left the
        // bounded `seen_txs` while it waited).
        let raw_hash = raw_hash_of(&tx);
        if self.by_hash.contains_key(&raw_hash) {
            return Err(format!("Duplicate transaction: {}", tx_hash).into());
        }
        // B98: a sender:sequence already waiting is refused before anything
        // else (it used to evict a parked transaction first, for free), or
        // replaced when the new price is REPLACE_PRICE_BUMP_PERCENT higher
        // and the old one is still queued (not on loan to a vertex).
        // B239: the waiting one found by a point lookup (it walked the
        // queue, hashing every transaction ahead of it, for free).
        let nonce_key = format!("{}:{}", parsed_tx.sender, parsed_tx.sequence_number);
        let replacing = if let Some(&old) = self.pending_nonces.get(&nonce_key) {
            match self.held.get(&old) {
                Some(waiting)
                    if parsed_tx.gas_price.saturating_mul(100)
                        >= waiting
                            .meta
                            .gas_price
                            .saturating_mul(100 + REPLACE_PRICE_BUMP_PERCENT) =>
                {
                    Some(old)
                }
                _ => {
                    return Err(format!(
                        "Duplicate pending nonce for sender {} sequence {} (a replacement \
                         must pay {REPLACE_PRICE_BUMP_PERCENT}% more)",
                        parsed_tx.sender, parsed_tx.sequence_number
                    )
                    .into());
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
                return Err(Refusal::for_now(format!(
                    "Gas price {} is below the base fee {}",
                    parsed_tx.gas_price, base_fee
                )));
            }
            // B16: a transaction the executor refuses for its nonce pays
            // nothing, so it is not admitted. Below the committed sequence
            // number it can never execute; far above it, it waits on a gap.
            let next_seq = executor::committed_sequence_number(storage, &parsed_tx.sender);
            if parsed_tx.sequence_number < next_seq {
                return Err(format!(
                    "Sequence number {} is already used: the sender's next is {}",
                    parsed_tx.sequence_number, next_seq
                )
                .into());
            }
            if parsed_tx.sequence_number - next_seq >= MAX_NONCE_AHEAD {
                return Err(Refusal::for_now(format!(
                    "Sequence number {} is {} or more above the sender's next, {}",
                    parsed_tx.sequence_number, MAX_NONCE_AHEAD, next_seq
                )));
            }
            // B16: the payer must cover every transaction of its still
            // waiting, not each one alone, or a balance for one buys many
            // that cannot all pay.
            let gas_cost = (parsed_tx.gas_limit as u128)
                .checked_mul(parsed_tx.gas_price)
                .ok_or_else(|| "Gas limit times gas price overflows".to_string())?;
            // B239: kept per payer (a scan of the pool an admission).
            let replaced_cost = replacing
                .and_then(|id| self.held.get(&id))
                .filter(|h| h.meta.payer == checked.payer)
                .map_or(0, |h| h.meta.cost);
            let waiting: u128 = self
                .payer_waiting
                .get(&checked.payer)
                .copied()
                .unwrap_or(0)
                .saturating_sub(replaced_cost);
            let need = waiting.saturating_add(gas_cost);
            match executor::committed_ain_balance(storage, &checked.payer) {
                Some(balance) if balance < need => {
                    return Err(Refusal::for_now(format!(
                        "Insufficient balance for gas: have {}, need {} (gas_limit {} × gas_price {}, plus {} for the payer's waiting transactions)",
                        balance, need, parsed_tx.gas_limit, parsed_tx.gas_price, waiting
                    )));
                }
                Some(_) => {}
                None => {
                    return Err(Refusal::for_now(format!(
                        "Gas payer {} has no AIN balance to pay gas (no CoinStore)",
                        checked.payer
                    )));
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
                    return Err(Refusal::for_now(format!(
                        "the gas limit leaves {execution} execution gas, under the {owed} \
                         owed before execution (object loads and account writes)"
                    )));
                }
                None => return Err("an account record does not parse".to_string().into()),
            }
        }

        // RE-AUDIT HIGH: the cap must count LOANED transactions too, or a pull
        // simply moves 500 into `inflight` and frees 500 slots for the attacker.
        // B70: a full pool makes room for a READY transaction by evicting a
        // parked one (behind a nonce gap, or priced under the base fee):
        // parked transactions are never offered to a block and pay nothing,
        // so they cannot hold the pool against transactions that can run.
        // B215: and by the bytes held (a replacement counts without the
        // transaction it replaces). B231: the parked transactions that must
        // go are chosen in one scan, and evicted only if together they make
        // room: B215 scanned the whole pool once a victim (a 100 KiB
        // newcomer against 400-byte parked ones, ~250 scans hashing up to
        // 8 MiB each) under the mempool lock the proposal waits on.
        let replaced_len = replacing
            .and_then(|id| self.held.get(&id))
            .map_or(0, |h| h.meta.raw_len);
        // Every held transaction is queued or on loan.
        let full_count = replacing.is_none() && self.held.len() >= MAX_PENDING_TXS;
        let held = self.held_bytes().saturating_sub(replaced_len);
        let over_bytes = held
            .saturating_add(tx.len())
            .saturating_sub(MAX_PENDING_BYTES);
        if full_count || over_bytes > 0 {
            let victims = match self.storage.clone() {
                Some(storage)
                    if self.is_ready(
                        &storage,
                        &parsed_tx.sender,
                        parsed_tx.sequence_number,
                        parsed_tx.gas_price,
                    ) =>
                {
                    self.parked_victims(&storage, usize::from(full_count), over_bytes, replacing)
                }
                _ => None,
            };
            let Some(victims) = victims else {
                return Err(Refusal::for_now(if full_count {
                    format!(
                        "Mempool full ({}+{} inflight / {})",
                        self.pending_txs.len(),
                        self.held.len().saturating_sub(self.pending_txs.len()),
                        MAX_PENDING_TXS
                    )
                } else {
                    format!("Mempool full ({held} bytes held / {MAX_PENDING_BYTES})")
                }));
            };
            self.drop_all_waiting(&victims);
            println!(
                "🧹 Mempool full: evicted {} parked transaction(s) for a ready one",
                victims.len()
            );
        }

        if let Some(old) = replacing {
            self.drop_waiting(old);
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
        let id = self.next_id;
        self.next_id += 1;
        self.pending_nonces.insert(nonce_key, id);
        self.by_hash.insert(raw_hash.clone(), id);
        let meta = TxMeta {
            sender: parsed_tx.sender.clone(),
            seq: parsed_tx.sequence_number,
            gas_price: parsed_tx.gas_price,
            cost: (parsed_tx.gas_limit as u128).saturating_mul(parsed_tx.gas_price),
            payer: checked.payer,
            raw_hash,
            charge: executor::Transaction {
                payload: String::new(),
                args: Vec::new(),
                ..parsed_tx.clone()
            },
            raw_len: tx.len(),
            dedup: tx_hash.clone(),
        };
        self.by_sender
            .entry(meta.sender.clone())
            .or_default()
            .entry(meta.seq)
            .or_default()
            .push(id);
        let waiting = self.payer_waiting.entry(meta.payer.clone()).or_default();
        *waiting = waiting.saturating_add(meta.cost);
        self.bytes_held = self.bytes_held.saturating_add(meta.raw_len);
        self.version += 1;
        self.held.insert(
            id,
            Held {
                raw: tx,
                meta,
                parked_since: None,
                unpaid_since: None,
                requeue_attempts: 0,
                loan: None,
            },
        );
        self.pending_txs.push_back(id);

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
        self.held.values().any(|h| matches(&h.raw))
    }

    /// B54: the raw transaction queued or on loan whose `StateDB::raw_tx_hash`
    /// is `hash`, without hashing anything under the lock.
    pub fn pending_with_raw_hash(&self, hash: &str) -> Option<&str> {
        self.by_hash
            .get(hash)
            .and_then(|id| self.held.get(id))
            .map(|h| h.raw.as_str())
    }

    /// How many times a loaned transaction was handed back to the queue and
    /// loaned again (0 for its first loan). B53: an observer forwards each
    /// new loan of a transaction to the next member.
    pub fn loan_attempts(&self, raw: &str) -> u8 {
        self.id_of(raw)
            .and_then(|id| self.held.get(&id))
            .and_then(|h| h.loan)
            .map_or(0, |(_, attempts)| attempts)
    }

    /// B239: the id of the held transaction `raw` (one hash of it).
    fn id_of(&self, raw: &str) -> Option<TxId> {
        self.by_hash.get(&raw_hash_of(raw)).copied()
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

        // B188: the queue moved out and back, not copied. B239: it holds ids,
        // and each is looked up by its id, not by its text.
        let ids: Vec<TxId> = std::mem::take(&mut self.pending_txs).into_iter().collect();
        self.version += 1;

        // sender -> [(sequence_number, gas_price, original_index)], nonce-ordered.
        let mut by_sender: BTreeMap<String, Vec<(u64, u128, usize)>> = BTreeMap::new();
        for (idx, id) in ids.iter().enumerate() {
            if let Some(h) = self.held.get(id) {
                by_sender.entry(h.meta.sender.clone()).or_default().push((
                    h.meta.seq,
                    h.meta.gas_price,
                    idx,
                ));
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
        let mut dead: Vec<TxId> = Vec::new();
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
                        dead.push(ids[idx]);
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
                    if let Some(h) = self.held.get_mut(&ids[idx]) {
                        let since = *h.parked_since.get_or_insert(now_secs);
                        if now_secs.saturating_sub(since) >= PARKED_TTL_SECS {
                            dead.push(ids[idx]);
                        }
                    }
                }
                for &(_, _, idx) in &ready {
                    if let Some(h) = self.held.get_mut(&ids[idx]) {
                        h.parked_since = None;
                    }
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

        let mut selected: Vec<usize> = Vec::with_capacity(limit.min(ids.len()));
        // B193: the senders whose payer covered their head this pass.
        let mut covered: HashSet<String> = HashSet::new();
        // B206: every sender's head in a heap (highest gas_price, then FIFO
        // index): picking the best scanned every sender, and an unpayable
        // head ended one pick, so one drained payer sponsoring 5,000 senders
        // cost ~25M lookups a pass.
        let mut heads: std::collections::BinaryHeap<(u128, std::cmp::Reverse<usize>, String)> =
            by_sender
                .iter()
                .filter_map(|(sender, q)| {
                    q.first()
                        .map(|&(_, gp, idx)| (gp, std::cmp::Reverse(idx), sender.clone()))
                })
                .collect();
        while selected.len() < limit {
            match heads.pop() {
                Some((_, std::cmp::Reverse(idx), sender)) => {
                    let payable = match &storage {
                        Some(storage) => self.payable(storage, ids[idx], &mut payer_left),
                        None => Payable::Yes,
                    };
                    match payable {
                        Payable::Yes => {
                            // B193: its payer covers it, so the run's earlier
                            // shortfall is over, the part this pass does not
                            // reach too (a stamp left there made a payable
                            // transaction evictable, and its TTL ran from the
                            // first shortfall). One that falls short again is
                            // stamped anew.
                            if covered.insert(sender.clone()) {
                                let from = cursor.get(&sender).copied().unwrap_or(usize::MAX);
                                for &(_, _, i) in by_sender[&sender].get(from..).unwrap_or(&[]) {
                                    if let Some(h) = self.held.get_mut(&ids[i]) {
                                        h.unpaid_since = None;
                                    }
                                }
                            }
                            selected.push(idx);
                            if let Some(c) = cursor.get_mut(&sender) {
                                *c += 1;
                                if let Some(&(_, gp, next)) = by_sender[&sender].get(*c) {
                                    heads.push((gp, std::cmp::Reverse(next), sender.clone()));
                                }
                            }
                        }
                        Payable::Never => {
                            dead.push(ids[idx]);
                            if let Some(c) = cursor.get_mut(&sender) {
                                *c = usize::MAX;
                            }
                        }
                        Payable::NotNow => {
                            // B188: the rest of the sender's run waits on
                            // its payer, at most PARKED_TTL_SECS.
                            let from = cursor.get(&sender).copied().unwrap_or(usize::MAX);
                            for &(_, _, i) in by_sender[&sender].get(from..).unwrap_or(&[]) {
                                if let Some(h) = self.held.get_mut(&ids[i]) {
                                    let since = *h.unpaid_since.get_or_insert(now_secs);
                                    if now_secs.saturating_sub(since) >= PARKED_TTL_SECS {
                                        dead.push(ids[i]);
                                    }
                                }
                            }
                            if let Some(c) = cursor.get_mut(&sender) {
                                *c = usize::MAX;
                            }
                        }
                    }
                }
                None => break, // all sender queues exhausted
            }
        }

        // What can never run leaves, and its sender may submit it again.
        let dead: HashSet<TxId> = dead.into_iter().collect();
        for &id in &dead {
            self.forget_unseen(id);
        }
        let selected_set: HashSet<usize> = selected.iter().copied().collect();
        let mut result: Vec<String> = Vec::with_capacity(selected.len());
        for &i in &selected {
            let id = ids[i];
            let Some(h) = self.held.get_mut(&id) else {
                continue;
            };
            // Loaned, not gone: see `held`. Attempts carry over across
            // re-queues so a permanently failing tx is bounded.
            h.unpaid_since = None;
            let attempts = std::mem::take(&mut h.requeue_attempts);
            h.loan = Some((now_secs, attempts));
            result.push(h.raw.clone());
            let key = format!("{}:{}", h.meta.sender, h.meta.seq);
            if self.pending_nonces.get(&key) == Some(&id) {
                self.pending_nonces.remove(&key);
            }
        }
        // Keep unselected txs in their original FIFO order for the next round.
        self.pending_txs = ids
            .into_iter()
            .enumerate()
            .filter(|(i, id)| !selected_set.contains(i) && !dead.contains(id))
            .map(|(_, id)| id)
            .collect();

        result
    }

    /// B215: the raw bytes held, queued and on loan.
    fn held_bytes(&self) -> usize {
        self.bytes_held
    }

    pub fn is_empty(&self) -> bool {
        self.pending_txs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending_txs.len()
    }

    /// The queued transactions, in order (not those on loan).
    pub fn get_all_pending(&self) -> Vec<String> {
        self.pending_txs
            .iter()
            .filter_map(|id| self.held.get(id))
            .map(|h| h.raw.clone())
            .collect()
    }

    /// Orphan-loss fix: consensus reports the raw transactions that actually
    /// EXECUTED in a committed block; only those leave the loan ledger for good.
    /// Deferred/failed ones stay inflight and come back via `requeue_stale`.
    pub fn mark_executed(&mut self, raws: &[String]) {
        if raws.is_empty() {
            return;
        }
        // Its nonce guard goes too: an executed tx must not keep blocking a
        // resubmission of the same sender:sequence. Its dedup identity stays.
        let done: HashSet<TxId> = raws.iter().filter_map(|raw| self.id_of(raw)).collect();
        for &id in &done {
            self.forget(id);
        }
        // An executed tx can also be sitting in the queue (returned by
        // return_unshipped or requeue_stale, then executed via another
        // validator's vertex): it leaves the queue too.
        if !done.is_empty() {
            self.pending_txs.retain(|id| !done.contains(id));
        }
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
            // Not held (executed, or dropped) or not on loan (re-queued
            // elsewhere): ignore.
            let Some(id) = self.id_of(raw) else {
                continue;
            };
            let Some(h) = self.held.get_mut(&id) else {
                continue;
            };
            let Some((_, attempts)) = h.loan.take() else {
                continue;
            };
            h.requeue_attempts = attempts;
            let key = format!("{}:{}", h.meta.sender, h.meta.seq);
            self.pending_nonces.insert(key, id);
            self.pending_txs.push_front(id);
            self.version += 1;
        }
    }

    /// B39: forwarded transactions a member refused, though too few members
    /// to drop them yet: back to the front of the queue as a failed attempt.
    /// One that is refused in every pass (its other members silent) is
    /// dropped after `MAX_REQUEUE_ATTEMPTS` instead of forwarded every pass
    /// forever. `raws` in reverse order, as `return_unshipped` takes them.
    pub fn return_refused(&mut self, raws: &[String]) {
        for raw in raws.iter() {
            let Some(id) = self.id_of(raw) else {
                continue;
            };
            let Some(h) = self.held.get_mut(&id) else {
                continue;
            };
            let Some((_, attempts)) = h.loan.take() else {
                continue;
            };
            if attempts + 1 >= MAX_REQUEUE_ATTEMPTS {
                self.forget(id);
                continue;
            }
            h.requeue_attempts = attempts + 1;
            let key = format!("{}:{}", h.meta.sender, h.meta.seq);
            self.pending_nonces.insert(key, id);
            self.pending_txs.push_front(id);
            self.version += 1;
        }
    }

    /// B133/B134: `requeue_stale_at` for a forwarding node: a stale loan
    /// goes back to the queue whatever its count (its forwarder bounds it by
    /// age and decides by stake when to give up; three re-forwards reached
    /// three members, all of which could be Byzantine).
    pub fn requeue_stale_uncapped_at(&mut self, max_age_secs: u64, now_secs: u64) -> usize {
        let stale = self.stale_loans(max_age_secs, now_secs);
        for &(id, attempts) in &stale {
            self.requeue(id, attempts.saturating_add(1));
        }
        stale.len()
    }

    /// B239: the loans at least `max_age_secs` old at `now_secs`, with their
    /// attempts, in the order they were admitted (they came back in the
    /// loan table's hash order).
    fn stale_loans(&self, max_age_secs: u64, now_secs: u64) -> Vec<(TxId, u8)> {
        let mut stale: Vec<(TxId, u8)> = self
            .held
            .iter()
            .filter_map(|(&id, h)| {
                let (at, attempts) = h.loan?;
                (now_secs.saturating_sub(at) >= max_age_secs).then_some((id, attempts))
            })
            .collect();
        stale.sort_unstable();
        stale
    }

    /// A loaned transaction back at the end of the queue, `attempts` carried.
    fn requeue(&mut self, id: TxId, attempts: u8) {
        let Some(h) = self.held.get_mut(&id) else {
            return;
        };
        h.loan = None;
        h.requeue_attempts = attempts;
        let key = format!("{}:{}", h.meta.sender, h.meta.seq);
        self.pending_nonces.insert(key, id);
        self.pending_txs.push_back(id);
        self.version += 1;
    }

    /// `requeue_stale_at` with the wall clock.
    pub fn requeue_stale(&mut self, max_age: std::time::Duration) -> usize {
        self.requeue_stale_at(max_age.as_secs(), wall_secs())
    }

    /// Re-queue loans at least `max_age_secs` old at `now_secs`, in the same
    /// clock the loans were stamped with.
    pub fn requeue_stale_at(&mut self, max_age_secs: u64, now_secs: u64) -> usize {
        let stale = self.stale_loans(max_age_secs, now_secs);
        let mut requeued = 0usize;
        let mut dropped = 0usize;
        for &(id, attempts) in &stale {
            // RE-AUDIT HIGH: bounded. A tx that keeps failing (bad nonce forever,
            // unpayable gas) must not become an immortal 30s loop that burns
            // every validator's CPU and block space.
            if attempts + 1 >= MAX_REQUEUE_ATTEMPTS {
                self.forget(id);
                dropped += 1;
                continue;
            }
            self.requeue(id, attempts + 1);
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
        for h in self.held.values().filter(|h| h.loan.is_some()) {
            out.entry(h.meta.sender.clone())
                .or_default()
                .insert(h.meta.seq);
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
        id: TxId,
        payer_left: &mut std::collections::HashMap<String, u128>,
    ) -> Payable {
        let Some(m) = self.held.get(&id).map(|h| &h.meta) else {
            return Payable::Never;
        };
        // B206: the payer's balance first (one read a payer a pass): a head
        // it cannot cover is not priced (a pricing reads the sender's and the
        // payer's records). One whose pre-charge no longer fits leaves once
        // its payer can pay again, or at PARKED_TTL_SECS.
        let left = payer_left
            .entry(m.payer.clone())
            .or_insert_with(|| executor::committed_ain_balance(storage, &m.payer).unwrap_or(0));
        if *left < m.cost {
            return Payable::NotNow;
        }
        let execution = m
            .charge
            .gas_limit
            .saturating_sub(executor::admission::intrinsic_gas(m.raw_len));
        #[cfg(test)]
        PRICINGS.with(|n| n.set(n.get() + 1));
        match executor::precharge_gas(storage, &m.charge) {
            Some(owed) if owed <= execution => {}
            _ => return Payable::Never,
        }
        *left -= m.cost;
        Payable::Yes
    }

    /// B70: whether `sender`'s transaction `seq` at `gas_price` is ready: at
    /// least the base fee, and its sequence number the committed next or
    /// right after a run of the sender's waiting and loaned transactions that
    /// starts there. B297: the run as selection reads it (`ready_run_end`):
    /// it stepped over every held number whatever its price, so behind a
    /// waiting head priced under the base fee (parked by selection, with all
    /// after it) a newcomer counted as ready and evicted other senders'
    /// parked transactions from a full pool, for one no block would take.
    fn is_ready(&mut self, storage: &StateDB, sender: &str, seq: u64, gas_price: u128) -> bool {
        let base_fee = executor::committed_base_fee(storage);
        if gas_price < base_fee {
            return false;
        }
        let committed = self.committed_next(storage, sender);
        self.ready_run_end(sender, committed, base_fee, seq) == seq
    }

    /// B297: where `sender`'s ready run ends, the rule selection parks by:
    /// from `committed` (its next sequence number) through every number it
    /// holds (B239: its own transactions, not a scan of the pool), up to the
    /// first that is waiting and priced under `base_fee`, and not past
    /// `limit`. Selection, the eviction scan and a newcomer's readiness all
    /// read it (B244 made two of them agree).
    fn ready_run_end(&self, sender: &str, committed: u64, base_fee: u128, limit: u64) -> u64 {
        let mut end = committed;
        if let Some(seqs) = self.by_sender.get(sender) {
            while end < limit {
                let Some(ids) = seqs.get(&end) else {
                    break;
                };
                let stops = ids.iter().any(|id| {
                    self.held
                        .get(id)
                        .is_some_and(|h| h.loan.is_none() && h.meta.gas_price < base_fee)
                });
                if stops {
                    break;
                }
                end += 1;
            }
        }
        end
    }

    /// B70/B231: the parked transactions (not ready, still waiting) to evict
    /// so that `slots` more fit and `bytes` more are free, `exclude` (B245:
    /// the transaction a replacement replaces, already counted out) apart:
    /// the furthest above their senders' next sequence numbers first, ties
    /// by their raw hashes (deterministic), at most
    /// `MAX_EVICTIONS_PER_ADMISSION`. `None`, and nothing evicted, when they
    /// cannot make that room. B239: the scan is remembered until the pool,
    /// the committed height or the base fee changes, so admissions refused
    /// for now do not scan the pool again and again.
    fn parked_victims(
        &mut self,
        storage: &StateDB,
        slots: usize,
        bytes: usize,
        exclude: Option<TxId>,
    ) -> Option<Vec<TxId>> {
        let base_fee = executor::committed_base_fee(storage);
        let height = storage.get("latest_height").ok().flatten();
        let fresh = self.parked_scan.as_ref().is_some_and(|scan| {
            scan.version == self.version && scan.height == height && scan.base_fee == base_fee
        });
        if !fresh {
            let parked = self.scan_parked(storage, &height, base_fee);
            self.parked_scan = Some(ParkedScan {
                version: self.version,
                height,
                base_fee,
                parked,
            });
        }
        let scan = self.parked_scan.as_ref()?;
        let (mut freed, mut victims) = (0usize, Vec::new());
        for &(_, _, len, id) in &scan.parked {
            if victims.len() >= slots && freed >= bytes {
                break;
            }
            if Some(id) == exclude {
                continue;
            }
            if victims.len() == MAX_EVICTIONS_PER_ADMISSION {
                return None;
            }
            freed = freed.saturating_add(len);
            victims.push(id);
        }
        (victims.len() >= slots && freed >= bytes).then_some(victims)
    }

    /// B70/B244: the queued transactions selection parks, in eviction
    /// order. A sender's ready run starts at its committed next and goes on
    /// over its held transactions (loaned or queued) while each is held, and
    /// stops at a queued one priced under the base fee: selection offers
    /// nothing of the sender from there, so all of it is parked (only that
    /// one transaction was, and the rest of its run was neither offered nor
    /// evictable). And one whose payer did not cover it at the last pass
    /// (B188).
    fn scan_parked(
        &mut self,
        storage: &StateDB,
        height: &Option<String>,
        base_fee: u128,
    ) -> Vec<(u64, String, usize, TxId)> {
        #[cfg(test)]
        EVICTION_SCANS.with(|n| n.set(n.get() + 1));
        let senders: Vec<String> = self.by_sender.keys().cloned().collect();
        let mut runs: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::with_capacity(senders.len());
        for sender in senders {
            let committed = self.committed_next_at(storage, height, &sender);
            let end = self.ready_run_end(&sender, committed, base_fee, u64::MAX);
            runs.insert(sender, (committed, end));
        }
        let mut parked: Vec<(u64, String, usize, TxId)> = Vec::new();
        for id in &self.pending_txs {
            let Some(h) = self.held.get(id) else {
                continue;
            };
            let m = &h.meta;
            let Some(&(committed, end)) = runs.get(&m.sender) else {
                continue;
            };
            if m.seq >= end || h.unpaid_since.is_some() {
                parked.push((
                    m.seq.saturating_sub(committed),
                    m.raw_hash.clone(),
                    m.raw_len,
                    *id,
                ));
            }
        }
        parked.sort_unstable_by(|a, b| (b.0, &b.1).cmp(&(a.0, &a.1)));
        parked
    }

    /// B231: `drop_waiting` for several, the queue filtered once.
    fn drop_all_waiting(&mut self, ids: &[TxId]) {
        let gone: HashSet<TxId> = ids.iter().copied().collect();
        self.pending_txs.retain(|id| !gone.contains(id));
        for &id in ids {
            self.forget_unseen(id);
        }
    }

    /// Remove a queued transaction for good (evicted, replaced, expired);
    /// its sender may submit it again.
    fn drop_waiting(&mut self, id: TxId) {
        self.pending_txs.retain(|x| *x != id);
        self.forget_unseen(id);
    }

    /// B239: a transaction leaves the pool (executed, or dropped after its
    /// requeues): its entry, its hash and its nonce guard. Its dedup identity
    /// stays (an executed one must not be replayed).
    fn forget(&mut self, id: TxId) -> Option<Held> {
        let h = self.held.remove(&id)?;
        self.version += 1;
        self.by_hash.remove(&h.meta.raw_hash);
        if let Some(seqs) = self.by_sender.get_mut(&h.meta.sender) {
            if let Some(ids) = seqs.get_mut(&h.meta.seq) {
                ids.retain(|x| *x != id);
                if ids.is_empty() {
                    seqs.remove(&h.meta.seq);
                }
            }
            if seqs.is_empty() {
                self.by_sender.remove(&h.meta.sender);
            }
        }
        if let Some(waiting) = self.payer_waiting.get_mut(&h.meta.payer) {
            *waiting = waiting.saturating_sub(h.meta.cost);
            if *waiting == 0 {
                self.payer_waiting.remove(&h.meta.payer);
            }
        }
        self.bytes_held = self.bytes_held.saturating_sub(h.meta.raw_len);
        let key = format!("{}:{}", h.meta.sender, h.meta.seq);
        if self.pending_nonces.get(&key) == Some(&id) {
            self.pending_nonces.remove(&key);
        }
        Some(h)
    }

    /// `forget`, and its dedup identity too: its sender may submit it again
    /// (evicted, replaced, expired, or never able to run).
    fn forget_unseen(&mut self, id: TxId) {
        if let Some(h) = self.forget(id) {
            self.seen_txs.remove(&h.meta.dedup);
        }
    }

    /// B98: the sender's committed next sequence number, read once per
    /// committed height.
    fn committed_next(&mut self, storage: &StateDB, sender: &str) -> u64 {
        let height = storage.get("latest_height").ok().flatten();
        self.committed_next_at(storage, &height, sender)
    }

    /// `committed_next` at a committed height read once by the caller
    /// (B231: a scan read it once a sender).
    fn committed_next_at(
        &mut self,
        storage: &StateDB,
        height: &Option<String>,
        sender: &str,
    ) -> u64 {
        if self.seq_cache_at != *height {
            self.seq_cache.clear();
            self.seq_cache_at = height.clone();
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
}

// Fungsi main bisa dihapus jika crate ini adalah library
// fn main() {
//     println!("Hello, world!");
// }
#[cfg(test)]
mod tests;
