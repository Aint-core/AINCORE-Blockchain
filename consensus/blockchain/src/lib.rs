use crypto::hash; // Use crypto module's hash function
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: String, // Hash dari blok sebelumnya
    pub tx_hash: String,   // Hash dari daftar transaksi dalam blok ini
    #[serde(default)]
    pub state_root: String, // Post-execution state root. Empty only for legacy blocks.
    #[serde(default)]
    pub receipts_root: String, // Root of per-transaction receipts. Empty only for legacy blocks.
    /// LIVENESS: hash binding `Block::committed_vertices` (the anchor's committed
    /// vertex sequence) into the header, so a follower adopting a synced block's
    /// sequence can trust it belongs to this block. Empty only for legacy blocks.
    #[serde(default)]
    pub vertices_root: String,
    pub proposer_id: String, // ID node yang mengusulkan blok ini
    #[serde(default)]
    pub round: u64, // Consensus Round (DAG)
    pub timestamp: u64,    // Waktu pembuatan blok
    pub hash: String,      // Hash dari header ini sendiri
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>, // Daftar transaksi dalam blok
    /// LIVENESS: the exact vertex hashes this block's anchor committed, in
    /// commit order. A catching-up follower folds this VERBATIM into its own
    /// ordering engine (OrderingEngine::adopt_synced_anchor) — the only way to
    /// move its cursor past a gossip hole while staying in byte-for-byte parity
    /// with the producer (same committed set, same cursor, same finality digest).
    #[serde(default)]
    pub committed_vertices: Vec<String>,
    /// The anchor vertex hash this block was built from (CommitInfo.anchor_hash).
    #[serde(default)]
    pub anchor_hash: String,
}

/// Maximum accepted drift for a block timestamp, shared with the DAG's vertex
/// ingest guard and the sync validator so all three agree on "too far ahead".
pub const MAX_BLOCK_TIME_DRIFT_SECS: u64 = 30;

/// Deterministic BFT block time: the stake-weighted median of the committed
/// vertices' timestamps, clamped to be monotonic against the parent block.
///
/// # Why (AUDIT-H1)
///
/// `new_with_roots` used to read `SystemTime::now()` and fold it into the header
/// hash, so two honest nodes committing byte-identical content derived DIFFERENT
/// block hashes — and because `prev_hash` chains, the divergence propagated
/// through the whole history, making QC aggregation over `block_{height}` and
/// cross-node state comparison impossible.
///
/// The fix is Tendermint/CometBFT's BFT-Time adapted to a DAG: the timestamp must
/// be a pure function of data every node already agreed on. Vertex timestamps
/// qualify — they are set by the vertex author, folded into `Vertex::hash`, signed,
/// and bounded on ingest — so a stake-weighted median over the committed sequence
/// is authenticated input that no single proposer controls. With >2/3 honest stake
/// the median is always inside the honest range.
///
/// `samples` is `(author, stake, timestamp)`; one vote per author (the max
/// timestamp that author contributed, since a committed sequence can span rounds).
pub fn bft_block_timestamp(samples: Vec<(String, u64, u64)>, parent_timestamp: u64) -> u64 {
    use std::collections::BTreeMap;

    // One vote per author, keeping that author's latest timestamp.
    let mut per_author: BTreeMap<String, (u64, u64)> = BTreeMap::new(); // author -> (stake, ts)
    for (author, stake, ts) in samples {
        if stake == 0 {
            continue; // non-validators carry no weight
        }
        let slot = per_author.entry(author).or_insert((stake, ts));
        slot.0 = stake;
        slot.1 = slot.1.max(ts);
    }
    if per_author.is_empty() {
        return parent_timestamp;
    }

    // Deterministic order: by timestamp, then author (BTreeMap already orders
    // authors, so the sort below is stable and total).
    let mut weighted: Vec<(u64, u64, String)> = per_author
        .into_iter()
        .map(|(author, (stake, ts))| (ts, stake, author))
        .collect();
    weighted.sort();

    let total_stake: u128 = weighted.iter().map(|(_, s, _)| *s as u128).sum();
    let mut cumulative: u128 = 0;
    let mut median = parent_timestamp;
    for (ts, stake, _) in &weighted {
        cumulative += *stake as u128;
        if cumulative * 2 > total_stake {
            median = *ts;
            break;
        }
    }

    // Monotonic: a block never moves time backwards.
    median.max(parent_timestamp)
}

impl Block {
    pub fn new(
        height: u64,
        round: u64,
        prev_hash: String,
        transactions: Vec<String>,
        proposer_id: String,
    ) -> Self {
        Self::new_with_roots(
            height,
            round,
            prev_hash,
            transactions,
            proposer_id,
            String::new(),
            String::new(),
        )
    }

    /// Legacy constructor that stamps the LOCAL clock.
    ///
    /// AUDIT-H1: this is NOT deterministic across nodes and must never be used on
    /// the block-production path — use [`Block::new_with_roots_at`] with a
    /// consensus-derived timestamp (see [`bft_block_timestamp`]). Retained only so
    /// existing tests and non-consensus tooling keep building.
    pub fn new_with_roots(
        height: u64,
        round: u64,
        prev_hash: String,
        transactions: Vec<String>,
        proposer_id: String,
        state_root: String,
        receipts_root: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
        Self::new_with_roots_at(
            height,
            round,
            prev_hash,
            transactions,
            proposer_id,
            state_root,
            receipts_root,
            timestamp,
            Vec::new(),
            String::new(),
        )
    }

    /// Build a block with an EXPLICIT, consensus-derived timestamp.
    ///
    /// This is the only constructor safe for block production: the header hash
    /// folds `timestamp`, so it must be a value every honest node derives
    /// identically from committed data.
    #[allow(clippy::too_many_arguments)] // header fields are intrinsic
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_roots_at(
        height: u64,
        round: u64,
        prev_hash: String,
        transactions: Vec<String>,
        proposer_id: String,
        state_root: String,
        receipts_root: String,
        timestamp: u64,
        committed_vertices: Vec<String>,
        anchor_hash: String,
    ) -> Self {
        let tx_hash = calculate_tx_hash(&transactions);
        let vertices_root = calculate_vertices_root(&committed_vertices);

        let mut header = BlockHeader {
            height,
            prev_hash,
            tx_hash,
            state_root,
            receipts_root,
            vertices_root,
            proposer_id,
            round,
            timestamp,
            hash: String::new(), // Akan diisi setelah semua field header siap
        };

        // Hitung hash header setelah semua field diisi
        header.hash = calculate_header_hash(&header);

        Block {
            header,
            transactions,
            committed_vertices,
            anchor_hash,
        }
    }
}

// Fungsi bantu untuk menghitung hash dari daftar transaksi
pub fn calculate_tx_hash(transactions: &[String]) -> String {
    let mut data = Vec::new();
    for tx in transactions {
        data.extend_from_slice(tx.as_bytes());
    }
    hex::encode(hash(&data))
}

// Fungsi bantu untuk menghitung hash dari header blok
pub fn calculate_header_hash(header: &BlockHeader) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(header.height.to_string().as_bytes());
    data.extend_from_slice(header.prev_hash.as_bytes());
    data.extend_from_slice(header.tx_hash.as_bytes());
    if !header.state_root.is_empty() || !header.receipts_root.is_empty() {
        data.extend_from_slice(header.state_root.as_bytes());
        data.extend_from_slice(header.receipts_root.as_bytes());
    }
    data.extend_from_slice(header.proposer_id.as_bytes());
    data.extend_from_slice(header.round.to_string().as_bytes());
    data.extend_from_slice(header.timestamp.to_string().as_bytes());
    if !header.vertices_root.is_empty() {
        data.extend_from_slice(header.vertices_root.as_bytes());
    }
    hex::encode(hash(&data))
}

/// Root binding a block's committed vertex sequence (order-sensitive). Empty
/// sequence => empty root, so legacy/empty blocks keep their old header hash.
pub fn calculate_vertices_root(vertices: &[String]) -> String {
    if vertices.is_empty() {
        return String::new();
    }
    let mut data = Vec::new();
    data.extend_from_slice((vertices.len() as u64).to_be_bytes().as_slice());
    for v in vertices {
        data.extend_from_slice(v.as_bytes());
    }
    hex::encode(hash(&data))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vertex {
    pub round: u64,
    pub author: String,
    pub parents: Vec<String>, // Hashes of parent vertices (from round r-1)
    pub payload: Vec<String>, // Transactions (or batch IDs)
    pub timestamp: u64,
    pub hash: String,
    /// BLS signature from the author (48 bytes hex encoded)
    #[serde(default)]
    pub signature: String,
    /// Aggregated BLS signatures from validators (optional, for committed vertices)
    #[serde(default)]
    pub aggregated_signature: Option<String>,
}

impl Vertex {
    pub fn new(round: u64, author: String, parents: Vec<String>, payload: Vec<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        let mut v = Vertex {
            round,
            author,
            parents,
            payload,
            timestamp,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
        };
        v.hash = v.calculate_hash();
        v
    }

    /// Sign the vertex hash with Ed25519 and set the signature field
    pub fn sign_with_ed25519(&mut self, secret_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let sig = secret_key.sign(self.hash.as_bytes());
        self.signature = hex::encode(sig.to_bytes());
    }

    /// Verify the Ed25519 signature
    pub fn verify_ed25519_signature(&self, public_key_hex: &str) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.signature.is_empty() {
            return false;
        }
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
        };
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(self.hash.as_bytes(), &signature)
            .is_ok()
    }

    // (REMOVED) sign_with_bls and verify_bls_signature have been deleted.
    // These used symmetric MAC verification (re-sign and compare) which is
    // fundamentally insecure. Per-vertex signing uses Ed25519.
    // BLS aggregate signatures for consensus quorum certificates will be
    // applied externally by DagConsensus using crypto::BLSEngine.
    pub fn calculate_hash(&self) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(self.round.to_string().as_bytes());
        data.extend_from_slice(self.author.as_bytes());
        for p in &self.parents {
            data.extend_from_slice(p.as_bytes());
        }
        for tx in &self.payload {
            data.extend_from_slice(tx.as_bytes());
        }
        data.extend_from_slice(self.timestamp.to_string().as_bytes());
        hex::encode(hash(&data))
    }
}

#[cfg(test)]
mod bft_time_tests {
    use super::*;

    /// AUDIT-H1: the block timestamp must be a pure function of committed data.
    /// Two nodes with wildly different local clocks that commit the same vertices
    /// must derive the SAME timestamp, and therefore the same header hash.
    #[test]
    fn bft_timestamp_is_deterministic_across_nodes() {
        // Same committed vertices, but collected in different orders (arrival
        // order differs per node) and with duplicate authors across rounds.
        let node_a = vec![
            ("val1".to_string(), 100u64, 1_000u64),
            ("val2".to_string(), 100, 1_010),
            ("val3".to_string(), 100, 1_020),
            ("val1".to_string(), 100, 1_005), // val1 again in a later round
        ];
        let mut node_b = node_a.clone();
        node_b.reverse();

        let ts_a = bft_block_timestamp(node_a, 0);
        let ts_b = bft_block_timestamp(node_b, 0);
        assert_eq!(ts_a, ts_b, "timestamp must not depend on sample order");
        assert!(
            (1_005..=1_020).contains(&ts_a),
            "median must sit inside the honest range, got {ts_a}"
        );
    }

    /// A single validator cannot drag block time to an arbitrary value: with
    /// >2/3 honest stake the stake-weighted median stays in the honest range.
    #[test]
    fn bft_timestamp_resists_a_single_liar() {
        let samples = vec![
            ("honest1".to_string(), 100u64, 1_000u64),
            ("honest2".to_string(), 100, 1_000),
            ("liar".to_string(), 100, 9_999_999),
        ];
        let ts = bft_block_timestamp(samples, 0);
        assert_eq!(ts, 1_000, "one out-of-range vote must not move the median");
    }

    /// Time never goes backwards, even if the committed vertices are older than
    /// the parent block (e.g. a late-arriving anchor).
    #[test]
    fn bft_timestamp_is_monotonic_against_parent() {
        let samples = vec![("val1".to_string(), 100u64, 500u64)];
        let ts = bft_block_timestamp(samples, 1_000);
        assert_eq!(ts, 1_000, "must clamp to the parent timestamp");
    }

    /// No committed samples (or only zero-stake authors) falls back to the parent.
    #[test]
    fn bft_timestamp_without_samples_uses_parent() {
        assert_eq!(bft_block_timestamp(vec![], 777), 777);
        assert_eq!(
            bft_block_timestamp(vec![("nobody".to_string(), 0, 5_000)], 777),
            777,
            "zero-stake authors carry no weight"
        );
    }

    /// The end-to-end property that H1 exists for: identical content + identical
    /// derived timestamp => identical header hash on every node.
    #[test]
    fn identical_content_yields_identical_header_hash() {
        let mk = |ts: u64| {
            Block::new_with_roots_at(
                7,
                42,
                "prev".to_string(),
                vec!["tx1".to_string(), "tx2".to_string()],
                "proposer".to_string(),
                "state".to_string(),
                "receipts".to_string(),
                ts,
                vec!["v1".to_string(), "v2".to_string()],
                "v2".to_string(),
            )
        };
        let samples = vec![
            ("val1".to_string(), 100u64, 1_000u64),
            ("val2".to_string(), 100, 1_010),
            ("val3".to_string(), 100, 1_020),
        ];
        // Two nodes derive the timestamp independently from the same samples.
        let ts_node_a = bft_block_timestamp(samples.clone(), 0);
        let ts_node_b = bft_block_timestamp(samples, 0);
        assert_eq!(
            mk(ts_node_a).header.hash,
            mk(ts_node_b).header.hash,
            "same committed content must hash identically on every node"
        );
    }

    /// LIVENESS: the committed vertex sequence is bound into the header hash, so
    /// a peer cannot swap the sequence a follower will adopt without changing
    /// the block hash (which sync already verifies against the chain).
    #[test]
    fn vertices_root_is_bound_into_header_hash() {
        let mk = |vs: Vec<&str>| {
            Block::new_with_roots_at(
                9,
                44,
                "prev".to_string(),
                vec![],
                "proposer".to_string(),
                "s".to_string(),
                "r".to_string(),
                1_000,
                vs.into_iter().map(String::from).collect(),
                "anchor".to_string(),
            )
        };
        let a = mk(vec!["x", "y"]);
        let b = mk(vec!["y", "x"]); // same set, different order
        let c = mk(vec!["x", "y"]);
        assert_eq!(a.header.hash, c.header.hash, "identical sequence => identical hash");
        assert_ne!(a.header.hash, b.header.hash, "order is part of the binding");
        assert_eq!(a.header.vertices_root, calculate_vertices_root(&a.committed_vertices));
        assert!(mk(vec![]).header.vertices_root.is_empty(), "empty sequence => empty root");
    }
}
