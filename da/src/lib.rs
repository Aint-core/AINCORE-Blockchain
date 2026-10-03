//! Data availability for AINCORE block bodies (bug ledger B1).
//!
//! The block header carries `da_root`, a commitment to a Reed-Solomon
//! extension of the block body. A light client that holds a QC-certified
//! header asks a full node for shards at indices it picks at random and checks
//! each one against `da_root`, without downloading the body.
//!
//! # Construction
//!
//! - Body: `L` bytes, the block's canonical body encoding
//!   (`blockchain::Block::body_bytes`).
//! - Layout: `k = clamp(ceil(L / 512), 1, 128)` data shards of
//!   `max(1, ceil(L / k))` bytes each, filled with the body in order and
//!   zero-padded. Systematic Reed-Solomon over GF(2^8) extends them to `n = 2k`
//!   shards (`reed-solomon-erasure` 6.0: Vandermonde rows `r^c` for
//!   `r = 0..n`, normalised so the top `k` rows are the identity; field
//!   polynomial 0x11D). Any `k` of the `n` shards recover the body.
//! - Tree: the RFC 6962 Merkle tree over the `n` shards, leaf
//!   `SHA-256(0x00 || index as u64 LE || shard)`, node
//!   `SHA-256(0x01 || left || right)`.
//! - Root: `SHA-256("AINCORE_DA_ROOT_V1\0" || L as u64 LE || tree root)`.
//!   Binding `L` binds `k` and `n`, so a server cannot narrow the range of
//!   indices a client samples from.
//!
//! 512 bytes per shard and the cap of 128 data shards are choices: 512 bytes
//! is Celestia's share size, and a GF(2^8) code holds at most 256 shards, which
//! the doubling turns into at most 128 data shards.
//!
//! # What a sample proves
//!
//! A body that nobody can recover has at most `k - 1` of its `2k` shards
//! served, so one uniformly random index is served with probability below 1/2,
//! and `s` independent samples all succeed with probability below `2^-s`
//! (Al-Bassam, Sonnino, Buterin, "Fraud and Data Availability Proofs", FC 2019,
//! the one-dimensional case). The client must pick the indices itself.
//!
//! # What it does not prove
//!
//! That the parity is a correct encoding: in a one-dimensional code, checking
//! that takes the whole body. Every validator recomputes `da_root` from the
//! body when it builds or imports a block, and a header is final only under a
//! QC of more than two thirds of the stake, so a certified header with a wrong
//! encoding needs more than a third of the stake to be faulty. A light client
//! already assumes otherwise when it trusts the header.

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Target bytes per shard.
pub const SHARD_TARGET_BYTES: u64 = 512;
/// The most data shards a body is split into.
pub const MAX_DATA_SHARDS: u64 = 128;
/// The longest inclusion proof: `ceil(log2(256))` siblings.
const MAX_PROOF_LEN: usize = 8;
/// Below this many bytes per shard, one thread encodes: a thread costs more
/// than it saves.
const MIN_COLUMNS_PER_THREAD: usize = 1024;
/// Bodies whose roots are remembered (see [`da_root`]).
const REMEMBERED_ROOTS: usize = 32;

const ROOT_DOMAIN: &[u8] = b"AINCORE_DA_ROOT_V1\0";
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

type Hash = [u8; 32];

/// How a body of `body_len` bytes is cut into shards. A function of the
/// length alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layout {
    pub body_len: u64,
    pub data_shards: u64,
    pub shard_size: u64,
}

impl Layout {
    pub fn of(body_len: u64) -> Self {
        let data_shards = body_len
            .div_ceil(SHARD_TARGET_BYTES)
            .clamp(1, MAX_DATA_SHARDS);
        let shard_size = body_len.div_ceil(data_shards).max(1);
        Self {
            body_len,
            data_shards,
            shard_size,
        }
    }

    /// Data shards plus as many parity shards.
    pub fn total_shards(&self) -> u64 {
        2 * self.data_shards
    }
}

/// A body extended into its `2k` shards, with the tree over them.
pub struct Extended {
    layout: Layout,
    shards: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
    root: Hash,
}

impl Extended {
    pub fn new(body: &[u8]) -> Self {
        let layout = Layout::of(body.len() as u64);
        let k = layout.data_shards as usize;
        let size = layout.shard_size as usize;
        let mut shards = vec![vec![0u8; size]; 2 * k];
        for (shard, chunk) in shards.iter_mut().zip(body.chunks(size)) {
            shard[..chunk.len()].copy_from_slice(chunk);
        }
        encode_columns(&codec(k), &mut shards);
        let leaves = hash_leaves(&shards);
        let root = commitment(layout.body_len, &tree_root(&leaves));
        Self {
            layout,
            shards,
            leaves,
            root,
        }
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// The commitment the block header carries, as lowercase hex.
    pub fn root(&self) -> String {
        hex::encode(self.root)
    }

    /// Shard `index` with its inclusion proof, or `None` past the last shard.
    pub fn sample(&self, index: u64) -> Option<Sample> {
        let i = usize::try_from(index)
            .ok()
            .filter(|i| *i < self.shards.len())?;
        Some(Sample {
            body_len: self.layout.body_len,
            index,
            shard: hex::encode(&self.shards[i]),
            proof: inclusion_path(i, &self.leaves)
                .iter()
                .map(hex::encode)
                .collect(),
        })
    }
}

/// The DA root of a body: what the block header carries.
///
/// A node checks the same body more than once (it builds a block, then checks
/// it again for its QC), so the roots of recent bodies are remembered, keyed by
/// the body's SHA-256: a repeat check costs one hash instead of an encode.
pub fn da_root(body: &[u8]) -> String {
    static RECENT: OnceLock<Mutex<Vec<(Hash, String)>>> = OnceLock::new();
    let recent = RECENT.get_or_init(Default::default);
    let key: Hash = Sha256::digest(body).into();
    if let Some((_, root)) = recent
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(k, _)| *k == key)
    {
        return root.clone();
    }
    let root = Extended::new(body).root();
    let mut recent = recent
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if recent.len() == REMEMBERED_ROOTS {
        recent.remove(0);
    }
    recent.push((key, root.clone()));
    root
}

/// One shard and the path from it to the DA root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub body_len: u64,
    pub index: u64,
    /// The shard's bytes, hex.
    pub shard: String,
    /// Sibling hashes from the leaf up, hex.
    pub proof: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleError {
    /// The root is not 32 bytes of hex.
    BadRoot,
    /// The index is past the last shard of a body of this length.
    IndexOutOfRange,
    /// The shard is not hex, or not the layout's shard size.
    BadShard,
    /// The proof is malformed or does not lead to a root.
    BadProof,
    /// The proof leads to a different root.
    RootMismatch,
}

/// Check one sample against a DA root. Total: hostile input is refused, never
/// a panic or an allocation larger than the sample itself.
///
/// Returns the number of shards of the body the root commits to (B62): a
/// client picks its indices from that range only. A count a server reports
/// beside the sample (`aincore_getDaStatus`) is a hint, and one smaller than
/// this lets a withholding server serve every index the client draws.
pub fn verify_sample(da_root: &str, sample: &Sample) -> Result<u64, SampleError> {
    let expected = decode_hash(da_root).ok_or(SampleError::BadRoot)?;
    let layout = Layout::of(sample.body_len);
    let total = layout.total_shards();
    if sample.index >= total {
        return Err(SampleError::IndexOutOfRange);
    }
    if sample.shard.len() as u64 != layout.shard_size.saturating_mul(2) {
        return Err(SampleError::BadShard);
    }
    let shard = hex::decode(&sample.shard).map_err(|_| SampleError::BadShard)?;
    if sample.proof.len() > MAX_PROOF_LEN {
        return Err(SampleError::BadProof);
    }
    let path: Vec<Hash> = sample
        .proof
        .iter()
        .map(|p| decode_hash(p))
        .collect::<Option<_>>()
        .ok_or(SampleError::BadProof)?;
    let tree = root_from_path(sample.index, total, leaf_hash(sample.index, &shard), &path)
        .ok_or(SampleError::BadProof)?;
    if commitment(sample.body_len, &tree) != expected {
        return Err(SampleError::RootMismatch);
    }
    Ok(total)
}

/// Rebuild a body from any `k` of its `2k` shards (`None` where missing) and
/// check that it is the body `da_root` commits to. `None` with fewer than `k`
/// shards, a shard of the wrong size, or a result that does not extend back to
/// `da_root` (a wrong shard, or a wrong encoding).
pub fn recover(da_root: &str, body_len: u64, mut shards: Vec<Option<Vec<u8>>>) -> Option<Vec<u8>> {
    let expected = decode_hash(da_root)?;
    let layout = Layout::of(body_len);
    let k = usize::try_from(layout.data_shards).ok()?;
    let size = usize::try_from(layout.shard_size).ok()?;
    let len = usize::try_from(body_len).ok()?;
    if shards.len() != 2 * k || shards.iter().flatten().any(|s| s.len() != size) {
        return None;
    }
    codec(k).reconstruct_data(&mut shards).ok()?;
    let mut body = Vec::with_capacity(k * size);
    for shard in shards.iter().take(k) {
        body.extend_from_slice(shard.as_deref()?);
    }
    body.truncate(len);
    (Extended::new(&body).root == expected).then_some(body)
}

fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Fill the parity shards. Reed-Solomon works on each byte position on its
/// own, so the shards are cut into column ranges and the ranges are encoded on
/// separate threads; the bytes are the same as one encode of the whole.
fn encode_columns(rs: &ReedSolomon, shards: &mut [Vec<u8>]) {
    let size = shards[0].len();
    let width = size.div_ceil(threads()).max(MIN_COLUMNS_PER_THREAD);
    let mut ranges: Vec<Vec<&mut [u8]>> = Vec::new();
    for shard in shards.iter_mut() {
        for (r, piece) in shard.chunks_mut(width).enumerate() {
            if ranges.len() == r {
                ranges.push(Vec::new());
            }
            ranges[r].push(piece);
        }
    }
    let encode = |mut range: Vec<&mut [u8]>| {
        rs.encode(&mut range)
            .expect("every range has 2k pieces of one width");
    };
    if ranges.len() == 1 {
        ranges.into_iter().for_each(encode);
        return;
    }
    std::thread::scope(|scope| {
        for range in ranges {
            scope.spawn(move || encode(range));
        }
    });
}

/// Leaf hashes, on as many threads as the encode used.
fn hash_leaves(shards: &[Vec<u8>]) -> Vec<Hash> {
    let hash = |(i, shard): (usize, &Vec<u8>)| leaf_hash(i as u64, shard);
    let total: usize = shards.iter().map(Vec::len).sum();
    let per = shards.len().div_ceil(threads()).max(1);
    if total < MIN_COLUMNS_PER_THREAD * shards.len() || per == shards.len() {
        return shards.iter().enumerate().map(hash).collect();
    }
    std::thread::scope(|scope| {
        let parts: Vec<_> = shards
            .chunks(per)
            .enumerate()
            .map(|(c, part)| {
                scope.spawn(move || {
                    part.iter()
                        .enumerate()
                        .map(|(i, shard)| hash((c * per + i, shard)))
                        .collect::<Vec<Hash>>()
                })
            })
            .collect();
        parts
            .into_iter()
            .flat_map(|part| part.join().expect("leaf hashing does not panic"))
            .collect()
    })
}

/// One codec per data-shard count, built once: building one inverts a
/// `k x k` matrix.
fn codec(data_shards: usize) -> Arc<ReedSolomon> {
    static CODECS: OnceLock<Mutex<HashMap<usize, Arc<ReedSolomon>>>> = OnceLock::new();
    let mut codecs = CODECS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(codecs.entry(data_shards).or_insert_with(|| {
        Arc::new(
            ReedSolomon::new(data_shards, data_shards)
                .expect("1..=128 data shards and as many parity shards fit GF(2^8)"),
        )
    }))
}

fn decode_hash(text: &str) -> Option<Hash> {
    if text.len() != 64 {
        return None;
    }
    hex::decode(text).ok()?.try_into().ok()
}

fn leaf_hash(index: u64, shard: &[u8]) -> Hash {
    Sha256::new()
        .chain_update([LEAF_TAG])
        .chain_update(index.to_le_bytes())
        .chain_update(shard)
        .finalize()
        .into()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update([NODE_TAG])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

fn commitment(body_len: u64, tree_root: &Hash) -> Hash {
    Sha256::new()
        .chain_update(ROOT_DOMAIN)
        .chain_update(body_len.to_le_bytes())
        .chain_update(tree_root)
        .finalize()
        .into()
}

/// RFC 6962's split point: the largest power of two below `n` (`n >= 2`).
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// RFC 6962 MTH over leaf hashes.
fn tree_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&tree_root(&leaves[..k]), &tree_root(&leaves[k..]))
        }
    }
}

/// RFC 6962 PATH(m, D[n]): sibling hashes from leaf `m` up.
fn inclusion_path(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split(n);
    let (mut path, sibling) = if m < k {
        (inclusion_path(m, &leaves[..k]), tree_root(&leaves[k..]))
    } else {
        (inclusion_path(m - k, &leaves[k..]), tree_root(&leaves[..k]))
    };
    path.push(sibling);
    path
}

/// RFC 9162 section 2.1.3.2: the root an inclusion proof leads to, or `None`
/// if the proof has the wrong length for this index and tree size.
fn root_from_path(index: u64, size: u64, leaf: Hash, path: &[Hash]) -> Option<Hash> {
    if index >= size {
        return None;
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = leaf;
    for p in path {
        if s == 0 {
            return None;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    (s == 0).then_some(r)
}

#[cfg(test)]
mod tests;
