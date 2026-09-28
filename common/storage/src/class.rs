//! Key classification for G3 (`docs/G3_STATE_AUTHENTICATION_CONTRACT.md`, CL-1).
//!
//! Every key the node writes belongs to exactly one class. Only `State` keys
//! go into the state commitment. Classification is by EXACT template,
//! including zero-padding, never by prefix: `sys:` alone holds state, local
//! and node-secret keys, and `block_` also matches `block_txs:`.
//!
//! Stage S0 only OBSERVES: `observe` counts unclassified keys and state keys
//! written outside the block transaction, without refusing anything. Refusal
//! arrives in S3, once the counters show nothing legitimate would be refused.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyClass {
    /// Consensus state: goes into the state commitment.
    State,
    /// Finalized history and its deterministic indexes.
    Chain,
    /// This node's own consensus view.
    Local,
    /// Operational data and secrets.
    Node,
    /// Fixed by the genesis inputs; recomputed, never stored as state.
    Constant,
    /// The state tree's own internals.
    Tree,
    /// Self-authenticating epoch transition log.
    Log,
    /// No live writer or reader; to be deleted before activation.
    Dead,
}

impl KeyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyClass::State => "state",
            KeyClass::Chain => "chain",
            KeyClass::Local => "local",
            KeyClass::Node => "node",
            KeyClass::Constant => "constant",
            KeyClass::Tree => "tree",
            KeyClass::Log => "log",
            KeyClass::Dead => "dead",
        }
    }
}

// ---- segment validators ------------------------------------------------

/// Canonical u64 decimal, as `{}` formats it: no sign, no leading zero.
fn dec(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
}

/// `{:020}`: exactly 20 digits.
fn dec20(s: &str) -> bool {
    s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Lowercase hex of any non-zero even length.
fn hex(s: &str) -> bool {
    !s.is_empty()
        && s.len().is_multiple_of(2)
        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && hex(s)
}

/// One free-form segment: non-empty, no separator.
fn seg(s: &str) -> bool {
    !s.is_empty() && !s.contains(':')
}

fn ident(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Move `StructTag` as move-core `Display` renders it:
/// `0x{addr}::{module}::{Name}` with optional, balanced `<…>` type arguments.
fn struct_tag(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("0x") else {
        return false;
    };
    let head = rest.split('<').next().unwrap_or("");
    let mut parts = head.split("::");
    let (Some(addr), Some(module), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if addr.is_empty()
        || !addr.bytes().all(|b| b.is_ascii_hexdigit())
        || !ident(module)
        || !ident(name)
    {
        return false;
    }
    let mut depth: i32 = 0;
    for c in rest.chars() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            c if c.is_whitespace() && c != ' ' => return false,
            _ => {}
        }
    }
    depth == 0
}

/// `{hex64}_{tail}` as used by `resource_`, `module_` and `meta_resource_`.
fn addr_then(s: &str) -> Option<&str> {
    if s.len() < 66 || !s.is_char_boundary(64) || s.as_bytes()[64] != b'_' {
        return None;
    }
    hex64(&s[..64]).then(|| &s[65..])
}

fn parts(s: &str) -> Vec<&str> {
    s.split(':').collect()
}

// ---- the classifier ----------------------------------------------------

/// Classify one key by exact template. `None` means no template matches: in
/// S0 the write is only counted; from S3 it will be refused.
pub fn classify(key: &[u8]) -> Option<KeyClass> {
    use KeyClass::*;
    let key = std::str::from_utf8(key).ok()?;

    // Fixed keys first, so a template below can never shadow one.
    let fixed = match key {
        "sys:validators"
        | "sys:validator_set:v1"
        | "genesis:validator_set:v1"
        | "consensus:epoch"
        | "sys:last_epoch_boundary"
        | "sys:chain_id"
        | "sys:config:epoch_block_interval"
        | "sys:config:require_exec_roots"
        | "sys:config:federation_addr"
        | "sys:config:base_reward"
        | "sys:config:halving_interval"
        | "sys:config:burn_percentage"
        | "sys:config:tip_agreement_n"
        | "sys:total_supply"
        | "total_burned"
        | "gov:active_proposal_ids"
        | "sys:stdlib_version" => Some(State),

        "latest_height"
        | "latest_block_hash"
        | "sys:last_executed_height"
        | "sys:state_root"
        | "genesis_stdlib_hash"
        | "genesis_stdlib_modules"
        | "genesis_stdlib_module_count"
        | "genesis_version" => Some(Chain),

        "latest_proposed_round"
        | "dag:checkpoint:latest"
        | "consensus:last_adopted_height"
        | "consensus:committed_rounds"
        | "consensus:finalized_round"
        | "consensus:next_anchor_round"
        | "consensus:last_anchor_round"
        | "consensus:last_anchor_hash"
        | "consensus:finality_digest"
        | "consensus:beacon_folded_qc_height"
        | "consensus:beacon_folded_anchor_round"
        | "consensus:qc:latest"
        | "consensus:qc:latest_height"
        | "consensus:qc:latest_round" => Some(Local),

        "sys:da:signing_key_enc_v1"
        | "sys:da:signing_key"
        | "sys:block_prune_cursor_v1"
        | "sys:tx_index_backfill_v1_complete"
        | "genesis_initialized"
        | "sync:halt_reason"
        | "sys:restore_in_progress" => Some(Node),

        "genesis_identity" => Some(Constant),

        "jmt:latest" | "jmt:floor" => Some(Tree),

        "sys:fhe:global_public_key" | "total_supply" | "consensus:committed_sequence" => Some(Dead),
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }

    // `_`-separated families.
    if let Some(rest) = key.strip_prefix("resource_") {
        return addr_then(rest).filter(|tag| struct_tag(tag)).map(|_| State);
    }
    if let Some(rest) = key.strip_prefix("module_") {
        return addr_then(rest).filter(|name| ident(name)).map(|_| State);
    }
    if let Some(rest) = key.strip_prefix("meta_resource_") {
        return addr_then(rest).filter(|tag| struct_tag(tag)).map(|_| Dead);
    }
    if let Some(rest) = key.strip_prefix("pqc_pubkey_") {
        return hex64(rest).then_some(State);
    }
    // `block_txs:{h}` shares the `block_` prefix; test it first.
    if let Some(rest) = key.strip_prefix("block_txs:") {
        return dec(rest).then_some(Chain);
    }
    if let Some(rest) = key.strip_prefix("block_") {
        return dec(rest).then_some(Chain);
    }
    // Accounts (64-hex) and governance proposals (free-form ids) share `obj:`.
    if let Some(id) = key.strip_prefix("obj:") {
        return (!id.is_empty()).then_some(State);
    }
    if let Some(rest) = key.strip_prefix("da_shard_") {
        let mut it = rest.splitn(2, '_');
        let (a, b) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        return (dec(a) && dec(b)).then_some(Local);
    }
    for prefix in [
        "da_commitment_",
        "da_data_",
        "da_meta_",
        "da_root_",
        "da_fraud_missingdata_",
    ] {
        if let Some(rest) = key.strip_prefix(prefix) {
            return dec(rest).then_some(Local);
        }
    }

    // `:`-separated families.
    let p = parts(key);
    let class = match p.as_slice() {
        // S
        ["sys", "validator_set", "epoch", e] if dec(e) => State,
        ["consensus", "epoch_start_height", e] if dec(e) => State,
        ["sys", "fee_sweep_queue", h, miner] if dec(h) && seg(miner) => State,
        ["sys", "slashed", a, r] if seg(a) && dec(r) => State,
        ["sys", "pending_slash", a] if seg(a) => State,
        ["validator", "jailed", a] if seg(a) => State,
        ["sys", "pending_module_upgrade", n] if ident(n) => State,
        ["sys", "committee", e] if dec20(e) => State,

        // C
        ["tx_index", h] if hex64(h) => Chain,
        ["tx_receipt", h] if hex64(h) => Chain,

        // L
        ["vertex", h] if hex64(h) => Local,
        ["validator", "last_seen", a] if seg(a) => Local,
        ["sys", "downtime_attestation", o, e, r] if seg(o) && dec(e) && seg(r) => Local,
        ["sys", "equiv_seen" | "equiv_carried" | "equiv_gossiped", o, r] if seg(o) && dec(r) => {
            Local
        }
        ["sys", "equiv_local_jail", o] if seg(o) => Local,
        ["dag", "checkpoint" | "checkpoint_sig", r] if dec(r) => Local,
        ["consensus", "cseq", r] if dec(r) => Local,
        ["consensus", "qc", h] if dec(h) => Local,
        ["consensus", "qc_by_round", r] if dec(r) => Local,
        ["consensus", "qc_pending", h] if dec20(h) => Local,
        ["consensus", "qc_vote" | "qc_vote_agg", r, a] if dec(r) && seg(a) => Local,
        ["consensus", "qc_signing", "v1", chain, pk, "height" | "round", n]
            if hex64(chain) && hex(pk) && dec(n) =>
        {
            Local
        }
        ["consensus", "vattest", "v1", cg, pk, e, author, r]
            if hex64(cg) && hex(pk) && dec(e) && seg(author) && dec20(r) =>
        {
            Local
        }

        // N
        ["peer" | "peer_ip" | "peer_addr", id] if seg(id) => Node,
        ["alarm", "anchor_height_violation", h] if dec(h) => Node,

        // T and log
        ["jmt", "node", n] if hex(n) => Tree,
        ["jmt", "val", kh, v] if hex64(kh) && dec20(v) => Tree,
        ["jmt", "stale", v, n] if dec20(v) && hex(n) => Tree,
        ["jmt", "pre", kh] if hex64(kh) => Tree,
        ["jmt", "pinned", v] if dec20(v) => Tree,
        ["ta", e] if dec20(e) => Log,

        // Dead
        ["vote_receipt", pid, voter] if seg(pid) && seg(voter) => Dead,
        ["delegation" | "unbonding", _, _] => Dead,
        ["validator_pool" | "token", _] => Dead,
        ["token_balance", _, _] => Dead,

        _ => return None,
    };
    Some(class)
}

// ---- S0 observe mode ---------------------------------------------------

/// Where a write happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WriteContext {
    /// Directly on the database, outside any transaction.
    Base,
    /// Inside a `StateDB::transaction` that is not the block transaction.
    Transaction,
    /// Inside the executor's block transaction.
    Block,
}

impl WriteContext {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteContext::Base => "base",
            WriteContext::Transaction => "transaction",
            WriteContext::Block => "block",
        }
    }
}

/// Distinct patterns remembered per database, so a runaway key space cannot
/// grow the table without bound.
const MAX_SAMPLES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// The key with hex runs and numbers masked, so values never appear.
    pub pattern: String,
    pub violation: &'static str,
    pub context: &'static str,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateClassStats {
    pub writes: u64,
    pub unclassified: u64,
    pub state_outside_block: u64,
    pub samples: Vec<Sample>,
}

/// Per-database counters. Stage S0 records; it never refuses.
#[derive(Default)]
pub(crate) struct Observer {
    writes: AtomicU64,
    unclassified: AtomicU64,
    state_outside_block: AtomicU64,
    samples: Mutex<BTreeMap<(String, &'static str, &'static str), u64>>,
}

impl Observer {
    pub(crate) fn observe(&self, key: &[u8], ctx: WriteContext) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let violation = match classify(key) {
            None => {
                self.unclassified.fetch_add(1, Ordering::Relaxed);
                "unclassified"
            }
            Some(KeyClass::State) if ctx != WriteContext::Block => {
                self.state_outside_block.fetch_add(1, Ordering::Relaxed);
                "state_outside_block"
            }
            Some(_) => return,
        };
        let pattern = mask(key);
        let slot = (pattern, violation, ctx.as_str());
        let first_sight = {
            let mut samples = self.samples.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = samples.get_mut(&slot) {
                *count += 1;
                false
            } else if samples.len() < MAX_SAMPLES {
                samples.insert(slot.clone(), 1);
                true
            } else {
                false
            }
        };
        // Printed after the lock is released: inside a transaction the writer
        // gate is held, and a blocked stderr must not also hold the samples.
        if first_sight {
            eprintln!("[STATE_CLASS] {} ({}): {}", slot.1, slot.2, slot.0);
        }
    }

    pub(crate) fn stats(&self) -> StateClassStats {
        let samples = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        StateClassStats {
            writes: self.writes.load(Ordering::Relaxed),
            unclassified: self.unclassified.load(Ordering::Relaxed),
            state_outside_block: self.state_outside_block.load(Ordering::Relaxed),
            samples: samples
                .iter()
                .map(|((pattern, violation, context), count)| Sample {
                    pattern: pattern.clone(),
                    violation,
                    context,
                    count: *count,
                })
                .collect(),
        }
    }
}

/// Mask hex runs of 16+ and every digit run, and cap the length, so a
/// sample shows a key's shape without its values.
fn mask(key: &[u8]) -> String {
    let text = String::from_utf8_lossy(key);
    let mut out = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() && out.len() < 120 {
        let hex_run = chars[i..]
            .iter()
            .take_while(|c| c.is_ascii_hexdigit())
            .count();
        if hex_run >= 16 {
            out.push_str("<hex>");
            i += hex_run;
        } else if chars[i].is_ascii_digit() {
            out.push_str("<n>");
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use KeyClass::*;

    const H64: &str = "dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42";

    fn c(key: &str) -> Option<KeyClass> {
        classify(key.as_bytes())
    }

    /// One concrete key per Appendix A template, with its expected class.
    #[test]
    fn every_appendix_a_template_has_its_class() {
        let bls = "a".repeat(96);
        let cases: Vec<(String, KeyClass)> = vec![
            // S
            (format!("resource_{H64}_0x1::coin::CoinStore<0x1::staking::AincoreCoin>"), State),
            (format!("resource_{H64}_0x1::dex::LiquidityPool<0x1::staking::AincoreCoin, 0x1::wbtc::WBTC>"), State),
            (format!("module_{H64}_staking"), State),
            (format!("obj:{H64}"), State),
            ("obj:proposal-7".into(), State),
            ("gov:active_proposal_ids".into(), State),
            ("sys:validators".into(), State),
            ("sys:validator_set:v1".into(), State),
            ("genesis:validator_set:v1".into(), State),
            ("sys:validator_set:epoch:12".into(), State),
            ("consensus:epoch".into(), State),
            ("consensus:epoch_start_height:12".into(), State),
            ("sys:last_epoch_boundary".into(), State),
            ("sys:chain_id".into(), State),
            ("sys:config:epoch_block_interval".into(), State),
            ("sys:config:require_exec_roots".into(), State),
            ("sys:config:tip_agreement_n".into(), State),
            ("sys:config:burn_percentage".into(), State),
            ("sys:config:federation_addr".into(), State),
            ("sys:config:base_reward".into(), State),
            ("sys:config:halving_interval".into(), State),
            ("sys:total_supply".into(), State),
            ("total_burned".into(), State),
            (format!("sys:fee_sweep_queue:70016:{H64}"), State),
            (format!("sys:slashed:{H64}:77"), State),
            (format!("sys:pending_slash:{H64}"), State),
            (format!("validator:jailed:{H64}"), State),
            ("sys:stdlib_version".into(), State),
            ("sys:pending_module_upgrade:staking".into(), State),
            (format!("pqc_pubkey_{H64}"), State),
            ("sys:committee:00000000000000000003".into(), State),
            // C
            ("block_70016".into(), Chain),
            ("block_txs:70016".into(), Chain),
            (format!("tx_index:{H64}"), Chain),
            (format!("tx_receipt:{H64}"), Chain),
            ("latest_height".into(), Chain),
            ("latest_block_hash".into(), Chain),
            ("sys:last_executed_height".into(), Chain),
            ("sys:state_root".into(), Chain),
            ("genesis_stdlib_hash".into(), Chain),
            ("genesis_version".into(), Chain),
            // L
            (format!("vertex:{H64}"), Local),
            ("latest_proposed_round".into(), Local),
            (format!("validator:last_seen:{H64}"), Local),
            (format!("sys:downtime_attestation:{H64}:3:{H64}"), Local),
            (format!("sys:equiv_seen:{H64}:42"), Local),
            (format!("sys:equiv_carried:{H64}:42"), Local),
            (format!("sys:equiv_gossiped:{H64}:42"), Local),
            (format!("sys:equiv_local_jail:{H64}"), Local),
            ("dag:checkpoint:213600".into(), Local),
            ("dag:checkpoint_sig:213600".into(), Local),
            ("dag:checkpoint:latest".into(), Local),
            ("consensus:cseq:214642".into(), Local),
            ("consensus:finality_digest".into(), Local),
            ("consensus:qc:1".into(), Local),
            ("consensus:qc:latest".into(), Local),
            ("consensus:qc:latest_height".into(), Local),
            ("consensus:qc_by_round:10".into(), Local),
            ("consensus:qc_pending:00000000000000070016".into(), Local),
            (format!("consensus:qc_vote:100000:{H64}"), Local),
            (format!("consensus:qc_vote_agg:100000:{H64}"), Local),
            (format!("consensus:qc_signing:v1:{H64}:{bls}:height:70016"), Local),
            (format!("consensus:qc_signing:v1:{H64}:{bls}:round:153030"), Local),
            (format!("consensus:vattest:v1:{H64}:{bls}:3:{H64}:00000000000000153030"), Local),
            ("da_shard_10000_0".into(), Local),
            ("da_commitment_1".into(), Local),
            ("da_data_1".into(), Local),
            ("da_meta_1".into(), Local),
            ("da_root_1".into(), Local),
            ("da_fraud_missingdata_1".into(), Local),
            // N
            (format!("peer:{H64}"), Node),
            (format!("peer_ip:{H64}"), Node),
            ("peer_addr:12D3KooWMF5ur249RNXQYw6bvhfDRsHaemio5gcV9mxHXn4ZtVc2".into(), Node),
            ("sys:da:signing_key_enc_v1".into(), Node),
            ("sys:da:signing_key".into(), Node),
            ("sys:block_prune_cursor_v1".into(), Node),
            ("sys:tx_index_backfill_v1_complete".into(), Node),
            ("genesis_initialized".into(), Node),
            ("alarm:anchor_height_violation:9".into(), Node),
            ("sync:halt_reason".into(), Node),
            ("sys:restore_in_progress".into(), Node),
            // K, T, log
            ("genesis_identity".into(), Constant),
            (format!("jmt:node:{H64}"), Tree),
            (format!("jmt:val:{H64}:00000000000000000009"), Tree),
            (format!("jmt:stale:00000000000000000009:{H64}"), Tree),
            (format!("jmt:pre:{H64}"), Tree),
            ("jmt:latest".into(), Tree),
            ("jmt:floor".into(), Tree),
            ("jmt:pinned:00000000000000000009".into(), Tree),
            ("ta:00000000000000000003".into(), Log),
            // Dead
            (format!("meta_resource_{H64}_0x1::coin::CoinStore<0x1::staking::AincoreCoin>"), Dead),
            (format!("vote_receipt:7:{H64}"), Dead),
            (format!("delegation:{H64}:{H64}"), Dead),
            (format!("unbonding:{H64}:5"), Dead),
            (format!("validator_pool:{H64}"), Dead),
            ("token:7".into(), Dead),
            (format!("token_balance:{H64}:7"), Dead),
            ("sys:fhe:global_public_key".into(), Dead),
            ("total_supply".into(), Dead),
            ("consensus:committed_sequence".into(), Dead),
        ];
        for (key, class) in &cases {
            assert_eq!(c(key), Some(*class), "{key}");
        }
        assert!(
            cases.len() >= 100,
            "positive control: {} cases",
            cases.len()
        );
    }

    /// The traps the reviews named: shared prefixes, zero-padding, and keys
    /// that look right but are not the template.
    #[test]
    fn near_misses_are_not_classified() {
        for key in [
            "consensus:qc_pending:70016",            // not zero-padded
            "consensus:vattest:v1:ab:cd:3:x:153030", // round not padded, cg not 64-hex
            "block_txs:abc",
            "block_",
            "block_007", // not canonical decimal
            "block_-1",
            "resource_xyz_0x1::coin::CoinStore",
            &format!("resource_{H64}_coin::CoinStore"), // no 0x address
            &format!("resource_{H64}_0x1::coin::CoinStore<0x1::a::B"), // unbalanced
            &format!("module_{H64}_9bad"),
            "obj:",
            "sys:validator_set:epoch:",
            "sys:validator_set:epoch:x",
            &format!("tx_index:{}", &H64[..63]),
            &format!("vertex:{}", H64.to_uppercase()),
            "sys:config:unknown",
            "consensus:qc:",
            "da_shard_1",
            "jmt:val:zz:00000000000000000009",
            "p:1",
            "",
        ] {
            assert_eq!(c(key), None, "{key:?}");
        }
        assert_eq!(classify(&[0xff, 0xfe]), None, "non-UTF-8");
    }

    /// Every key template found in a real validator database (the pre-wipe r1
    /// census, 104 patterns over 2,982,055 keys) is classified.
    #[test]
    fn every_key_in_the_measured_database_is_classified() {
        let keys: Vec<&str> = include_str!("fixtures/census_keys_r1.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            keys.len(),
            104,
            "positive control: the whole census was loaded"
        );
        let mut by_class = BTreeMap::new();
        for key in &keys {
            let class = c(key).unwrap_or_else(|| panic!("unclassified census key: {key}"));
            *by_class.entry(class).or_insert(0) += 1;
        }
        // The census S instances (79 keys) come from these patterns; the
        // point here is that nothing real falls through.
        assert!(by_class[&State] > 0 && by_class[&Local] > 0 && by_class[&Chain] > 0);
    }

    fn temp_db(name: &str) -> crate::StateDB {
        let path =
            std::env::temp_dir().join(format!("aincore_class_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        crate::StateDB::open(path.to_str().unwrap()).unwrap()
    }

    /// S0 observes and never refuses. Only the block transaction may write
    /// state without being counted.
    #[test]
    fn observer_counts_state_outside_the_block_and_unclassified_keys() {
        let db = temp_db("observer");
        let state_key = format!("obj:{H64}");

        db.put(&state_key, "base")
            .expect("S0 never refuses a base write");
        db.transaction(|v| v.put(&state_key, "txn").map_err(Into::into))
            .expect("S0 never refuses a transaction write");
        db.block_transaction(|v| v.put(&state_key, "block").map_err(Into::into))
            .unwrap();
        db.put("latest_height", "1").unwrap(); // chain data on base: fine
        db.put("no:such:template", "x").unwrap();

        let s = db.db.state_class_stats();
        assert_eq!(s.writes, 5, "positive control: every write was seen");
        assert_eq!(s.state_outside_block, 2, "base + plain transaction");
        assert_eq!(s.unclassified, 1);
        assert_eq!(
            db.get(&state_key).unwrap().as_deref(),
            Some("block"),
            "nothing refused"
        );

        let contexts: Vec<_> = s
            .samples
            .iter()
            .filter(|x| x.violation == "state_outside_block")
            .map(|x| x.context)
            .collect();
        assert!(contexts.contains(&"base") && contexts.contains(&"transaction"));
        assert!(!contexts.contains(&"block"));
        assert!(
            s.samples.iter().all(|x| !x.pattern.contains(H64)),
            "samples mask values"
        );
    }

    #[test]
    fn samples_are_bounded() {
        let db = temp_db("bounded");
        // Distinct short patterns that survive masking: only non-hex letters,
        // no digits, well under the 120-character cut.
        let letters: Vec<char> = "ghijklmnopqrstuvwxyz".chars().collect();
        let patterns: Vec<String> = letters
            .iter()
            .flat_map(|a| letters.iter().map(move |b| format!("junk:{a}{b}")))
            .take(MAX_SAMPLES + 50)
            .collect();
        assert_eq!(patterns.len(), MAX_SAMPLES + 50, "positive control");
        for key in &patterns {
            assert_eq!(classify(key.as_bytes()), None, "{key} must be unclassified");
            db.put(key, "x").unwrap();
        }
        let s = db.db.state_class_stats();
        assert_eq!(s.unclassified as usize, MAX_SAMPLES + 50);
        assert_eq!(
            s.samples.len(),
            MAX_SAMPLES,
            "the table fills and stops at the cap"
        );
    }
}
