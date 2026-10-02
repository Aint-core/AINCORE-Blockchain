//! G5 A4-S6: the incentivized testnet's scoring (docs/research/incentivized_testnet.md,
//! IT-1..IT-7).
//!
//! It reads chain data only, from a stopped testnet node's datadir (or a copy):
//! blocks with their proposers and anchor rounds, the committee records of each
//! epoch, jail and conviction records, and transaction receipts. It writes the
//! mainnet genesis inputs: `allocations.json` (each qualified operator's bonded
//! stake and bootstrap weight, for `gen-multi --allocations-file`),
//! `accounts.json` (the public track, for `gen-multi --accounts-file`) and
//! `report.json` (every number behind them). Run on any node's datadir at least
//! W (7 days) past the snapshot, so every offense of the window has landed, it
//! gives the same output.

use clap::Args;
use consensus::v4::epoch;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use storage::StateDB;

/// IT-1: the operator track, bonded at mainnet genesis.
pub const OPERATOR_POOL_AIN: u64 = 1_000_000;
/// IT-1: the public track, liquid at mainnet genesis.
pub const PUBLIC_POOL_AIN: u64 = 500_000;
/// IT-6: the most one public account receives.
pub const PUBLIC_CAP_AIN: u64 = 1_000;
/// IT-6: points must fall on this many distinct days.
pub const MIN_DAYS: usize = 3;
/// IT-3: the share of window epochs an operator must sit in the committee.
pub const COMMITTEE_SHARE_BPS: u64 = 9_000;
/// IT-3: an operator's commit share against the median member's.
pub const RELATIVE_COMMIT_BPS: u64 = 9_000;
/// IT-5: mainnet needs at least this many qualified independent operators.
pub const MIN_OPERATORS: usize = 3;
/// IT-5: the founder's bootstrap weight is at most this share of s_min.
pub const FOUNDER_MAX_BPS: u64 = 3_000;

#[derive(Args, Debug)]
pub struct ScoreArgs {
    /// A stopped testnet node's datadir, or a copy of it.
    #[arg(long)]
    pub datadir: String,
    /// The window's first block (IT-2: announced in advance).
    #[arg(long)]
    pub from_height: u64,
    /// The window's last block, the snapshot (IT-2: announced in advance).
    #[arg(long)]
    pub to_height: u64,
    /// The founder's testnet validators: never scored, never paid (IT-3).
    #[arg(long, value_delimiter = ',')]
    pub founder: Vec<String>,
    /// The mainnet s_min in whole AIN (BW-1: 18.5 M).
    #[arg(long, default_value_t = 18_500_000)]
    pub s_min_ain: u64,
    /// The founder's bootstrap weight in whole AIN, at most 30 % of s_min
    /// (IT-5: 5.55 M).
    #[arg(long, default_value_t = 5_550_000)]
    pub founder_bootstrap_ain: u64,
    /// Where to write allocations.json, accounts.json and report.json.
    #[arg(long)]
    pub out_dir: PathBuf,
}

/// One qualified operator's mainnet genesis allocation (IT-4, IT-5).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub address: String,
    pub stake_ain: u64,
    pub bootstrap_ain: u64,
}

/// What the window shows of one committee member (IT-3).
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct OperatorScore {
    pub epochs_in_committee: u64,
    pub slots: u64,
    pub commits: u64,
    /// The lowest BW-6 score over the window, parts per million.
    pub min_score: u64,
    pub jailed: bool,
    pub founder: bool,
    pub qualified: bool,
    /// Why it did not qualify, if it did not.
    pub reason: Option<String>,
}

/// One public account's points (IT-6).
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct PublicScore {
    pub points: u64,
    pub days: usize,
    pub ain: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Report {
    pub from_height: u64,
    pub to_height: u64,
    pub epochs: Vec<u64>,
    /// The median member's commit share, parts per million.
    pub median_commit_ppm: u64,
    pub operators: BTreeMap<String, OperatorScore>,
    pub allocations: Vec<Allocation>,
    pub founder_bootstrap_ain: u64,
    pub public: BTreeMap<String, PublicScore>,
}

fn err(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    msg.into().into()
}

fn block_at(db: &StateDB, height: u64) -> Result<blockchain::Block, Box<dyn std::error::Error>> {
    let raw = db
        .get(&format!("block_{height}"))?
        .ok_or_else(|| err(format!("block {height} is missing from the datadir")))?;
    Ok(serde_json::from_str(&raw)?)
}

/// IT-6: what a successful transaction earns, and for a delegation, that it
/// must be held for an epoch first.
enum Action {
    Points(u64),
    Delegate,
    Undelegate,
    None,
}

fn classify(tx: &executor::Transaction) -> Action {
    let Ok(bytes) = hex::decode(tx.payload.trim_start_matches("0x")) else {
        return Action::None;
    };
    let Ok(vm_move::TransactionPayload::EntryFunction(call)) =
        bcs::from_bytes::<vm_move::TransactionPayload>(&bytes)
    else {
        return Action::None;
    };
    if *call.module.address() != vm_move::system_address() {
        return Action::None;
    }
    match (call.module.name().as_str(), call.function.as_str()) {
        // A transfer to oneself proves nothing.
        ("coin", "transfer") => {
            let to: Option<move_core_types::account_address::AccountAddress> =
                call.args.first().and_then(|a| bcs::from_bytes(a).ok());
            let from = hex::decode(tx.sender.trim_start_matches("0x")).ok();
            match (to, from) {
                (Some(to), Some(from)) if to.to_vec() != from => Action::Points(1),
                _ => Action::None,
            }
        }
        ("delegation", "delegate") => Action::Delegate,
        ("delegation", "undelegate") => Action::Undelegate,
        ("dex", "swap_x_to_y" | "swap_y_to_x" | "add_liquidity") => Action::Points(2),
        ("governance", "vote") => Action::Points(2),
        _ => Action::None,
    }
}

/// Score the window and derive the mainnet allocations (IT-2..IT-6).
pub fn score(
    db: &StateDB,
    from_height: u64,
    to_height: u64,
    founder: &[String],
    s_min_ain: u64,
    founder_bootstrap_ain: u64,
) -> Result<Report, Box<dyn std::error::Error>> {
    if from_height == 0 || to_height < from_height {
        return Err(err("the window must be 1 <= from-height <= to-height"));
    }
    if founder_bootstrap_ain as u128 * 10_000 > s_min_ain as u128 * FOUNDER_MAX_BPS as u128 {
        return Err(err(format!(
            "the founder's bootstrap weight {founder_bootstrap_ain} AIN is over 30 % of s_min"
        )));
    }
    let interval =
        epoch::epoch_interval(db).ok_or_else(|| err("the datadir pins no epoch length"))?;
    let founder: BTreeSet<String> = founder.iter().map(|a| a.to_ascii_lowercase()).collect();

    // IT-3: committee membership, slots and commits per epoch, by the
    // leader schedule exactly as BW-6 counts it.
    let first_epoch = epoch::epoch_of_height(from_height, interval);
    let last_epoch = epoch::epoch_of_height(to_height, interval);
    let mut committees: BTreeMap<u64, Vec<(String, u64)>> = BTreeMap::new();
    for e in first_epoch..=last_epoch {
        let mut stakes: Vec<(String, u64)> = epoch::committee_of(db, e)
            .ok_or_else(|| err(format!("the committee record of epoch {e} is missing")))?
            .into_iter()
            .map(|m| (m.address, m.stake))
            .collect();
        stakes.sort();
        committees.insert(e, stakes);
    }
    let mut per_epoch: BTreeMap<u64, BTreeMap<String, (u64, u64)>> = BTreeMap::new();
    let mut last_round = if from_height > 1 {
        block_at(db, from_height - 1)?.header.round
    } else {
        0
    };
    let mut blocks = Vec::new();
    for h in from_height..=to_height {
        let block = block_at(db, h)?;
        let e = epoch::epoch_of_height(h, interval);
        let stakes = &committees[&e];
        let anchor = block.header.round;
        let counts = per_epoch.entry(e).or_default();
        let mut round = last_round + 1;
        round += round % 2;
        while round <= anchor {
            let leader = blockchain::committee::leader_for_round(round, stakes, 0);
            let entry = counts.entry(leader.clone()).or_insert((0, 0));
            entry.0 += 1;
            if round == anchor && block.header.proposer_id.starts_with(&leader) {
                entry.1 += 1;
            }
            round += 2;
        }
        last_round = last_round.max(anchor);
        blocks.push(block);
    }
    let snapshot_round = blocks.last().map_or(0, |b| b.header.round);

    let mut operators: BTreeMap<String, OperatorScore> = BTreeMap::new();
    for stakes in committees.values() {
        for (address, _) in stakes {
            let s = operators.entry(address.clone()).or_insert(OperatorScore {
                min_score: executor::BOOTSTRAP_SCORE_SCALE,
                ..Default::default()
            });
            s.epochs_in_committee += 1;
        }
    }
    let mut scores: BTreeMap<String, u64> = BTreeMap::new();
    for counts in per_epoch.values() {
        for (address, &(slots, commits)) in counts {
            let Some(s) = operators.get_mut(address) else {
                continue;
            };
            s.slots += slots;
            s.commits += commits;
            let score = scores
                .entry(address.clone())
                .or_insert(executor::BOOTSTRAP_SCORE_SCALE);
            *score = executor::next_bootstrap_score(*score, slots, commits);
            s.min_score = s.min_score.min(*score);
        }
    }
    let mut shares: Vec<u64> = operators
        .values()
        .filter(|s| s.slots > 0)
        .map(|s| (s.commits as u128 * 1_000_000 / s.slots as u128) as u64)
        .collect();
    shares.sort_unstable();
    let median_commit_ppm = if shares.is_empty() {
        0
    } else if shares.len() % 2 == 1 {
        shares[shares.len() / 2]
    } else {
        (shares[shares.len() / 2 - 1] + shares[shares.len() / 2]) / 2
    };
    let epochs = committees.len() as u64;
    for (address, s) in operators.iter_mut() {
        // A jail record names the round of the offense; an offense up to the
        // snapshot's round counts. A conviction comes with a jail record.
        let jail = db.get(&format!("validator:jailed:{address}"))?;
        s.jailed = jail
            .as_deref()
            .map(|r| {
                r.trim()
                    .parse::<u64>()
                    .map_or(true, |round| round <= snapshot_round)
            })
            .unwrap_or(false)
            || db
                .get(&format!("validator:convicted_full:{address}"))?
                .is_some();
        s.founder = founder.contains(address);
        let share = if s.slots == 0 {
            0
        } else {
            (s.commits as u128 * 1_000_000 / s.slots as u128) as u64
        };
        s.reason = if s.founder {
            Some("founder".into())
        } else if s.epochs_in_committee * 10_000 < epochs * COMMITTEE_SHARE_BPS {
            Some(format!(
                "in {} of {epochs} committees",
                s.epochs_in_committee
            ))
        } else if share as u128 * 10_000 < median_commit_ppm as u128 * RELATIVE_COMMIT_BPS as u128 {
            Some(format!(
                "committed {share} ppm of its slots, median {median_commit_ppm}"
            ))
        } else if s.min_score < executor::BOOTSTRAP_SCORE_FLOOR {
            Some(format!("its score fell to {}", s.min_score))
        } else if s.jailed {
            Some("jailed or convicted".into())
        } else {
            None
        };
        s.qualified = s.reason.is_none();
    }

    // IT-4, IT-5: equal stake from the operator track, equal bootstrap
    // weight from what the founder's share leaves; no member at a third.
    let qualified: Vec<String> = operators
        .iter()
        .filter(|(_, s)| s.qualified)
        .map(|(a, _)| a.clone())
        .collect();
    if qualified.len() < MIN_OPERATORS {
        return Err(err(format!(
            "{} operators qualified; mainnet needs at least {MIN_OPERATORS}",
            qualified.len()
        )));
    }
    let n = qualified.len() as u64;
    let stake = OPERATOR_POOL_AIN / n;
    let rest = s_min_ain
        .checked_sub(stake * n + founder_bootstrap_ain)
        .ok_or_else(|| err("s_min is below the operators' stake and the founder's weight"))?;
    let (boot, extra) = (rest / n, rest % n);
    let allocations: Vec<Allocation> = qualified
        .iter()
        .enumerate()
        .map(|(i, address)| Allocation {
            address: address.clone(),
            stake_ain: stake,
            bootstrap_ain: boot + u64::from((i as u64) < extra),
        })
        .collect();
    if let Some(a) = allocations
        .iter()
        .find(|a| 3 * (a.stake_ain as u128 + a.bootstrap_ain as u128) >= s_min_ain as u128)
    {
        return Err(err(format!("{} would hold a third of s_min", a.address)));
    }

    // IT-6: points on at least three distinct days, by transactions that
    // succeeded; a delegation counts once held for an epoch inside the window.
    let validators: BTreeSet<&String> = operators.keys().collect();
    let mut points: BTreeMap<String, (u64, BTreeSet<u64>)> = BTreeMap::new();
    let mut delegations: Vec<(String, u64, u64)> = Vec::new();
    let mut undelegations: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for block in &blocks {
        let day = block.header.timestamp / 86_400;
        for raw in &block.transactions {
            let Ok(tx) = serde_json::from_str::<executor::Transaction>(raw) else {
                continue;
            };
            let receipt_key = format!("tx_receipt:{}", crypto::hash_hex(raw.as_bytes()));
            let succeeded = db
                .get(&receipt_key)?
                .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
                .is_some_and(|r| r["status"] == "success");
            if !succeeded {
                continue;
            }
            let sender = tx.sender.trim_start_matches("0x").to_ascii_lowercase();
            if validators.contains(&sender) || founder.contains(&sender) {
                continue;
            }
            match classify(&tx) {
                Action::Points(p) => {
                    let entry = points.entry(sender).or_default();
                    entry.0 += p;
                    entry.1.insert(day);
                }
                Action::Delegate => delegations.push((sender, block.header.height, day)),
                Action::Undelegate => undelegations
                    .entry(sender)
                    .or_default()
                    .push(block.header.height),
                Action::None => {}
            }
        }
    }
    for (sender, height, day) in delegations {
        let held = height + interval <= to_height
            && !undelegations
                .get(&sender)
                .is_some_and(|hs| hs.iter().any(|&u| u > height && u <= height + interval));
        if held {
            let entry = points.entry(sender).or_default();
            entry.0 += 3;
            entry.1.insert(day);
        }
    }
    let eligible: BTreeMap<String, (u64, usize)> = points
        .into_iter()
        .filter(|(_, (_, days))| days.len() >= MIN_DAYS)
        .map(|(a, (p, days))| (a, (p, days.len())))
        .collect();
    let total: u128 = eligible.values().map(|(p, _)| *p as u128).sum();
    let public: BTreeMap<String, PublicScore> = eligible
        .into_iter()
        .map(|(a, (p, days))| {
            let pro_rata = (PUBLIC_POOL_AIN as u128 * p as u128 / total.max(1)) as u64;
            (
                a,
                PublicScore {
                    points: p,
                    days,
                    ain: pro_rata.min(PUBLIC_CAP_AIN),
                },
            )
        })
        .collect();

    Ok(Report {
        from_height,
        to_height,
        epochs: committees.keys().copied().collect(),
        median_commit_ppm,
        operators,
        allocations,
        founder_bootstrap_ain,
        public,
    })
}

/// `score-testnet`: score the window and write the three files.
pub fn run(args: ScoreArgs) -> Result<(), Box<dyn std::error::Error>> {
    let db = StateDB::open(&args.datadir)
        .map_err(|e| format!("cannot open {} (stop the node first): {e}", args.datadir))?;
    let report = score(
        &db,
        args.from_height,
        args.to_height,
        &args.founder,
        args.s_min_ain,
        args.founder_bootstrap_ain,
    )?;
    std::fs::create_dir_all(&args.out_dir)?;
    let accounts: Vec<crate::multi_genesis::AccountSpec> = report
        .public
        .iter()
        .filter(|(_, p)| p.ain > 0)
        .map(|(a, p)| crate::multi_genesis::AccountSpec {
            address: a.clone(),
            balance_ain: p.ain as u128,
        })
        .collect();
    let write = |name: &str, json: String| std::fs::write(args.out_dir.join(name), json);
    write(
        "allocations.json",
        serde_json::to_string_pretty(&report.allocations)?,
    )?;
    write("accounts.json", serde_json::to_string_pretty(&accounts)?)?;
    write("report.json", serde_json::to_string_pretty(&report)?)?;
    let qualified = report.allocations.len();
    let paid: u64 = accounts.iter().map(|a| a.balance_ain as u64).sum();
    println!(
        "🏁 {qualified} operators qualified ({} AIN bonded, {} AIN of bootstrap weight each), \
         {} public accounts paid {paid} AIN; written to {}",
        report.allocations[0].stake_ain,
        report.allocations[0].bootstrap_ain,
        accounts.len(),
        args.out_dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockchain::{Block, BlockHeader};
    use std::sync::Arc;

    fn temp_db(name: &str) -> Arc<StateDB> {
        let dir = std::env::temp_dir().join(format!(
            "aincore_score_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Arc::new(StateDB::open(dir.to_str().unwrap()).unwrap())
    }

    fn member(seed: u8, stake: u64) -> blockchain::committee::ValidatorInfo {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        blockchain::committee::ValidatorInfo {
            address: crypto::derive_address(key.verifying_key().as_bytes()).unwrap(),
            stake,
            ed25519_public_key: hex::encode(key.verifying_key().as_bytes()),
            bls_public_key: String::new(),
            bls_pop: String::new(),
        }
    }

    fn tx(sender_seed: u8, module: &str, function: &str, args: Vec<Vec<u8>>) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[sender_seed; 32]);
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                vm_move::system_address(),
                move_core_types::identifier::Identifier::new(module).unwrap(),
            ),
            function: function.into(),
            ty_args: vec![],
            args,
        };
        serde_json::json!({
            "chain_id": "AINCORE-TESTNET",
            "sender": crypto::derive_address(key.verifying_key().as_bytes()).unwrap(),
            "input_objects": [],
            "payload": hex::encode(
                bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap()
            ),
            "gas_limit": 100_000,
            "gas_price": 1,
            "sequence_number": sender_seed as u64,
            "public_key": hex::encode(key.verifying_key().as_bytes()),
            "signature": "",
        })
        .to_string()
    }

    fn address_of(seed: u8) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        crypto::derive_address(key.verifying_key().as_bytes()).unwrap()
    }

    /// A testnet of four equal validators over 3 epochs of I = 20 (60 blocks,
    /// one a day): blocks follow the leader schedule, and `offline` members'
    /// rounds are skipped. `txs` go into the given heights, all succeeding.
    fn testnet(
        name: &str,
        offline: &[usize],
        txs: &[(u64, String)],
    ) -> (Arc<StateDB>, Vec<String>) {
        let db = temp_db(name);
        let members: Vec<_> = (1..=4).map(|s| member(s, 1_000)).collect();
        let addresses: Vec<String> = members.iter().map(|m| m.address.clone()).collect();
        let _seed = db.seeding();
        db.put(epoch::EPOCH_INTERVAL_KEY, "20").unwrap();
        db.put(
            "genesis:validator_set:v1",
            &serde_json::to_string(&members).unwrap(),
        )
        .unwrap();
        for e in 1..3u64 {
            let start = epoch::EpochStart {
                epoch: e,
                first_round: 0,
                sentinel: String::new(),
                committee: members.clone(),
                prev_closing_round: 0,
                prev_anchor: String::new(),
                prev_block_hash: String::new(),
                prev_height: 0,
                prev_timestamp: 0,
            };
            db.put(
                &epoch::epoch_start_key(e),
                &serde_json::to_string(&start).unwrap(),
            )
            .unwrap();
        }
        let mut stakes: Vec<(String, u64)> = addresses.iter().map(|a| (a.clone(), 1_000)).collect();
        stakes.sort();
        let mut round = 0;
        for h in 1..=60u64 {
            round += 2;
            while offline.iter().any(|&i| {
                addresses[i] == blockchain::committee::leader_for_round(round, &stakes, 0)
            }) {
                round += 2;
            }
            let transactions: Vec<String> = txs
                .iter()
                .filter(|(at, _)| *at == h)
                .map(|(_, t)| t.clone())
                .collect();
            for t in &transactions {
                db.put(
                    &format!("tx_receipt:{}", crypto::hash_hex(t.as_bytes())),
                    &serde_json::json!({ "status": "success" }).to_string(),
                )
                .unwrap();
            }
            let block = Block {
                header: BlockHeader {
                    height: h,
                    prev_hash: String::new(),
                    tx_hash: String::new(),
                    state_root: String::new(),
                    receipts_root: String::new(),
                    vertices_root: String::new(),
                    evidence_root: String::new(),
                    proposer_id: blockchain::committee::leader_for_round(round, &stakes, 0),
                    round,
                    timestamp: h * 86_400,
                    hash: String::new(),
                },
                transactions,
                committed_vertices: vec![],
                anchor_hash: String::new(),
                proposer_signature: String::new(),
                proposer_signer: String::new(),
                slash_evidence: vec![],
            };
            db.put(
                &format!("block_{h}"),
                &serde_json::to_string(&block).unwrap(),
            )
            .unwrap();
        }
        drop(_seed);
        (db, addresses)
    }

    /// IT-3..IT-5: online operators qualify and share the operator track and
    /// what the founder's bootstrap weight leaves; an offline one, a jailed
    /// one and the founder do not, each with its reason.
    #[test]
    fn the_testnet_scores_operators_by_their_leader_slots() {
        let (db, a) = testnet("operators", &[3], &[]);
        {
            let _seed = db.seeding();
            db.put(&format!("validator:jailed:{}", a[2]), "7").unwrap();
        }
        let refused = score(&db, 1, 60, &[a[0].clone()], 18_500_000, 5_550_000).unwrap_err();
        assert!(refused.to_string().contains("at least 3"), "{refused}");

        // Without the jail and the founder, three qualify.
        let (db, a) = testnet("operators3", &[3], &[]);
        let r = score(&db, 1, 60, &[], 18_500_000, 5_550_000).unwrap();
        assert_eq!(r.epochs, vec![0, 1, 2]);
        let offline = &r.operators[&a[3]];
        assert!(offline.slots > 0 && offline.commits == 0);
        assert!(offline
            .reason
            .as_deref()
            .unwrap()
            .contains("committed 0 ppm"));
        let online = &r.operators[&a[0]];
        assert_eq!(online.commits, online.slots);
        assert_eq!(online.epochs_in_committee, 3);
        assert_eq!(r.allocations.len(), 3);
        // 1,000,000 / 3 = 333,333 bonded each; (18,500,000 - 999,999 -
        // 5,550,000) / 3 = 3,983,333 rest 2: the first two take 1 more.
        let boots: Vec<u64> = r.allocations.iter().map(|x| x.bootstrap_ain).collect();
        assert!(r.allocations.iter().all(|x| x.stake_ain == 333_333));
        assert_eq!(boots, vec![3_983_334, 3_983_334, 3_983_333]);
        let total: u64 = r
            .allocations
            .iter()
            .map(|x| x.stake_ain + x.bootstrap_ain)
            .sum();
        assert_eq!(
            total + 5_550_000,
            18_500_000,
            "the genesis committee weighs s_min"
        );

        // A founder over 30 % is refused.
        assert!(score(&db, 1, 60, &[], 18_500_000, 5_550_001).is_err());
    }

    /// A jail whose offense round is past the snapshot does not count.
    #[test]
    fn a_jail_counts_only_up_to_the_snapshot() {
        let (db, a) = testnet("jail", &[], &[]);
        {
            let _seed = db.seeding();
            db.put(&format!("validator:jailed:{}", a[1]), "999999")
                .unwrap();
            db.put(&format!("validator:jailed:{}", a[2]), "8").unwrap();
        }
        let r = score(&db, 1, 60, &[], 18_500_000, 5_550_000).unwrap();
        assert!(r.operators[&a[1]].qualified, "jailed after the snapshot");
        assert_eq!(
            r.operators[&a[2]].reason.as_deref(),
            Some("jailed or convicted")
        );
    }

    /// IT-6: points by kind, on three distinct days, from successful
    /// transactions only; a delegation counts once held for an epoch; a
    /// transfer to oneself counts nothing; validators earn nothing here; the
    /// pool is shared pro rata under the cap.
    #[test]
    fn the_public_track_counts_points_on_three_days() {
        let addr = |seed: u8| {
            move_core_types::account_address::AccountAddress::from_hex_literal(&format!(
                "0x{}",
                address_of(seed)
            ))
            .unwrap()
        };
        let transfer = |from: u8, to: u8| {
            tx(
                from,
                "coin",
                "transfer",
                vec![
                    bcs::to_bytes(&addr(to)).unwrap(),
                    bcs::to_bytes(&1u128).unwrap(),
                ],
            )
        };
        let mut txs = vec![
            // 50 on 3 days: transfers and a swap.
            (1, transfer(50, 51)),
            (2, transfer(50, 51)),
            (3, tx(50, "dex", "swap_x_to_y", vec![])),
            // 51 on 2 days: not eligible.
            (4, transfer(51, 50)),
            (5, transfer(51, 50)),
            // 52: a vote, a delegation held, and one undelegated too soon.
            (6, tx(52, "governance", "vote", vec![])),
            (7, tx(52, "delegation", "delegate", vec![])),
            (30, tx(52, "delegation", "delegate", vec![])),
            (35, tx(52, "delegation", "undelegate", vec![])),
            (40, transfer(52, 50)),
            // 53: only transfers to itself.
            (8, transfer(53, 53)),
            (9, transfer(53, 53)),
            (10, transfer(53, 53)),
            // A validator earns nothing on the public track.
            (11, transfer(1, 50)),
            (12, transfer(1, 50)),
            (13, transfer(1, 50)),
        ];
        // 54 transacts on 3 days but its third transaction failed.
        txs.push((14, transfer(54, 50)));
        txs.push((15, transfer(54, 50)));
        let failed = transfer(54, 51);
        txs.push((16, failed.clone()));
        let (db, _) = testnet("public", &[], &txs);
        {
            let _seed = db.seeding();
            db.put(
                &format!("tx_receipt:{}", crypto::hash_hex(failed.as_bytes())),
                &serde_json::json!({ "status": "aborted" }).to_string(),
            )
            .unwrap();
        }
        let r = score(&db, 1, 60, &[], 18_500_000, 5_550_000).unwrap();
        let p = |seed: u8| r.public.get(&address_of(seed)).cloned();
        assert_eq!(p(50).map(|s| (s.points, s.days)), Some((4, 3)));
        assert_eq!(p(51), None, "two days");
        assert_eq!(p(52).map(|s| (s.points, s.days)), Some((2 + 3 + 1, 3)));
        assert_eq!(p(53), None, "transfers to itself");
        assert_eq!(p(1), None, "a validator");
        assert_eq!(p(54), None, "the failed third");
        // 500,000 x 4 / 10 is over the 1,000 cap.
        assert_eq!(p(50).unwrap().ain, PUBLIC_CAP_AIN);
    }
}
