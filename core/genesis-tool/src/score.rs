//! G5 A4-S6: the incentivized testnet's scoring (docs/research/incentivized_testnet.md,
//! IT-1..IT-7).
//!
//! It reads chain data only, from a stopped testnet node's datadir (or a copy):
//! blocks with their proposers and anchor rounds, the committee records of each
//! epoch, jail records, and transaction receipts. It writes the mainnet genesis
//! inputs: `allocations.json` (each qualified operator's bonded stake and
//! bootstrap weight, for `gen-multi --allocations-file`), `accounts.json` (the
//! public track, for `gen-multi --accounts-file`) and `report.json` (every
//! number behind them). Run on an archive node's datadir
//! (`AINCORE_STORAGE_MODE=archive`: a full node prunes blocks and receipts
//! past 100,000 blocks, B91) at least W (7 days) past the snapshot, so every
//! offense of the window has landed, it gives the same output on any of
//! them.

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
/// IT-6: the most one funding cluster receives.
pub const PUBLIC_CAP_AIN: u64 = 1_000;
/// IT-6: points must fall on this many distinct days.
pub const MIN_DAYS: usize = 3;
/// IT-3: the share of window blocks an operator must sit in the committee.
pub const COMMITTEE_SHARE_BPS: u64 = 9_000;
/// IT-3: an operator's commit share against the median operator's.
pub const RELATIVE_COMMIT_BPS: u64 = 9_000;
/// IT-5: mainnet needs at least this many qualified operators, so that two
/// forfeits still leave four parties (BW-11).
pub const MIN_OPERATORS: usize = 5;
/// IT-5: the founder's bootstrap weight is at most this share of s_min.
pub const FOUNDER_MAX_BPS: u64 = 3_000;

#[derive(Args, Debug)]
pub struct ScoreArgs {
    /// A stopped testnet archive node's datadir, or a copy of it.
    #[arg(long)]
    pub datadir: String,
    /// The window's first block (IT-2: announced in advance).
    #[arg(long)]
    pub from_height: u64,
    /// The window's last block, the snapshot (IT-2: announced in advance).
    #[arg(long)]
    pub to_height: u64,
    /// The founder's testnet validators: never scored, never paid, and below
    /// a third of every window committee (IT-2, IT-3).
    #[arg(long, value_delimiter = ',')]
    pub founder: Vec<String>,
    /// The testnet faucet account: the root of every funding cluster (IT-6).
    #[arg(long)]
    pub faucet: String,
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
    pub blocks_in_committee: u64,
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
    /// The account the faucet funded, from which this one's funds came.
    pub cluster: String,
    pub ain: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Report {
    pub from_height: u64,
    pub to_height: u64,
    pub epochs: Vec<u64>,
    /// The median non-founder member's commit share, parts per million.
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

/// An address argument of an entry call, as lowercase hex.
fn address_arg(call: &vm_move::EntryFunctionCall, index: usize) -> Option<String> {
    let addr: move_core_types::account_address::AccountAddress =
        bcs::from_bytes(call.args.get(index)?).ok()?;
    Some(hex::encode(addr.to_vec()))
}

/// IT-6: what a successful transaction does that the public track counts.
/// Argument 0 of an entry call is the signer slot; the call's own arguments
/// follow it.
#[derive(Debug, PartialEq)]
enum Action {
    Transfer { to: String, amount: u128 },
    Delegate { validator: String },
    Undelegate { validator: String },
    Points { kind: &'static str, points: u64 },
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
        // B79: only AIN, and only an amount: a zero transfer, or one of
        // another coin, made a Sybil's "funder" anyone it liked.
        ("coin", "transfer") => {
            let ain = matches!(call.ty_args.as_slice(), [tag] if is_ain(tag));
            let amount = call
                .args
                .get(2)
                .and_then(|a| bcs::from_bytes::<u128>(a).ok());
            match (ain, amount, address_arg(&call, 1)) {
                (true, Some(n), Some(to)) if n > 0 => Action::Transfer { to, amount: n },
                _ => Action::None,
            }
        }
        ("delegation", "delegate") => {
            address_arg(&call, 1).map_or(Action::None, |validator| Action::Delegate { validator })
        }
        ("delegation", "undelegate") => {
            address_arg(&call, 1).map_or(Action::None, |validator| Action::Undelegate { validator })
        }
        ("dex", "swap_x_to_y" | "swap_y_to_x" | "add_liquidity") => Action::Points {
            kind: "dex",
            points: 2,
        },
        ("governance", "vote") => Action::Points {
            kind: "vote",
            points: 2,
        },
        _ => Action::None,
    }
}

/// B79: `0x1::staking::AincoreCoin`.
fn is_ain(tag: &move_core_types::language_storage::TypeTag) -> bool {
    matches!(tag, move_core_types::language_storage::TypeTag::Struct(s)
        if s.address == vm_move::system_address()
            && s.module.as_str() == "staking"
            && s.name.as_str() == "AincoreCoin"
            && s.type_params.is_empty())
}

/// B79: the cluster of every account whose funding does not lead back to
/// the faucet (funded through a module, by an account outside the tree, or
/// not at all): one cluster, capped once, so such accounts gain nothing by
/// being many.
pub const UNATTRIBUTED: &str = "unattributed";

fn canonical(address: &str) -> String {
    address.trim_start_matches("0x").to_ascii_lowercase()
}

/// Score the window and derive the mainnet allocations (IT-2..IT-6).
pub fn score(
    db: &StateDB,
    from_height: u64,
    to_height: u64,
    founder: &[String],
    faucet: &str,
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
    // B91: the funding tree reads every block from 1 with its receipts, and
    // a full node prunes blocks and their receipts past its retention
    // (100,000 blocks by default): only an archive node holds them all.
    for h in [1, to_height] {
        if db.get(&format!("block_{h}"))?.is_none() {
            return Err(err(format!(
                "block {h} is missing: score an archive node's datadir \
                 (AINCORE_STORAGE_MODE=archive); a full node prunes old blocks and receipts"
            )));
        }
    }
    let interval =
        epoch::epoch_interval(db).ok_or_else(|| err("the datadir pins no epoch length"))?;
    // The founder holds the faucet: if the faucet's account validates, it
    // counts as the founder's.
    let faucet = canonical(faucet);
    let founder: BTreeSet<String> = founder
        .iter()
        .map(|a| canonical(a))
        .chain(std::iter::once(faucet.clone()))
        .collect();

    // IT-2: every window committee, with the founder below a third of each.
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
        let total: u128 = stakes.iter().map(|(_, w)| *w as u128).sum();
        let held: u128 = stakes
            .iter()
            .filter(|(a, _)| founder.contains(a))
            .map(|(_, w)| *w as u128)
            .sum();
        if 3 * held >= total {
            return Err(err(format!(
                "the founder held {held} of {total} in epoch {e}'s committee: a third or more, \
                 so the window was not fair"
            )));
        }
        committees.insert(e, stakes);
    }

    // IT-3: membership, slots and commits per epoch, by the leader schedule
    // exactly as BW-6 counts it.
    let mut per_epoch: BTreeMap<u64, BTreeMap<String, (u64, u64)>> = BTreeMap::new();
    let mut operators: BTreeMap<String, OperatorScore> = BTreeMap::new();
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
        for (address, _) in stakes {
            operators
                .entry(address.clone())
                .or_insert(OperatorScore {
                    min_score: executor::BOOTSTRAP_SCORE_SCALE,
                    ..Default::default()
                })
                .blocks_in_committee += 1;
        }
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
    let share_of =
        |s: &OperatorScore| (s.commits as u128 * 1_000_000 / s.slots.max(1) as u128) as u64;
    // The median of the operators, never of the founder's nodes: the founder
    // cannot move the bar.
    let mut shares: Vec<u64> = operators
        .iter()
        .filter(|(a, s)| s.slots > 0 && !founder.contains(*a))
        .map(|(_, s)| share_of(s))
        .collect();
    shares.sort_unstable();
    let median_commit_ppm = match shares.len() {
        0 => 0,
        n if n % 2 == 1 => shares[n / 2],
        n => (shares[n / 2 - 1] + shares[n / 2]) / 2,
    };
    let window_blocks = to_height - from_height + 1;
    for (address, s) in operators.iter_mut() {
        // A jail record names the round of the offense; an offense up to the
        // snapshot's round counts. A conviction always comes with one.
        s.jailed = db
            .get(&format!("validator:jailed:{address}"))?
            .is_some_and(|r| {
                r.trim()
                    .parse::<u64>()
                    .map_or(true, |round| round <= snapshot_round)
            });
        s.founder = founder.contains(address);
        let share = share_of(s);
        s.reason = if s.founder {
            Some("founder".into())
        } else if s.blocks_in_committee * 10_000 < window_blocks * COMMITTEE_SHARE_BPS {
            Some(format!(
                "in the committee for {} of {window_blocks} blocks",
                s.blocks_in_committee
            ))
        } else if s.slots == 0 {
            Some("no leader slots in the window".into())
        } else if share as u128 * 10_000 < median_commit_ppm as u128 * RELATIVE_COMMIT_BPS as u128 {
            Some(format!(
                "committed {share} ppm of its slots, median {median_commit_ppm}"
            ))
        } else if s.min_score < executor::BOOTSTRAP_SCORE_FLOOR {
            Some(format!("its score fell to {}", s.min_score))
        } else if s.jailed {
            Some("jailed".into())
        } else {
            None
        };
        s.qualified = s.reason.is_none();
    }

    // IT-4, IT-5: equal stake from the operator track, equal bootstrap
    // weight from what the founder's share leaves. With five or more
    // operators no share can reach a third: (s_min - 0) / 5 is 20 %.
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

    // IT-6: the funding tree. Each account's funder is the sender of the
    // first successful transfer it received, from genesis on; its cluster is
    // the account the faucet funded at the top of that chain. B79: an AIN
    // transfer of some amount, or a paymaster sponsoring the account's
    // transaction (it pays for the account); a chain that does not reach the
    // faucet is `UNATTRIBUTED`.
    let succeeded = |raw: &str| -> Result<bool, Box<dyn std::error::Error>> {
        let key = format!("tx_receipt:{}", crypto::hash_hex(raw.as_bytes()));
        Ok(db
            .get(&key)?
            .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
            .is_some_and(|r| r["status"] == "success"))
    };
    // B128: an account is funded by the sender that sent it the most AIN in
    // all (the first sender was its funder, so one quantum sent ahead moved
    // an honest account into the sender's cluster); a direct faucet transfer
    // makes it a root (B113); a paymaster funds only an account no AIN
    // transfer did.
    let mut rooted: BTreeSet<String> = BTreeSet::new();
    let mut received: BTreeMap<String, BTreeMap<String, u128>> = BTreeMap::new();
    let mut sponsor: BTreeMap<String, String> = BTreeMap::new();
    for h in 1..=to_height {
        let block = if h >= from_height {
            blocks[(h - from_height) as usize].clone()
        } else {
            block_at(db, h)?
        };
        for raw in &block.transactions {
            let Ok(tx) = serde_json::from_str::<executor::Transaction>(raw) else {
                continue;
            };
            let sender = canonical(&tx.sender);
            let payer = executor::admission::payer_address(&tx).map(|p| canonical(&p));
            let sponsored = payer.filter(|p| *p != sender);
            let transfer = match classify(&tx) {
                Action::Transfer { to, amount } if to != sender => Some((to, amount)),
                _ => None,
            };
            if sponsored.is_none() && transfer.is_none() {
                continue;
            }
            if !succeeded(raw)? {
                continue;
            }
            if let Some(payer) = sponsored {
                sponsor.entry(sender.clone()).or_insert(payer);
            }
            if let Some((to, amount)) = transfer {
                if sender == faucet {
                    rooted.insert(to);
                } else {
                    let sent = received.entry(to).or_default().entry(sender).or_insert(0);
                    *sent = sent.saturating_add(amount);
                }
            }
        }
    }
    let mut funder: BTreeMap<String, String> = sponsor;
    for (to, senders) in received {
        // The largest total; among equal totals, the smallest address.
        if let Some((from, _)) = senders
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        {
            funder.insert(to, from.clone());
        }
    }
    for to in rooted {
        funder.insert(to, faucet.clone());
    }
    let cluster_of = |account: &str| -> String {
        let mut at = account.to_string();
        let mut seen = BTreeSet::new();
        loop {
            match funder.get(&at) {
                Some(f) if *f == faucet => return at,
                Some(f) if seen.insert(at.clone()) => at = f.clone(),
                _ => return UNATTRIBUTED.to_string(),
            }
        }
    };

    // Points: each kind counts once per account and UTC day of block time;
    // a delegation counts once held for an epoch inside the window (no
    // undelegation from the same pool within I blocks); only successful
    // transactions; never validators of the window or the founder.
    let validators: BTreeSet<&String> = operators.keys().collect();
    let mut earned: BTreeMap<String, BTreeMap<(u64, &'static str), u64>> = BTreeMap::new();
    let mut delegations: Vec<(String, String, u64, u64)> = Vec::new();
    let mut undelegations: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();
    for block in &blocks {
        let day = block.header.timestamp / 86_400;
        for raw in &block.transactions {
            let Ok(tx) = serde_json::from_str::<executor::Transaction>(raw) else {
                continue;
            };
            let sender = canonical(&tx.sender);
            if validators.contains(&sender) || founder.contains(&sender) || sender == faucet {
                continue;
            }
            let action = classify(&tx);
            if action == Action::None || !succeeded(raw)? {
                continue;
            }
            match action {
                Action::Transfer { to, .. } if to != sender => {
                    earned
                        .entry(sender)
                        .or_default()
                        .insert((day, "transfer"), 1);
                }
                Action::Points { kind, points } => {
                    earned
                        .entry(sender)
                        .or_default()
                        .insert((day, kind), points);
                }
                Action::Delegate { validator } => {
                    delegations.push((sender, validator, block.header.height, day))
                }
                Action::Undelegate { validator } => undelegations
                    .entry((sender, validator))
                    .or_default()
                    .push(block.header.height),
                _ => {}
            }
        }
    }
    for (sender, validator, height, day) in delegations {
        let pulled = undelegations
            .get(&(sender.clone(), validator))
            .is_some_and(|hs| hs.iter().any(|&u| u > height && u <= height + interval));
        if height + interval <= to_height && !pulled {
            earned
                .entry(sender)
                .or_default()
                .insert((day, "delegation"), 3);
        }
    }
    let mut eligible: BTreeMap<String, (u64, usize, String)> = BTreeMap::new();
    for (account, days) in earned {
        let distinct: BTreeSet<u64> = days.keys().map(|(d, _)| *d).collect();
        if distinct.len() >= MIN_DAYS {
            let points = days.values().sum();
            let cluster = cluster_of(&account);
            eligible.insert(account, (points, distinct.len(), cluster));
        }
    }
    // The pool pro rata by points, capped per funding cluster; a cluster's
    // share is split among its accounts by points. What the cap leaves stays
    // unminted.
    let total: u128 = eligible.values().map(|(p, _, _)| *p as u128).sum();
    let mut clusters: BTreeMap<&String, u64> = BTreeMap::new();
    for (p, _, c) in eligible.values() {
        *clusters.entry(c).or_default() += p;
    }
    let cluster_ain: BTreeMap<&String, (u64, u64)> = clusters
        .iter()
        .map(|(c, &p)| {
            let pro_rata = (PUBLIC_POOL_AIN as u128 * p as u128 / total.max(1)) as u64;
            (*c, (pro_rata.min(PUBLIC_CAP_AIN), p))
        })
        .collect();
    let public: BTreeMap<String, PublicScore> = eligible
        .iter()
        .map(|(a, (p, days, c))| {
            let (ain, points) = cluster_ain[c];
            (
                a.clone(),
                PublicScore {
                    points: *p,
                    days: *days,
                    cluster: c.clone(),
                    ain: (ain as u128 * *p as u128 / points.max(1) as u128) as u64,
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
        &args.faucet,
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
    let paid: u64 = accounts.iter().map(|a| a.balance_ain as u64).sum();
    println!(
        "🏁 {} operators qualified ({} AIN bonded, {} AIN of bootstrap weight each), \
         {} public accounts paid {paid} AIN; written to {}",
        report.allocations.len(),
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
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = storage::test_dir::process_dir().join(format!(
            "aincore_score_{name}_{}_{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(StateDB::open(dir.to_str().unwrap()).unwrap())
    }

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn address_of(seed: u8) -> String {
        crypto::derive_address(key(seed).verifying_key().as_bytes()).unwrap()
    }

    fn move_address(seed: u8) -> move_core_types::account_address::AccountAddress {
        move_core_types::account_address::AccountAddress::from_hex_literal(&format!(
            "0x{}",
            address_of(seed)
        ))
        .unwrap()
    }

    fn member(seed: u8, stake: u64) -> blockchain::committee::ValidatorInfo {
        blockchain::committee::ValidatorInfo {
            address: address_of(seed),
            stake,
            ed25519_public_key: hex::encode(key(seed).verifying_key().as_bytes()),
            bls_public_key: String::new(),
            bls_pop: String::new(),
        }
    }

    /// An entry call as clients send it: argument 0 is the signer slot (the
    /// sender), the call's own arguments follow.
    fn tx(sender: u8, module: &str, function: &str, args: Vec<Vec<u8>>, nonce: u64) -> String {
        let mut all = vec![bcs::to_bytes(&move_address(sender)).unwrap()];
        all.extend(args);
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                vm_move::system_address(),
                move_core_types::identifier::Identifier::new(module).unwrap(),
            ),
            function: function.into(),
            ty_args: vec![],
            args: all,
        };
        serde_json::json!({
            "chain_id": "AINCORE-TESTNET",
            "sender": address_of(sender),
            "input_objects": [],
            "payload": hex::encode(
                bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap()
            ),
            "gas_limit": 100_000,
            "gas_price": 1,
            "sequence_number": nonce,
            "public_key": hex::encode(key(sender).verifying_key().as_bytes()),
            "signature": "",
        })
        .to_string()
    }

    fn transfer(from: u8, to: u8, nonce: u64) -> String {
        coin_transfer(from, to, 1, ain(), nonce)
    }

    fn ain() -> move_core_types::language_storage::TypeTag {
        coin_tag("staking", "AincoreCoin")
    }

    fn coin_tag(module: &str, name: &str) -> move_core_types::language_storage::TypeTag {
        move_core_types::language_storage::TypeTag::Struct(Box::new(
            move_core_types::language_storage::StructTag {
                address: vm_move::system_address(),
                module: move_core_types::identifier::Identifier::new(module).unwrap(),
                name: move_core_types::identifier::Identifier::new(name).unwrap(),
                type_params: vec![],
            },
        ))
    }

    fn coin_transfer(
        from: u8,
        to: u8,
        amount: u128,
        coin: move_core_types::language_storage::TypeTag,
        nonce: u64,
    ) -> String {
        let raw = tx(
            from,
            "coin",
            "transfer",
            vec![
                bcs::to_bytes(&move_address(to)).unwrap(),
                bcs::to_bytes(&amount).unwrap(),
            ],
            nonce,
        );
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                vm_move::system_address(),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".into(),
            ty_args: vec![coin],
            args: vec![
                bcs::to_bytes(&move_address(from)).unwrap(),
                bcs::to_bytes(&move_address(to)).unwrap(),
                bcs::to_bytes(&amount).unwrap(),
            ],
        };
        v["payload"] = serde_json::json!(hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap()
        ));
        v.to_string()
    }

    /// `raw` with `payer`'s key as its paymaster.
    fn sponsored(raw: String, payer: u8) -> String {
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["paymaster"] = serde_json::json!(hex::encode(key(payer).verifying_key().as_bytes()));
        v["paymaster_signature"] = serde_json::json!("");
        v.to_string()
    }

    /// A testnet of `stakes` (validators seeded 1..) over 3 epochs of I = 20
    /// (60 blocks, one a day): blocks follow the leader schedule, and
    /// `offline` validators' rounds are skipped. `txs` go into the given
    /// heights, all succeeding.
    fn testnet(
        name: &str,
        stakes: &[u64],
        offline: &[usize],
        txs: &[(u64, String)],
    ) -> (Arc<StateDB>, Vec<String>) {
        let db = temp_db(name);
        let members: Vec<_> = stakes
            .iter()
            .enumerate()
            .map(|(i, &s)| member(i as u8 + 1, s))
            .collect();
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
        let mut sorted: Vec<(String, u64)> = members
            .iter()
            .map(|m| (m.address.clone(), m.stake))
            .collect();
        sorted.sort();
        let mut round = 0;
        for h in 1..=60u64 {
            round += 2;
            while offline.iter().any(|&i| {
                addresses[i] == blockchain::committee::leader_for_round(round, &sorted, 0)
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
                    da_root: String::new(),
                    proposer_id: blockchain::committee::leader_for_round(round, &sorted, 0),
                    round,
                    timestamp: h * 86_400,
                    hash: String::new(),
                },
                transactions,
                committed_vertices: vec![],
                committed_authors: vec![],
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

    const FAUCET: u8 = 90;

    /// IT-3..IT-5: online operators qualify and share the operator track and
    /// what the founder's bootstrap weight leaves; an offline one does not,
    /// and the founder's nodes neither qualify nor set the median.
    #[test]
    fn the_testnet_scores_operators_by_their_leader_slots() {
        // Four founder nodes of 500 (indices 0-3, 25 % together), all
        // offline, and six operators of 1,000, one of them (index 9) offline.
        let stakes = [500, 500, 500, 500, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000];
        let (db, a) = testnet("operators", &stakes, &[0, 1, 2, 3, 9], &[]);
        let faucet = address_of(FAUCET);
        let founder: Vec<String> = a[..4].to_vec();
        let r = score(&db, 1, 60, &founder, &faucet, 18_500_000, 5_550_000).unwrap();
        assert_eq!(r.epochs, vec![0, 1, 2]);
        let offline = &r.operators[&a[9]];
        assert!(offline.slots > 0 && offline.commits == 0);
        assert!(offline
            .reason
            .as_deref()
            .unwrap()
            .contains("committed 0 ppm"));
        assert_eq!(r.operators[&a[0]].reason.as_deref(), Some("founder"));
        let online = &r.operators[&a[4]];
        assert_eq!(online.commits, online.slots);
        assert_eq!(online.blocks_in_committee, 60);
        // The median is the operators' (1,000,000 for the five online, 0 for
        // the offline). The founder's offline nodes are not in it: with them
        // it would be 500,000, and a slow operator could pass.
        assert!((0..4).all(|i| r.operators[&a[i]].slots > 0));
        assert_eq!(r.median_commit_ppm, 1_000_000);
        assert_eq!(r.allocations.len(), 5);
        // 1,000,000 / 5 = 200,000 bonded each; (18,500,000 - 1,000,000 -
        // 5,550,000) / 5 = 2,390,000.
        assert!(r.allocations.iter().all(|x| x.stake_ain == 200_000));
        assert!(r.allocations.iter().all(|x| x.bootstrap_ain == 2_390_000));
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

        // A founder over 30 % is refused, and so is a window with fewer than
        // five qualified operators.
        assert!(score(&db, 1, 60, &founder, &faucet, 18_500_000, 5_550_001).is_err());
        let (db, a) = testnet("few", &stakes, &[0, 1, 2, 3, 8, 9], &[]);
        let few = score(&db, 1, 60, &a[..4], &faucet, 18_500_000, 5_550_000).unwrap_err();
        assert!(few.to_string().contains("at least 5"), "{few}");
    }

    /// IT-2: a window in which the founder's nodes held a third of a
    /// committee is refused: the founder could have decided who qualified.
    #[test]
    fn a_window_the_founder_dominated_is_refused() {
        let (db, a) = testnet(
            "founder_third",
            &[3_000, 1_000, 1_000, 1_000, 1_000, 1_000],
            &[],
            &[],
        );
        let refused = score(
            &db,
            1,
            60,
            &[a[0].clone()],
            &address_of(FAUCET),
            18_500_000,
            5_550_000,
        )
        .unwrap_err();
        assert!(refused.to_string().contains("not fair"), "{refused}");
        // The faucet's account counts as the founder's.
        let refused = score(&db, 1, 60, &[], &a[0], 18_500_000, 5_550_000).unwrap_err();
        assert!(refused.to_string().contains("not fair"), "{refused}");
    }

    /// B91: a datadir whose first block was pruned is refused at once, naming
    /// the archive node.
    #[test]
    fn a_pruned_datadir_is_refused_up_front() {
        let (db, a) = testnet("pruned", &[1_000; 6], &[], &[]);
        {
            let _seed = db.seeding();
            db.delete("block_1").unwrap();
        }
        let refused = score(
            &db,
            1,
            60,
            &[a[0].clone()],
            &address_of(FAUCET),
            18_500_000,
            0,
        )
        .unwrap_err();
        assert!(refused.to_string().contains("archive node"), "{refused}");
    }

    /// A jail whose offense round is past the snapshot does not count.
    #[test]
    fn a_jail_counts_only_up_to_the_snapshot() {
        let (db, a) = testnet("jail", &[1_000; 7], &[], &[]);
        {
            let _seed = db.seeding();
            db.put(&format!("validator:jailed:{}", a[1]), "999999")
                .unwrap();
            db.put(&format!("validator:jailed:{}", a[2]), "8").unwrap();
        }
        let r = score(
            &db,
            1,
            60,
            &[a[0].clone()],
            &address_of(FAUCET),
            18_500_000,
            5_550_000,
        )
        .unwrap();
        assert!(r.operators[&a[1]].qualified, "jailed after the snapshot");
        assert_eq!(r.operators[&a[2]].reason.as_deref(), Some("jailed"));
    }

    /// IT-6: points by kind, once per kind per day, on three distinct days,
    /// from successful transactions only; a delegation counts once held for
    /// an epoch, and an undelegation from another pool does not void it; a
    /// transfer to oneself counts nothing; validators and the faucet earn
    /// nothing; the pool is capped per funding cluster.
    #[test]
    fn the_public_track_counts_points_on_three_days() {
        let pool = |seed: u8| bcs::to_bytes(&move_address(seed)).unwrap();
        let amount = || bcs::to_bytes(&100u128).unwrap();
        let mut txs = vec![
            // The faucet funds 50 and 52; 50 funds 55 (55 is in 50's cluster).
            (1, transfer(FAUCET, 50, 0)),
            (1, transfer(FAUCET, 52, 1)),
            (1, transfer(FAUCET, 53, 2)),
            (1, transfer(FAUCET, 54, 3)),
            (2, transfer(50, 55, 0)),
            // 50: transfers on days 2, 3 and 4 (twice on day 3: once), a
            // swap on day 5.
            (3, transfer(50, 51, 1)),
            (3, transfer(50, 52, 2)),
            (4, transfer(50, 51, 3)),
            (5, tx(50, "dex", "swap_x_to_y", vec![], 4)),
            // 55 (funded by 50): three days of transfers.
            (6, transfer(55, 51, 0)),
            (7, transfer(55, 51, 1)),
            (8, transfer(55, 51, 2)),
            // 52: a vote, a delegation to pool 1 (block 7) held although 52
            // left pool 2 at block 10, inside pool 1's epoch; the one to pool 2
            // (block 8) pulled too soon; a transfer.
            (6, tx(52, "governance", "vote", vec![], 3)),
            (
                7,
                tx(52, "delegation", "delegate", vec![pool(1), amount()], 4),
            ),
            (
                8,
                tx(52, "delegation", "delegate", vec![pool(2), amount()], 5),
            ),
            (
                10,
                tx(52, "delegation", "undelegate", vec![pool(2), amount()], 6),
            ),
            (40, transfer(52, 50, 7)),
            // 53: only transfers to itself.
            (8, transfer(53, 53, 0)),
            (9, transfer(53, 53, 1)),
            (10, transfer(53, 53, 2)),
            // A validator earns nothing on the public track.
            (11, transfer(1, 50, 0)),
            (12, transfer(1, 50, 1)),
            (13, transfer(1, 50, 2)),
        ];
        // 54 transacts on 3 days but its third transaction failed.
        txs.push((14, transfer(54, 50, 0)));
        txs.push((15, transfer(54, 50, 1)));
        let failed = transfer(54, 51, 2);
        txs.push((16, failed.clone()));
        let (db, a) = testnet("public", &[1_000; 7], &[], &txs);
        {
            let _seed = db.seeding();
            db.put(
                &format!("tx_receipt:{}", crypto::hash_hex(failed.as_bytes())),
                &serde_json::json!({ "status": "aborted" }).to_string(),
            )
            .unwrap();
        }
        let r = score(
            &db,
            1,
            60,
            &[a[0].clone()],
            &address_of(FAUCET),
            18_500_000,
            5_550_000,
        )
        .unwrap();
        let p = |seed: u8| r.public.get(&address_of(seed)).cloned();
        assert_eq!(p(50).map(|s| (s.points, s.days)), Some((1 + 1 + 1 + 2, 4)));
        assert_eq!(
            p(55).map(|s| (s.points, s.cluster)),
            Some((3, address_of(50)))
        );
        assert_eq!(p(52).map(|s| (s.points, s.days)), Some((2 + 3 + 1, 3)));
        assert_eq!(p(53), None, "transfers to itself");
        assert_eq!(p(1), None, "a validator");
        assert_eq!(p(54), None, "the failed third");
        // The cluster of 50 (8 points) and of 52 (6): 500,000 x 8 / 14 is
        // over the 1,000 cap, which 50 and 55 share 5 : 3.
        assert_eq!(p(50).unwrap().ain, 625);
        assert_eq!(p(55).unwrap().ain, 375);
        assert_eq!(p(52).unwrap().ain, PUBLIC_CAP_AIN);
    }

    /// B79 witness: a zero transfer or another coin's transfer funds no
    /// one, so accounts "funded" that way, or not at all, share one capped
    /// cluster however many they are; a paymaster funds the accounts it
    /// sponsors.
    #[test]
    fn sybils_outside_the_funding_tree_share_one_cap() {
        let mut txs = vec![
            (1, transfer(FAUCET, 50, 0)),
            (1, coin_transfer(FAUCET, 60, 0, ain(), 1)),
            (
                1,
                coin_transfer(FAUCET, 61, 5, coin_tag("bridge", "WBTC"), 2),
            ),
            // B113: 50 sends 64 a quantum before the faucet funds it.
            (2, transfer(50, 64, 0)),
            (3, transfer(FAUCET, 64, 3)),
            // B128: 60 (unattributed) sends 65 a quantum, then 50 (funded
            // by the faucet) sends it 100.
            (4, transfer(60, 65, 9)),
            (5, coin_transfer(50, 65, 100, ain(), 9)),
        ];
        // 60, 61, 62 and 63 transact on three days; 62's transactions are
        // sponsored by 50; 63 received nothing at all.
        for (i, s) in [60u8, 61, 62, 63, 64, 65].into_iter().enumerate() {
            for (n, day) in [10u64, 11, 12].into_iter().enumerate() {
                let raw = transfer(s, 51, n as u64);
                let raw = if s == 62 { sponsored(raw, 50) } else { raw };
                txs.push((day + i as u64 * 5, raw));
            }
        }
        let (db, a) = testnet("sybil", &[1_000; 7], &[], &txs);
        let r = score(
            &db,
            1,
            60,
            &[a[0].clone()],
            &address_of(FAUCET),
            18_500_000,
            5_550_000,
        )
        .unwrap();
        let cluster = |seed: u8| r.public[&address_of(seed)].cluster.clone();
        assert_eq!(cluster(60), UNATTRIBUTED, "a zero transfer funds no one");
        assert_eq!(cluster(61), UNATTRIBUTED, "another coin funds no one");
        assert_eq!(cluster(63), UNATTRIBUTED, "nothing received");
        assert_eq!(cluster(62), address_of(50), "the paymaster funds it");
        assert_eq!(
            cluster(64),
            address_of(64),
            "the faucet's transfer makes a root"
        );
        assert_eq!(
            cluster(65),
            address_of(50),
            "the largest funder, not the first"
        );
        let shared: u64 = [60u8, 61, 63]
            .iter()
            .map(|s| r.public[&address_of(*s)].ain)
            .sum();
        assert!(shared <= PUBLIC_CAP_AIN, "{shared} AIN to the unattributed");
        assert!(shared > 0, "vacuous: nothing paid to the unattributed");
    }
}
