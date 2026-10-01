//! G1 CE-3 recovery tool (`docs/CERT_CONFLICT_RECOVERY_RUNBOOK.md`). Run it on
//! a STOPPED validator's database; a running node holds the database lock and
//! the tool refuses to open it.
//!
//!   cert_recovery inspect --db DB
//!   cert_recovery choose DIGEST_A DIGEST_B [ORDERED_DIGEST ...]
//!   cert_recovery export --db DB --epoch E --round R --author A --digest D --out FILE
//!   cert_recovery pin --db DB --cert FILE
//!
//! DB is `{datadir}/validator_{port}.db`.

use consensus::v4::recovery;
use consensus::vcert::VertexCertificate;
use std::collections::HashMap;
use storage::StateDB;

fn usage() -> ! {
    eprintln!(
        "usage:\n  cert_recovery inspect --db DB\n  cert_recovery choose DIGEST_A DIGEST_B \
         [ORDERED_DIGEST ...]\n  cert_recovery export --db DB --epoch E --round R --author A \
         --digest D --out FILE\n  cert_recovery pin --db DB --cert FILE"
    );
    std::process::exit(2)
}

fn flags(args: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let Some(name) = k.strip_prefix("--") else {
            usage()
        };
        let Some(v) = it.next() else { usage() };
        out.insert(name.to_string(), v.clone());
    }
    out
}

fn need<'a>(f: &'a HashMap<String, String>, name: &str) -> &'a str {
    f.get(name).map(String::as_str).unwrap_or_else(|| usage())
}

/// Opens an existing database only: `StateDB::open` would create one at a
/// mistyped path.
fn open(path: &str) -> Result<StateDB, String> {
    if !std::path::Path::new(path).join("CURRENT").exists() {
        return Err(format!("{path} is not a node database"));
    }
    StateDB::open(path).map_err(|e| format!("{e} (is the node still running?)"))
}

fn stored(db: &StateDB, key: &str) -> Result<String, String> {
    db.get(key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{key} is missing: not a V4 chain database"))
}

fn inspect(db: &StateDB) -> Result<(), String> {
    println!("chain_id: {}", stored(db, "sys:chain_id")?);
    println!(
        "latest_height: {}",
        db.get("latest_height").ok().flatten().unwrap_or_default()
    );
    println!(
        "latest height with a QC: {}",
        db.get("consensus:qc:latest_height")
            .ok()
            .flatten()
            .unwrap_or_else(|| "none".into())
    );
    let slots = recovery::alarmed_slots(db)?;
    if slots.is_empty() {
        println!("no certificate-conflict alarm on this node");
    }
    for s in slots {
        println!(
            "slot epoch {} round {} author {}",
            s.epoch, s.round, s.author
        );
        if let Some((a, b)) = &s.alarm_digests {
            println!("  alarm pair: {a} {b}");
        }
        println!(
            "  certificate row: {}",
            s.cert_digest.as_deref().unwrap_or("none")
        );
        println!("  known digests: {:?}", s.digests);
        println!("  ordered by this node: {:?}", s.ordered);
        let evidence = recovery::evidence_row(db, s.epoch, s.round, &s.author).is_some();
        println!("  evidence row held: {evidence}");
    }
    Ok(())
}

fn export(db: &StateDB, f: &HashMap<String, String>) -> Result<(), String> {
    let parse = |n: &str| need(f, n).parse::<u64>().map_err(|e| format!("--{n}: {e}"));
    let (epoch, round) = (parse("epoch")?, parse("round")?);
    let (author, digest) = (need(f, "author"), need(f, "digest"));
    let mut found: Option<VertexCertificate> = None;
    if let Some(raw) = db
        .get(&recovery::alarm_key(epoch, round, author))
        .map_err(|e| e.to_string())?
    {
        let pair: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        for field in ["held", "other"] {
            if let Ok(c) = serde_json::from_value::<VertexCertificate>(pair[field].clone()) {
                if c.body.digest == digest {
                    found = Some(c);
                }
            }
        }
    }
    if found.is_none() {
        let key = consensus::staging::vcert_key(epoch, round, author);
        if let Some(raw) = db.get(&key).map_err(|e| e.to_string())? {
            let c: VertexCertificate = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            if c.body.digest == digest {
                found = Some(c);
            }
        }
    }
    let cert = found.ok_or("this node holds no certificate with that digest for the slot")?;
    let out = need(f, "out");
    let json = serde_json::to_string_pretty(&cert).map_err(|e| e.to_string())?;
    std::fs::write(out, json).map_err(|e| format!("{out}: {e}"))?;
    println!("wrote the certificate of {digest} to {out}");
    Ok(())
}

fn pin(db: &StateDB, f: &HashMap<String, String>) -> Result<(), String> {
    let path = need(f, "cert");
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let cert: VertexCertificate = serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))?;
    let chain_id = stored(db, "sys:chain_id")?;
    let genesis_identity = stored(db, "genesis_identity")?;
    let committee = consensus::qc_producer::load_validator_set_for_epoch(db, cert.body.epoch)
        .ok_or_else(|| format!("no committee is recorded for epoch {}", cert.body.epoch))?;
    let pinned = recovery::pin_canonical(db, &cert, &committee, &chain_id, &genesis_identity)?;
    println!(
        "pinned {} for epoch {} round {} author {}",
        cert.body.digest, cert.body.epoch, cert.body.round, cert.body.author
    );
    if let Some(old) = pinned.replaced {
        println!("  replaced the certificate row of {old}");
    }
    for d in pinned.demoted {
        println!("  took the certified role from {d}");
    }
    println!("  alarm cleared: {}", pinned.alarm_cleared);
    let left = recovery::alarmed_slots(db)?;
    if left.is_empty() {
        println!("no alarm is left: the node may be restarted");
    } else {
        println!(
            "{} alarm(s) left: pin each slot before restarting",
            left.len()
        );
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let result = match cmd.as_str() {
        "choose" => {
            if args.len() < 3 {
                usage()
            }
            recovery::choose_canonical(
                (args[1].as_str(), args[2].as_str()),
                args[3..].iter().map(String::as_str),
            )
            .map(|d| println!("canonical: {d}"))
        }
        "inspect" | "export" | "pin" => {
            let f = flags(&args[1..]);
            open(need(&f, "db")).and_then(|db| match cmd.as_str() {
                "inspect" => inspect(&db),
                "export" => export(&db, &f),
                _ => pin(&db, &f),
            })
        }
        _ => usage(),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
