use blockchain::{ParentRef, Vertex};
use consensus::DagConsensus;
use crypto::{Signer, SigningKey};
use executor::Executor;
use mempool::Mempool;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use storage::object::{Object, Owner};
use storage::StateDB;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aincore-parent-identity-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn address(seed: u8) -> String {
    crypto::derive_address(key(seed).verifying_key().as_bytes()).unwrap()
}

fn open(path: &TestDir) -> DagConsensus {
    let db = Arc::new(StateDB::open(path.0.to_str().unwrap()).unwrap());
    let committee: Vec<_> = (31..=34).map(|seed| (address(seed), 1000u64)).collect();
    db.put(
        "sys:validators",
        &serde_json::to_string(&committee).unwrap(),
    )
    .unwrap();
    for seed in 31..=34 {
        let a = address(seed);
        let data =
            serde_json::json!({"public_key": hex::encode(key(seed).verifying_key().to_bytes())});
        db.put_object(&Object::new(
            a.clone(),
            Owner::Address(a),
            serde_json::to_vec(&data).unwrap(),
            "0x1::account::AccountData".into(),
        ))
        .unwrap();
    }
    // Observer identity: exercise real ingress without executing unrelated blocks.
    let mut node = DagConsensus::new(
        address(200),
        Arc::new(Mutex::new(HashMap::new())),
        Arc::new(Mutex::new(Mempool::new())),
        Arc::new(Executor::new(db.clone())),
        db,
        None,
        None,
        [200; 32],
    );
    node.now_secs = Arc::new(|| 1_700_000_000);
    node
}

fn sign(v: &mut Vertex, seed: u8) {
    v.hash = v.calculate_hash();
    v.sign_with_ed25519(&key(seed));
}

fn parents() -> Vec<Vertex> {
    (31..=34)
        .map(|seed| {
            let mut v = Vertex::new(1, address(seed), vec!["genesis".into()], vec![]);
            v.timestamp = 1000;
            sign(&mut v, seed);
            v
        })
        .collect()
}

fn child(parents: &[Vertex], seed: u8) -> Vertex {
    let mut v = Vertex::new(
        2,
        address(seed),
        parents.iter().map(|p| p.hash.clone()).collect(),
        vec![],
    );
    v.timestamp = 1001;
    v.parent_refs = parents
        .iter()
        .zip(31..=34)
        .map(|(p, s)| ParentRef::authenticated(p, hex::encode(key(s).verifying_key().to_bytes())))
        .collect();
    sign(&mut v, seed);
    v
}

fn deliver(node: &mut DagConsensus, v: &Vertex) {
    node.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(v).unwrap()));
}

fn present(node: &DagConsensus, v: &Vertex) -> bool {
    node.dag.lock().unwrap().contains_key(&v.hash)
}

#[test]
fn authenticated_child_arrives_before_parent_bodies() {
    let dir = TestDir::new();
    let mut node = open(&dir);
    let ps = parents();
    let v = child(&ps, 31);
    assert!(v.verify_parent_identities());
    deliver(&mut node, &v);
    assert!(
        present(&node, &v),
        "valid identity proof must not depend on body arrival"
    );
    assert!(ps.iter().all(|p| !present(&node, p)));
    for p in &ps {
        deliver(&mut node, p);
    }
    assert!(present(&node, &v));
    assert!(ps.iter().all(|p| present(&node, p)));
}

#[test]
fn parent_ingress_does_not_replace_missing_epoch_committee() {
    let bls = crypto::bls::BLSEngine::consensus();
    let set: Vec<_> = (31..=34).map(|seed| {
        let bls_seed = consensus::qc::derive_validator_bls_seed(&[seed; 32]);
        consensus::qc::ValidatorInfo {
            address: address(seed), stake: 1000,
            ed25519_public_key: hex::encode(key(seed).verifying_key().to_bytes()),
            bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
        }
    }).collect();
    let snapshot = serde_json::to_string(&set).unwrap();
    for (current, bad_snapshot) in [("3", None), ("3", Some("[]")), ("0", Some("not json")), ("invalid", None)] {
        let dir = TestDir::new();
        let mut node = open(&dir);
        node.storage.put("consensus:epoch", current).unwrap();
        let epoch = current.parse::<u64>().unwrap_or(0);
        let snapshot_key = format!("sys:validator_set:epoch:{epoch}");
        if let Some(raw) = bad_snapshot {
            node.storage.put(&snapshot_key, raw).unwrap();
        }
        let v = child(&parents(), 31);
        deliver(&mut node, &v);
        assert!(!present(&node, &v), "ingress fell back for epoch {current:?}, snapshot {bad_snapshot:?}");
        assert!(node.storage.get(&format!("vertex:{}", v.hash)).unwrap().is_none());

        node.storage.put("consensus:epoch", &epoch.to_string()).unwrap();
        node.storage.put(&snapshot_key, &snapshot).unwrap();
        if epoch == 0 {
            node.storage.put("genesis:validator_set:v1", &snapshot).unwrap();
        }
        deliver(&mut node, &v);
        assert!(present(&node, &v), "same valid vertex must be retryable once its committee is available");
    }
}

#[test]
fn forged_identity_rejected_before_and_after_parent_arrival() {
    for forge_round in [false, true] {
        let dir = TestDir::new();
        let mut node = open(&dir);
        let ps = parents();
        let honest = child(&ps, 34);
        let mut forged = child(&ps, 31);
        if forge_round {
            forged.round = 3;
            for r in &mut forged.parent_refs {
                r.round = 2;
            }
        } else {
            for (i, r) in forged.parent_refs.iter_mut().enumerate() {
                r.author = ps[(i + 1) % ps.len()].author.clone();
            }
        }
        sign(&mut forged, 31);
        assert!(forged.verify_ed25519_signature(&hex::encode(key(31).verifying_key().to_bytes())));
        let committee: Vec<_> = (31..=34).map(|s| (address(s), 1000u64)).collect();
        assert!(consensus::qc::parent_refs_admissible(&forged, &committee).is_ok());
        deliver(&mut node, &forged);
        assert!(!present(&node, &forged));
        for p in &ps {
            deliver(&mut node, p);
        }
        deliver(&mut node, &forged);
        assert!(!present(&node, &forged));
        assert!(node
            .storage
            .get(&format!("vertex:{}", forged.hash))
            .unwrap()
            .is_none());
        deliver(&mut node, &honest);
        assert!(present(&node, &honest), "positive control must be accepted");
    }
}

#[test]
fn malformed_evidence_does_not_poison_a_later_valid_copy() {
    let ps = parents();
    let honest = child(&ps, 31);
    for case in 0..7 {
        let dir = TestDir::new();
        let mut node = open(&dir);
        let mut bad = honest.clone();
        if case == 0 {
            bad.parent_refs[0].proof = None;
        } else {
            let p = bad.parent_refs[0].proof.as_mut().unwrap();
            match case {
                1 => p.signature = "00".repeat(64),
                2 => p.public_key = hex::encode(key(32).verifying_key().to_bytes()),
                3 => p.timestamp += 1,
                4 => p.parents_root = "00".repeat(32),
                5 => p.payload_root = "00".repeat(33),
                _ => p.payload_root = "zz".repeat(32),
            }
        }
        assert_eq!(
            bad.calculate_hash(),
            honest.hash,
            "evidence is not an identity field"
        );
        deliver(&mut node, &bad);
        assert!(!present(&node, &bad), "case {case}");
        deliver(&mut node, &honest);
        assert!(
            present(&node, &honest),
            "case {case}: valid retransmission was poisoned"
        );
    }
}

#[test]
fn identity_evidence_survives_pruning_and_restart_without_parent_bodies() {
    let dir = TestDir::new();
    let mut node = open(&dir);
    let ps = parents();
    for p in &ps {
        deliver(&mut node, p);
    }
    let v = child(&ps, 31);
    deliver(&mut node, &v);
    node.prune_dag(2);
    assert!(ps.iter().all(|p| !present(&node, p)));
    node.storage.flush().unwrap();
    drop(node);
    let recovered = open(&dir);
    assert!(present(&recovered, &v));
    assert!(ps.iter().all(|p| !present(&recovered, p)));
}

fn recovery_rejects_forgery(mode: &str) {
    let dir = TestDir::new();
    let node = open(&dir);
    let ps = parents();
    let honest = child(&ps, 34);
    let checkpoint_only = child(&ps, 33);
    let mut forged = child(&ps, 31);
    if mode == "legacy" {
        for r in &mut forged.parent_refs {
            r.proof = None;
        }
    } else {
        forged.parent_refs[0].proof.as_mut().unwrap().timestamp += 1;
    }
    assert!(!forged.verify_parent_identities());
    for v in [&honest, &forged] {
        node.storage
            .put(
                &format!("vertex:{}", v.hash),
                &serde_json::to_string(v).unwrap(),
            )
            .unwrap();
    }
    if mode != "scan" && mode != "legacy" {
        let (round, contents) = if mode == "checkpoint" {
            (
                2,
                serde_json::to_string(&vec![
                    honest.clone(),
                    forged.clone(),
                    checkpoint_only.clone(),
                ])
                .unwrap(),
            )
        } else {
            (1, serde_json::to_string(&ps).unwrap())
        };
        let signature = hex::encode(key(200).sign(contents.as_bytes()).to_bytes());
        node.storage
            .save_dag_checkpoint_signed(round, &contents, &signature)
            .unwrap();
    }
    node.storage.flush().unwrap();
    drop(node);
    let recovered = open(&dir);
    if mode == "checkpoint" {
        assert!(
            present(&recovered, &checkpoint_only),
            "valid checkpoint-only entry lost"
        );
    }
    assert!(
        present(&recovered, &honest),
        "{mode}: valid retained child lost"
    );
    assert!(
        !present(&recovered, &forged),
        "{mode}: forged child revived"
    );
    let indexed: BTreeSet<_> = recovered
        .round_index
        .lock()
        .unwrap()
        .values()
        .flatten()
        .cloned()
        .collect();
    assert!(indexed.contains(&honest.hash));
    assert!(!indexed.contains(&forged.hash));
}

#[test]
fn recovery_scan_rejects_parent_forgery() {
    recovery_rejects_forgery("scan");
}
#[test]
fn recovery_checkpoint_rejects_parent_forgery() {
    recovery_rejects_forgery("checkpoint");
}
#[test]
fn recovery_tail_rejects_parent_forgery() {
    recovery_rejects_forgery("tail");
}
#[test]
fn recovery_does_not_grandfather_unsigned_parent_claims() {
    recovery_rejects_forgery("legacy");
}

#[test]
fn parent_identity_proof_is_domain_bound_and_payload_size_independent() {
    let mut p = parents().remove(0);
    let public_key = hex::encode(key(31).verifying_key().to_bytes());
    let before = ParentRef::authenticated(&p, public_key.clone());
    assert!(before.verify_identity());
    p.payload = vec!["x".repeat(100_000)];
    sign(&mut p, 31);
    let after = ParentRef::authenticated(&p, public_key.clone());
    assert!(after.verify_identity());
    assert_eq!(
        serde_json::to_vec(&before).unwrap().len(),
        serde_json::to_vec(&after).unwrap().len()
    );
    p.hash = p.calculate_hash_with_domain("other-chain", "other-genesis");
    p.sign_with_ed25519(&key(31));
    assert!(!ParentRef::authenticated(&p, public_key).verify_identity());
}

#[test]
fn even_a_valid_signature_cannot_authorize_noncanonical_roots() {
    let mut p = parents().remove(0);
    let public_key = hex::encode(key(31).verifying_key().to_bytes());
    for root in ["zz".repeat(32), "AB".repeat(32)] {
        p.parents_root = Some(root);
        sign(&mut p, 31);
        assert!(p.verify_ed25519_signature(&public_key));
        assert!(!ParentRef::authenticated(&p, public_key.clone()).verify_identity());
    }
}
