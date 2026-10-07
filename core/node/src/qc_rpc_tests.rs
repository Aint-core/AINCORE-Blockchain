use consensus::qc::{
    build_qc, expected_chain_id, validator_set_hash, FinalityVote, QuorumCertificate, ValidatorInfo,
};

// The includer provides `state`. `cert` signs under `expected_chain_id()` and
// the RPC verifies under it again. Both read `sys:chain_id` as installed at
// boot, never the env, so no test can change it in between (G3 FX-6).

struct QcDir(std::path::PathBuf);
impl QcDir {
    fn new() -> Self {
        Self(storage::test_dir::process_dir().join(format!(
            "qc-rpc-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )))
    }
    fn open(&self) -> Arc<StateDB> {
        Arc::new(StateDB::open(self.0.to_str().unwrap()).unwrap())
    }
}
impl Drop for QcDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cert(db: &StateDB, epoch: u64, height: u64) -> QuorumCertificate {
    let _seed = db.seeding();
    let bls = crypto::bls::BLSEngine::consensus();
    let mut target = vec![];
    for (e, seed) in [(0, [7; 32]), (1, [8; 32])] {
        let set = vec![ValidatorInfo {
            address: "local".into(),
            stake: 100,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&seed)),
        }];
        let key = if e == 0 {
            "genesis:validator_set:v1"
        } else {
            "sys:validator_set:epoch:1"
        };
        db.put(key, &serde_json::to_string(&set).unwrap()).unwrap();
        if epoch == e {
            target = set;
        }
    }
    db.put("consensus:epoch", "1").unwrap();
    db.put("consensus:epoch_start_height:1", "21").unwrap();
    let vote = FinalityVote {
        chain_id: expected_chain_id(),
        epoch,
        finalized_round: height + 1,
        anchor_round: height + 1,
        anchor_hash: "01".repeat(32),
        block_height: height,
        block_hash: "02".repeat(32),
        state_root: "03".repeat(32),
        receipts_root: "04".repeat(32),
        finality_digest: "05".repeat(32),
        validator_set_hash: validator_set_hash(&target),
        next_validator_set_hash: String::new(),
    };
    let signature = bls.sign_raw(&vote.to_signing_bytes(), &[7 + epoch as u8; 32]);
    let qc = build_qc(&vote, &target, &[0], &[signature]).unwrap();
    consensus::qc::verify_qc(&qc, &target, &expected_chain_id()).unwrap();
    qc
}

type StoredRow = (Box<[u8]>, Box<[u8]>);

fn rows(db: &StateDB) -> Vec<StoredRow> {
    db.db
        .iterator(storage::rocksdb::IteratorMode::Start)
        .map(Result::unwrap)
        .collect()
}

async fn call(db: Arc<StateDB>, method: &str, params: serde_json::Value) -> serde_json::Value {
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(state(db.clone())))
            .route("/rpc", web::post().to(json_rpc_handler)),
    )
    .await;
    let before = rows(&db);
    let request = actix_web::test::TestRequest::post()
        .uri("/rpc")
        .set_json(serde_json::json!({"jsonrpc":"2.0", "id":17, "method":method, "params":params}))
        .to_request();
    let value = actix_web::test::call_and_read_body_json(&app, request).await;
    assert_eq!(rows(&db), before, "QC RPC changed database rows");
    value
}

#[actix_web::test]
async fn rpc_rejects_valid_bls_certificate_outside_epoch_height_range() {
    for (height, epoch) in [(20, 1), (21, 0)] {
        let dir = QcDir::new();
        let db = dir.open();
        let qc = cert(&db, epoch, height);
        db.put(
            &format!("consensus:qc:{height}"),
            &serde_json::to_string(&qc).unwrap(),
        )
        .unwrap();
        db.put("consensus:qc:latest_height", &height.to_string())
            .unwrap();
        for method in [
            "aincore_getQuorumCert",
            "aincore_getLatestQuorumCertificate",
            "aincore_getQuorumCertificate",
        ] {
            let value = call(db.clone(), method, serde_json::json!([])).await;
            assert_eq!(
                value["result"]["verified"], false,
                "wrong epoch accepted by {method}: {value}"
            );
        }
    }
}

#[actix_web::test]
async fn rpc_external_verifier_rejects_wrong_epoch() {
    for (height, epoch) in [(20, 1), (21, 0)] {
        let dir = QcDir::new();
        let db = dir.open();
        let qc = cert(&db, epoch, height);
        let value = call(
            db,
            "aincore_verifyQuorumCertificate",
            serde_json::json!([qc]),
        )
        .await;
        assert_eq!(
            value["result"]["valid"], false,
            "wrong epoch verified: {value}"
        );
    }
}

#[actix_web::test]
async fn rpc_rejects_certificate_in_wrong_height_index() {
    let dir = QcDir::new();
    let db = dir.open();
    let qc = cert(&db, 1, 21);
    db.put("consensus:qc:22", &serde_json::to_string(&qc).unwrap())
        .unwrap();
    let value = call(db, "aincore_getQuorumCertificate", serde_json::json!([22])).await;
    assert_eq!(
        value["result"]["verified"], false,
        "index mismatch was reported verified: {value}"
    );
}

#[actix_web::test]
async fn rpc_accepts_boundary_and_successor_under_local_committee() {
    for (height, epoch) in [(20, 0), (21, 1)] {
        let dir = QcDir::new();
        let db = dir.open();
        let qc = cert(&db, epoch, height);
        db.put(
            &format!("consensus:qc:{height}"),
            &serde_json::to_string(&qc).unwrap(),
        )
        .unwrap();
        let value = call(
            db.clone(),
            "aincore_getQuorumCertificate",
            serde_json::json!([height]),
        )
        .await;
        assert_eq!(value["result"]["verified"], true, "{value}");
        assert_eq!(
            value["result"]["verification_scope"],
            "local_committee_and_epoch"
        );
        let value = call(
            db,
            "aincore_verifyQuorumCertificate",
            serde_json::json!([qc]),
        )
        .await;
        assert_eq!(value["result"]["valid"], true, "{value}");
        assert_eq!(
            value["result"]["verification_scope"],
            "local_committee_and_epoch"
        );
    }
}

#[actix_web::test]
async fn rpc_unknown_history_or_committee_is_unavailable_not_valid() {
    for (key, replacement, reason) in [
        (
            "consensus:epoch_start_height:1",
            None,
            "epoch activation history unavailable",
        ),
        (
            "consensus:epoch_start_height:1",
            Some("broken"),
            "epoch activation history unavailable",
        ),
        (
            "consensus:epoch",
            Some("broken"),
            "epoch activation history unavailable",
        ),
        (
            "sys:validator_set:epoch:1",
            None,
            "validator set unavailable",
        ),
        (
            "sys:validator_set:epoch:1",
            Some("broken"),
            "validator set unavailable",
        ),
    ] {
        let dir = QcDir::new();
        let db = dir.open();
        let qc = cert(&db, 1, 21);
        db.put("consensus:qc:21", &serde_json::to_string(&qc).unwrap())
            .unwrap();
        if let Some(value) = replacement {
            let _seed = db.seeding();
            db.put(key, value).unwrap();
        } else {
            let _seed = db.seeding();
            db.delete(key).unwrap();
        }
        let value = call(
            db.clone(),
            "aincore_getQuorumCertificate",
            serde_json::json!([21]),
        )
        .await;
        assert_eq!(value["result"]["verified"], false, "{value}");
        assert_eq!(value["result"]["verify_error"], reason, "{value}");
        let value = call(
            db,
            "aincore_verifyQuorumCertificate",
            serde_json::json!([qc]),
        )
        .await;
        assert_eq!(value["error"]["code"], -32000, "{value}");
        assert_eq!(value["error"]["message"], reason, "{value}");
        assert!(value["result"].is_null(), "{value}");
    }
}

#[actix_web::test]
async fn rpc_still_rejects_tampered_signature_chain_and_vote() {
    for mutation in 0..3 {
        let dir = QcDir::new();
        let db = dir.open();
        let mut qc = cert(&db, 1, 21);
        match mutation {
            0 => qc.aggregate_signature[0] ^= 1,
            1 => qc.chain_id.push_str("-other"),
            _ => qc.state_root = "06".repeat(32),
        }
        db.put("consensus:qc:21", &serde_json::to_string(&qc).unwrap())
            .unwrap();
        let value = call(
            db.clone(),
            "aincore_getQuorumCertificate",
            serde_json::json!([21]),
        )
        .await;
        assert_eq!(value["result"]["verified"], false, "{value}");
        let value = call(
            db,
            "aincore_verifyQuorumCertificate",
            serde_json::json!([qc]),
        )
        .await;
        assert_eq!(value["result"]["valid"], false, "{value}");
        assert!(value["result"]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()));
    }
}

#[actix_web::test]
async fn rpc_preserves_invalid_params_errors_and_rejects_zero_height() {
    let dir = QcDir::new();
    let db = dir.open();
    let qc = cert(&db, 0, 0);
    let value = call(
        db.clone(),
        "aincore_verifyQuorumCertificate",
        serde_json::json!([qc]),
    )
    .await;
    assert_eq!(value["result"]["valid"], false, "{value}");
    assert_eq!(value["result"]["error"], "QC block height is zero");
    for params in [serde_json::json!([]), serde_json::json!([{}])] {
        let value = call(db.clone(), "aincore_verifyQuorumCertificate", params).await;
        assert_eq!(value["error"]["code"], -32602, "{value}");
    }
}

/// B182 witness: with every verification slot busy, `getQuorumCert` still
/// answers with the stored certificate, its verification unknown (an error
/// in its place stalled every client that verifies it itself, the bridge
/// among them, for as long as the slots were kept busy).
#[actix_web::test]
async fn a_busy_node_still_serves_a_stored_certificate() {
    let dir = QcDir::new();
    let db = dir.open();
    let qc = cert(&db, 1, 37);
    db.put("consensus:qc:37", &serde_json::to_string(&qc).unwrap())
        .unwrap();
    let data = web::Data::new(state(db.clone()));
    let held: Vec<_> = (0..DRY_RUNS_AT_ONCE)
        .map(|_| DryRun::begin(&data.dry_runs).expect("a free slot"))
        .collect();
    let answer = handle_rpc_method("aincore_getQuorumCert", serde_json::json!([37]), &data)
        .expect("the certificate, not an error");
    assert_eq!(answer["available"], true, "{answer}");
    assert!(answer["verified"].is_null(), "{answer}");
    assert_eq!(
        answer["quorum_certificate"],
        serde_json::to_value(&qc).unwrap()
    );
    drop(held);
    let answer = handle_rpc_method("aincore_getQuorumCert", serde_json::json!([37]), &data)
        .expect("an answer");
    assert_eq!(answer["verified"], true, "{answer}");
    // B240: the slots are the dry runs' queue's too: with its permits held
    // (estimates waiting their turn), a certificate not remembered is
    // answered unverified, not verified on a slot the queue counts on.
    let other = cert(&db, 1, 38);
    db.put("consensus:qc:38", &serde_json::to_string(&other).unwrap())
        .unwrap();
    let permits: Vec<_> = (0..DRY_RUNS_AT_ONCE)
        .map(|_| {
            Arc::clone(&data.queues.dry)
                .try_acquire_owned()
                .expect("a permit")
        })
        .collect();
    let answer = handle_rpc_method("aincore_getQuorumCert", serde_json::json!([38]), &data)
        .expect("the certificate, not an error");
    assert!(answer["verified"].is_null(), "{answer}");
    drop(permits);
    let answer = handle_rpc_method("aincore_getQuorumCert", serde_json::json!([38]), &data)
        .expect("an answer");
    assert_eq!(answer["verified"], true, "{answer}");
}

/// B254 witness: a stored certificate not remembered is verified only on a
/// turn of its client's network group free now: with that group's dry gate
/// held it is answered unverified (its certificate all the same) while a
/// client of another group has it verified (one client or group missing on
/// past epochs held both dry permits, a pairing each).
#[test]
fn a_stored_certificate_is_verified_on_its_groups_turn() {
    use std::net::{IpAddr, Ipv4Addr};
    let dir = QcDir::new();
    let db = dir.open();
    let qc = cert(&db, 1, 39);
    db.put("consensus:qc:39", &serde_json::to_string(&qc).unwrap())
        .unwrap();
    let data = state(db.clone());
    let busy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let _held = data
        .queues
        .gate(heavy_group(busy), true)
        .try_acquire_owned()
        .expect("a free gate");
    let neighbour = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let answer =
        stored_certificate(&data, &serde_json::json!([39]), neighbour).expect("the certificate");
    assert!(answer["verified"].is_null(), "{answer}");
    assert_eq!(
        answer["quorum_certificate"],
        serde_json::to_value(&qc).unwrap()
    );
    let other = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)));
    let answer =
        stored_certificate(&data, &serde_json::json!([39]), other).expect("the certificate");
    assert_eq!(answer["verified"], true, "{answer}");
}
