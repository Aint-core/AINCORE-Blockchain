use consensus::qc::{
    build_qc, expected_chain_id, validator_set_hash, FinalityVote, QuorumCertificate, ValidatorInfo,
};

struct QcDir(std::path::PathBuf);
impl QcDir {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
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
            db.put(key, value).unwrap();
        } else {
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
