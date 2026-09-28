//! G3 FX-6: execution checks the chain id INSTALLED at boot, not the default
//! and not the env. Its own test binary, because the installed id is set once
//! per process.
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;

fn tx(chain_id: &str) -> String {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let sender = crypto::derive_address(sk.verifying_key().as_bytes()).unwrap();
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![
            9, 1,
        ]]))
        .unwrap(),
    );
    let msg = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, 0u64, 100_000u64, 1u128, ""
    );
    let sig = hex::encode(sk.sign(msg.as_bytes()).to_bytes());
    serde_json::json!({
        "chain_id": chain_id, "sender": sender, "input_objects": [], "payload": payload,
        "args": [], "gas_limit": 100_000, "gas_price": 1, "sequence_number": 0,
        "public_key": pk, "signature": sig,
    })
    .to_string()
}

#[test]
fn the_installed_chain_id_governs_execution() {
    std::env::set_var("AINCORE_CHAIN_ID", blockchain::DEFAULT_CHAIN_ID);
    blockchain::set_vertex_domain("AINCORE-LOCALTEST-4V-HEAD", "deadbeef");
    assert_eq!(executor::expected_chain_id(), "AINCORE-LOCALTEST-4V-HEAD");
    // A transaction for the default chain is dropped at the chain-id check.
    let path = std::env::temp_dir().join(format!("installed_chain_exec_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let db = Arc::new(storage::StateDB::open(path.to_str().unwrap()).unwrap());
    let executor = executor::Executor::new(db);
    assert!(executor
        .execute_transaction(&tx(blockchain::DEFAULT_CHAIN_ID))
        .is_none());
}
