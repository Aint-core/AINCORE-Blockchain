//! G3 FX-6: the chain id INSTALLED at boot governs admission, not the default
//! and not the env. It runs as its own test binary because the installed id is
//! set once per process. (Written by the S0b adversarial reviewer.)
use ed25519_dalek::{Signer, SigningKey};

fn tx(chain_id: &str, seq: u64) -> String {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let sender = crypto::derive_address(sk.verifying_key().as_bytes()).unwrap();
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![
            seq as u8, 1,
        ]]))
        .unwrap(),
    );
    // B14: the limit covers the transaction's ~450 bytes of byte gas.
    let msg = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, seq, 1_000_000u64, 1u128, ""
    );
    let sig = hex::encode(sk.sign(msg.as_bytes()).to_bytes());
    serde_json::json!({
        "chain_id": chain_id, "sender": sender, "input_objects": [], "payload": payload,
        "args": [], "gas_limit": 1_000_000, "gas_price": 1, "sequence_number": seq,
        "public_key": pk, "signature": sig,
    })
    .to_string()
}

#[test]
fn the_installed_chain_id_governs_admission() {
    // The env names the default chain; the node installed another one.
    std::env::set_var("AINCORE_CHAIN_ID", blockchain::DEFAULT_CHAIN_ID);
    blockchain::set_vertex_domain("AINCORE-LOCALTEST-4V-HEAD", "deadbeef");
    assert_eq!(blockchain::chain_id(), "AINCORE-LOCALTEST-4V-HEAD");
    let mut mempool = mempool::Mempool::new();
    mempool
        .add_transaction(tx("AINCORE-LOCALTEST-4V-HEAD", 0))
        .expect("a transaction for the installed chain is admitted");
    let err = mempool
        .add_transaction(tx(blockchain::DEFAULT_CHAIN_ID, 1))
        .expect_err("the default chain is refused once another is installed");
    assert!(err.contains("Invalid Chain ID"), "{err}");
}
