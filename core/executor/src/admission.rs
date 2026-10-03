//! The stateless half of transaction validity (bug ledger B8, B12, B13).
//!
//! One predicate decides whether a string is a well-formed, authenticated
//! transaction for this chain, using nothing but the string and the chain id.
//! The mempool runs it at admission, vertex ingress runs it on every payload
//! item, and the executor runs it before it reads state, so the three cannot
//! disagree about what a transaction is. What it cannot decide (nonce, balance,
//! the paymaster's balance) is the executor's.

use crate::{Transaction, MAX_GAS_LIMIT};
use crypto::TxScheme;
use sha2::{Digest, Sha256};

/// The largest transaction, as raw JSON bytes.
pub const MAX_TX_BYTES: usize = 100 * 1024;
/// The lowest gas price.
pub const MIN_GAS_PRICE: u128 = 1;

/// A transaction that passed [`check_stateless`].
#[derive(Debug, Clone)]
pub struct CheckedTx {
    pub tx: Transaction,
    /// The sender's signature scheme.
    pub scheme: TxScheme,
    /// The address that pays gas: the sender, or the paymaster's address.
    pub payer: String,
}

/// The bytes the sender signs (F4: seven fields, ':'-joined).
pub fn signing_message(tx: &Transaction) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        tx.chain_id,
        tx.sender,
        tx.payload,
        tx.sequence_number,
        tx.gas_limit,
        tx.gas_price,
        tx.input_objects.join(",")
    )
}

/// The bytes a paymaster signs: SHA-256 of
/// `PAYMASTER_AUTH:{chain_id}:{sender}:{payload}:{gas_limit}:{sequence_number}`.
pub fn paymaster_message(tx: &Transaction) -> [u8; 32] {
    Sha256::digest(
        format!(
            "PAYMASTER_AUTH:{}:{}:{}:{}:{}",
            tx.chain_id, tx.sender, tx.payload, tx.gas_limit, tx.sequence_number
        )
        .as_bytes(),
    )
    .into()
}

/// The paymaster's address: `paymaster` holds its public key (hex), and the
/// address is derived from it like every other address (B13: it used to be
/// the raw key, which is no account's address).
pub fn paymaster_address(paymaster_public_key_hex: &str) -> Option<String> {
    let key = hex::decode(paymaster_public_key_hex).ok()?;
    crypto::derive_address(&key).ok()
}

/// Whether `raw` is a well-formed transaction for `chain_id`, signed by the
/// key its sender address is derived from (and by its paymaster, if any).
pub fn check_stateless(raw: &str, chain_id: &str) -> Result<CheckedTx, String> {
    if raw.len() > MAX_TX_BYTES {
        return Err(format!(
            "transaction too large: {} bytes, limit {MAX_TX_BYTES}",
            raw.len()
        ));
    }
    let tx: Transaction =
        serde_json::from_str(raw).map_err(|_| "Invalid JSON format".to_string())?;
    if tx.chain_id != chain_id {
        return Err(format!(
            "Invalid Chain ID (Expected {}, Got {})",
            chain_id, tx.chain_id
        ));
    }
    if tx.gas_price < MIN_GAS_PRICE {
        return Err(format!(
            "Gas price too low: {} < minimum {MIN_GAS_PRICE}",
            tx.gas_price
        ));
    }
    if tx.gas_limit == 0 {
        return Err("Gas limit must be greater than 0".to_string());
    }
    if tx.gas_limit > MAX_GAS_LIMIT {
        return Err(format!(
            "Gas limit {} exceeds MAX_GAS_LIMIT {MAX_GAS_LIMIT}",
            tx.gas_limit
        ));
    }
    match crate::payload_kind(&tx.payload)? {
        PayloadKind::EntryFunction | PayloadKind::PublishModule => {}
        PayloadKind::Script => return Err("Raw script payloads are disabled".to_string()),
    }
    if let Some(proof) = tx.zkp_proof.as_deref().filter(|p| !p.is_empty()) {
        let canonical = format!(
            "{}:{}:{}:{}",
            tx.chain_id, tx.sender, tx.payload, tx.sequence_number
        );
        crypto::zkp::verify_tx_attached_proof(proof, canonical.as_bytes())
            .map_err(|e| format!("ZKP proof rejected: {e}"))?;
    }

    let key = hex::decode(&tx.public_key).map_err(|_| "public key is not hex".to_string())?;
    let derived =
        crypto::derive_address(&key).map_err(|e| format!("Address derivation failed: {e}"))?;
    if derived != tx.sender {
        return Err(format!(
            "Sender mismatch (expected {derived}, got {})",
            tx.sender
        ));
    }
    let signature = hex::decode(&tx.signature).map_err(|_| "signature is not hex".to_string())?;
    let scheme = crypto::verify_tx_signature(&key, signing_message(&tx).as_bytes(), &signature)
        .map_err(|e| format!("Invalid signature: {e}"))?;

    let payer = match &tx.paymaster {
        None => tx.sender.clone(),
        Some(paymaster) => {
            let pm_signature = tx
                .paymaster_signature
                .as_deref()
                .ok_or_else(|| "a paymaster without a signature".to_string())?;
            let pm_key = hex::decode(paymaster)
                .map_err(|_| "paymaster public key is not hex".to_string())?;
            let pm_signature = hex::decode(pm_signature)
                .map_err(|_| "paymaster signature is not hex".to_string())?;
            crypto::verify_tx_signature(&pm_key, &paymaster_message(&tx), &pm_signature)
                .map_err(|e| format!("Invalid paymaster signature: {e}"))?;
            crypto::derive_address(&pm_key)
                .map_err(|e| format!("Paymaster address derivation failed: {e}"))?
        }
    };
    Ok(CheckedTx { tx, scheme, payer })
}

/// The kind of a transaction payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    EntryFunction,
    PublishModule,
    Script,
}

/// A transaction that publishes `module` (any bytes), signed with the Ed25519
/// key whose secret is `key_seed`: well-formed for [`check_stateless`]. For
/// tests and tools that need valid payload items.
pub fn signed_publish(
    key_seed: [u8; 32],
    chain_id: &str,
    sequence_number: u64,
    module: Vec<u8>,
) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&key_seed);
    let public_key = key.verifying_key().to_bytes();
    let payload = vm_move::TransactionPayload::PublishModule(vec![module]);
    let mut tx = Transaction {
        chain_id: chain_id.to_string(),
        sender: crypto::derive_address(&public_key).expect("a 32-byte key"),
        input_objects: vec![],
        payload: hex::encode(bcs::to_bytes(&payload).expect("a payload encodes")),
        args: vec![],
        gas_limit: 1000,
        gas_price: 1,
        sequence_number,
        public_key: hex::encode(public_key),
        signature: String::new(),
        paymaster: None,
        paymaster_signature: None,
        zkp_proof: None,
    };
    tx.signature = hex::encode(key.sign(signing_message(&tx).as_bytes()).to_bytes());
    serde_json::to_string(&tx).expect("a transaction serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &str = "AINCORE-ADMISSION-TEST";

    #[test]
    fn a_signed_publish_passes_and_any_change_fails() {
        let tx = signed_publish([1; 32], CHAIN, 3, vec![1, 2, 3]);
        let checked = check_stateless(&tx, CHAIN).expect("valid");
        assert_eq!(checked.scheme, TxScheme::Ed25519);
        assert_eq!(checked.payer, checked.tx.sender);
        assert!(check_stateless(&tx, "ANOTHER-CHAIN").is_err());

        let v: serde_json::Value = serde_json::from_str(&tx).unwrap();
        for (field, value) in [
            ("sequence_number", serde_json::json!(4)),
            ("gas_limit", serde_json::json!(1001)),
            ("gas_price", serde_json::json!(2)),
            ("input_objects", serde_json::json!(["ab"])),
            ("sender", serde_json::json!("ab".repeat(32))),
        ] {
            let mut t = v.clone();
            t[field] = value;
            assert!(check_stateless(&t.to_string(), CHAIN).is_err(), "{field}");
        }
    }

    #[test]
    fn junk_and_out_of_bounds_transactions_fail() {
        for junk in ["", "tx", "x".repeat(1000).as_str(), "{}", "[1,2]"] {
            assert!(check_stateless(junk, CHAIN).is_err(), "{junk:.20}");
        }
        assert!(check_stateless(&"x".repeat(MAX_TX_BYTES + 1), CHAIN)
            .unwrap_err()
            .contains("too large"));
        let tx = signed_publish([1; 32], CHAIN, 0, vec![]);
        let v: serde_json::Value = serde_json::from_str(&tx).unwrap();
        for (field, value, needle) in [
            ("gas_price", serde_json::json!(0), "Gas price too low"),
            ("gas_limit", serde_json::json!(0), "greater than 0"),
            (
                "gas_limit",
                serde_json::json!(MAX_GAS_LIMIT + 1),
                "MAX_GAS_LIMIT",
            ),
            ("payload", serde_json::json!("zz"), "TransactionPayload"),
        ] {
            let mut t = v.clone();
            t[field] = value;
            let err = check_stateless(&t.to_string(), CHAIN).unwrap_err();
            assert!(err.contains(needle), "{field}: {err}");
        }
        let script = vm_move::TransactionPayload::Script(vec![]);
        let mut t = v.clone();
        t["payload"] = serde_json::json!(hex::encode(bcs::to_bytes(&script).unwrap()));
        assert!(check_stateless(&t.to_string(), CHAIN)
            .unwrap_err()
            .contains("disabled"));
    }

    /// B13: a paymaster is named by its public key and pays from the address
    /// derived from it; its signature covers chain, sender, payload, gas limit
    /// and sequence number.
    #[test]
    fn a_paymaster_pays_from_its_derived_address() {
        use ed25519_dalek::{Signer, SigningKey};
        let tx = signed_publish([1; 32], CHAIN, 0, vec![9]);
        let pm = SigningKey::from_bytes(&[2; 32]);
        let mut v: serde_json::Value = serde_json::from_str(&tx).unwrap();
        let parsed: Transaction = serde_json::from_value(v.clone()).unwrap();
        v["paymaster"] = serde_json::json!(hex::encode(pm.verifying_key().to_bytes()));
        v["paymaster_signature"] =
            serde_json::json!(hex::encode(pm.sign(&paymaster_message(&parsed)).to_bytes()));
        let checked = check_stateless(&v.to_string(), CHAIN).expect("sponsored");
        let address = crypto::derive_address(pm.verifying_key().as_bytes()).unwrap();
        assert_eq!(checked.payer, address);
        assert_ne!(
            checked.payer,
            v["paymaster"].as_str().unwrap(),
            "not the raw key"
        );

        // The paymaster's signature does not carry over to another sequence number.
        let mut replay = v.clone();
        replay["sequence_number"] = serde_json::json!(1);
        let replay_tx: Transaction = serde_json::from_value(replay.clone()).unwrap();
        replay["signature"] = serde_json::json!(hex::encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(signing_message(&replay_tx).as_bytes())
                .to_bytes()
        ));
        let err = check_stateless(&replay.to_string(), CHAIN).unwrap_err();
        assert!(err.contains("Invalid paymaster signature"), "{err}");
    }

    #[test]
    fn an_ml_dsa_65_sender_is_accepted() {
        let key = crypto::MlDsa65Key::from_seed(&[5; 32]);
        let tx = signed_publish([1; 32], CHAIN, 0, vec![7]);
        let mut v: serde_json::Value = serde_json::from_str(&tx).unwrap();
        v["public_key"] = serde_json::json!(hex::encode(key.public_key()));
        v["sender"] = serde_json::json!(crypto::derive_address(&key.public_key()).unwrap());
        let parsed: Transaction = serde_json::from_value(v.clone()).unwrap();
        v["signature"] =
            serde_json::json!(hex::encode(key.sign(signing_message(&parsed).as_bytes())));
        let checked = check_stateless(&v.to_string(), CHAIN).expect("ML-DSA-65");
        assert_eq!(checked.scheme, TxScheme::MlDsa65);
    }
}
