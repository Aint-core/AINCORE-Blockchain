//! The stateless half of transaction validity (bug ledger B8, B12, B13).
//!
//! One predicate decides whether a string is a well-formed, authenticated
//! transaction for this chain, using nothing but the string and the chain id.
//! The mempool runs it at admission, vertex ingress runs it on every payload
//! item, and the executor runs it before it reads state, so the three cannot
//! disagree about what a transaction is. What it cannot decide (nonce, balance,
//! the paymaster's balance) is the executor's.

use crate::{Transaction, MAX_BLOCK_GAS_LIMIT, MAX_GAS_LIMIT};
use crypto::TxScheme;
use sha2::{Digest, Sha256};

/// The largest transaction, as raw JSON bytes.
pub const MAX_TX_BYTES: usize = 100 * 1024;
/// The lowest gas price any transaction may name. The price a block charges
/// is its base fee (B15), at least the chain's `sys:config:min_base_fee`.
pub const MIN_GAS_PRICE: u128 = 1;
/// B14: gas per byte of the raw transaction, part of the `gas_limit` it must
/// declare. Derived in docs/research/fees_and_block_resources.md: blocks may
/// use half of the 100 GB minimum disk over the 100,000 blocks a full node
/// keeps, 500 KB a block; less the ~10 KB empty-block overhead and with each
/// body byte stored about twice, a 245 KB target body; the EIP-1559 target of
/// 100M gas over it is 408 gas a byte, rounded down to 400.
pub const BYTE_GAS: u64 = 400;

/// The gas a transaction of `raw_len` bytes owes for its bytes.
pub fn intrinsic_gas(raw_len: usize) -> u64 {
    (raw_len as u64).saturating_mul(BYTE_GAS)
}

/// A transaction that passed [`check_stateless`].
#[derive(Debug, Clone)]
pub struct CheckedTx {
    pub tx: Transaction,
    /// The sender's signature scheme.
    pub scheme: TxScheme,
    /// The address that pays gas: the sender, or the paymaster's address.
    pub payer: String,
    /// `gas_limit` less the intrinsic byte gas: what Move execution may use.
    pub execution_gas: u64,
}

/// The bytes the sender signs (F4: seven fields, ':'-joined). B73: and,
/// for a sponsored transaction, an eighth, the paymaster's key: a relay
/// could strip the paymaster (the sender then paid in full) or name one.
/// Input objects are lowercase hex (`check_stateless`), so no field holds a
/// ':' or a ',' and the message reads one way only.
pub fn signing_message(tx: &Transaction) -> String {
    let mut message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        tx.chain_id,
        tx.sender,
        tx.payload,
        tx.sequence_number,
        tx.gas_limit,
        tx.gas_price,
        tx.input_objects.join(",")
    );
    if let Some(paymaster) = &tx.paymaster {
        message.push(':');
        message.push_str(paymaster);
    }
    message
}

/// B73: the one JSON encoding of a transaction: compact, its fields in this
/// order (the SDK's), an absent paymaster or proof left out, `args` never
/// (they must be empty). Nodes keep, forward and order transactions only in
/// it, and vertex ingress refuses any other, so a relay cannot change a
/// transaction's bytes: its id (the hash of these bytes) or its byte gas.
pub fn canonical_json(tx: &Transaction) -> String {
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        chain_id: &'a str,
        sender: &'a str,
        input_objects: &'a [String],
        payload: &'a str,
        gas_limit: u64,
        gas_price: u128,
        sequence_number: u64,
        public_key: &'a str,
        signature: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        paymaster: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        paymaster_signature: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        zkp_proof: Option<&'a str>,
    }
    serde_json::to_string(&Canonical {
        chain_id: &tx.chain_id,
        sender: &tx.sender,
        input_objects: &tx.input_objects,
        payload: &tx.payload,
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        sequence_number: tx.sequence_number,
        public_key: &tx.public_key,
        signature: &tx.signature,
        paymaster: tx.paymaster.as_deref(),
        paymaster_signature: tx.paymaster_signature.as_deref(),
        zkp_proof: tx.zkp_proof.as_deref().filter(|p| !p.is_empty()),
    })
    .expect("a transaction serializes")
}

/// B73: `raw` in its canonical encoding (`canonical_json`).
pub fn canonicalize(raw: &str) -> Result<String, String> {
    if raw.len() > MAX_TX_BYTES {
        return Err(format!(
            "transaction too large: {} bytes, limit {MAX_TX_BYTES}",
            raw.len()
        ));
    }
    let tx: Transaction =
        serde_json::from_str(raw).map_err(|_| "Invalid JSON format".to_string())?;
    Ok(canonical_json(&tx))
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// B73: what no signature covers may not vary: `args` (scripts are
/// disabled) must be empty, a paymaster signature needs a paymaster, and
/// keys, signatures and object ids are lowercase hex (`hex::decode` reads
/// either case, so a relay could change the case and the bytes).
fn unsigned_parts_fixed(tx: &Transaction) -> Result<(), String> {
    if !tx.args.is_empty() {
        return Err("args are not signed (scripts are disabled): send none".to_string());
    }
    if tx.paymaster.is_none() && tx.paymaster_signature.is_some() {
        return Err("a paymaster signature without a paymaster".to_string());
    }
    for object in &tx.input_objects {
        if object.is_empty() || object.len() > 64 || !is_lower_hex(object) {
            return Err(format!(
                "input object {object:.70} is not an object id (1 to 64 lowercase hex digits)"
            ));
        }
    }
    for (field, value) in [
        ("public_key", Some(&tx.public_key)),
        ("signature", Some(&tx.signature)),
        ("paymaster", tx.paymaster.as_ref()),
        ("paymaster_signature", tx.paymaster_signature.as_ref()),
    ] {
        if value.is_some_and(|v| !is_lower_hex(v)) {
            return Err(format!("{field} is not lowercase hex"));
        }
    }
    Ok(())
}

/// The bytes a paymaster signs: SHA-256 of `PAYMASTER_AUTH_V2:` and the
/// sender's signing message, so the paymaster binds every field the sender
/// does. B28: the first form left out the gas price and the input objects,
/// so a sponsored sender could set the price as high as the paymaster's
/// balance allowed.
pub fn paymaster_message(tx: &Transaction) -> [u8; 32] {
    Sha256::digest(format!("PAYMASTER_AUTH_V2:{}", signing_message(tx)).as_bytes()).into()
}

/// Gas charged up front per input object (N-2).
pub const OBJECT_LOAD_GAS: u64 = 100;
/// The most input objects a transaction may name: a block skips one with
/// more (B70: admission refuses it, so it never waits for free).
pub const MAX_INPUT_OBJECTS: usize = 128;
/// The execution gas a module bundle must carry, per byte and per module
/// (audit M-5: verification work scales with the bundle).
pub const PUBLISH_GAS_PER_BYTE: u64 = 10;
pub const PUBLISH_GAS_PER_MODULE: u64 = 5_000;

/// The execution gas publishing `modules` requires.
pub fn publish_floor(modules: &[Vec<u8>]) -> u64 {
    let bytes: u64 = modules.iter().map(|m| m.len() as u64).sum();
    bytes
        .saturating_mul(PUBLISH_GAS_PER_BYTE)
        .saturating_add((modules.len() as u64).saturating_mul(PUBLISH_GAS_PER_MODULE))
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
    // B70: the count first (a structural bound, whatever the gas).
    if tx.input_objects.len() > MAX_INPUT_OBJECTS {
        return Err(format!(
            "{} input objects, the most is {MAX_INPUT_OBJECTS}",
            tx.input_objects.len()
        ));
    }
    unsigned_parts_fixed(&tx)?;
    if tx.gas_price < MIN_GAS_PRICE {
        return Err(format!(
            "Gas price too low: {} < minimum {MIN_GAS_PRICE}",
            tx.gas_price
        ));
    }
    if tx.gas_limit == 0 {
        return Err("Gas limit must be greater than 0".to_string());
    }
    let intrinsic = intrinsic_gas(raw.len());
    let Some(execution_gas) = tx.gas_limit.checked_sub(intrinsic) else {
        return Err(format!(
            "Gas limit {} is below the intrinsic gas {intrinsic} of a {}-byte transaction ({BYTE_GAS} a byte)",
            tx.gas_limit,
            raw.len()
        ));
    };
    // B65: Move execution is capped at MAX_GAS_LIMIT when it runs; the rest
    // of a limit pays for the transaction's writes, so the whole limit is
    // bounded by what a block holds.
    if tx.gas_limit > MAX_BLOCK_GAS_LIMIT {
        return Err(format!(
            "Gas limit {} is over MAX_BLOCK_GAS_LIMIT {MAX_BLOCK_GAS_LIMIT}",
            tx.gas_limit
        ));
    }
    let (kind, publish_floor) = crate::payload_kind(&tx.payload)?;
    match kind {
        PayloadKind::EntryFunction | PayloadKind::PublishModule => {}
        PayloadKind::Script => return Err("Raw script payloads are disabled".to_string()),
    }
    // B27: what execution refuses before it charges, decided here, so no
    // block reserves space for it (vertex ingress runs this check).
    let object_load = (tx.input_objects.len() as u64).saturating_mul(OBJECT_LOAD_GAS);
    if object_load > execution_gas {
        return Err(format!(
            "{} input objects need {object_load} gas, the limit leaves {execution_gas}",
            tx.input_objects.len()
        ));
    }
    if publish_floor > execution_gas.min(MAX_GAS_LIMIT) {
        return Err(format!(
            "the module bundle needs {publish_floor} execution gas, the limit leaves {}",
            execution_gas.min(MAX_GAS_LIMIT)
        ));
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
    Ok(CheckedTx {
        tx,
        scheme,
        payer,
        execution_gas,
    })
}

/// B65 (`aincore_estimateGas`): what `check_stateless` checks of a
/// transaction's form and identity, without its gas fields and signatures,
/// which an estimate is asked for before they are final. The signature must
/// have its scheme's length (zeros do): the byte gas counts it.
/// `execution_gas` is left 0 for the caller to set.
pub fn check_unsigned(raw: &str, chain_id: &str) -> Result<CheckedTx, String> {
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
    if crate::payload_kind(&tx.payload)?.0 == PayloadKind::Script {
        return Err("Raw script payloads are disabled".to_string());
    }
    unsigned_parts_fixed(&tx)?;
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
    let scheme = TxScheme::of(key.len(), signature.len()).ok_or_else(|| {
        format!(
            "no scheme has a {}-byte key and a {}-byte signature (send zeros of the signature's length)",
            key.len(),
            signature.len()
        )
    })?;
    let payer = payer_address(&tx).ok_or_else(|| "paymaster key is not hex".to_string())?;
    Ok(CheckedTx {
        tx,
        scheme,
        payer,
        execution_gas: 0,
    })
}

/// B16: whoever pays `tx`'s gas: the address of its paymaster key, or its
/// sender. Unverified; `check_stateless` checks the paymaster's signature.
pub fn payer_address(tx: &Transaction) -> Option<String> {
    match &tx.paymaster {
        None => Some(tx.sender.clone()),
        Some(paymaster) => crypto::derive_address(&hex::decode(paymaster).ok()?).ok(),
    }
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
/// tests and tools that need valid payload items. Its execution gas is the
/// bundle's publish floor (B27).
pub fn signed_publish(
    key_seed: [u8; 32],
    chain_id: &str,
    sequence_number: u64,
    module: Vec<u8>,
) -> String {
    let execution = publish_floor(std::slice::from_ref(&module));
    signed_publish_with(
        key_seed,
        chain_id,
        sequence_number,
        module,
        execution,
        MIN_GAS_PRICE,
    )
}

/// The `gas_limit` for a transaction whose JSON is `len_with_zero_gas` bytes
/// when its `gas_limit` is written `0`: `execution` for Move plus the
/// intrinsic gas of the JSON once the limit's own digits are in it. The
/// smallest digit count that holds is used, so the limit covers the bytes,
/// and is exact whenever a digit count fits the limit it produces.
pub fn gas_limit_covering(len_with_zero_gas: usize, execution: u64) -> u64 {
    let without_digits = len_with_zero_gas.saturating_sub(1);
    for digits in 1..=20usize {
        let limit = execution.saturating_add(intrinsic_gas(without_digits + digits));
        if limit.to_string().len() <= digits {
            return limit;
        }
    }
    execution.saturating_add(intrinsic_gas(without_digits + 20))
}

/// `signed_publish` with `execution` gas for Move on top of the intrinsic
/// byte gas, at `gas_price`.
pub fn signed_publish_with(
    key_seed: [u8; 32],
    chain_id: &str,
    sequence_number: u64,
    module: Vec<u8>,
    execution: u64,
    gas_price: u128,
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
        gas_limit: 0,
        gas_price,
        sequence_number,
        public_key: hex::encode(public_key),
        signature: "0".repeat(128),
        paymaster: None,
        paymaster_signature: None,
        zkp_proof: None,
    };
    // In the canonical encoding (B73), the only one vertex ingress takes.
    let unsized_len = canonical_json(&tx).len();
    tx.gas_limit = gas_limit_covering(unsized_len, execution);
    tx.signature = hex::encode(key.sign(signing_message(&tx).as_bytes()).to_bytes());
    canonical_json(&tx)
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

    /// B14: a signed transaction's limit is its execution gas plus exactly
    /// its own bytes' gas. B65: execution gas past MAX_GAS_LIMIT pays for
    /// writes, up to what a block holds.
    #[test]
    fn the_limit_covers_exactly_the_transactions_own_bytes() {
        // From the 40-byte bundle's publish floor (B27) up.
        for execution in [5_400, 10_000, 999_999, MAX_GAS_LIMIT, 5 * MAX_GAS_LIMIT] {
            let tx = signed_publish_with([1; 32], CHAIN, 0, vec![5; 40], execution, 1);
            let checked = check_stateless(&tx, CHAIN).expect("valid");
            assert_eq!(checked.execution_gas, execution, "{execution}");
            assert_eq!(checked.tx.gas_limit, execution + intrinsic_gas(tx.len()));
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
                serde_json::json!(u64::MAX / 2),
                "MAX_BLOCK_GAS_LIMIT",
            ),
            (
                "gas_limit",
                serde_json::json!(MAX_BLOCK_GAS_LIMIT + 1),
                "MAX_BLOCK_GAS_LIMIT",
            ),
            ("gas_limit", serde_json::json!(10), "intrinsic gas"),
            (
                "input_objects",
                serde_json::json!(vec!["ab"; MAX_INPUT_OBJECTS + 1]),
                "input objects",
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
        // Execution headroom pays for the paymaster fields added after signing.
        let tx = signed_publish_with([1; 32], CHAIN, 0, vec![9], 1_000_000, 1);
        let pm = SigningKey::from_bytes(&[2; 32]);
        let v = sponsor(serde_json::from_str(&tx).unwrap(), &pm);
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
        // Room for the 1,952-byte key and the 3,309-byte signature (B14).
        v["gas_limit"] = serde_json::json!(10_000_000);
        let parsed: Transaction = serde_json::from_value(v.clone()).unwrap();
        v["signature"] =
            serde_json::json!(hex::encode(key.sign(signing_message(&parsed).as_bytes())));
        let checked = check_stateless(&v.to_string(), CHAIN).expect("ML-DSA-65");
        assert_eq!(checked.scheme, TxScheme::MlDsa65);
    }

    /// `v` sponsored by `pm`: the paymaster named, the sender's signature
    /// renewed over it (B73), then the paymaster's.
    fn sponsor(mut v: serde_json::Value, pm: &ed25519_dalek::SigningKey) -> serde_json::Value {
        use ed25519_dalek::Signer;
        v["paymaster"] = serde_json::json!(hex::encode(pm.verifying_key().to_bytes()));
        let mut v = resign(v);
        let parsed: Transaction = serde_json::from_value(v.clone()).unwrap();
        v["paymaster_signature"] =
            serde_json::json!(hex::encode(pm.sign(&paymaster_message(&parsed)).to_bytes()));
        v
    }

    /// Re-sign `v` as the sender (seed `[1; 32]`) after a field change.
    fn resign(mut v: serde_json::Value) -> serde_json::Value {
        use ed25519_dalek::{Signer, SigningKey};
        let tx: Transaction = serde_json::from_value(v.clone()).unwrap();
        v["signature"] = serde_json::json!(hex::encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(signing_message(&tx).as_bytes())
                .to_bytes()
        ));
        v
    }

    /// B28 witness: the paymaster's signature binds the gas price and the
    /// input objects (it binds the sender's whole message). Before, a
    /// sponsored sender re-signed a higher price and the paymaster paid it.
    #[test]
    fn the_paymaster_binds_the_gas_price_and_the_objects() {
        use ed25519_dalek::SigningKey;
        let tx = signed_publish_with([1; 32], CHAIN, 0, vec![9], 1_000_000, 1);
        let pm = SigningKey::from_bytes(&[2; 32]);
        let v = sponsor(serde_json::from_str(&tx).unwrap(), &pm);
        check_stateless(&v.to_string(), CHAIN).expect("positive control: sponsored");
        for (field, value) in [
            ("gas_price", serde_json::json!(1_000_000_000u64)),
            ("input_objects", serde_json::json!(["ab"])),
        ] {
            let mut t = v.clone();
            t[field] = value;
            let err = check_stateless(&resign(t).to_string(), CHAIN).unwrap_err();
            assert!(
                err.contains("Invalid paymaster signature"),
                "{field}: {err}"
            );
        }
    }

    /// B27 witness: what execution refuses before it charges (objects that
    /// need more gas than the limit leaves, a module bundle under its
    /// publish floor) is refused here, so vertex ingress keeps it out of
    /// every block and no block reserves space for it.
    #[test]
    fn what_execution_refuses_before_charging_is_refused_at_admission() {
        // 2,000 bytes and one module: a floor of 2,000 * 10 + 5,000 = 25,000.
        assert_eq!(publish_floor(&[vec![1; 2_000]]), 25_000);
        let tx = signed_publish_with([1; 32], CHAIN, 0, vec![1; 2_000], 20_000, 1);
        let err = check_stateless(&tx, CHAIN).unwrap_err();
        assert!(err.contains("module bundle needs"), "{err}");
        let ok = signed_publish_with([1; 32], CHAIN, 0, vec![1; 2_000], 25_000, 1);
        check_stateless(&ok, CHAIN).expect("positive control: the floor is met");

        // 100 objects need 10,000 gas; leave 9,000 for execution (above the
        // 10-byte bundle's publish floor, 5,100). The limit is fitted to the
        // transaction's final length.
        let call = signed_publish_with([1; 32], CHAIN, 0, vec![1; 10], 1_000_000, 1);
        let mut v: serde_json::Value = serde_json::from_str(&call).unwrap();
        v["input_objects"] =
            serde_json::json!((0..100).map(|i| format!("{i:02x}")).collect::<Vec<_>>());
        for _ in 0..4 {
            let len = resign(v.clone()).to_string().len();
            v["gas_limit"] = serde_json::json!(intrinsic_gas(len) + 9_000);
        }
        let raw = resign(v).to_string();
        let err = check_stateless(&raw, CHAIN).unwrap_err();
        assert!(
            err.contains("input objects need") && err.contains("leaves 9000"),
            "{err}"
        );
    }

    /// B73 witness: the sender's signature binds its paymaster, so a relay
    /// can neither strip it (the sender would pay) nor name another; what no
    /// signature covers cannot vary; and every encoding of a transaction
    /// comes back as one canonical string, the same id.
    #[test]
    fn a_relay_cannot_change_what_a_transaction_is() {
        use ed25519_dalek::SigningKey;
        let tx = signed_publish_with([1; 32], CHAIN, 0, vec![9], 1_000_000, 1);
        let pm = SigningKey::from_bytes(&[2; 32]);
        let v = sponsor(serde_json::from_str(&tx).unwrap(), &pm);
        check_stateless(&v.to_string(), CHAIN).expect("positive control: sponsored");
        let mut stripped = v.clone();
        stripped.as_object_mut().unwrap().remove("paymaster");
        stripped
            .as_object_mut()
            .unwrap()
            .remove("paymaster_signature");
        let err = check_stateless(&stripped.to_string(), CHAIN).unwrap_err();
        assert!(err.contains("Invalid signature"), "stripped: {err}");
        let other = SigningKey::from_bytes(&[3; 32]);
        let mut swapped = v.clone();
        swapped["paymaster"] = serde_json::json!(hex::encode(other.verifying_key().to_bytes()));
        let err = check_stateless(&swapped.to_string(), CHAIN).unwrap_err();
        assert!(err.contains("Invalid signature"), "swapped: {err}");

        // What no signature covers: refused if it varies.
        let plain: serde_json::Value = serde_json::from_str(&tx).unwrap();
        for (field, value, needle) in [
            ("args", serde_json::json!(["00"]), "args"),
            (
                "paymaster_signature",
                serde_json::json!("00"),
                "without a paymaster",
            ),
            (
                "signature",
                serde_json::json!(plain["signature"].as_str().unwrap().to_uppercase()),
                "lowercase hex",
            ),
            (
                "public_key",
                serde_json::json!(plain["public_key"].as_str().unwrap().to_uppercase()),
                "lowercase hex",
            ),
        ] {
            let mut t = plain.clone();
            t[field] = value;
            let err = check_stateless(&t.to_string(), CHAIN).unwrap_err();
            assert!(err.contains(needle), "{field}: {err}");
        }
        for objects in [vec!["ab,cd"], vec!["ab:cd"], vec!["AB"], vec![""]] {
            let mut t = plain.clone();
            t["input_objects"] = serde_json::json!(objects);
            let err = check_stateless(&resign(t).to_string(), CHAIN).unwrap_err();
            assert!(err.contains("not an object id"), "{objects:?}: {err}");
        }

        // Any encoding (key order, spacing, an unknown field, an empty proof)
        // canonicalizes to one string, which is its own canonical form.
        let canonical = canonicalize(&tx).unwrap();
        let mut padded = plain.clone();
        padded["junk"] = serde_json::json!("x".repeat(1_000));
        padded["zkp_proof"] = serde_json::json!("");
        let spaced = serde_json::to_string_pretty(&padded).unwrap();
        assert_eq!(canonicalize(&spaced).unwrap(), canonical);
        assert_eq!(canonicalize(&canonical).unwrap(), canonical);
        assert!(canonical.len() < spaced.len());
        assert!(canonical.starts_with("{\"chain_id\":"), "{canonical:.40}");
        let sponsored = v.to_string();
        let c = canonicalize(&sponsored).unwrap();
        assert_eq!(canonicalize(&c).unwrap(), c);
        check_stateless(&c, CHAIN).expect("the canonical form is the same transaction");
    }
}
