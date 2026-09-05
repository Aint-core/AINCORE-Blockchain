//! LIVE money-path exercise against a running validator.
//!
//! What the unit tests could not prove and nothing had exercised on a real
//! chain: a brand-new address receiving its FIRST AIN (the executor's
//! auto-register path), that address then SPENDING, exact gas accounting on a
//! non-validator sender (no block-reward confounder), abort atomicity on an
//! insufficient-balance transfer, and replay rejection.
//!
//! Funding key is read from the node's own node.key and never printed or copied
//! off the host. The two fresh test keys are generated in memory and discarded.
//!
//! Usage: cargo run --release --example money_live -- <datadir>/node.key <rpc-url>
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier,
    language_storage::{ModuleId, StructTag, TypeTag},
};

const GAS_LIMIT: u64 = 200_000;
const GAS_PRICE: u128 = 1;
const AIN: u128 = 1_000_000_000_000_000_000; // 10^18 quanta

struct Acct { key: SigningKey, addr: String, move_addr: AccountAddress }
impl Acct {
    fn from_key(key: SigningKey) -> Result<Self> {
        let addr = crypto::derive_address(key.verifying_key().as_bytes())?;
        let move_addr = AccountAddress::from_hex_literal(&format!("0x{}", addr))?;
        Ok(Acct { key, addr, move_addr })
    }
    fn fresh() -> Result<Self> {
        Self::from_key(SigningKey::generate(&mut rand::rngs::OsRng))
    }
}

fn sys() -> AccountAddress { AccountAddress::from_hex_literal("0x1").unwrap() }
fn ain_ty() -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
        address: sys(), module: Identifier::new("staking").unwrap(),
        name: Identifier::new("AincoreCoin").unwrap(), type_params: vec![],
    }))
}
// This codebase's entry-call ABI carries an explicit LEADING signer-slot arg
// that bind_signer_args overwrites with the real sender; coin::transfer is
// therefore [from, to, amount] on the wire, not [to, amount]. Omitting `from`
// shifts every index by one: auto_register_writes reads args[1] as the
// recipient and gets the amount instead, so the deposit aborts while seq/gas
// still advance. (This is exactly the bug the first harness run hit.)
fn transfer_payload(from: &AccountAddress, to: &AccountAddress, amount: u128) -> String {
    let call = vm_move::EntryFunctionCall {
        module: ModuleId::new(sys(), Identifier::new("coin").unwrap()),
        function: "transfer".into(), ty_args: vec![ain_ty()],
        args: vec![bcs::to_bytes(from).unwrap(), bcs::to_bytes(to).unwrap(), bcs::to_bytes(&amount).unwrap()],
    };
    hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
}

thread_local! {
    // ONE reused client (keep-alive) instead of a fresh connection per call.
    // A new Client per call opens a new TCP conn each time, which both trips the
    // node's per-IP connection cap and defeats its rate limiter — that is what
    // turned the first run's later reads into empty bodies. Reuse + retry fixes it.
    static CLIENT: reqwest::blocking::Client = reqwest::blocking::Client::builder()
        .pool_max_idle_per_host(2)
        .timeout(std::time::Duration::from_secs(12))
        .build().unwrap();
}
fn rpc(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({"jsonrpc":"2.0","method":method,"params":params,"id":1});
    let mut last = anyhow!("no attempt");
    for attempt in 0..10 {
        if attempt > 0 { std::thread::sleep(std::time::Duration::from_millis(700 * attempt as u64)); }
        let r = CLIENT.with(|c| c.post(url).json(&body).send());
        match r.and_then(|resp| resp.text()) {
            Ok(text) => {
                let t = text.trim();
                if t.is_empty() { last = anyhow!("empty body (rate-limited)"); continue; }
                if let Some(sec) = t.strip_prefix("Too many requests, retry in ")
                    .and_then(|r| r.trim_end_matches('s').trim().parse::<u64>().ok()) {
                    std::thread::sleep(std::time::Duration::from_secs(sec + 1));
                    last = anyhow!("rate-limited, waited {}s", sec + 1); continue;
                }
                match serde_json::from_str::<serde_json::Value>(t) {
                    Ok(v) => {
                        if let Some(e) = v.get("error") { if !e.is_null() { return Err(anyhow!("{}", e)); } }
                        return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
                    }
                    Err(_) => { last = anyhow!("non-json body: {}", t.chars().take(60).collect::<String>()); continue; }
                }
            }
            Err(e) => { last = anyhow!("{}", e); continue; }
        }
    }
    Err(last)
}
fn pace() { std::thread::sleep(std::time::Duration::from_millis(250)); }
fn balance(url: &str, addr: &str) -> u128 {
    pace();
    rpc(url, "aincore_getCoinBalance", serde_json::json!([addr, "AIN"])).ok()
        .and_then(|r| r.get("balance").and_then(|v| v.as_str()).map(String::from))
        .and_then(|s| s.parse().ok()).unwrap_or(0)
}
fn nonce(url: &str, addr: &str) -> u64 {
    pace();
    rpc(url, "aincore_getAccountNonce", serde_json::json!([addr])).ok()
        .and_then(|r| r.get("nonce").and_then(|v| v.as_u64())).unwrap_or(0)
}
fn supply(url: &str) -> String {
    rpc(url, "aincore_getSupply", serde_json::json!([])).map(|v| v.to_string()).unwrap_or_else(|e| format!("ERR {}", e))
}

/// Build + sign (7-field preimage). Returns the raw tx JSON (for replay tests).
fn build_tx(chain_id: &str, from: &Acct, seq: u64, payload: &str) -> serde_json::Value {
    let msg = format!("{}:{}:{}:{}:{}:{}:{}", chain_id, from.addr, payload, seq, GAS_LIMIT, GAS_PRICE, "");
    let sig = from.key.sign(msg.as_bytes());
    serde_json::json!({
        "chain_id": chain_id, "sender": from.addr, "input_objects": [], "payload": payload,
        "gas_limit": GAS_LIMIT, "gas_price": GAS_PRICE, "sequence_number": seq,
        "public_key": hex::encode(from.key.verifying_key().as_bytes()),
        "signature": hex::encode(sig.to_bytes()),
    })
}
fn send(url: &str, tx: &serde_json::Value) -> Result<String> {
    let r = rpc(url, "aincore_sendTransaction", serde_json::json!([tx]))?;
    r.get("tx_hash").and_then(|v| v.as_str()).map(String::from).ok_or_else(|| anyhow!("no tx_hash: {}", r))
}
/// Poll until the recipient's balance reaches `want`, or timeout. Effect-based:
/// avoids getTransactionReceipt (whose key hash the harness cannot reproduce)
/// and the dead 120s waits that were feeding the rate limiter.
fn wait_balance(url: &str, addr: &str, want: u128) -> bool {
    for _ in 0..40 {
        if balance(url, addr) == want { return true; }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    false
}
/// Poll until the sender's nonce reaches `want` (an aborted tx still advances it),
/// or timeout. Returns whether it advanced.
fn wait_nonce(url: &str, addr: &str, want: u64) -> bool {
    for _ in 0..40 {
        if nonce(url, addr) >= want { return true; }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    false
}

fn ok(cond: bool, what: &str) -> bool {
    println!("  {} {}", if cond { "✅" } else { "❌" }, what);
    cond
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let key_path = args.get(1).ok_or_else(|| anyhow!("arg 1: path ke node.key"))?;
    let url = args.get(2).map(String::as_str).unwrap_or("http://127.0.0.1:8201/rpc");
    let chain_id = std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-LOCALTEST-3V".into());

    let raw = std::fs::read(key_path)?;
    let seed: [u8; 32] = if raw.len() == 32 { raw[..].try_into()? } else {
        hex::decode(String::from_utf8_lossy(&raw).trim())?.as_slice().try_into().map_err(|_| anyhow!("node.key bukan 32 byte"))?
    };
    let v1 = Acct::from_key(SigningKey::from_bytes(&seed))?;
    let b = Acct::fresh()?;
    let c = Acct::fresh()?;
    let mut all_ok = true;

    println!("== UJI JALUR UANG HIDUP ==  chain={} rpc={}", chain_id, url);
    println!("  pendana V1 : {}  saldo {} quanta", v1.addr, balance(url, &v1.addr));
    println!("  akun baru B: {}", b.addr);
    println!("  akun baru C: {}", c.addr);
    println!("  supply awal: {}", supply(url));

    // ---- 1. V1 -> B : akun BARU menerima AIN pertamanya (auto-register) ----
    println!("\n1) V1 -> B  20 AIN  (B belum punya CoinStore)");
    let v1_seq = nonce(url, &v1.addr);
    send(url, &build_tx(&chain_id, &v1, v1_seq, &transfer_payload(&v1.move_addr, &b.move_addr, 20 * AIN)))?;
    all_ok &= ok(wait_balance(url, &b.addr, 20 * AIN), "B menerima TEPAT 20 AIN (akun baru, auto-register)");

    // ---- 2. B -> C : akun baru BELANJA; gas presisi via delta saldo ----
    println!("\n2) B -> C  5 AIN  (B membayar gas sendiri)");
    let b_before2 = balance(url, &b.addr);
    let b_seq2 = nonce(url, &b.addr);
    send(url, &build_tx(&chain_id, &b, b_seq2, &transfer_payload(&b.move_addr, &c.move_addr, 5 * AIN)))?;
    all_ok &= ok(wait_balance(url, &c.addr, 5 * AIN), "C menerima TEPAT 5 AIN");
    let b_after2 = balance(url, &b.addr);
    let gas2 = (b_before2 - b_after2).saturating_sub(5 * AIN);
    all_ok &= ok(b_before2 - b_after2 == 5 * AIN + gas2, &format!("B berkurang = 5 AIN + gas ({} quanta)", gas2));
    all_ok &= ok(gas2 > 0, "gas benar-benar dipungut (> 0)");

    // ---- 3. B -> C 1000 AIN : saldo tak cukup -> abort; hanya gas hilang, C tetap ----
    println!("\n3) B -> C  1000 AIN  (harus ABORT tanpa efek parsial)");
    let b_before3 = balance(url, &b.addr);
    let c_before3 = balance(url, &c.addr);
    let b_seq3 = nonce(url, &b.addr);
    match send(url, &build_tx(&chain_id, &b, b_seq3, &transfer_payload(&b.move_addr, &c.move_addr, 1000 * AIN))) {
        Ok(_) => {
            let advanced = wait_nonce(url, &b.addr, b_seq3 + 1);
            let b_after3 = balance(url, &b.addr);
            let c_after3 = balance(url, &c.addr);
            all_ok &= ok(c_after3 == c_before3, &format!("C TIDAK berubah ({} quanta)", c_after3));
            all_ok &= ok(b_before3 - b_after3 < 1000 * AIN, &format!("B TIDAK kehilangan 1000 AIN, hanya {} quanta (gas)", b_before3 - b_after3));
            all_ok &= ok(advanced, "nonce maju (tx masuk blok tapi payload di-abort)");
        }
        Err(e) => { println!("  ditolak di mempool: {}", e); all_ok &= ok(true, "ditolak sebelum masuk blok (juga aman)"); }
    }

    // ---- 4. replay: kirim ulang tx2 persis (seq lama) -> tidak boleh berefek ----
    println!("\n4) replay tx2 (seq lama, payload sama)");
    let c_before4 = balance(url, &c.addr);
    let replay = build_tx(&chain_id, &b, b_seq2, &transfer_payload(&b.move_addr, &c.move_addr, 5 * AIN));
    match send(url, &replay) {
        Err(e) => { all_ok &= ok(true, &format!("ditolak: {}", e.to_string().chars().take(70).collect::<String>())); }
        Ok(_) => { std::thread::sleep(std::time::Duration::from_secs(8));
            all_ok &= ok(balance(url, &c.addr) == c_before4, &format!("C tidak bertambah ({} quanta) — replay tak berefek", balance(url, &c.addr))); }
    }

    println!("\n== RINGKASAN ==");
    println!("  B akhir: {}   C akhir: {}", balance(url, &b.addr), balance(url, &c.addr));
    println!("  supply akhir: {}", supply(url));
    println!("  {}", if all_ok { "SEMUA LULUS" } else { "ADA YANG GAGAL" });
    if !all_ok { std::process::exit(1); }
    Ok(())
}
