//! LIVE DEX exercise against a running validator.
//!
//! `0x1::dex` had never executed on a running chain: the pair asset (wBTC) was
//! unmintable until genesis seeded `wbtc::BridgeConfig`. This drives the whole
//! flow — register, mint, create pool, add liquidity, swap — as the bridge
//! authority (genesis validator #1), then reads the reserves back.
//!
//! The signing key is read from the node's own `node.key` and NEVER printed or
//! copied off the host: run this ON the validator machine.
//!
//! Usage: cargo run --release --example dex_live -- <datadir>/node.key <rpc-url>
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier,
    language_storage::{ModuleId, StructTag, TypeTag},
};

const CHAIN_ID_ENV: &str = "AINCORE_CHAIN_ID";
const GAS_LIMIT: u64 = 200_000;
const GAS_PRICE: u128 = 1;

fn sys() -> AccountAddress {
    AccountAddress::from_hex_literal("0x1").expect("0x1")
}
fn coin_ty(module: &str, name: &str) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
        address: sys(),
        module: Identifier::new(module).unwrap(),
        name: Identifier::new(name).unwrap(),
        type_params: vec![],
    }))
}
fn ain() -> TypeTag { coin_ty("staking", "AincoreCoin") }
fn wbtc() -> TypeTag { coin_ty("wbtc", "WBTC") }

fn payload(module: &str, function: &str, ty_args: Vec<TypeTag>, args: Vec<Vec<u8>>) -> String {
    let call = vm_move::EntryFunctionCall {
        module: ModuleId::new(sys(), Identifier::new(module).unwrap()),
        function: function.to_string(),
        ty_args,
        args,
    };
    hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
}

fn rpc(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({"jsonrpc":"2.0","method":method,"params":params,"id":1});
    let resp: serde_json::Value = reqwest::blocking::Client::new()
        .post(url).json(&body).send()?.json()?;
    if let Some(e) = resp.get("error") {
        if !e.is_null() {
            return Err(anyhow!("{} -> {}", method, e));
        }
    }
    Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

fn nonce(url: &str, addr: &str) -> Result<u64> {
    let r = rpc(url, "aincore_getAccountNonce", serde_json::json!([addr]))?;
    Ok(r.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0))
}

fn ain_balance(url: &str, addr: &str) -> String {
    rpc(url, "aincore_getCoinBalance", serde_json::json!([addr, "AIN"]))
        .ok()
        .and_then(|r| r.get("balance").and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_else(|| "?".into())
}
fn wbtc_balance(url: &str, addr: &str) -> String {
    rpc(url, "aincore_getCoinBalance", serde_json::json!([addr, "WBTC"]))
        .ok()
        .and_then(|r| r.get("balance").and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_else(|| "?".into())
}

/// Build, sign (7-field F4 preimage) and submit one entry-function call.
#[allow(clippy::too_many_arguments)]
fn submit(
    url: &str, chain_id: &str, key: &SigningKey, sender: &str, seq: u64,
    label: &str, module: &str, function: &str, ty: Vec<TypeTag>, args: Vec<Vec<u8>>,
) -> Result<()> {
    let p = payload(module, function, ty, args);
    let msg = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, p, seq, GAS_LIMIT, GAS_PRICE, ""
    );
    let sig = key.sign(msg.as_bytes());
    let tx = serde_json::json!({
        "chain_id": chain_id, "sender": sender, "input_objects": [], "payload": p,
        "gas_limit": GAS_LIMIT, "gas_price": GAS_PRICE, "sequence_number": seq,
        "public_key": hex::encode(key.verifying_key().as_bytes()),
        "signature": hex::encode(sig.to_bytes()),
    });
    match rpc(url, "aincore_sendTransaction", serde_json::json!([tx])) {
        Ok(v) => { println!("  [{}] seq={} diterima: {}", label, seq, v); Ok(()) }
        Err(e) => { println!("  [{}] seq={} DITOLAK: {}", label, seq, e); Err(e) }
    }
}

fn wait_blocks(url: &str, n: u64) {
    let start = rpc(url, "aincore_getStatus", serde_json::json!([]))
        .ok().and_then(|r| r.get("latest_height").and_then(|v| v.as_str()).map(String::from))
        .and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let h = rpc(url, "aincore_getStatus", serde_json::json!([]))
            .ok().and_then(|r| r.get("latest_height").and_then(|v| v.as_str()).map(String::from))
            .and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        if h >= start + n { return; }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let key_path = args.get(1).ok_or_else(|| anyhow!("arg 1: path ke node.key"))?;
    let url = args.get(2).map(String::as_str).unwrap_or("http://127.0.0.1:8201/rpc");
    let chain_id = std::env::var(CHAIN_ID_ENV).unwrap_or_else(|_| "AINCORE-LOCALTEST-3V".into());

    // Key stays on this host; only the derived public address is printed.
    let raw = std::fs::read(key_path)?;
    let seed: [u8; 32] = if raw.len() == 32 {
        raw[..32].try_into()?
    } else {
        let t = String::from_utf8_lossy(&raw).trim().to_string();
        hex::decode(&t)?.as_slice().try_into().map_err(|_| anyhow!("node.key bukan 32 byte"))?
    };
    let key = SigningKey::from_bytes(&seed);
    let sender = crypto::derive_address(key.verifying_key().as_bytes())?;
    let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", sender))?;

    println!("== UJI DEX HIDUP ==");
    println!("  chain    : {}", chain_id);
    println!("  rpc      : {}", url);
    println!("  pengirim : {}", sender);
    println!("  AIN      : {}", ain_balance(url, &sender));
    println!("  WBTC     : {}", wbtc_balance(url, &sender));

    let mut seq = nonce(url, &sender)?;
    println!("  nonce    : {}\n", seq);

    let a = |v: &AccountAddress| bcs::to_bytes(v).unwrap();
    let u = |v: u128| bcs::to_bytes(&v).unwrap();

    // 1. register a WBTC store (idempotent since the coin::register fix)
    println!("1) wbtc::register");
    submit(url, &chain_id, &key, &sender, seq, "register", "wbtc", "register", vec![], vec![a(&sender_addr)])?;
    seq += 1; wait_blocks(url, 2);

    // 2. mint wBTC as the bridge authority
    let mint_amt: u128 = 500_000_000; // 5 wBTC @ 8 decimals
    println!("2) wbtc::mint {}", mint_amt);
    submit(url, &chain_id, &key, &sender, seq, "mint", "wbtc", "mint", vec![],
           vec![a(&sender_addr), a(&sender_addr), u(mint_amt)])?;
    seq += 1; wait_blocks(url, 2);
    println!("   WBTC sekarang: {}", wbtc_balance(url, &sender));

    // 3. create the AIN/wBTC pool (lexicographic order: AIN is X, wBTC is Y)
    println!("3) dex::create_pool<AincoreCoin, WBTC>");
    submit(url, &chain_id, &key, &sender, seq, "create_pool", "dex", "create_pool",
           vec![ain(), wbtc()], vec![a(&sender_addr)])?;
    seq += 1; wait_blocks(url, 2);

    // 4. seed liquidity
    let (dx, dy): (u128, u128) = (100_000_000_000_000_000, 200_000_000);
    println!("4) dex::add_liquidity x={} y={}", dx, dy);
    submit(url, &chain_id, &key, &sender, seq, "add_liquidity", "dex", "add_liquidity",
           vec![ain(), wbtc()], vec![a(&sender_addr), a(&sender_addr), u(dx), u(dy), u(0)])?;
    seq += 1; wait_blocks(url, 2);

    println!("\n== pool setelah likuiditas ==");
    println!("  {}", rpc(url, "aincore_getDexPools", serde_json::json!([]))?);

    // 5. swap AIN -> wBTC
    let amt_in: u128 = 1_000_000_000_000_000;
    let quote = rpc(url, "aincore_getDexQuote",
        serde_json::json!(["AIN", "WBTC", amt_in.to_string()])).unwrap_or(serde_json::Value::Null);
    println!("\n5) dex::swap_x_to_y {} AIN  (kuotasi: {})", amt_in, quote);
    let before = wbtc_balance(url, &sender);
    submit(url, &chain_id, &key, &sender, seq, "swap", "dex", "swap_x_to_y",
           vec![ain(), wbtc()], vec![a(&sender_addr), a(&sender_addr), u(amt_in), u(0)])?;
    wait_blocks(url, 2);
    let after = wbtc_balance(url, &sender);

    println!("\n== HASIL ==");
    println!("  WBTC sebelum swap : {}", before);
    println!("  WBTC sesudah swap : {}", after);
    println!("  pool akhir        : {}", rpc(url, "aincore_getDexPools", serde_json::json!([]))?);
    Ok(())
}
