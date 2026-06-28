use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::Serialize;
use std::time::Instant;

fn aincore_coin_type() -> move_core_types::language_storage::TypeTag {
    move_core_types::language_storage::TypeTag::Struct(Box::new(
        move_core_types::language_storage::StructTag {
            address: move_core_types::account_address::AccountAddress::ONE,
            module: move_core_types::identifier::Identifier::new("staking").unwrap(),
            name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
            type_params: vec![],
        },
    ))
}

fn parse_move_address(addr: &str) -> move_core_types::account_address::AccountAddress {
    move_core_types::account_address::AccountAddress::from_hex_literal(&format!("0x{}", addr))
        .unwrap()
}

fn transfer_payload(sender: &str, recipient: &str, amount: u128) -> String {
    let call = vm_move::EntryFunctionCall {
        module: move_core_types::language_storage::ModuleId::new(
            move_core_types::account_address::AccountAddress::ONE,
            move_core_types::identifier::Identifier::new("coin").unwrap(),
        ),
        function: "transfer".to_string(),
        ty_args: vec![aincore_coin_type()],
        args: vec![
            bcs::to_bytes(&parse_move_address(sender)).unwrap(),
            bcs::to_bytes(&parse_move_address(recipient)).unwrap(),
            bcs::to_bytes(&amount).unwrap(),
        ],
    };
    hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
}

#[derive(Serialize)]
struct Transaction {
    chain_id: String,
    sender: String,
    input_objects: Vec<String>,
    payload: String,
    args: Vec<String>,
    gas_limit: u64,
    gas_price: u64,
    sequence_number: u64,
    public_key: String,
    signature: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target_url = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:3030");
    let tx_count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);

    println!("╔══════════════════════════════════════════╗");
    println!("║     AINCORE Bench-TPS Stress Tester      ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║ Target:       {}                    ║", target_url);
    println!("║ Transactions: {}                       ║", tx_count);
    println!("╚══════════════════════════════════════════╝");
    println!();

    // 1. Generate unique keypairs for each transaction (simulates unique users)
    println!("🔑 Generating {} keypairs...", tx_count);
    let mut txs = Vec::with_capacity(tx_count);

    for i in 0..tx_count {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        let sender_addr = crypto::derive_address(verifying_key.as_bytes())
            .expect("generated public key must derive an address");

        // Self-transfer (will fail due to 0 balance, but stresses consensus pipeline)
        let payload = transfer_payload(&sender_addr, &sender_addr, 1);
        let sequence_number: u64 = 0;

        // Sign with full message format
        // F4: chain_id:sender:payload:seq:gas_limit:gas_price:input_objects
        // gas_limit=10000, gas_price=1, input_objects=[] (must match tx below).
        let chain_id = "AINCORE-MAINNET-1";
        let message = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            chain_id, sender_addr, payload, sequence_number, 10000u64, 1u128, ""
        );
        let signature = signing_key.sign(message.as_bytes());

        let tx = Transaction {
            chain_id: chain_id.to_string(),
            sender: sender_addr,
            input_objects: vec![],
            payload,
            args: vec![],
            gas_limit: 10000,
            gas_price: 1,
            sequence_number,
            public_key: public_key_hex,
            signature: hex::encode(signature.to_bytes()),
        };

        txs.push(serde_json::to_string(&tx).expect("Failed to serialize TX"));

        if (i + 1) % 100 == 0 {
            println!("   Generated {}/{} transactions...", i + 1, tx_count);
        }
    }

    println!("✅ All {} transactions generated!\n", tx_count);

    // 2. Fire all transactions as fast as possible
    println!("🚀 FIRING {} transactions at {}...", tx_count, target_url);
    let submit_url = format!("{}/submit_tx", target_url);

    let start = Instant::now();
    let mut success = 0u64;
    let mut failures = 0u64;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("Failed to build HTTP client");

    for (i, tx_json) in txs.iter().enumerate() {
        match client
            .post(&submit_url)
            .header("Content-Type", "application/json")
            .body(tx_json.clone())
            .send()
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    success += 1;
                } else {
                    failures += 1;
                }
            }
            Err(_) => {
                failures += 1;
            }
        }

        if (i + 1) % 100 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let tps = (i + 1) as f64 / elapsed;
            println!(
                "   Sent {}/{} | TPS: {:.1} | OK: {} | FAIL: {}",
                i + 1,
                tx_count,
                tps,
                success,
                failures
            );
        }
    }

    let total_elapsed = start.elapsed();
    let final_tps = tx_count as f64 / total_elapsed.as_secs_f64();

    println!();
    println!("╔══════════════════════════════════════════╗");
    println!("║         STRESS TEST RESULTS              ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║ Total TX:     {}                       ║", tx_count);
    println!("║ Success:      {}                       ║", success);
    println!("║ Failures:     {}                       ║", failures);
    println!(
        "║ Time:         {:.2}s                    ║",
        total_elapsed.as_secs_f64()
    );
    println!("║ Avg TPS:      {:.1}                     ║", final_tps);
    println!("╚══════════════════════════════════════════╝");

    if failures == 0 {
        println!("\n🎉 PERFECT SCORE! All transactions accepted by mempool.");
    } else if success > 0 {
        println!("\n⚠️  Some transactions failed (expected if accounts have 0 balance).");
        println!("   The important metric is: Did the node stay alive? Check node logs!");
    } else {
        println!(
            "\n❌ All transactions failed. Is the node running at {}?",
            target_url
        );
    }
}
