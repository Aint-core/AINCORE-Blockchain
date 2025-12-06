use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::time::Duration;
use tokio::time::sleep;

pub struct BitcoinWatcher {
    rpc: Option<Client>,
    mock_height: u64,
}

impl BitcoinWatcher {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        let rpc = Client::new(url, Auth::UserPass(user.to_string(), pass.to_string()));
        match rpc {
            Ok(client) => {
                println!("🔌 Connecting to Bitcoin Core at {}", url);
                Self { rpc: Some(client), mock_height: 0 }
            }
            Err(e) => {
                println!("⚠️ Failed to connect to Bitcoin Core: {}. Using MOCK mode.", e);
                Self { rpc: None, mock_height: 0 }
            }
        }
    }

    pub async fn check_new_blocks(&mut self) -> Option<Vec<(u64, String)>> {
        let mut deposits = Vec::new();

        // 1. Try Real RPC (If available)
        if let Some(rpc) = &self.rpc {
             match rpc.get_block_count() {
                 Ok(height) => {
                     // Simple state tracking: If mock_height is 0 (first run), start from TIP - 1 or 0?
                     // For regtest, start from 0 is fine, but safe to start from 'height' if we only want NEW deposits.
                     // But for this demo, we want to catch the deposit we just made. 
                     // Let's assume we start scanning from the last checked block.
                     // Since we don't persist state, we'll scan from 'height - 5' to 'height' on startup, then track.
                     // To simplify: Just Scan the LATEST block each time for the demo? 
                     // Or scan from self.mock_height.
                     
                     let start = if self.mock_height == 0 { height.max(1) - 1 } else { self.mock_height + 1 };
                     
                     if height >= start {
                         let vault_addr = std::fs::read_to_string("vault_address.txt").unwrap_or_default().trim().to_string();
                         println!("🔍 Scanning blocks {} to {} for Vault: {}", start, height, vault_addr);

                         for h in start..=height {
                             if let Ok(hash) = rpc.get_block_hash(h) {
                                 if let Ok(block) = rpc.get_block(&hash) {
                                     for tx in block.txdata {
                                         // Check For Vault Input? No, Vault Output (Deposit).
                                         let mut amount_sats = 0;
                                         let mut recipient_ain = String::new();
                                         let mut is_vault_deposit = false;
                                         
                                         for out in &tx.output {
                                             // 1. Check if paying to Vault
                                             // Convert script to address (Complex in raw bitcoin-rust without Network param)
                                             // Simpler: Check if script_pub_key matches address?
                                             // Address-to-Script: bitcoincore-rpc doesn't help much here.
                                             // Helper: "gettransaction" via RPC is easier? 
                                             // BUT "getblock" returns raw blocks.
                                             // Optimization for Demo: Use "listtransactions" logic?
                                             // No, let's just use address string matching if possible, or
                                             // Assuming P2WPKH: 00 14 <20-byte-hash>
                                             // Vault Address is bech32.
                                             // Let's use `bitcoin::Address` to parse `vault_addr` and get script_pubkey.
                                             
                                             use std::str::FromStr;
                                             if let Ok(addr) = bitcoin::Address::from_str(&vault_addr) {
                                                 // Need to ensure Network match. Regtest usually checks out if address format is valid.
                                                 if out.script_pubkey == addr.assume_checked().script_pubkey() {
                                                     amount_sats += out.value;
                                                     is_vault_deposit = true;
                                                 }
                                             }
                                             
                                             // 2. Check for OP_RETURN
                                             if out.script_pubkey.is_op_return() {
                                                 // Extract Data
                                                 // Instruction: OP_RETURN <generated-push> <DATA>
                                                 // bitcoin crate has `.instructions()`
                                                 for instr in out.script_pubkey.instructions() {
                                                     if let Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes)) = instr {
                                                         // AIN Address is 32 hex chars = 16 bytes? Or 32 bytes?
                                                         // Node 2 address e1d8... is 32 hex chars = 16 bytes.
                                                         // Let's try to convert bytes to hex string.
                                                         let hex_str = hex::encode(bytes.as_bytes());
                                                         // Filter noise: AIN addresses are usually length 32 (hex) or more?
                                                         // User e1d895... is 32 chars.
                                                         if hex_str.len() == 32 { 
                                                             recipient_ain = hex_str;
                                                         }
                                                     }
                                                 }
                                             }
                                         }
                                         
                                         if is_vault_deposit && !recipient_ain.is_empty() {
                                             println!("🚀 REAL DEPOSIT DETECTED: {} Sats -> {}", amount_sats, recipient_ain);
                                             deposits.push((amount_sats, recipient_ain));
                                         }
                                     }
                                 }
                             }
                         }
                         self.mock_height = height;
                     }
                 },
                 Err(e) => { 
                     // println!("RPC Error: {}", e); 
                 }
             }
        }

        // 2. MOCK MODE (Fallback)
        use std::path::Path;

        if Path::new("bridge_incoming.json").exists() {
            println!("📂 Found 'bridge_incoming.json' deposit file!");
            if let Ok(content) = std::fs::read_to_string("bridge_incoming.json") {
                #[derive(serde::Deserialize)]
                struct Deposit {
                    amount: u64,
                    recipient: String,
                }
                
                if let Ok(dep) = serde_json::from_str::<Deposit>(&content) {
                    println!("💰 Detected Deposit: {} Sats for {}", dep.amount, dep.recipient);
                    std::fs::remove_file("bridge_incoming.json").unwrap_or_default();
                    deposits.push((dep.amount, dep.recipient));
                }
            }
        }
        
        if deposits.is_empty() {
            None
        } else {
            Some(deposits)
        }
    }
}
