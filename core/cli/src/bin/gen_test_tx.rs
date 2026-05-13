use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::Serialize;

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
    // 1. Generate Keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    // Print Private Key for extraction
    println!("PRIVATE_KEY: {}", hex::encode(signing_key.to_bytes()));
    
    // 2. Format Keys
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    // In AINCORE, address is first 16 bytes (32 hex chars) of SHA256 of public key
    let sender_addr = crypto::derive_address(verifying_key.as_bytes()).unwrap();

    // 3. Create Payload
    let payload = format!("transfer:{}:1", sender_addr); // Self-transfer to ensure receiver exists (or creates a new one)
    let sequence_number = 0;

    // 4. Sign
    // Message format from executor::execute_transaction: "{}:{}:{}:{}" (chain_id:sender:payload:seq_num)
    let chain_id = "AINCORE-MAINNET-1";
    let message = format!("{}:{}:{}:{}", chain_id, sender_addr, payload, sequence_number);
    let signature = signing_key.sign(message.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    // 5. Construct TX
    let tx = Transaction {
        chain_id: chain_id.to_string(),
        sender: sender_addr.clone(),
        input_objects: vec![], // No input objects for simple tests or ignored
        payload,
        args: vec![],
        gas_limit: 10000,
        gas_price: 1,
        sequence_number,
        public_key: public_key_hex,
        signature: signature_hex,
    };

    // 6. Output JSON
    let json = serde_json::to_string(&tx).expect("Failed to serialize");
    println!("{}", json);
}
