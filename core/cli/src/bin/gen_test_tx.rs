use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::Serialize;

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
    // 1. Generate Keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Print Private Key for extraction
    println!("PRIVATE_KEY: {}", hex::encode(signing_key.to_bytes()));

    // 2. Format Keys
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    // In AINCORE, address is the full 32-byte SHA256 of the public key (64 hex chars)
    let sender_addr = crypto::derive_address(verifying_key.as_bytes()).unwrap();

    // 3. Create Payload
    let payload = transfer_payload(&sender_addr, &sender_addr, 1);
    let sequence_number = 0;

    // 4. Sign
    // F4: Message format now chain_id:sender:payload:seq:gas_limit:gas_price:input_objects
    // gas_limit=10000, gas_price=1, input_objects=[] (must match tx below).
    let chain_id = "AINCORE-MAINNET-1";
    let message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender_addr, payload, sequence_number, 10000u64, 1u128, ""
    );
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
