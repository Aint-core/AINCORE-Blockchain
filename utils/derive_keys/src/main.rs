use ed25519_dalek::SigningKey;
fn main() {
    let keys = vec![
        "8721d8bf414f27cac0e11e92ebac68bb64aa4ccdbae68b145318e69cdb7822c0",
        "fa26110d3a14e793f07fbf15b2ba85b90a219535f52cbfd61e188dbf0b8f6797",
        "2847ed43485380633d445a7397f056ca4925a51e5c8f5ba5b9d4461c529c1040",
        "ecd6af9d7b37d2b39582dcfd36ff6cdd6f00d37e7a98f03b9ad1ae633ea46816",
    ];
    for hex_sk in keys {
        let mut key_bytes = [0u8; 32];
        hex::decode_to_slice(hex_sk, &mut key_bytes).unwrap();
        let sk = SigningKey::from_bytes(&key_bytes);
        let pk = sk.verifying_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let addr = crypto::derive_address(&pk.to_bytes()).unwrap();
        println!("SK: {}", hex_sk);
        println!("PK: {}", pk_hex);
        println!("ADDR: {}", addr);
        println!("---");
    }
}
