import { Connection, Keypair, Transaction } from './src';

async function main() {
    const args = process.argv.slice(2);
    if (args.length < 2) {
        console.error("Usage: ts-node submit_proof.ts <device_id> <bqi>");
        process.exit(1);
    }

    const deviceId = args[0];
    const bqi = args[1];

    // 3. Read Private Key from STDIN (Secure)
    const chunks: Buffer[] = [];
    process.stdin.on('data', chunk => chunks.push(chunk));
    await new Promise(resolve => process.stdin.on('end', resolve));
    const privateKeyHex = Buffer.concat(chunks).toString().trim();

    if (!privateKeyHex) {
        console.error("❌ No private key provided via STDIN");
        process.exit(1);
    }

    // Create Keypair from Private Key
    const secretBytes = new Uint8Array(Buffer.from(privateKeyHex, 'hex'));
    let oracleKey: Keypair;
    if (secretBytes.length === 32) {
        oracleKey = Keypair.fromSeed(secretBytes);
    } else if (secretBytes.length === 64) {
        oracleKey = Keypair.fromSecretKey(secretBytes);
    } else {
        throw new Error(`Invalid key length: ${secretBytes.length} bytes (Expected 32 or 64)`);
    }

    const connection = new Connection('http://127.0.0.1:8001/rpc');

    // Payload: mining_proof:DEVICE_ID:BQI
    const payload = `mining_proof:${deviceId}:${bqi}`;

    console.log(`🔮 Oracle submitting proof for ${deviceId} (BQI: ${bqi})...`);

    // Create Transaction (0 amount, just payload)
    const tx = Transaction.createTransfer(oracleKey, "00000000000000000000000000000000", 0, 0);
    tx.payload = payload;
    tx.sign(oracleKey);

    try {
        const result = await connection.sendTransaction(tx.toString());
        console.log(`✅ Proof Tx Sent! Hash: ${result}`);
    } catch (e) {
        console.error("❌ Failed to send proof tx:", e);
        process.exit(1);
    }
}

main();
