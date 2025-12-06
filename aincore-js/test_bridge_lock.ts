import { Connection, Keypair, Transaction } from './src';

async function main() {
    const connection = new Connection('http://127.0.0.1:8001/rpc');
    console.log('🌉 Testing Bridge Lock...');

    // Use a random sender
    const sender = Keypair.generate();
    console.log(`👤 Sender: ${sender.address}`);

    // Payload format: bridge_lock:AMOUNT:ETH_ADDR
    const amount = 100;
    const ethAddr = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
    const payload = `bridge_lock:${amount}:${ethAddr}`;

    console.log(`📝 Sending Tx with Payload: ${payload}`);

    const tx = Transaction.createTransfer(sender, "00000000000000000000000000000000", 0, 0);
    tx.payload = payload; // Override payload
    tx.sign(sender);

    try {
        const result = await connection.sendTransaction(tx.toString());
        console.log(`✅ Tx Sent! Result: ${JSON.stringify(result)}`);
    } catch (e) {
        console.error("❌ Failed to send tx:", e);
    }
}

main();
