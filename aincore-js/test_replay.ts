import { Connection, Keypair, Transaction } from './src';
import * as path from 'path';
import * as fs from 'fs';

async function main() {
    try {
        const connection = new Connection('http://localhost:8002/rpc');
        console.log('✅ Connected to AINCORE Node');

        // Load Genesis Key
        const genesisKeyPath = path.join(__dirname, '../aincore_data/node_identity.key');
        if (!fs.existsSync(genesisKeyPath)) {
            console.error('❌ Keyfile not found at:', genesisKeyPath);
            return;
        }
        const secretKey = fs.readFileSync(genesisKeyPath);
        const genesisKeypair = Keypair.fromSeed(new Uint8Array(secretKey));
        console.log('🔑 Loaded Genesis Account:', genesisKeypair.address);

        // Fetch Sequence Number
        const senderAccount = await connection.getAccount(genesisKeypair.address);
        console.log(`🔢 Sender Sequence Number: ${senderAccount.sequence_number}`);

        // Create Transaction
        const tx = Transaction.createTransfer(
            genesisKeypair,
            "2f8d1e76efa208b4db1b911685806b54", // Random receiver
            100,
            senderAccount.sequence_number
        );
        tx.sign(genesisKeypair);
        const signedTx = tx.toString();

        // 1. Send First Time
        console.log('🚀 Sending Transaction (1st time)...');
        const txHash1 = await connection.sendTransaction(signedTx);
        console.log('✅ Sent 1st time. Hash:', txHash1);

        // Wait for it to be processed (and sequence number to increment)
        console.log('⏳ Waiting 3 seconds...');
        await new Promise(resolve => setTimeout(resolve, 3000));

        // 2. Send Second Time (Replay Attack)
        console.log('🔁 Sending Transaction (2nd time - REPLAY)...');
        try {
            const txHash2 = await connection.sendTransaction(signedTx);
            console.log('⚠️ Sent 2nd time (Unexpected). Hash:', txHash2);

            // If it was sent, we need to check if it was actually executed or just queued.
            // But ideally, the node should reject it or the mempool should drop it.
            // If mempool drops it, sendTransaction might return the hash (if it was already there) or error?
            // Wait, my mempool implementation ignores duplicates but doesn't return error to API (API just returns hash).
            // However, if it's ignored, it won't be executed again.
            // The REAL test is checking the sequence number or balance.

            console.log('⏳ Waiting 3 seconds...');
            await new Promise(resolve => setTimeout(resolve, 3000));

            const finalAccount = await connection.getAccount(genesisKeypair.address);
            console.log(`🔢 Final Sequence Number: ${finalAccount.sequence_number}`);

            if (finalAccount.sequence_number === senderAccount.sequence_number + 1) {
                console.log('🎉 Replay Attack FAILED (Protected)! Sequence number only incremented once.');
            } else {
                console.log(`❌ Replay Attack SUCCEEDED? Sequence incremented by ${finalAccount.sequence_number - senderAccount.sequence_number}`);
            }

        } catch (e: any) {
            console.log('✅ Replay Attack Blocked (API Error):', e.message);
        }

    } catch (error) {
        console.error('❌ Test Failed:', error);
    }
}

main();
