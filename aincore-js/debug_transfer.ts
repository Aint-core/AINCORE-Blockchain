import { Connection, Keypair, Transaction } from './src';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    try {
        const connection = new Connection('http://192.168.18.90:8002/rpc');
        console.log('✅ Connected to AINCORE Node');

        // Path to node_identity.key (relative to aincore-js root, assuming run from aincore-js dir)
        // aincore-js is in /Users/macbookpro/Documents/aincore/aincore-js
        // data is in /Users/macbookpro/Documents/aincore/data
        const keyPath = path.resolve(__dirname, '../data/node_identity.key');

        if (!fs.existsSync(keyPath)) {
            console.error('❌ Keyfile not found at:', keyPath);
            return;
        }

        const secretKey = fs.readFileSync(keyPath);
        // Keypair.fromSeed takes 32 bytes. node_identity.key is 32 bytes.
        const senderKeypair = Keypair.fromSeed(new Uint8Array(secretKey));
        console.log('🔑 Sender Address:', senderKeypair.address);

        const recipient = '9e1289745b7ebd72cb17064a2c44458f'; // 32 chars
        const amount = 1;

        console.log(`💸 Preparing to send ${amount} AIN to ${recipient}...`);

        const senderAccount = await connection.getAccount(senderKeypair.address);
        console.log(`🔢 Sender Sequence: ${senderAccount.sequence_number}, Balance: ${senderAccount.balance}`);

        const tx = Transaction.createTransfer(
            senderKeypair,
            recipient,
            amount,
            senderAccount.sequence_number
        );
        tx.sign(senderKeypair);

        console.log('🚀 Sending Transaction...');
        const txHash = await connection.sendTransaction(tx.toString());
        console.log('✅ Transaction Sent! Hash:', txHash);

        console.log('⏳ Waiting 5s for confirmation...');
        await new Promise(r => setTimeout(r, 5000));

        const recipientAccount = await connection.getAccount(recipient);
        console.log(`💰 Recipient Balance: ${recipientAccount.balance}`);

    } catch (e) {
        console.error('❌ Error:', e);
    }
}

main();
