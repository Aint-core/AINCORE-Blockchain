import { Connection, Keypair, Transaction } from './src';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    try {
        // 1. Connect to Node (with Indexer)
        const connection = new Connection('http://localhost:8002/rpc', 'http://localhost:3001');
        console.log('✅ Connected to AINCORE Node & Indexer');

        // 2. Load Genesis Key
        const genesisKeyPath = path.join(__dirname, '../aincore_data/node_identity.key');
        if (!fs.existsSync(genesisKeyPath)) {
            console.error('❌ Keyfile not found at:', genesisKeyPath);
            return;
        }
        const secretKey = fs.readFileSync(genesisKeyPath);
        const genesisKeypair = Keypair.fromSeed(new Uint8Array(secretKey));
        console.log('🔑 Loaded Genesis Account:', genesisKeypair.address);

        // 3. Check Genesis Balance
        const genesisBalance = await connection.getBalance(genesisKeypair.address);
        console.log('💰 Genesis Balance:', genesisBalance);

        // 4. Generate New Wallet
        const newWallet = Keypair.generate();
        console.log('👤 Generated New Wallet:', newWallet.address);

        // 5. Check New Wallet Balance (Should be 0)
        const initialBalance = await connection.getBalance(newWallet.address);
        console.log('💰 New Wallet Initial Balance:', initialBalance);

        // 4. Send Transaction
        console.log('💸 Sending 500 AIN to New Wallet...');

        // Fetch Sender Account to get Sequence Number
        const senderAccount = await connection.getAccount(genesisKeypair.address);
        console.log(`🔢 Sender Sequence Number: ${senderAccount.sequence_number}`);

        const tx = Transaction.createTransfer(
            genesisKeypair,
            newWallet.address,
            500,
            senderAccount.sequence_number
        );
        tx.sign(genesisKeypair);

        const txHash = await connection.sendTransaction(tx.toString());
        console.log('✅ Transaction Sent! Hash:', txHash);

        // 7. Wait for Confirmation (Simple sleep for prototype)
        console.log('⏳ Waiting for confirmation...');
        await new Promise(r => setTimeout(r, 10000));

        // 8. Verify New Balance
        const finalBalance = await connection.getBalance(newWallet.address);
        console.log('💰 New Wallet Final Balance:', finalBalance);

        if (finalBalance === initialBalance + 500) {
            console.log('🎉 Balance Check PASSED!');
        } else {
            console.error('❌ Balance Check FAILED: Balance mismatch');
        }

        // 9. Verify History via Indexer
        console.log('📜 Checking Transaction History via Indexer...');
        // Wait a bit more for indexer to catch up
        await new Promise(r => setTimeout(r, 2000));

        const history = await connection.getHistory(genesisKeypair.address);
        console.log(`Found ${history.length} transactions for Genesis Account.`);

        const found = history.find((t: any) => t.sender === genesisKeypair.address && t.receiver === newWallet.address);
        if (found) {
            console.log('🎉 Indexer Check PASSED! Found transaction:', found.hash);
        } else {
            console.error('❌ Indexer Check FAILED: Transaction not found in history');
            console.log('History:', history);
        }

    } catch (e) {
        console.error('❌ Test Error:', e);
    }
}

main();
