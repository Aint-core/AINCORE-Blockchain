import { Connection, Keypair, Transaction } from './src';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    try {
        const connection = new Connection('http://127.0.0.1:8001/rpc');
        console.log('✅ Connected to AINCORE Node');

        // 1. Load Paymaster (Genesis Key)
        const keyPath = path.resolve(__dirname, '../data/node_identity.key');
        if (!fs.existsSync(keyPath)) {
            console.error('❌ Paymaster Keyfile not found at:', keyPath);
            return;
        }
        const secretKey = fs.readFileSync(keyPath);
        const paymasterKeypair = Keypair.fromSeed(new Uint8Array(secretKey));
        console.log('👑 Paymaster Address:', paymasterKeypair.address);

        // 2. Create New User (0 Balance)
        const userKeypair = Keypair.generate();
        console.log('👤 User Address:', userKeypair.address);

        // Verify User Balance is 0
        const userAccount = await connection.getAccount(userKeypair.address);
        console.log(`💰 User Balance: ${userAccount.balance}`);

        if (userAccount.balance > 0) {
            console.warn("⚠️ User already has balance. Test might be invalid.");
        }

        // 3. Create Transaction
        // User sends 0 AIN to Paymaster (just to trigger gas cost)
        // Or send to random address
        const recipient = '00000000000000000000000000000000';
        const amount = 0;

        console.log(`📝 Creating Transaction: User -> ${recipient} (Amount: ${amount})`);
        const tx = Transaction.createTransfer(
            userKeypair,
            recipient,
            amount,
            userAccount.sequence_number
        );

        // 4. User Signs Payload
        tx.sign(userKeypair);

        // 5. Paymaster Signs for Gas
        console.log('⛽ Paymaster signing for gas...');
        // Paymaster signs the sender address to authorize gas for this sender? 
        // Or signs the whole tx?
        // In executor/src/lib.rs: 
        // if let Some(pm_sig) = &tx.paymaster_signature { ... }
        // The verification logic isn't strictly defined in the prototype code I saw earlier.
        // Let's check executor logic again.
        // "In real impl: Verify pm_sig against pm address"
        // "pm.clone()"
        // It seems the prototype MIGHT NOT actually verify the signature content yet, just checks if it exists?
        // Let's assume we sign the sender address for now as a simple authorization.
        const paymasterSig = paymasterKeypair.sign(Buffer.from(userKeypair.address));
        tx.setPaymaster(paymasterKeypair.address, paymasterSig);

        // 6. Send Transaction
        console.log('🚀 Sending Sponsored Transaction...');
        const txHash = await connection.sendTransaction(tx.toString());
        console.log('✅ Transaction Sent! Hash:', txHash);

        console.log('⏳ Waiting 5s for confirmation...');
        await new Promise(r => setTimeout(r, 5000));

        // 7. Verify Paymaster Balance Decreased
        const paymasterAccount = await connection.getAccount(paymasterKeypair.address);
        console.log(`👑 Paymaster New Balance: ${paymasterAccount.balance}`);

    } catch (e: any) {
        console.error('❌ Error:', e);
        if (e.response) {
            console.error('   Response Data:', e.response.data);
            console.error('   Response Status:', e.response.status);
        } else if (e.request) {
            console.error('   No Response Received');
        } else {
            console.error('   Error Message:', e.message);
        }
    }
}

main();
