
import { Connection, Keypair, Transaction } from './src';
import * as fs from 'fs';
import * as path from 'path';

// --- USER CONFIGURATION ---
// 1. Ganti nama token & symbol sesuai keinginan
const TOKEN_NAME = "My First Token";
const TOKEN_SYMBOL = "MFT";
const DECIMALS = 8;
const MAX_SUPPLY = BigInt("100000000000000000"); // 1 Billion (scaled)
const INITIAL_SUPPLY = BigInt("100000000000000000");

// 2. Masukkan URL Gambar dari IPFS (Hasil Upload Tadi)
// Contoh: "https://gateway.pinata.cloud/ipfs/QmHash..."
const ICON_URL = "https://tan-academic-buzzard-879.mypinata.cloud/ipfs/bafybeig63t3oloqzp7b4usu4jhyaxuid4heuwwb3xueqevhaf55scxung4";
const PROJECT_URL = "https://aincore.io"; // Ganti dengan website project lu

const RPC_URL = 'http://127.0.0.1:8002/rpc'; // Local node RPC

async function main() {
    try {
        console.log("🚀 Starting Token Creation...");
        const connection = new Connection(RPC_URL);

        // Load Keypair (Node Identity or My Wallet)
        // Pastikan path ini benar!
        const keyPath = path.resolve(__dirname, '../data/node_identity.key');
        if (!fs.existsSync(keyPath)) {
            console.error('❌ Keyfile not found at:', keyPath);
            console.log('💡 Tips: Copy your wallet key to one of these locations or update keyPath.');
            return;
        }

        const secretKey = fs.readFileSync(keyPath);
        const senderKeypair = Keypair.fromSeed(new Uint8Array(secretKey));
        console.log('🔑 Creator Address:', senderKeypair.address);

        // Get Account Info for Sequence Number
        const senderAccount = await connection.getAccount(senderKeypair.address);
        console.log(`POLLING: Sequence ${senderAccount.sequence_number}`);

        // Construct Transaction
        const tx = Transaction.createToken(
            senderKeypair,
            TOKEN_NAME,
            TOKEN_SYMBOL,
            DECIMALS,
            MAX_SUPPLY,
            INITIAL_SUPPLY,
            ICON_URL,
            PROJECT_URL,
            senderAccount.sequence_number
        );

        // Sign
        tx.sign(senderKeypair);

        // Send
        console.log('📡 Sending Create Token Transaction...');
        const txHash = await connection.sendTransaction(tx.toString());
        console.log('✅ Transaction Sent! Hash:', txHash);
        console.log('-------------------------------------------');
        console.log(`Token Created: ${TOKEN_NAME} (${TOKEN_SYMBOL})`);
        console.log(`Logo URL: ${ICON_URL}`);
        console.log('-------------------------------------------');

    } catch (e) {
        console.error('❌ Error creating token:', e);
    }
}

main();
