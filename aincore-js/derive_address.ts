import { Keypair } from './src';

const privateKeyHex = '249853fa0835cfcdc51ab0956995688d92571ebdb2818d89930c5f8e836ec096';

function main() {
    try {
        // Convert hex string to Uint8Array
        const seed = new Uint8Array(Buffer.from(privateKeyHex, 'hex'));

        // Derive Keypair
        const keypair = Keypair.fromSeed(seed);

        console.log('🔑 Private Key:', privateKeyHex);
        console.log('📬 Derived Address:', keypair.address);

    } catch (e) {
        console.error('❌ Error deriving address:', e);
    }
}

main();
