import { Keypair } from './src';

const seedHex = process.env.AINCORE_SEED_HEX;
if (!seedHex || !/^[0-9a-f]{64}$/i.test(seedHex)) {
    console.error('Set AINCORE_SEED_HEX to a 32-byte hexadecimal seed.');
    process.exitCode = 1;
} else {
    console.log(Keypair.fromSeed(Buffer.from(seedHex, 'hex')).address);
}
