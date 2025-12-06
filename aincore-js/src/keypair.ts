import * as nacl from 'tweetnacl';
import * as bip39 from 'bip39';

export class Keypair {
    private _keypair: nacl.SignKeyPair;

    constructor(keypair: nacl.SignKeyPair) {
        this._keypair = keypair;
    }

    /**
     * Generate a new random Keypair
     */
    static generate(): Keypair {
        const keypair = nacl.sign.keyPair();
        return new Keypair(keypair);
    }

    /**
     * Create a Keypair from a secret key (64 bytes)
     */
    static fromSecretKey(secretKey: Uint8Array): Keypair {
        const keypair = nacl.sign.keyPair.fromSecretKey(secretKey);
        return new Keypair(keypair);
    }

    /**
     * Create a Keypair from a seed (32 bytes)
     */
    static fromSeed(seed: Uint8Array): Keypair {
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        return new Keypair(keypair);
    }

    /**
     * Create a Keypair from a mnemonic phrase (BIP39)
     * Note: This uses a simplified derivation for prototype.
     */
    static fromMnemonic(mnemonic: string): Keypair {
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic');
        }
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        // Use the first 32 bytes of the seed as the entropy for Ed25519
        const entropy = seed.slice(0, 32);
        const keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(entropy));
        return new Keypair(keypair);
    }

    /**
     * Get the Public Key as a hex string
     */
    get publicKey(): string {
        return Buffer.from(this._keypair.publicKey).toString('hex');
    }

    /**
     * Get the Secret Key as a hex string
     */
    get secretKey(): string {
        return Buffer.from(this._keypair.secretKey).toString('hex');
    }

    /**
     * Get the AINCORE Address (First 16 bytes of Public Key)
     */
    get address(): string {
        return this.publicKey.slice(0, 32);
    }

    /**
     * Sign a message (bytes)
     */
    sign(message: Uint8Array): string {
        const signature = nacl.sign.detached(message, this._keypair.secretKey);
        return Buffer.from(signature).toString('hex');
    }
}
