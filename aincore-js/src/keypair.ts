import * as nacl from 'tweetnacl';
import * as bip39 from 'bip39';
import * as crypto from 'crypto';

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
     * Get the AINCORE address: the FULL SHA256 of the public key, 32 bytes /
     * 64 hex chars. It used to be truncated to the first 16 bytes, which does
     * not match crypto::derive_address on the node -- so the derived address
     * never equalled the `sender` the node recomputes, and every transaction
     * was rejected.
     */
    get address(): string {
        const hash = crypto.createHash('sha256').update(this._keypair.publicKey).digest();
        return hash.toString('hex');
    }

    /**
     * Sign a message (bytes)
     */
    sign(message: Uint8Array): string {
        const signature = nacl.sign.detached(message, this._keypair.secretKey);
        return Buffer.from(signature).toString('hex');
    }

    /**
     * Verify a signature against a message
     */
    verify(message: Uint8Array, signatureHex: string): boolean {
        try {
            const signature = Buffer.from(signatureHex, 'hex');
            return nacl.sign.detached.verify(message, signature, this._keypair.publicKey);
        } catch {
            return false;
        }
    }

    /**
     * Generate a new random mnemonic phrase (24 words)
     */
    static generateMnemonic(): string {
        return bip39.generateMnemonic(256); // 256 bits = 24 words
    }

    /**
     * Validate a mnemonic phrase
     */
    static validateMnemonic(mnemonic: string): boolean {
        return bip39.validateMnemonic(mnemonic);
    }
}
