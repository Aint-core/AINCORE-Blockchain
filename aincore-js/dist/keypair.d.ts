import * as nacl from 'tweetnacl';
export declare class Keypair {
    private _keypair;
    constructor(keypair: nacl.SignKeyPair);
    /**
     * Generate a new random Keypair
     */
    static generate(): Keypair;
    /**
     * Create a Keypair from a secret key (64 bytes)
     */
    static fromSecretKey(secretKey: Uint8Array): Keypair;
    /**
     * Create a Keypair from a seed (32 bytes)
     */
    static fromSeed(seed: Uint8Array): Keypair;
    /**
     * Create a Keypair from a mnemonic phrase (BIP39)
     * Note: This uses a simplified derivation for prototype.
     */
    static fromMnemonic(mnemonic: string): Keypair;
    /**
     * Get the Public Key as a hex string
     */
    get publicKey(): string;
    /**
     * Get the Secret Key as a hex string
     */
    get secretKey(): string;
    /**
     * Get the AINCORE address: the FULL SHA256 of the public key, 32 bytes /
     * 64 hex chars. It used to be truncated to the first 16 bytes, which does
     * not match crypto::derive_address on the node -- so the derived address
     * never equalled the `sender` the node recomputes, and every transaction
     * was rejected.
     */
    get address(): string;
    /**
     * The same address in its human-readable, checksummed form (`A1n…`).
     * Show this to people; transactions keep using `address` (64-hex).
     */
    get addressA1n(): string;
    /**
     * Sign a message (bytes)
     */
    sign(message: Uint8Array): string;
    /**
     * Verify a signature against a message
     */
    verify(message: Uint8Array, signatureHex: string): boolean;
    /**
     * Generate a new random mnemonic phrase (24 words)
     */
    static generateMnemonic(): string;
    /**
     * Validate a mnemonic phrase
     */
    static validateMnemonic(mnemonic: string): boolean;
}
