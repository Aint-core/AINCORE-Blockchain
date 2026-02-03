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
     * Get the AINCORE Address (First 16 bytes of Public Key)
     */
    get address(): string;
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
