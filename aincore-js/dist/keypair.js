"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Keypair = void 0;
const nacl = __importStar(require("tweetnacl"));
const bip39 = __importStar(require("bip39"));
const crypto = __importStar(require("crypto"));
class Keypair {
    constructor(keypair) {
        this._keypair = keypair;
    }
    /**
     * Generate a new random Keypair
     */
    static generate() {
        const keypair = nacl.sign.keyPair();
        return new Keypair(keypair);
    }
    /**
     * Create a Keypair from a secret key (64 bytes)
     */
    static fromSecretKey(secretKey) {
        const keypair = nacl.sign.keyPair.fromSecretKey(secretKey);
        return new Keypair(keypair);
    }
    /**
     * Create a Keypair from a seed (32 bytes)
     */
    static fromSeed(seed) {
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        return new Keypair(keypair);
    }
    /**
     * Create a Keypair from a mnemonic phrase (BIP39)
     * Note: This uses a simplified derivation for prototype.
     */
    static fromMnemonic(mnemonic) {
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
    get publicKey() {
        return Buffer.from(this._keypair.publicKey).toString('hex');
    }
    /**
     * Get the Secret Key as a hex string
     */
    get secretKey() {
        return Buffer.from(this._keypair.secretKey).toString('hex');
    }
    /**
     * Get the AINCORE Address (First 16 bytes of SHA256(Public Key))
     */
    get address() {
        const hash = crypto.createHash('sha256').update(this._keypair.publicKey).digest();
        return hash.subarray(0, 16).toString('hex');
    }
    /**
     * Sign a message (bytes)
     */
    sign(message) {
        const signature = nacl.sign.detached(message, this._keypair.secretKey);
        return Buffer.from(signature).toString('hex');
    }
    /**
     * Verify a signature against a message
     */
    verify(message, signatureHex) {
        try {
            const signature = Buffer.from(signatureHex, 'hex');
            return nacl.sign.detached.verify(message, signature, this._keypair.publicKey);
        }
        catch {
            return false;
        }
    }
    /**
     * Generate a new random mnemonic phrase (24 words)
     */
    static generateMnemonic() {
        return bip39.generateMnemonic(256); // 256 bits = 24 words
    }
    /**
     * Validate a mnemonic phrase
     */
    static validateMnemonic(mnemonic) {
        return bip39.validateMnemonic(mnemonic);
    }
}
exports.Keypair = Keypair;
