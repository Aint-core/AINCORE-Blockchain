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
exports.A1N_LEN = exports.A1N_PREFIX = exports.A1N_VERSION = void 0;
exports.toA1n = toA1n;
exports.fromA1n = fromA1n;
exports.parseAddress = parseAddress;
exports.toHexAddress = toHexAddress;
exports.toA1nAddress = toA1nAddress;
exports.isValidAddress = isValidAddress;
const crypto = __importStar(require("crypto"));
/**
 * Human-readable AINCORE addresses: `A1n…`.
 *
 * On chain an address is 32 bytes (SHA-256 of the public key), and signed
 * transactions keep using its lowercase 64-hex form. `A1n` is for people:
 * Base58 over `A1N_VERSION ‖ address ‖ checksum`, where the checksum is the
 * first 4 bytes of SHA-256(SHA-256(A1N_VERSION ‖ address)).
 *
 * Mirrors `common/crypto/src/address.rs`; both are tested against the same
 * vector. Every address encodes to exactly 53 characters starting `A1n`.
 */
exports.A1N_VERSION = Uint8Array.from([0x0d, 0xce, 0x00]);
exports.A1N_PREFIX = 'A1n';
exports.A1N_LEN = 53;
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ADDRESS_BYTES = 32;
const CHECKSUM_LEN = 4;
const RAW_LEN = exports.A1N_VERSION.length + ADDRESS_BYTES + CHECKSUM_LEN;
function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}
function checksum(versioned) {
    return sha256(sha256(versioned)).subarray(0, CHECKSUM_LEN);
}
function base58Encode(bytes) {
    let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));
    let out = '';
    while (n > 0n) {
        out = ALPHABET[Number(n % 58n)] + out;
        n /= 58n;
    }
    for (const b of bytes) {
        if (b !== 0)
            break;
        out = '1' + out;
    }
    return out;
}
function base58Decode(text) {
    let n = 0n;
    for (const ch of text) {
        const digit = ALPHABET.indexOf(ch);
        if (digit < 0)
            throw new Error('address contains a character that is not Base58');
        n = n * 58n + BigInt(digit);
    }
    let hex = n === 0n ? '' : n.toString(16);
    if (hex.length % 2)
        hex = '0' + hex;
    const body = Buffer.from(hex, 'hex');
    let zeros = 0;
    while (zeros < text.length && text[zeros] === '1')
        zeros++;
    return Uint8Array.from([...new Uint8Array(zeros), ...body]);
}
function hexToBytes(input) {
    const trimmed = input.trim();
    const digits = /^0x/i.test(trimmed) ? trimmed.slice(2) : trimmed;
    if (digits.length !== ADDRESS_BYTES * 2) {
        throw new Error(`address has ${trimmed.length} characters; expected ${exports.A1N_LEN} (A1n…), 64 hex, or 0x + 64 hex`);
    }
    if (!/^[0-9a-fA-F]+$/.test(digits))
        throw new Error('hex address contains a non-hex character');
    return Uint8Array.from(Buffer.from(digits, 'hex'));
}
/** Encode 32 address bytes as `A1n…`. */
function toA1n(address) {
    if (address.length !== ADDRESS_BYTES)
        throw new Error(`address must be ${ADDRESS_BYTES} bytes`);
    const versioned = Uint8Array.from([...exports.A1N_VERSION, ...address]);
    return base58Encode(Uint8Array.from([...versioned, ...checksum(versioned)]));
}
/** Decode `A1n…` to 32 bytes, verifying version and checksum. */
function fromA1n(encoded) {
    if (encoded.length !== exports.A1N_LEN) {
        throw new Error(`address has ${encoded.length} characters; expected ${exports.A1N_LEN}`);
    }
    const raw = base58Decode(encoded);
    if (raw.length !== RAW_LEN)
        throw new Error(`address has ${encoded.length} characters; expected ${exports.A1N_LEN}`);
    const versioned = raw.subarray(0, RAW_LEN - CHECKSUM_LEN);
    const check = raw.subarray(RAW_LEN - CHECKSUM_LEN);
    if (!exports.A1N_VERSION.every((b, i) => versioned[i] === b)) {
        throw new Error('not an AINCORE address (wrong version bytes)');
    }
    if (!Buffer.from(checksum(versioned)).equals(Buffer.from(check))) {
        throw new Error('address checksum does not match; check it for a typo');
    }
    return Uint8Array.from(versioned.subarray(exports.A1N_VERSION.length));
}
/** `A1n…`, 64-hex or `0x` + 64-hex → 32 bytes. Whitespace around it is ignored. */
function parseAddress(input) {
    const trimmed = input.trim();
    if (!trimmed)
        throw new Error('address is empty');
    return trimmed.startsWith(exports.A1N_PREFIX) ? fromA1n(trimmed) : hexToBytes(trimmed);
}
/** Any accepted form → the lowercase 64-hex that transactions and the node use. */
function toHexAddress(input) {
    return Buffer.from(parseAddress(input)).toString('hex');
}
/** Any accepted form → `A1n…`. */
function toA1nAddress(input) {
    return toA1n(parseAddress(input));
}
/** True when `input` is a well-formed address in any accepted form. */
function isValidAddress(input) {
    try {
        parseAddress(input);
        return true;
    }
    catch {
        return false;
    }
}
