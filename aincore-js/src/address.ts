import * as crypto from 'crypto';

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

export const A1N_VERSION = Uint8Array.from([0x0d, 0xce, 0x00]);
export const A1N_PREFIX = 'A1n';
export const A1N_LEN = 53;

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ADDRESS_BYTES = 32;
const CHECKSUM_LEN = 4;
const RAW_LEN = A1N_VERSION.length + ADDRESS_BYTES + CHECKSUM_LEN;

function sha256(data: Uint8Array): Buffer {
    return crypto.createHash('sha256').update(data).digest();
}

function checksum(versioned: Uint8Array): Buffer {
    return sha256(sha256(versioned)).subarray(0, CHECKSUM_LEN);
}

function base58Encode(bytes: Uint8Array): string {
    let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));
    let out = '';
    while (n > 0n) {
        out = ALPHABET[Number(n % 58n)] + out;
        n /= 58n;
    }
    for (const b of bytes) {
        if (b !== 0) break;
        out = '1' + out;
    }
    return out;
}

function base58Decode(text: string): Uint8Array {
    let n = 0n;
    for (const ch of text) {
        const digit = ALPHABET.indexOf(ch);
        if (digit < 0) throw new Error('address contains a character that is not Base58');
        n = n * 58n + BigInt(digit);
    }
    let hex = n === 0n ? '' : n.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const body = Buffer.from(hex, 'hex');
    let zeros = 0;
    while (zeros < text.length && text[zeros] === '1') zeros++;
    return Uint8Array.from([...new Uint8Array(zeros), ...body]);
}

function hexToBytes(input: string): Uint8Array {
    const trimmed = input.trim();
    const digits = /^0x/i.test(trimmed) ? trimmed.slice(2) : trimmed;
    if (digits.length !== ADDRESS_BYTES * 2) {
        throw new Error(`address has ${trimmed.length} characters; expected ${A1N_LEN} (A1n…), 64 hex, or 0x + 64 hex`);
    }
    if (!/^[0-9a-fA-F]+$/.test(digits)) throw new Error('hex address contains a non-hex character');
    return Uint8Array.from(Buffer.from(digits, 'hex'));
}

/** Encode 32 address bytes as `A1n…`. */
export function toA1n(address: Uint8Array): string {
    if (address.length !== ADDRESS_BYTES) throw new Error(`address must be ${ADDRESS_BYTES} bytes`);
    const versioned = Uint8Array.from([...A1N_VERSION, ...address]);
    return base58Encode(Uint8Array.from([...versioned, ...checksum(versioned)]));
}

/** Decode `A1n…` to 32 bytes, verifying version and checksum. */
export function fromA1n(encoded: string): Uint8Array {
    if (encoded.length !== A1N_LEN) {
        throw new Error(`address has ${encoded.length} characters; expected ${A1N_LEN}`);
    }
    const raw = base58Decode(encoded);
    if (raw.length !== RAW_LEN) throw new Error(`address has ${encoded.length} characters; expected ${A1N_LEN}`);
    const versioned = raw.subarray(0, RAW_LEN - CHECKSUM_LEN);
    const check = raw.subarray(RAW_LEN - CHECKSUM_LEN);
    if (!A1N_VERSION.every((b, i) => versioned[i] === b)) {
        throw new Error('not an AINCORE address (wrong version bytes)');
    }
    if (!Buffer.from(checksum(versioned)).equals(Buffer.from(check))) {
        throw new Error('address checksum does not match; check it for a typo');
    }
    return Uint8Array.from(versioned.subarray(A1N_VERSION.length));
}

/** `A1n…`, 64-hex or `0x` + 64-hex → 32 bytes. Whitespace around it is ignored. */
export function parseAddress(input: string): Uint8Array {
    const trimmed = input.trim();
    if (!trimmed) throw new Error('address is empty');
    return trimmed.startsWith(A1N_PREFIX) ? fromA1n(trimmed) : hexToBytes(trimmed);
}

/** Any accepted form → the lowercase 64-hex that transactions and the node use. */
export function toHexAddress(input: string): string {
    return Buffer.from(parseAddress(input)).toString('hex');
}

/** Any accepted form → `A1n…`. */
export function toA1nAddress(input: string): string {
    return toA1n(parseAddress(input));
}

/** True when `input` is a well-formed address in any accepted form. */
export function isValidAddress(input: string): boolean {
    try {
        parseAddress(input);
        return true;
    } catch {
        return false;
    }
}
