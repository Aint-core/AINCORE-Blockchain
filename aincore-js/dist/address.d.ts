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
export declare const A1N_VERSION: Uint8Array<ArrayBuffer>;
export declare const A1N_PREFIX = "A1n";
export declare const A1N_LEN = 53;
/** Encode 32 address bytes as `A1n…`. */
export declare function toA1n(address: Uint8Array): string;
/** Decode `A1n…` to 32 bytes, verifying version and checksum. */
export declare function fromA1n(encoded: string): Uint8Array;
/** `A1n…`, 64-hex or `0x` + 64-hex → 32 bytes. Whitespace around it is ignored. */
export declare function parseAddress(input: string): Uint8Array;
/** Any accepted form → the lowercase 64-hex that transactions and the node use. */
export declare function toHexAddress(input: string): string;
/** Any accepted form → `A1n…`. */
export declare function toA1nAddress(input: string): string;
/** True when `input` is a well-formed address in any accepted form. */
export declare function isValidAddress(input: string): boolean;
