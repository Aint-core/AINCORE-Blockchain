import * as crypto from 'crypto';

/**
 * G3 PF: verify an AINCORE state proof (`aincore_getStateProof`).
 *
 * Mirrors `common/state_proof/src/lib.rs` line for line. Both are tested
 * against the same vectors, `common/state_proof/vectors/pf_vectors.json`,
 * which are generated from real Jellyfish Merkle trees (PF-4).
 *
 * The algorithm is that of `jmt` 0.12 with SHA-256:
 * - `keyHash = SHA-256(key)`, derived here from the canonical key, never
 *   taken from the server;
 * - `valueHash = SHA-256(value)`, over the exact stored bytes;
 * - `leaf = SHA-256("JMT::LeafNode" ‖ keyHash ‖ valueHash)`;
 * - `internal = SHA-256("JMT::IntrnalNode" ‖ left ‖ right)`;
 * - an empty subtree is `"SPARSE_MERKLE_PLACEHOLDER_HASH__"`;
 * - siblings run bottom to root; sibling `i` of `n` sits on the side given
 *   by bit `n - 1 - i` of the key hash, counting from the most significant
 *   bit.
 *
 * This checks the Merkle proof against a root. A full answer check (PF-2)
 * also verifies the quorum certificate (BLS) under a trusted committee, and
 * takes the root from that certificate. The BLS half is not in this SDK
 * yet: use `consensus::state_proof_client::verify_answer` in Rust, or a
 * root you already trust.
 */

export interface WireLeaf {
    key_hash: string;
    value_hash: string;
}

export interface WireProof {
    leaf: WireLeaf | null;
    siblings: string[];
}

const LEAF_DOMAIN = Buffer.from('JMT::LeafNode');
const INTERNAL_DOMAIN = Buffer.from('JMT::IntrnalNode');
export const PLACEHOLDER = Buffer.from('SPARSE_MERKLE_PLACEHOLDER_HASH__');
export const MAX_SIBLINGS = 256;

function sha256(...parts: Uint8Array[]): Buffer {
    const h = crypto.createHash('sha256');
    for (const p of parts) h.update(p);
    return h.digest();
}

export function keyHash(key: string): Buffer {
    return sha256(Buffer.from(key, 'utf8'));
}

function parseHash(hex: string): Buffer {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error(`malformed proof: not a 32-byte hex hash: ${hex}`);
    }
    return Buffer.from(hex, 'hex');
}

function bit(hash: Uint8Array, index: number): boolean {
    return (hash[index >> 3] & (0x80 >> (index & 7))) !== 0;
}

function commonPrefixBits(a: Uint8Array, b: Uint8Array): number {
    let n = 0;
    while (n < 256 && bit(a, n) === bit(b, n)) n++;
    return n;
}

/**
 * Verify that `key` has `value` (a string: stored values are UTF-8) or is
 * absent (`null`) in the tree whose root is `rootHex`. Throws on failure.
 */
export function verifyStateProof(
    rootHex: string,
    key: string,
    value: string | null,
    proof: WireProof,
): void {
    if (proof.siblings.length > MAX_SIBLINGS) {
        throw new Error(`malformed proof: ${proof.siblings.length} siblings`);
    }
    const root = parseHash(rootHex);
    const kh = keyHash(key);
    const leaf = proof.leaf
        ? { key: parseHash(proof.leaf.key_hash), value: parseHash(proof.leaf.value_hash) }
        : null;
    if (value !== null) {
        if (!leaf) throw new Error('the proof shows the key absent');
        if (!leaf.key.equals(kh)) throw new Error('the proof is for another key');
        if (!leaf.value.equals(sha256(Buffer.from(value, 'utf8')))) {
            throw new Error('the value does not match the proof');
        }
    } else if (leaf) {
        if (leaf.key.equals(kh)) throw new Error('the proof shows the key present');
        if (commonPrefixBits(kh, leaf.key) < proof.siblings.length) {
            throw new Error("the proof's leaf is not on the key's path");
        }
    }
    let hash = leaf ? sha256(LEAF_DOMAIN, leaf.key, leaf.value) : PLACEHOLDER;
    const n = proof.siblings.length;
    proof.siblings.forEach((siblingHex, i) => {
        const sibling = parseHash(siblingHex);
        hash = bit(kh, n - 1 - i)
            ? sha256(INTERNAL_DOMAIN, sibling, hash)
            : sha256(INTERNAL_DOMAIN, hash, sibling);
    });
    if (!hash.equals(root)) throw new Error('the proof does not reach the trusted root');
}
