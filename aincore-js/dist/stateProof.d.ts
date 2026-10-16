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
export declare const PLACEHOLDER: Buffer<ArrayBuffer>;
export declare const MAX_SIBLINGS = 256;
export declare function keyHash(key: string): Buffer;
/**
 * Verify that `key` has `value` (a string: stored values are UTF-8) or is
 * absent (`null`) in the tree whose root is `rootHex`. Throws on failure.
 */
export declare function verifyStateProof(rootHex: string, key: string, value: string | null, proof: WireProof): void;
