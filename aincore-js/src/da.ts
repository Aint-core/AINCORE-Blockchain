import * as crypto from 'crypto';

/**
 * B1: verify a data availability sample (`aincore_sampleDA`) against the
 * `da_root` of a block header.
 *
 * Mirrors `verify_sample` in `da/src/lib.rs`. Both are tested against
 * `da/vectors/da_vectors.json`, which an independent reference
 * (`da/reference/da_ref.py`) generates.
 *
 * The construction:
 * - a body of `L` bytes is cut into `k = clamp(ceil(L / 512), 1, 128)` data
 *   shards of `max(1, ceil(L / k))` bytes and extended to `2k` shards;
 * - `leaf = SHA-256(0x00 ‖ index as u64 LE ‖ shard)`,
 *   `node = SHA-256(0x01 ‖ left ‖ right)`, an RFC 6962 tree over the `2k`
 *   leaves, proofs checked as RFC 9162 section 2.1.3.2 says;
 * - `da_root = SHA-256("AINCORE_DA_ROOT_V1\0" ‖ L as u64 LE ‖ tree root)`.
 *
 * Take `da_root` from a header you hold under a QC, never from the sampling
 * response, and pick the indices yourself, uniformly at random: `s` samples
 * that all verify leave a body nobody can recover undetected with
 * probability below `2^-s`.
 */

export interface DaSample {
    body_len: number;
    index: number;
    /** The shard's bytes, hex. */
    shard: string;
    /** Sibling hashes from the leaf up, hex. */
    proof: string[];
}

export type DaSampleError = 'BadRoot' | 'IndexOutOfRange' | 'BadShard' | 'BadProof' | 'RootMismatch';

const SHARD_TARGET_BYTES = 512n;
const MAX_DATA_SHARDS = 128n;
const MAX_PROOF_LEN = 8;
const ROOT_DOMAIN = Buffer.from('AINCORE_DA_ROOT_V1\0', 'latin1');
const HEX = /^[0-9a-fA-F]*$/;

export interface DaLayout {
    bodyLen: bigint;
    dataShards: bigint;
    shardSize: bigint;
    totalShards: bigint;
}

export function daLayout(bodyLen: bigint): DaLayout {
    const ceil = (a: bigint, b: bigint) => (a + b - 1n) / b;
    let dataShards = ceil(bodyLen, SHARD_TARGET_BYTES);
    if (dataShards < 1n) dataShards = 1n;
    if (dataShards > MAX_DATA_SHARDS) dataShards = MAX_DATA_SHARDS;
    let shardSize = ceil(bodyLen, dataShards);
    if (shardSize < 1n) shardSize = 1n;
    return { bodyLen, dataShards, shardSize, totalShards: 2n * dataShards };
}

function u64le(n: bigint): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(n);
    return b;
}

function sha256(...parts: Buffer[]): Buffer {
    const h = crypto.createHash('sha256');
    for (const p of parts) h.update(p);
    return h.digest();
}

function decodeHash(text: string): Buffer | null {
    return text.length === 64 && HEX.test(text) ? Buffer.from(text, 'hex') : null;
}

const leafHash = (index: bigint, shard: Buffer) => sha256(Buffer.from([0]), u64le(index), shard);
const nodeHash = (left: Buffer, right: Buffer) => sha256(Buffer.from([1]), left, right);

/** RFC 9162 section 2.1.3.2: the root a proof leads to, or null. */
function rootFromPath(index: bigint, size: bigint, leaf: Buffer, path: Buffer[]): Buffer | null {
    if (index >= size) return null;
    let f = index;
    let s = size - 1n;
    let r = leaf;
    for (const p of path) {
        if (s === 0n) return null;
        if ((f & 1n) === 1n || f === s) {
            r = nodeHash(p, r);
            if ((f & 1n) === 0n) {
                while ((f & 1n) === 0n && f !== 0n) {
                    f >>= 1n;
                    s >>= 1n;
                }
            }
        } else {
            r = nodeHash(r, p);
        }
        f >>= 1n;
        s >>= 1n;
    }
    return s === 0n ? r : null;
}

/** Check one sample against a DA root; `null` if it verifies. */
export function verifyDaSample(daRoot: string, sample: DaSample): DaSampleError | null {
    const expected = decodeHash(daRoot);
    if (!expected) return 'BadRoot';
    if (!Number.isFinite(sample.body_len) || sample.body_len < 0) return 'BadShard';
    const layout = daLayout(BigInt(Math.trunc(sample.body_len)));
    if (!Number.isInteger(sample.index) || sample.index < 0) return 'IndexOutOfRange';
    const index = BigInt(sample.index);
    if (index >= layout.totalShards) return 'IndexOutOfRange';
    if (BigInt(sample.shard.length) !== 2n * layout.shardSize) return 'BadShard';
    if (!HEX.test(sample.shard)) return 'BadShard';
    const shard = Buffer.from(sample.shard, 'hex');
    if (sample.proof.length > MAX_PROOF_LEN) return 'BadProof';
    const path: Buffer[] = [];
    for (const p of sample.proof) {
        const h = decodeHash(p);
        if (!h) return 'BadProof';
        path.push(h);
    }
    const tree = rootFromPath(index, layout.totalShards, leafHash(index, shard), path);
    if (!tree) return 'BadProof';
    const root = sha256(ROOT_DOMAIN, u64le(layout.bodyLen), tree);
    return root.equals(expected) ? null : 'RootMismatch';
}
