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
 * response, and pick the indices yourself, uniformly at random, passing each
 * one to `verifyDaSample` with its answer (B455: a server holding one shard
 * could answer every draw with it). B478: draw them from `[0, totalShards)`,
 * the count a verified sample returns (the body the root commits to, as
 * `verify_sample` returns it, B62). The `total_shards` of
 * `aincore_getDaStatus` is a hint for the first draw only, and a hint below
 * the verified count is a lie: a server holding 2 shards of 256 answered 2
 * and passed every draw. Then `s` samples that all verify leave a body
 * nobody can recover undetected with probability below `2^-s`.
 */

/** The shape of an `aincore_sampleDA` answer's `sample`. */
export interface DaSample {
    body_len: number;
    index: number;
    /** The shard's bytes, hex. */
    shard: string;
    /** Sibling hashes from the leaf up, hex. */
    proof: string[];
}

/**
 * Why a sample is refused: `SampleError` in `da/src/lib.rs`, plus
 * `Malformed` (B478), an answer not shaped like a `DaSample` (a field
 * missing or of another JSON type, a number that is not an integer a u64
 * holds), which Rust's decode refuses before `verify_sample` runs.
 */
export type DaSampleError = 'Malformed' | 'BadRoot' | 'WrongIndex' | 'IndexOutOfRange' | 'BadShard' | 'BadProof' | 'RootMismatch';

/**
 * B478: a verified sample carries `totalShards`, the number of shards of the
 * body the root commits to (`verify_sample`'s `Ok`, B62); draw indices from
 * that range only.
 */
export type DaSampleVerdict = { ok: true; totalShards: number } | { ok: false; error: DaSampleError };

const SHARD_TARGET_BYTES = 512n;
const MAX_DATA_SHARDS = 128n;
const MAX_PROOF_LEN = 8;
const ROOT_DOMAIN = Buffer.from('AINCORE_DA_ROOT_V1\0', 'latin1');
const HEX = /^[0-9a-fA-F]*$/;
/** B478: the double `u64::MAX` parses to, the largest number serde takes as a u64. */
const U64_CEILING = 2 ** 64;

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

function decodeHash(text: unknown): Buffer | null {
    return typeof text === 'string' && text.length === 64 && HEX.test(text) ? Buffer.from(text, 'hex') : null;
}

/** B478: a JSON number serde decodes as a u64. */
function isU64(n: unknown): n is number {
    return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= U64_CEILING;
}

/** B478: shaped as serde decodes a `Sample`, so nothing below can throw. */
function isSampleShaped(sample: unknown): sample is DaSample {
    if (typeof sample !== 'object' || sample === null) return false;
    const { body_len, index, shard, proof } = sample as Record<string, unknown>;
    return (
        isU64(body_len) &&
        isU64(index) &&
        typeof shard === 'string' &&
        Array.isArray(proof) &&
        proof.every((p) => typeof p === 'string')
    );
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

/**
 * Check one sample, the answer to a request for shard `index`, against a DA
 * root. B455: `index` is the one you drew, never the sample's own: a genuine
 * sample of another index verified, so a server holding one shard passed
 * every draw.
 *
 * B478: `sample` is the answer's `sample` as the server sent it. Total over
 * any JSON value: a mis-shaped one is refused as `Malformed`, never thrown
 * on (a fractional `body_len` was truncated and verified). A sample that
 * verifies returns `{ ok: true, totalShards }`, the shard count the root
 * commits to, as `verify_sample` does; it returned `null` and no count, so a
 * client drew from the count the server reported.
 */
export function verifyDaSample(daRoot: string, index: number, sample: unknown): DaSampleVerdict {
    const refuse = (error: DaSampleError): DaSampleVerdict => ({ ok: false, error });
    if (!isSampleShaped(sample)) return refuse('Malformed');
    const expected = decodeHash(daRoot);
    if (!expected) return refuse('BadRoot');
    if (sample.index !== index) return refuse('WrongIndex');
    const layout = daLayout(BigInt(sample.body_len));
    const at = BigInt(sample.index);
    if (at >= layout.totalShards) return refuse('IndexOutOfRange');
    // A body past 2^59 bytes has shards of more than 2^53 hex digits, longer
    // than any string, so `u64le` below never meets a length past u64.
    if (BigInt(sample.shard.length) !== 2n * layout.shardSize) return refuse('BadShard');
    if (!HEX.test(sample.shard)) return refuse('BadShard');
    const shard = Buffer.from(sample.shard, 'hex');
    if (sample.proof.length > MAX_PROOF_LEN) return refuse('BadProof');
    const path: Buffer[] = [];
    for (const p of sample.proof) {
        const h = decodeHash(p);
        if (!h) return refuse('BadProof');
        path.push(h);
    }
    const tree = rootFromPath(at, layout.totalShards, leafHash(at, shard), path);
    if (!tree) return refuse('BadProof');
    const root = sha256(ROOT_DOMAIN, u64le(layout.bodyLen), tree);
    if (!root.equals(expected)) return refuse('RootMismatch');
    return { ok: true, totalShards: Number(layout.totalShards) };
}
