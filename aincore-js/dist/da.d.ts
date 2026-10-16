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
export type DaSampleVerdict = {
    ok: true;
    totalShards: number;
} | {
    ok: false;
    error: DaSampleError;
};
export interface DaLayout {
    bodyLen: bigint;
    dataShards: bigint;
    shardSize: bigint;
    totalShards: bigint;
}
export declare function daLayout(bodyLen: bigint): DaLayout;
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
export declare function verifyDaSample(daRoot: string, index: number, sample: unknown): DaSampleVerdict;
