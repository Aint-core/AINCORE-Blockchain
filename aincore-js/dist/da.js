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
exports.daLayout = daLayout;
exports.verifyDaSample = verifyDaSample;
const crypto = __importStar(require("crypto"));
const SHARD_TARGET_BYTES = 512n;
const MAX_DATA_SHARDS = 128n;
const MAX_PROOF_LEN = 8;
const ROOT_DOMAIN = Buffer.from('AINCORE_DA_ROOT_V1\0', 'latin1');
const HEX = /^[0-9a-fA-F]*$/;
/** B478: the double `u64::MAX` parses to, the largest number serde takes as a u64. */
const U64_CEILING = 2 ** 64;
function daLayout(bodyLen) {
    const ceil = (a, b) => (a + b - 1n) / b;
    let dataShards = ceil(bodyLen, SHARD_TARGET_BYTES);
    if (dataShards < 1n)
        dataShards = 1n;
    if (dataShards > MAX_DATA_SHARDS)
        dataShards = MAX_DATA_SHARDS;
    let shardSize = ceil(bodyLen, dataShards);
    if (shardSize < 1n)
        shardSize = 1n;
    return { bodyLen, dataShards, shardSize, totalShards: 2n * dataShards };
}
function u64le(n) {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(n);
    return b;
}
function sha256(...parts) {
    const h = crypto.createHash('sha256');
    for (const p of parts)
        h.update(p);
    return h.digest();
}
function decodeHash(text) {
    return typeof text === 'string' && text.length === 64 && HEX.test(text) ? Buffer.from(text, 'hex') : null;
}
/** B478: a JSON number serde decodes as a u64. */
function isU64(n) {
    return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= U64_CEILING;
}
/** B478: shaped as serde decodes a `Sample`, so nothing below can throw. */
function isSampleShaped(sample) {
    if (typeof sample !== 'object' || sample === null)
        return false;
    const { body_len, index, shard, proof } = sample;
    return (isU64(body_len) &&
        isU64(index) &&
        typeof shard === 'string' &&
        Array.isArray(proof) &&
        proof.every((p) => typeof p === 'string'));
}
const leafHash = (index, shard) => sha256(Buffer.from([0]), u64le(index), shard);
const nodeHash = (left, right) => sha256(Buffer.from([1]), left, right);
/** RFC 9162 section 2.1.3.2: the root a proof leads to, or null. */
function rootFromPath(index, size, leaf, path) {
    if (index >= size)
        return null;
    let f = index;
    let s = size - 1n;
    let r = leaf;
    for (const p of path) {
        if (s === 0n)
            return null;
        if ((f & 1n) === 1n || f === s) {
            r = nodeHash(p, r);
            if ((f & 1n) === 0n) {
                while ((f & 1n) === 0n && f !== 0n) {
                    f >>= 1n;
                    s >>= 1n;
                }
            }
        }
        else {
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
function verifyDaSample(daRoot, index, sample) {
    const refuse = (error) => ({ ok: false, error });
    if (!isSampleShaped(sample))
        return refuse('Malformed');
    const expected = decodeHash(daRoot);
    if (!expected)
        return refuse('BadRoot');
    if (sample.index !== index)
        return refuse('WrongIndex');
    const layout = daLayout(BigInt(sample.body_len));
    const at = BigInt(sample.index);
    if (at >= layout.totalShards)
        return refuse('IndexOutOfRange');
    // A body past 2^59 bytes has shards of more than 2^53 hex digits, longer
    // than any string, so `u64le` below never meets a length past u64.
    if (BigInt(sample.shard.length) !== 2n * layout.shardSize)
        return refuse('BadShard');
    if (!HEX.test(sample.shard))
        return refuse('BadShard');
    const shard = Buffer.from(sample.shard, 'hex');
    if (sample.proof.length > MAX_PROOF_LEN)
        return refuse('BadProof');
    const path = [];
    for (const p of sample.proof) {
        const h = decodeHash(p);
        if (!h)
            return refuse('BadProof');
        path.push(h);
    }
    const tree = rootFromPath(at, layout.totalShards, leafHash(at, shard), path);
    if (!tree)
        return refuse('BadProof');
    const root = sha256(ROOT_DOMAIN, u64le(layout.bodyLen), tree);
    if (!root.equals(expected))
        return refuse('RootMismatch');
    return { ok: true, totalShards: Number(layout.totalShards) };
}
