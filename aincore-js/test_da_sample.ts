// B1: the JS DA sample verifier against the shared vectors.
// Run: npx ts-node test_da_sample.ts
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { verifyDaSample } from './src';

const file = path.join(__dirname, '..', 'da', 'vectors', 'da_vectors.json');
const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
const refused = (error: string) => ({ ok: false, error });
// B478: the shard count each valid body commits to, worked out by hand from
// the construction (k = clamp(ceil(L / 512), 1, 128) data shards, 2k in all),
// not by the code under test.
const TOTAL_SHARDS: Record<number, number> = { 0: 2, 1: 2, 1000: 4, 5000: 20 };
for (const v of doc.valid) {
    const totalShards = TOTAL_SHARDS[v.sample.body_len];
    assert.ok(totalShards !== undefined, `a count for a body of ${v.sample.body_len} bytes`);
    assert.deepStrictEqual(verifyDaSample(v.da_root, v.sample.index, v.sample), { ok: true, totalShards }, `shard ${v.sample.index} of ${v.sample.body_len} bytes`);
    // B455: a genuine sample is no answer to a draw of another index.
    assert.deepStrictEqual(verifyDaSample(v.da_root, v.sample.index + 1, v.sample), refused('WrongIndex'), `shard ${v.sample.index} answering a draw of ${v.sample.index + 1}`);
}
// A vector's optional top-level `index` is the index the client drew (B455);
// without it the sample answers a draw of its own index.
let drawnElsewhere = 0;
for (const v of doc.invalid) {
    const drawn = v.index ?? v.sample.index;
    if (drawn !== v.sample.index) drawnElsewhere += 1;
    assert.deepStrictEqual(verifyDaSample(v.da_root, drawn, v.sample), refused(v.error), v.name);
}
assert.ok(doc.valid.length >= 12 && doc.invalid.length >= 13, 'positive control: the vectors loaded');
assert.ok(drawnElsewhere > 0, 'B455 control: a vector draws another index than its sample');

// B478, B62's SDK half: a server holding shards 0 and 1 of the 5000-byte
// body (20 shards) reports total_shards 2. A client drawing from that hint
// gets genuine answers that verify; the count each returns shows the lie.
const wide = doc.valid.find((v: any) => v.sample.body_len === 5000 && v.sample.index === 0);
assert.ok(wide, 'a sample of the 5000-byte body');
const hint = 2;
const verdict = verifyDaSample(wide.da_root, 0, wide.sample);
assert.ok(verdict.ok && verdict.totalShards > hint, 'the verified count exposes a hint below it');

// B478: total over JSON. A mis-shaped answer is refused as Malformed, never
// thrown on: each of these threw a TypeError, or was truncated and verified.
const base = doc.valid.find((v: any) => v.sample.body_len === 1000 && v.sample.index === 0);
assert.ok(base, 'a sample of the 1000-byte body');
const verdictOf = (root: unknown, drawn: number, sample: unknown) => {
    try {
        return verifyDaSample(root as string, drawn, sample);
    } catch (e) {
        return `threw ${e}`;
    }
};
const withField = (key: string, value: unknown) => ({ ...base.sample, [key]: value });
const without = (key: string) => {
    const sample = { ...base.sample };
    delete sample[key];
    return sample;
};
const siblings: string[] = base.sample.proof;
const misshaped: Array<[string, unknown, number]> = [
    ['no sample', null, 0],
    ['a sample that is a string', 'sample', 0],
    ['a sample that is an array', [], 0],
    ['no shard', without('shard'), 0],
    ['a numeric shard', withField('shard', 7), 0],
    ['no proof', without('proof'), 0],
    ['a proof that is an object with a length', withField('proof', { length: 1 }), 0],
    ['a proof that is a string', withField('proof', siblings.join('')), 0],
    ['a null sibling', withField('proof', [null, ...siblings.slice(1)]), 0],
    ['a numeric sibling', withField('proof', [1, ...siblings.slice(1)]), 0],
    ['no body length', without('body_len'), 0],
    ['a fractional body length', withField('body_len', 1000.5), 0],
    ['a negative body length', withField('body_len', -1), 0],
    ['a body length as a string', withField('body_len', '1000'), 0],
    ['a body length past u64', withField('body_len', 2 ** 65), 0],
    ['a fractional index', withField('index', 0.5), 0.5],
    ['an index as a string', withField('index', '0'), 0],
];
for (const [name, sample, drawn] of misshaped) {
    assert.deepStrictEqual(verdictOf(base.da_root, drawn, sample), refused('Malformed'), name);
}
assert.deepStrictEqual(verdictOf(undefined, 0, base.sample), refused('BadRoot'), 'a root that is not a string');
// Controls: the sample the cases were cut from verifies, and the largest
// body length a u64 holds is well shaped (refused for its shard size).
assert.deepStrictEqual(verdictOf(base.da_root, 0, base.sample), { ok: true, totalShards: 4 }, 'the base sample');
assert.deepStrictEqual(verdictOf(base.da_root, 0, withField('body_len', 2 ** 64)), refused('BadShard'), 'a body length of 2^64');
console.log(`DA vectors: ${doc.valid.length} valid accepted, ${doc.invalid.length} invalid refused with the expected error (${drawnElsewhere} drawn elsewhere); ${misshaped.length} mis-shaped answers refused`);
