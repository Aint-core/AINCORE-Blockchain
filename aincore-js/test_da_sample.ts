// B1: the JS DA sample verifier against the shared vectors.
// Run: npx ts-node test_da_sample.ts
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { verifyDaSample } from './src';

const file = path.join(__dirname, '..', 'da', 'vectors', 'da_vectors.json');
const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
for (const v of doc.valid) {
    assert.strictEqual(verifyDaSample(v.da_root, v.sample), null, `shard ${v.sample.index} of ${v.sample.body_len} bytes`);
}
for (const v of doc.invalid) {
    assert.strictEqual(verifyDaSample(v.da_root, v.sample), v.error, v.name);
}
assert.ok(doc.valid.length >= 12 && doc.invalid.length >= 12, 'positive control: the vectors loaded');
console.log(`DA vectors: ${doc.valid.length} valid accepted, ${doc.invalid.length} invalid refused with the expected error`);
