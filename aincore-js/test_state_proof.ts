// PF-4: the JS verifier against the shared vectors. Run: npx ts-node test_state_proof.ts
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { verifyStateProof, PLACEHOLDER } from './src';

const file = path.join(__dirname, '..', 'common', 'state_proof', 'vectors', 'pf_vectors.json');
const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
let valid = 0;
let invalid = 0;
let emptySubtree = 0;
for (const v of doc.vectors) {
    let error: unknown = null;
    try {
        verifyStateProof(v.root, v.key, v.value, v.proof);
    } catch (e) {
        error = e;
    }
    if (v.valid) {
        assert.strictEqual(error, null, `${v.name}: ${error}`);
        valid++;
        if (v.proof.leaf === null) emptySubtree++;
    } else {
        assert.notStrictEqual(error, null, `${v.name} must be refused`);
        invalid++;
    }
}
assert.ok(valid >= 12 && invalid >= 12, `positive control: ${valid} / ${invalid}`);
assert.ok(emptySubtree >= 3, 'both exclusion shapes are covered');

// The empty tree: every key is absent under the placeholder root.
verifyStateProof(PLACEHOLDER.toString('hex'), 'anything', null, { leaf: null, siblings: [] });
assert.throws(() =>
    verifyStateProof(PLACEHOLDER.toString('hex'), 'anything', 'x', { leaf: null, siblings: [] }),
);

// A lone surrogate encodes as U+FFFD, so it would pass for a value (or key)
// that really holds U+FFFD. Both are refused before hashing.
const fffd = doc.vectors.find((v: any) => v.valid && typeof v.value === 'string');
assert.ok(fffd, 'a vector with a value');
assert.throws(
    () => verifyStateProof(fffd.root, fffd.key, fffd.value + '\uD800', fffd.proof),
    /well-formed/,
);
assert.throws(
    () => verifyStateProof(PLACEHOLDER.toString('hex'), 'k\uDC00', null, { leaf: null, siblings: [] }),
    /well-formed/,
);

console.log(`state proof vectors passed (${valid} valid, ${invalid} refused)`);
