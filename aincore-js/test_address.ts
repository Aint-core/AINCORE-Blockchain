// Parity + safety tests for A1n addresses. Run: npx ts-node test_address.ts
import * as assert from 'assert';
import * as crypto from 'crypto';
import { A1N_LEN, A1N_PREFIX, fromA1n, parseAddress, toA1n, toA1nAddress, toHexAddress, isValidAddress, Keypair } from './src';

// Same vector as common/crypto/src/address.rs.
const HEX = 'dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42';
const A1N = 'A1nB31ipYCNJJR7Gcsat1oE8J6kFPdEbJP5pAkq7u2ZLjdokxA3nH';
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

assert.strictEqual(toA1nAddress(HEX), A1N, 'known vector matches Rust');
assert.strictEqual(toHexAddress(A1N), HEX);
assert.strictEqual(toHexAddress('0x' + HEX.toUpperCase()), HEX);
assert.strictEqual(toHexAddress(`  ${A1N}\n`), HEX);

for (const fill of [0x00, 0xff]) {
    const s = toA1n(new Uint8Array(32).fill(fill));
    assert.strictEqual(s.length, A1N_LEN);
    assert.ok(s.startsWith(A1N_PREFIX), s);
}
for (let i = 0; i < 1000; i++) {
    const a = crypto.randomBytes(32);
    const s = toA1n(a);
    assert.strictEqual(s.length, A1N_LEN);
    assert.ok(s.startsWith(A1N_PREFIX), s);
    assert.ok(Buffer.from(fromA1n(s)).equals(a));
}

let tried = 0;
for (let pos = 0; pos < A1N.length; pos++) {
    for (const ch of ALPHABET) {
        if (ch === A1N[pos]) continue;
        const typo = A1N.slice(0, pos) + ch + A1N.slice(pos + 1);
        assert.ok(!isValidAddress(typo), `typo at ${pos} accepted: ${typo}`);
        tried++;
    }
}
assert.strictEqual(tried, A1N_LEN * 57, 'positive control: every substitution tried');

assert.throws(() => parseAddress('0x1'), /characters/);
assert.throws(() => parseAddress(''), /empty/);
assert.throws(() => fromA1n(A1N.slice(0, -1) + '0'), /Base58/);

const kp = Keypair.fromSeed(new Uint8Array(32).fill(44));
assert.strictEqual(kp.addressA1n, toA1nAddress(kp.address));
assert.strictEqual(toHexAddress(kp.addressA1n), kp.address);

console.log(`A1n address tests passed (${tried} typo variants refused, 1000 round trips)`);
