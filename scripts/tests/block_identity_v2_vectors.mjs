// Independent, fixed-fixture BCS encoder. Does not import the Rust codec.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const u64 = n => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(n));
  return out;
};
const uleb = n => {
  const out = [];
  do {
    const part = n & 127;
    n = Math.floor(n / 128);
    out.push(part | (n ? 128 : 0));
  } while (n);
  return Buffer.from(out);
};
const bytes = b => Buffer.concat([uleb(b.length), b]);
const digest = (domain, b) => createHash('sha256').update(domain).update(b).digest();
const version = Buffer.from([2, 0]);
const chain = Buffer.from('AIN-TEST');
const wire = Buffer.concat([
  version, bytes(chain), Buffer.alloc(32, 1), u64(2), u64(7),
  Buffer.from([1]), Buffer.alloc(32, 2), u64(12), Buffer.alloc(32, 3), u64(34),
  ...[4, 5, 6, 7, 8, 9, 10].map(n => Buffer.alloc(32, n)),
]);
const hash = digest('AINCORE_BLOCK_ID_V2\0', wire);
const signing = Buffer.concat([Buffer.from('AINCORE_BLOCK_PROPOSER_V2\0'), hash]);
const listRoot = (domain, items) => digest(domain,
  Buffer.concat([version, uleb(items.length), ...items.map(bytes)]));
const emptyTransactions = listRoot('AINCORE_BLOCK_TRANSACTIONS_V2\0', []);
assert.notDeepEqual(listRoot('AINCORE_BLOCK_TRANSACTIONS_V2\0', [Buffer.from('a'), Buffer.from('bc')]),
  listRoot('AINCORE_BLOCK_TRANSACTIONS_V2\0', [Buffer.from('ab'), Buffer.from('c')]));
assert.notDeepEqual(emptyTransactions, listRoot('AINCORE_BLOCK_EVIDENCE_V2\0', []));
const golden = readFileSync(new URL('../../consensus/blockchain/test-vectors/block_identity_v2.hex', import.meta.url), 'utf8').trim();
assert.equal(wire.toString('hex'), golden);
assert.equal(hash.toString('hex'), '0407086884bb9b846531bed71ef1e963c8012694c7fbafad39a22f829e5d2f78');
assert.equal(signing.toString('hex'), '41494e434f52455f424c4f434b5f50524f504f5345525f5632000407086884bb9b846531bed71ef1e963c8012694c7fbafad39a22f829e5d2f78');
assert.equal(emptyTransactions.toString('hex'), '8fb38df1efad444ac9c18deae026b6fd958c88be41aca777ead558f9f75c05a5');
console.log('V2 fixed vector, domain separation and list-boundary checks passed');

const policyWire = Buffer.concat([
  Buffer.from([1, 0]), Buffer.alloc(32, 11), bytes(chain), u64(21),
]);
const policyGolden = readFileSync(new URL('../../consensus/blockchain/test-vectors/genesis_format_policy.hex', import.meta.url), 'utf8').trim();
assert.equal(policyWire.toString('hex'), policyGolden);
assert.equal(digest('AINCORE_BLOCK_FORMAT_GENESIS_V1\0', policyWire).toString('hex'),
  'dd4a5ea91fcaab9fa3f9282bd9c8ca8285d38ce4e3031346bd6e3c1d979ea5dd');
console.log('Genesis format-policy fixed bytes and pin passed');

// Test seeds only. RFC 8410 Ed25519 PKCS#8 wrapping, no Rust/dalek dependency.
const privateKey = seed => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = seed => createPublicKey(privateKey(seed))
  .export({ format: 'der', type: 'spki' }).subarray(-32);
const envelopePin = digest('AINCORE_BLOCK_FORMAT_GENESIS_V1\0', Buffer.concat([
  Buffer.from([1, 0]), Buffer.alloc(32, 1), bytes(chain), u64(7),
]));
const nonemptyVertices = digest('AINCORE_BLOCK_VERTICES_V2\0', Buffer.concat([
  version, uleb(2), Buffer.alloc(32, 11), Buffer.alloc(32, 12),
]));
const envelopeIdentity = Buffer.concat([
  version, bytes(chain), envelopePin, u64(2), u64(7), Buffer.from([1]), Buffer.alloc(32, 2),
  u64(12), Buffer.alloc(32, 3), u64(34), digest('', publicKey(78)),
  listRoot('AINCORE_BLOCK_TRANSACTIONS_V2\0', [Buffer.from('a'), Buffer.from('bc')]),
  Buffer.alloc(32, 6), Buffer.alloc(32, 7), nonemptyVertices,
  listRoot('AINCORE_BLOCK_EVIDENCE_V2\0', [Buffer.from('x'), Buffer.from('yz')]),
  Buffer.alloc(32, 10),
]);
const envelopeHash = digest('AINCORE_BLOCK_ID_V2\0', envelopeIdentity);
const envelopeSigningBytes = Buffer.concat([Buffer.from('AINCORE_BLOCK_PROPOSER_V2\0'), envelopeHash]);
const envelopeSignature = sign(null, envelopeSigningBytes, privateKey(77));
assert.equal(envelopeIdentity.toString('hex'), readFileSync(new URL(
  '../../consensus/blockchain/test-vectors/envelope_identity_v2.hex', import.meta.url), 'utf8').trim());
assert.equal(envelopeSignature.toString('hex'), readFileSync(new URL(
  '../../consensus/blockchain/test-vectors/envelope_signature_v2.hex', import.meta.url), 'utf8').trim());
assert.equal(envelopeHash.toString('hex'), 'c94897f19a1046839a356fe600bdf4c5e341ce45d6bbcdd21e740385a5a3eb23');
assert.equal(publicKey(77).toString('hex'), '62a611b472d89b0e5fc93c069b9f700b4c552d55bc0e87b56008ef17b6b2bebe');
assert(verify(null, envelopeSigningBytes, createPublicKey(privateKey(77)), envelopeSignature));
assert(!verify(null, envelopeHash, createPublicKey(privateKey(77)), envelopeSignature));
assert(!verify(null, envelopeSigningBytes, createPublicKey(privateKey(78)), envelopeSignature));
console.log('Nonempty V2 identity and Ed25519 cross-implementation vector passed');

const envelopeWire = Buffer.concat([
  version, bytes(envelopeIdentity), digest('', publicKey(77)), bytes(envelopeSignature),
  uleb(2), bytes(Buffer.from('a')), bytes(Buffer.from('bc')),
  uleb(2), Buffer.alloc(32, 11), Buffer.alloc(32, 12),
  uleb(2), bytes(Buffer.from('x')), bytes(Buffer.from('yz')),
]);
assert.equal(envelopeWire.toString('hex'), readFileSync(new URL(
  '../../consensus/blockchain/test-vectors/envelope_wire_v2.hex', import.meta.url), 'utf8').trim());
console.log('Full V2 bounded-transport fixed vector passed');
