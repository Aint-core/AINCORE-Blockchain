# Canonical block identity and activation

Status: a prototype canonical codec is implemented and isolated; production
wiring, activation and migration are NOT implemented or approved. No live
deployment, reset or genesis migration.

## Reproduced evidence

`sync/src/block_identity_tests.rs` drives the real `process_blocks` path with
authenticated proposer records, real Ed25519 signatures, matching empty-execution
roots and independent RocksDB stores. The two stores accept and persist:

- An original round 1 / timestamp 23 block versus round 12 / timestamp 3 using
  exactly the same header hash and unchanged proposer signature.
- An original anchor hash versus a substituted anchor hash using exactly the
  same header hash and unchanged proposer signature.

The honest unchanged-block control passes. The two required rejection tests fail:

```sh
cargo test --locked --offline -p chain_sync --lib block_identity -- --include-ignored --test-threads=1 --nocapture
```

Result: 1 passed, 2 failed. This reaches execution and block persistence, not just
`validate_block`. It does NOT prove two conflicting QCs, a multi-validator ordering
fork, or a cryptographic hash collision. The input bytes are equal because the
encoding omits boundaries/fields. Both witnesses are explicitly ignored in the
default developer suite and must be selected for readiness decisions.

The separate transaction hash also concatenates variable-length transaction
strings without count/length boundaries. This is a static encoding finding in
`blockchain::calculate_tx_hash` AND a duplicate in `ChainSync::calculate_tx_hash`;
no valid-transaction execution exploit is claimed by the two tests above.

## Required protocol contract

1. A versioned, domain-separated canonical preimage must commit to every value
   whose substitution changes accepted block identity or subsequent consensus:
   chain identity, version, committee epoch, height, parent, anchor round, anchor
   hash, timestamp, proposer identity, transaction commitment, execution state
   root, receipt commitment, ordered vertex commitment and evidence commitment.
   The cumulative finality digest is also committed, rather than left as a
   detached value that ordering uses to seed subsequent consensus context.
2. Collections include their length and individually delimited values. Integers
   use fixed typed encodings. Empty lists have an explicit deterministic
   commitment, not an omitted optional suffix. Hashes/addresses use fixed-width
   validated bytes where the protocol defines them; no silent text normalization
   that lets producer and verifier interpret different identities.
3. Derived block hash and signatures are excluded from their own hash preimage.
   The proposer signature covers the versioned block identity under a distinct
   signing domain. Signer membership/key binding remains independently required;
   a block hash does not authenticate its signer or prove execution.
4. The parent representation must distinguish genesis from a block hash without
   an ambiguous string sentinel. Chain identity is bound so the same signed
   block cannot be transplanted across chains sharing validator keys.
5. One shared implementation owns body commitments, block identity, signature
   bytes and version rejection. Sync must not maintain a second hashing loop.
   Decoders reject unsupported versions rather than inferring a format from
   whether a signature/hash happens to verify.

BCS is already used by FinalityVote and appears at version 0.1.6 in Cargo.lock.
It is a candidate codec, not a completed protocol choice: its
[primary specification](https://github.com/diem/bcs) guarantees canonical bytes
for a particular type, while requiring applications to distinguish types and
plan versioning explicitly. A BCS struct alone supplies neither domain separation
nor consensus activation. Define the concrete schema and frozen cross-language
vectors before selecting the wire contract.

## Activation and history

There is no current block-version field or authenticated block-format activation
schedule. `protocol_version: 1` in the API status response is not such a schedule.
Do not change `calculate_header_hash` in place and silently reinterpret history.

- For a separately authorized new lineage, pin the required format/schedule into
  genesis identity. The current `genesis_identity_hash` already pins the epoch
  interval and execution-root requirement; block format must receive equivalent
  protection and startup validation, with updated fixtures/tooling.
- For an existing lineage, require an authenticated upgrade decision and a
  precise effective height/epoch tied to the chain's trusted history. A local
  environment flag or mutable uncommitted DB key is not activation authority.
  Until that mechanism is reviewed, do not advertise rolling compatibility.
- For each height there must be one allowed production/verification format.
  Reject legacy blocks after activation, premature new-format blocks, unknown
  versions and downgrade attempts. Never try both formats and accept either.
- Historical verification must retain the applicable format schedule, committee
  context and parent linkage. Do not rewrite legacy block hashes, QC indexes,
  signing guards or state. Existing signatures cannot retroactively authenticate
  an omitted anchor/ambiguous legacy encoding; label that trust limitation.
- Snapshot/join packages must carry the pinned identity and authenticated
  schedule. Unknown or pruned context fails closed with an explicit recovery
  requirement, rather than using today's configuration for historical blocks.

## Caller inventory

| Surface | Current site | Required change |
|---|---|---|
| Block schema, hash and proposer signature | `consensus/blockchain/src/lib.rs` | Versioned canonical schema, shared commitments and typed/domain-separated signing |
| Local accepted block construction | `consensus/consensus/src/dag.rs`, `try_commit` | Resolve authorized format for accepted height within the acceptance boundary; construct/sign that format |
| Incoming sync validation | `sync/src/lib.rs`, `validate_block`, `verify_block_hash` | Use the same format policy, commitment checks and signer verification; remove duplicate transaction hashing |
| Sync persistence/reorg identity | `sync/src/lib.rs`, `process_blocks` | Do not treat a legacy matching hash as proof that different consensus fields are the same block |
| QC signing, aggregation and import | `consensus/consensus/src/qc_producer.rs` | Bind QC to the accepted versioned block identity; retain epoch/height and durable signing guards |
| Ordering adoption/reload | `consensus/consensus/src/ordering.rs`, `dag.rs` | Consume authenticated anchor/sequence/epoch context; do not adopt unsigned side fields |
| Genesis and recovery | `core/node/src/genesis.rs`, join/snapshot tooling | Pin and validate format schedule; preserve historical limitations and explicit migration authorization |
| API/indexer/SDK and release assets | Node APIs, indexer, aincore-js, release packaging | Version-aware schemas and vectors; fresh-machine compatibility and reproducible artifacts |

This inventory is a starting point, not proof that all downstream readers have
been covered. The separate `consensus::Block`/`BlockHeader` types also need caller
classification before unifying or changing them.

## Evidence required to close this blocker

- The two signed substitution witnesses become ordinary passing rejection tests,
  while the unchanged-block control remains accepted at the intended format.
- Independent vectors cover integer/string boundaries, empty/nonempty lists,
  order changes, field omission, chain/epoch/version changes and fixed-byte
  parsing. Mutation of each committed field changes identity/signature bytes.
- Differential encoding verification against another implementation, including
  malformed/trailing/noncanonical bytes and unknown versions. Rust self-roundtrip
  alone is insufficient.
- Caller tests cover producer, sync execution/persistence, ordering adoption,
  imported QC, reload, checkpoint recovery and signer guards, including crash
  before/after acceptance and concurrent sync/local production.
- Activation tests cover the boundary and successor, old/new clients, downgrade,
  historical replay, unavailable schedule and snapshot/waypoint recovery.
- Document and test bounded payload sizes and decoding work; canonical encoding
  does not by itself prevent network/CPU/memory exhaustion.
- A release gate runs these witnesses even when default developer tests skip
  them. The current release workflow builds/packages binaries without these
  security tests; a successful artifact build is not readiness evidence.
- Independent review of schema and activation, then an explicitly authorized
  operational rollout/recovery exercise. No mainnet clearance from this plan.

Reject a partial fix that only hashes the new anchor field, changes timestamp
heuristics, accepts both versions indefinitely, or adds a second signature while
keeping an ambiguous identifier for QC/indexing. Those preserve the wrong identity
contract instead of establishing the required one.

## Prototype codec contract

`consensus/blockchain/src/identity_v2.rs` proposes the following exact BCS tuple:

```text
(version: u16 = 2, BlockIdentityV2 {
  chain_id: String, genesis_hash: [u8;32], epoch: u64, height: u64,
  parent: enum { Genesis, Block([u8;32]) },
  anchor_round: u64, anchor_hash: [u8;32], timestamp: u64,
  proposer: [u8;32], transactions_root: [u8;32], state_root: [u8;32],
  receipts_root: [u8;32], vertices_root: [u8;32], evidence_root: [u8;32],
  finality_digest: [u8;32]
})
```

The chain's genesis identity is explicit, separate from the parent enum. Version
is an encoded u16, not an inferred BCS enum ordinal. Integers and list lengths
follow BCS, and field order above is fixed for the proposal. Identity hash is
SHA-256(`AINCORE_BLOCK_ID_V2\0` || encoded tuple). Proposer signing bytes are
`AINCORE_BLOCK_PROPOSER_V2\0` || identity hash. Transaction/evidence roots each hash
their distinct `AINCORE_BLOCK_TRANSACTIONS_V2\0` / `AINCORE_BLOCK_EVIDENCE_V2\0`
domain plus BCS `(2u16, Vec<Vec<u8>>)`. Vertex roots use
`AINCORE_BLOCK_VERTICES_V2\0` plus BCS `(2u16, Vec<[u8;32]>)`. No empty-root omission.

The codec validates positive block height/anchor round, the parent kind at height
1 versus later heights, and nonempty chain ID of at most 128 UTF-8 bytes. Identity
input is capped at 1024 bytes before decoding. Proposed body bounds: 10,000 items,
1 MiB per transaction/evidence item, and a conservative 16 MiB framed aggregate
bound checked before BCS serialization. These are draft protocol limits needing
activation-policy review, not claims that current network decoders enforce them.
Callers must bound allocation before constructing these input vectors.

The codec does not authenticate its supplied chain/epoch, reconstruct a finality
digest, validate transaction/evidence semantics, or verify execution. It is not a
replacement for the acceptance/state-proof checks. There is no adapter silently
converting a legacy block into V2 and no version fallback in the decoder.

The fixed non-genesis vector is in
`consensus/blockchain/test-vectors/block_identity_v2.hex`. Its SHA-256 identity is
`0407086884bb9b846531bed71ef1e963c8012694c7fbafad39a22f829e5d2f78`.
Rust and `scripts/tests/block_identity_v2_vectors.mjs` independently encode the
same typed fixture and compare against these frozen bytes/hash/signing bytes.
The JavaScript reference imports neither the Rust codec nor a BCS package.
This is one cross-language vector plus boundary/domain checks, not broad
differential fuzzing, independent audit or production interoperability proof.

## Isolated genesis format-policy proposal

`identity_v2::policy` now defines a proposed genesis commitment:

```text
proof = BCS((1u16, GenesisFormatProof {
  base_genesis_identity: [u8;32], chain_id: String, v2_from_height: u64
}))
candidate_pin = SHA-256("AINCORE_BLOCK_FORMAT_GENESIS_V1\0" || proof)
```

The base identity commits the existing genesis inputs. This candidate is a NEW
identity, not a compatible replacement for a running chain's pin. The verifier
accepts only canonical bounded proof bytes matching a separately trusted pin.
Computing a pin from a peer's proof and passing it back to the verifier provides
NO bootstrap authentication. Distribution and acceptance of the trusted pin,
and verification that the actual genesis matches its committed base, remain
caller responsibilities not yet wired into startup.

The resulting private-field `VerifiedFormatPolicy` permits exactly legacy V1
below the positive activation height and V2 at/above it, including `u64::MAX`.
Height zero, unknown versions, downgrades and wrong chain/genesis context are
rejected. Policy-checked signing still does not verify the epoch committee,
execution, finality-digest derivation, or authorize a post-genesis upgrade.

The policy proof input cap is 512 bytes, checked before BCS decode; the chain ID
uses the codec's 128-byte bound. `genesis_format_policy.hex` and the independent
JavaScript encoder freeze the proof fixture and its pin:
`dd4a5ea91fcaab9fa3f9282bd9c8ca8285d38ce4e3031346bd6e3c1d979ea5dd`.
The node test derives the base from actual temporary genesis initialization,
rejects base/activation mutations against that candidate pin, and checks every
stored row remains unchanged through verification and legacy genesis reopen.
It is not a migration or an end-to-end activation test.

This explicit version/domain contract follows the
[BCS specification](https://github.com/diem/bcs): canonical encoding is per type,
and application versioning and type-specific hash domains are not automatic.

Next implementation gate remains bootstrap/upgrade authorization and all caller
wiring above. No activation environment variable, runtime policy writer or live
genesis change has been introduced. The two legacy substitution witnesses remain
open until integration is completed; codec/policy tests cannot close that gate.

## In-memory envelope contract

`identity_v2::envelope` adds a proposed `SignedBlockV2` containing one canonical
identity, raw transaction/evidence byte lists, typed committed vertex digests, a
signer address and an Ed25519 signature. It has no unrestricted serde
deserializer; the bounded wire codec is described below. Incoming-byte/allocation
bounds and compatibility negotiation must be handled before materializing this
object, not inferred from its post-allocation validation.

`EnvelopeContext` requires the caller's trusted format policy, expected epoch,
height, parent and eligible address-to-Ed25519-key map. The caller must derive
positive-stake eligibility from the appropriate authenticated epoch committee,
not peer metadata or the current live set for a historical block. Both the
proposer/leader and the copy signer must be in that map with correct key/address
binding. Empty/missing authority is rejected. This preserves the existing
distinction between a deterministic proposer and the validator signing a copy;
the same identity can have signatures from different eligible validators.

Construction checks the content before signing. Authentication checks the
context, three recomputed body roots, a combined 16 MiB conservative framed body
budget, and a strict Ed25519 signature over the existing V2 signing domain.
Selected weak public keys are rejected. The per-list item and byte limits still
apply, but transaction and evidence lists cannot each consume a separate 16 MiB
budget in the same envelope. Empty lists must carry their computed roots, not
zero/omitted values. The authenticated result borrows the block immutably; it is
not a database snapshot, cached adoption permission, or an execution result.
The receiver checks context and the small identity signature before recomputing
large-body commitments; invalid signatures cannot force that hashing stage just
by naming a known validator. This is not a complete network resource budget.

Tests cover all fifteen identity fields, the exact legacy round/timestamp
resegmentation, body/list-order substitution with and without recomputed roots,
valid signatures over wrong epoch/parent/height/chain context, missing/inconsistent
committee keys, signer substitution, signature length/domain, weak proposer keys,
empty bodies and the exact aggregate byte boundary. A scope test demonstrates
that signed state/receipt/finality claims still need independent execution and
ordering/QC verification: a content authenticator must not claim to do that work.

`envelope_identity_v2.hex` and `envelope_signature_v2.hex` freeze a nonempty fixture
whose identity hash is
`c94897f19a1046839a356fe600bdf4c5e341ce45d6bbcdd21e740385a5a3eb23`.
The JavaScript reference manually encodes BCS and uses Node's crypto implementation
to independently derive/sign/verify the same fixed test seed as Rust/dalek. Its
test-only Ed25519 PKCS#8 wrapping follows [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html).
This is fixed-vector interoperability, not differential fuzzing or independent
security review.

No production Block, producer, sync, ordering, QC, genesis or RPC caller consumes
this type yet. G0 remains open. Next integration must bind these checks to the
same durable execution/parent/epoch snapshot and authenticated activation policy,
then exercise actual acceptance and recovery rather than only this in-memory API.

## Bounded wire codec (isolated, not activated)

`envelope/wire.rs` specifies BCS transport as the tuple
`(2u16, identity_bytes, signer[32], signature_bytes, (transactions, vertices, evidence))`.
`identity_bytes` contains the existing canonical V2 identity encoding, including
its own identity version. Both versions are mandatory; unknown versions and
noncanonical BCS lengths, trailing bytes and truncations are rejected. The
signature still authenticates the identity domain, not a new transport domain.
Body roots bind the transmitted lists. Eligible copy signers can differ, so wire
bytes need not be unique per block identity; they are canonical per envelope.

The slice-backed BCS 0.1.6 `from_bytes_seed` path supplies exact sequence lengths
and borrowed byte slices. Custom seeds reject counts over 10,000 before reserving
item vectors or requesting elements. Identity and signature slices are bounded
to 1,024 and 64 bytes before copying; the signature must be exactly 64 bytes.
Trusted context and strict header authentication precede all body decoding.
Payloads are bounded to 1 MiB per byte item before copying, sharing the existing
16 MiB conservative body budget across transactions, vertices and evidence.
The budget charges `7 + 5*count + payload_bytes` per byte list and
`7 + 32*count` for vertices. This intentionally matches the content contract,
not just the exact smaller wire framing. The raw input cap is that body budget
plus `2 + 5 + 1024 + 32 + 5 + 64` bytes of maximum header framing/content.

These bounds are not a 16 MiB process-memory promise: input storage, vector
metadata, temporary root encoding and output coexist. Network framing must
reject oversized requests before buffering them; queues, concurrency and rate
limits remain separate work. Invalid signatures cannot trigger body copying,
but eligible Byzantine signers can still consume the bounded per-request work.

`decode_wire` returns a mutable owned block after content authentication, not a
cached acceptance token. Consumers must reauthenticate parent/epoch/authority
in the eventual durable acceptance snapshot and verify execution, ordering and
QC separately. No production deserializer or activation rule is switched here.

Tests cover full canonical round trip, all truncations, trailing/unknown versions,
nonminimal ULEB lengths, maximum counts and one-over-limit counts, exact aggregate
budget and one byte over, body tampering, changed acceptance context, and header
rejection before a missing body. A sequence spy panics if an element is requested
before rejecting invalid count/framing budgets. A borrowed-slice check verifies
no payload copy is needed to enforce the item limit. `envelope_wire_v2.hex` is
checked against the independent JavaScript encoder as well as Rust.

## Admission snapshot prerequisite

While locating the V2 execution integration, the existing sync path reproduced a
separate check/use gap: author/key and parent validation ran before taking the
executor/storage writer locks. A controlled storage mutation in that interval
let the previously eligible author's block execute after revocation, or let a
child execute after its held parent was replaced. These are deterministic local
interleaving fixtures, not proof that a peer can arbitrarily mutate local storage.

`Executor::execute_block_admitted_at` now runs a supplied read-only admission
callback on the writer-gated pre-execution view, before entering the VM/execution
path. Its acceptance callback shares the same staged transaction. Legacy sync
uses it to re-read parent, current author/key and held QC before execution;
root-policy checks use the transaction view as well. Unlocked network checks
remain early rejection only. Existing `execute_block_checked_at` callers retain
their prior callback contract; they are not implicitly upgraded to authenticated
admission. The local producer still requires a separate context integration.

This prerequisite does NOT activate V2 or repair legacy hash ambiguity. It also
does not resolve legacy empty-set fallback, historical epoch authority, fork
choice, authenticated state recovery or a durable QC outbox. V2 must use a
trusted pinned policy and the correct epoch committee in this transaction,
not copy the legacy mutable-current-set rules into a new protocol.

Follow-on admission correction: legacy sync now uses a checked current-committee
loader. Missing/empty/corrupt records and duplicate addresses reject admission;
zero stake grants neither proposer nor copy-signer eligibility. A present but
invalid v1 record cannot fall back to a legacy mirror. This resolves that specific
sync empty-set fallback, not historical epoch authentication or the behavior of
other callers still using the compatibility getter. It does not activate V2.
