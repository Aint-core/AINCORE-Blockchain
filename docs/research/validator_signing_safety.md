# Validator signing safety: restored, rolled-back and cloned keys

> Research note for AINCORE, 2026-09-29. Read-only against worktree `g3-activation` (branch `g3/activation`, HEAD `2c7c4e4`).
> Nothing was modified, built, committed or run on a node. Every production claim below carries a primary-source URL (code, spec or vendor documentation).
> File:line citations were checked at `2c7c4e4`.

**For the founder, in one paragraph.** A validator can double-sign, and so lose 100% of its stake, if it forgets what it has already signed. It forgets when its database is restored from a backup, when it is copied to a second machine, or when it is rebuilt from a snapshot. Every chain that has run for years uses the same four defences:
1. Write down every signature on disk before sending it.
2. When moving a validator, carry that record with it.
3. On every start, look and listen before signing: "is my key already active somewhere?"
4. Keep one live copy of the key, and turn the old machine off before starting a new one.

AINCORE already has defence 1 in its new design. This note specifies 2 and 3 with concrete numbers, and turns 4 into written operating rules.

Two things change as a result:
- A restore from a backup, which the G1 contract today calls undetectable, becomes either detected at boot or provably harmless:
  - it is detected when the old copy signed within the last ≈ 5 minutes;
  - otherwise nothing it signed can still conflict.
- The recovery cost falls from "sit out the rest of the epoch" (up to about 100 minutes at the recommended epoch length) to about 70–80 seconds per restart.

---

## (a) DECISION table

| # | Rule | Value for AINCORE | Production precedent | Citation |
|---|---|---|---|---|
| D1 | A signature leaves the process only after its guard row is fsynced | Every vertex, attestation and FinalityVote, in the same transaction as the guard row (AT-2, PR-4, `qc_signing`); the V3 producer must be reordered (F1) | Ethereum honest-validator spec (record to disk, then broadcast); CometBFT FilePV (O_SYNC before returning the vote); Aptos SafetyRules (persist, then return the vote); GRANDPA (`prevoted` written before the message is queued) | [spec][eth-spec], [FilePV][cmt-file], [tempfile][cmt-tmp], [Aptos 2-chain][aptos-2c], [finality-grandpa][grandpa-vr] |
| D2 | Guard shape: exact per-slot rows, per-epoch high-water marks, and a monotone low-watermark floor | Proposals: strictly increasing per (key, epoch). Attestations: one row per (E, author, r) plus a floor. QC votes: one row per height and anchor round, plus a floor | EIP-3076 minimal format with a low watermark; Web3Signer low watermark; CometBFT height/round/step; Aptos `SafetyData{epoch, last_voted_round, ...}`; Sui `last_known_proposed_round` | [EIP-3076][eip3076], [Web3Signer changelog][w3s-cl], [FilePV][cmt-file], [SafetyData][aptos-sd], [Sui core][sui-core] |
| D3 | The guard's identity is bound to the key, not to the `--port` | `consensus:guard_origin{cg, ed25519_pk, bls_pk, instance_id}` plus a `{datadir}/node.key.guard` sidecar holding the same `instance_id`. A mismatch means amnesia mode | Aptos keeps the consensus key and the safety data in one file (`secure-data.json`); Solana `--require-tower` refuses to start without the tower | [validator.yaml][aptos-yaml], [agave args][agave-args], [agave validator.rs][agave-val] |
| D4 | Guard interchange for planned migrations | `aincore-signing-guard-interchange v1` JSON, shaped like EIP-3076, bound to `cg`, merged by max; exporting "sunsets" the source guard | EIP-3076; Prysm and Web3Signer import/export; Cosmos KMS migration rule (the new signer starts at or above the old one's high-water mark); Web3Signer `--set-high-watermark` | [EIP-3076][eip3076], [Prysm][prysm-sp], [Cosmos KMS][cosmos-kms], [Web3Signer changelog][w3s-cl] |
| D5 | QUERY (look back) on every boot | Ask all 3 other members for their copies of this key's signatures and for their certified frontier. Timeout 10 s, retried. Proceed on ≥ f+1 = 2 responders; the full floor needs all 3 | Sui `fetch_own_last_block` (f+1 stake, 5 s, retries); Prysm (network activity newer than the local watermark means refuse to start); CometBFT `double_sign_check_height`; Solana rebuilds the tower from on-chain votes | [Sui synchronizer][sui-sync], [Sui params][sui-params], [Prysm status.go][prysm-srv], [Prysm client][prysm-cli], [CometBFT state.go][cmt-state], [agave validator.rs][agave-val] |
| D6 | LISTEN (doppelganger) on every boot | 20 rounds of observed certified progress: 60 s at the 3 s tick, up to 180 s when rounds are slow. On a continuous guard only, a wall-clock cap of 180 s. Jitter of 0–5 rounds. A signed presence heartbeat throughout | Lighthouse 2–3 epochs (12.8–19.2 min); Teku ≤ 2 epochs; Nimbus 1–2 epochs; all of them re-run it on every start | [Lighthouse book][lh-dp], [Teku][teku-dp], [Nimbus][nimbus-dp], [Nimbus code][nimbus-code] |
| D7 | Detection and action | Any signature by this key at round > R0 + 3, a presence heartbeat from another instance, or equivocation evidence naming this key: halt, exit with a dedicated code, and never auto-restart | Lighthouse shuts the VC down and says not to restart; Nimbus exits with code 129; Teku exits with code 2 | [Lighthouse book][lh-dp], [Nimbus][nimbus-dp], [Teku][teku-dp] |
| D8 | Floor after amnesia | floor = max(local guard, own signatures returned by peers). If any member stayed silent, also ≥ R0 + 1 for own proposals and for that member's slots. Returned signatures become exact rows, so identical re-sends stay allowed | Sui `set_last_known_proposed_round`; EIP-3076 conditions 2 and 5; CometBFT same-HRS signature reuse | [Sui core][sui-core], [EIP-3076][eip3076], [FilePV][cmt-file] |
| D9 | Snapshot restore (G3 SN-6′) | Guard rows are never restored. Whatever the key, the node syncs to the QC-verified tip and runs the amnesia QUERY + LISTEN before its first signature. Membership is read at the tip, not at the checkpoint | Ethereum spec, "Recovered validator" (an empty slashing DB means import history first); Sui amnesia recovery after `rm -rf consensus_db` | [spec][eth-spec], [Sui validator-tasks][sui-tasks], [Sui synchronizer][sui-sync] |
| D10 | Backup restore | DB backups do not carry `node.key` by default. A restore stamps a `GUARD_RESTORED` marker, and the boot takes the amnesia path. The old machine is fenced first | Cosmos: stop, then copy the latest state, never two signers; Aptos: only one validator running at any time; Polkadot: never duplicate keystores | [Cosmos KMS][cosmos-kms], [Aptos upgrade][aptos-upg], [Polkadot offenses][dot-off] |
| D11 | Continuous monitoring and pause guard | While ARMED, any own-key signature not in the guard, or a foreign presence, halts the node. A process pause over 30 s (10 rounds) re-enters LISTEN | Lighthouse "lessons learned" (suspend/wake "time travel"); Ethereum spec, "far future" / long-gap refusal | [Hauner][lh-lessons], [spec][eth-spec] |
| D12 | What detection cannot cover is an operating rule | One live copy of `node.key`. Failover is fenced (power off, then `mv`, never `cp`). No hot standby holds the key. Never restore two validators at once | Every client above calls doppelganger best-effort and forbids redundant instances; incidents: Staked (75 validators slashed in 2021), Launchnodes (20 in 2023) | [Lighthouse book][lh-dp], [Nimbus][nimbus-dp], [tmkms][tmkms], [The Block][staked], [Lido][lido] |

Headline numbers: at the 3 s tick with n = 4, a routine restart stays silent for **≈ 70–80 s** (worst case ≈ 190 s), and the chance of missing a live clone that is running and connected is **≤ 1.3 × 10⁻¹²** (derived in section (c)).

---

## (b) Mechanism specification

### B.0 What is being protected

| Signed message | Key | Slot (conflict = two different bodies for one slot) | Guard today | Slashable today |
|---|---|---|---|---|
| DAG vertex | Ed25519 `node.key` | (E, r, author=self) | V3: `latest_proposed_round`, written **after** broadcast (`dag.rs:955-960`). V4: `vproposed` (PR-4, not implemented) | Yes, 100% (EQUIV_PROOF, `dag.rs:2528`) |
| Vertex attestation | BLS derived from `node.key` | (E, author, r) | `vattest`, via `vcert::attest_slot{,_in}` (`vcert.rs:437-474`, library only) | Evidence only (`ATTEST_EQUIV`); slashing is G5 |
| FinalityVote (QC vote) | BLS | height h, and anchor round | `consensus:qc_signing:v1:{chain}:{bls}:{height\|round}:{n}` (`qc_producer.rs:298-311, :333-335, :373-377`) | Evidence only |

**Why a single counter is wrong for a DAG.** CometBFT and Aptos can use one strictly increasing counter because each validator signs one thing per round, in order. In a DAG an honest attester legitimately signs author B's round r *after* author C's round r+1, because delivery order varies. So AINCORE keeps:
- exact per-slot rows as the runtime guard (as AT-2 already does);
- a strictly increasing high-water mark only for its **own proposals** and **QC votes**, which are naturally ordered;
- a floor that is raised only at discontinuities and at GC. Below the floor nothing new is signed unless an exact row already exists.

This is the EIP-3076 shape: recent messages plus a low watermark ([EIP-3076][eip3076]). Web3Signer ships it as "do not sign below the watermark" ([changelog][w3s-cl]).

### B.1 Guard rows (SG-1 … SG-4)

- **SG-1 (durable before release).** This is unchanged from G1 AT-2 and PR-4 and `qc_producer::with_durable_qc`. A signature is released only after the transaction holding its guard row commits through `StateDB::transaction` → `write_durable` (fsync, `common/storage/src/transaction.rs:316-318`). The V3 producer violates this today (F1).
- **SG-2 (high-water marks).** New row `consensus:sign_hwm:v1:{cg}:{ed25519_pk}:{E}` holding `{prop_hi, att_hi, qc_height_hi, qc_round_hi}`.
  - It is max-merged **in the same transaction** as every guard row.
  - It is never deleted by GC (GC-3 range deletes must skip it).
  - It is what export reads, and what QUERY compares against.
- **SG-3 (floor).** New row `consensus:sign_floor:v1:{cg}:{ed25519_pk}` holding `{epoch, prop_round, att_round, att_round_by_author{a: r}, qc_height}`.
  - A **new** signature at a slot at or below the floor is refused. The only exception is re-sending the byte-identical signed body from an existing exact row, which follows CometBFT's same-HRS rule ([FilePV][cmt-file]).
  - The floor only rises. It rises at three points:
    - (a) in the GC-3 deletion batch, to `g − RETAIN_SLACK`, so a deleted row can never be re-signed differently even if AT-1's `round > g` check is ever bypassed;
    - (b) at interchange import;
    - (c) at the end of an amnesia QUERY.
- **SG-4 (strict proposal monotonicity).** Propose at (E, r) only if r > `prop_hi[E]`. QC-vote at height h only if h > `qc_height_hi`, or if an exact row exists (a retry).

### B.2 Guard identity and continuity (SG-5)

- `consensus:guard_origin` (already in the G1 key table, `docs/G1_CONSENSUS_CONTRACT.md:297`) gains a random 128-bit `instance_id`, generated when a datadir's guard is first initialized. It is **never** copied by export, restore or snapshot.
- A sidecar file `{datadir}/node.key.guard` holds `{instance_id, cg, ed25519_pk}`. It is written with the same fsync-then-rename discipline as CometBFT's state file ([tempfile][cmt-tmp]).
  - Its purpose is to close the hazard the G1 status note already records (`docs/G1_CONSENSUS_CONTRACT.md:28`): `node.key` lives in the datadir, but the guard DB is `validator_{port}.db` (`core/node/src/main.rs:463`), so a port change silently starts an empty guard.
- **Continuity holds iff all of the following:**
  - the DB's `guard_origin` exists and equals the sidecar;
  - there is no `sys:restore_in_progress` or `sys:restored_by` newer than `guard_origin`;
  - there is no `GUARD_RESTORED` marker file;
  - QUERY found no own-key signature that the local guard lacks (B.4).

  Otherwise the boot is in **AMNESIA** mode.
- **Scope of the continuity check.**
  - It catches a wiped DB, a port change, a new datadir and a snapshot restore locally.
  - It cannot catch a restore of datadir, key and sidecar *together* from one backup: they match each other.
  - That case is caught by QUERY: peers hold signatures newer than the restored guard. This is what Prysm does against the beacon chain ([status.go][prysm-srv], [client][prysm-cli]).
  - ROTE's result is why only an external witness can see this: local sealed state cannot detect its own rollback, so rollback protection needs other machines ([ROTE][rote]).

### B.3 Guard interchange format (SG-6), for planned migrations

```json
{
  "format": "aincore-signing-guard-interchange",
  "version": 1,
  "chain_id": "AINCORE-…",
  "genesis_identity": "…",
  "cg": "hex(SHA256(put(chain_id) || put(genesis_identity)))",
  "exported_by_instance": "hex128",
  "exported_at_round": {"epoch": 7, "round": 1236},
  "keys": [{
    "address": "64-hex", "ed25519_pk": "…", "bls_pk": "…",
    "high_water": [{"epoch": 7, "prop_hi": 1234, "att_hi": 1235, "qc_height_hi": 612, "qc_round_hi": 1232}],
    "floor": {"epoch": 7, "prop_round": 1180, "att_round": 1180, "qc_height": 590},
    "proposals":    [{"epoch": 7, "round": 1234, "vertex": {"…full signed V4 vertex…"}}],
    "attestations": [{"attestation": {"…full signed VertexAttestation…"}}],
    "qc_votes":     [{"vote": {"…full signed QcVoteMessage…"}}]
  }]
}
```

**Export (node stopped).** Web3Signer similarly forbids pruning during import/export ([configure][w3s-conf]).
- **X-1.** Refuse to export if the DB `LOCK` is held.
- **X-2.** Include every exact row with round ≥ `g − RETAIN_SLACK`, plus the high-water marks and the floor.
- **X-3.** Write `consensus:guard_exported{instance_id, at}` to the **source** DB. The source then refuses to sign again until an explicit `guard reclaim`, which runs the amnesia boot. This is Web3Signer's `--set-high-watermark` idea: the old signer is sunset at a known point ([changelog][w3s-cl], [issue #696][w3s-696]).

**Import.** These rules follow EIP-3076 ([EIP-3076][eip3076]).
- **I-1.** Refuse if `cg` differs from the local `cg`. This is the analogue of `genesis_validators_root`.
- **I-2.** Verify every included signature under the file's keys. One failure rejects the whole file, so no unauthenticated row ever enters a guard.
- **I-3.** Merge by max: high-water marks become the max of local and file; the floor becomes max(local floor, file `high_water`). This is EIP-3076's instruction to take the maximum per validator on a minimal import.
- **I-4.** Insert the exact rows. If a file row conflicts with a local row for the same slot, refuse the import and raise `alarm:guard_import_conflict`: the two rows *are* an equivocation.
- **I-5.** Write a new `guard_origin.instance_id` and sidecar. The next boot still runs QUERY and LISTEN. Prysm notes that export/import protects more than waiting ([Prysm][prysm-sp]); Lighthouse still runs its doppelganger check after an import.

### B.4 Boot signing gate (SG-7): the state machine

```
BOOT → SYNC → QUERY → LISTEN → ARMED
         any state ──(evidence of another live instance)──► HALTED (exit 42, no auto-restart)
         ARMED ──(pause > 10 rounds, or > GC_DEPTH behind the frontier)──► QUERY
```

**SYNC.**
- No signing of any kind.
- The node imports blocks and QCs to the QC-verified tip (G1 IM-*, G3 SN-3).
- The committee C_{E_active} is read at the tip. This is what closes SN-6's "key became a validator after the checkpoint" gap.

**QUERY.** A new request/response pair `SIGNER_STATUS_REQ{cg, epoch, key}` / `SIGNER_STATUS_RESP`, served in `chain_sync::handle_message`. Each response carries four things, every one verified by the requester:
- the responder's highest-round staged vertex authored by `key` (full signed body);
- the attestations by `key` it holds for its own slots at rounds ≥ g (from `vcollect`, or as the signer bit in `vcert`);
- the highest QC with `key`'s bit set, plus any `QC_VOTE` from `key` it holds;
- its highest certified round, with the certificate, so it cannot be inflated.

How the requester handles the responses:
- Every item must verify under `key` (vertex Ed25519; attestation/vote BLS) or under C_E (certificates). Anything else is discarded.
- Signatures cannot be forged (SA-3), so a Byzantine responder can only **withhold**. It can never raise the floor above what this key really signed. That also defeats the spec's "far-future signing" lock-out ([spec][eth-spec]).
- Ask all 3 other members. Wait up to 10 s, retrying with backoff (Sui: 5 s, backoff ×1.5 capped at 4 s ([synchronizer][sui-sync])). Proceed once ≥ f+1 = 2 members have answered validly, which is Sui's `reached_validity` rule.
- **R0** := the maximum verified certified round over the local view and all responses.
- **Continuity test.** If any returned item is a slot the local guard lacks, or a proposal with round > local `prop_hi`, the guard is **discontinuous**. Write `alarm:guard_rollback{count, max_round}`. For a restore from backup this is the expected, now visible, outcome.
- **AMNESIA floor** (one durable transaction, before leaving QUERY):
  - import every returned item as an exact row, so identical re-sends stay allowed (RC-1 step 6: rebroadcast the exact own body);
  - `prop_floor = max(local prop_hi, max returned own-vertex round)`;
  - `att_floor[a] = max(local, max returned attestation round for a's slots)`;
  - `qc_floor = max(local qc_height_hi, highest QC with own bit, own QC_VOTEs, tip height)`;
  - **if not all 3 others answered:** `prop_floor ≥ R0 + 1`, and `att_floor[a] ≥ R0 + 1` for every silent member a;
  - write the new `guard_origin`, the sidecar and the high-water marks.
- In CONTINUOUS mode the local rows are authoritative. QUERY only confirms that nothing is newer.

**LISTEN.** Send presence heartbeats (B.5) and watch all gossip.
- **HALT** if any of these appears:
  - (i) a vertex, attestation (as a signer bit in a verified certificate, or directly) or QC vote signed by `key` whose (E, r) > (E0, R0 + 3);
  - (ii) a presence conflict;
  - (iii) an `EQUIV_PROOF` or `ATTEST_EQUIV` naming `key`.
- An own-key item at a round ≤ R0 + 3 that the guard lacks is a late copy of a dead instance's message. **Import it** and raise the floor; do not halt.
- **Completion:**

  | Mode | LISTEN ends when |
  |---|---|
  | CONTINUOUS | 20 rounds of certified progress past R0, **or** 180 s of wall clock with ≥ f+1 members connected (the stall case: the network is waiting for this node), plus uniform jitter of 0–5 rounds |
  | AMNESIA | 20 rounds of certified progress past R0, **or** 180 s only if all 3 others answered QUERY. Otherwise stay quiet |

  An explicit, logged operator override `--accept-amnesia-risk` exists for disaster recovery. It is Sui's documented trade-off: Sui's code comment says it will "prioritise liveness over the complete de-risking of block equivocation" ([params][sui-params]).

**ARMED.** Normal signing, subject to the rows (SG-1), the floor (SG-3) and monotonicity (SG-4), with continuous monitoring (B.6).

**HALTED.**
- Exit with a dedicated code (42 is proposed). The systemd unit sets `RestartPreventExitStatus=42`, so the node is not restarted automatically.
- Write `alarm:doppelganger{evidence}`.
- Lighthouse's instruction applies: do not restart until you are certain no other instance is running ([book][lh-dp]).

### B.5 Presence heartbeat (SG-8). An AINCORE extension, not copied from any chain

Why it is needed:
- A clone that is silent during LISTEN cannot be seen through signatures. Two instances started within one detection latency of each other both see silence, and both arm.
- libp2p gives no help: its identity is random on every boot (`core/node/src/p2p.rs:64`), so a clone does not show up as a duplicate peer ID.

The message:
- `SIGNER_PRESENCE{cg, ed25519_pk, instance_id, boot_round = R0 of this instance, obs_round, seq}`, signed with Ed25519 under the domain `AINCORE_SIGNER_PRESENCE_V1`.
- It is non-consensus: it is never slashable and never counts as equivocation evidence.
- It is gossiped every tick in QUERY, LISTEN and ARMED.

Conflict rule, applied at every receiver:
- Presence from instance X with `obs_round(X) > boot_round(Y) + 3`, where Y ≠ X is another instance of the same key, proves that X was alive after Y booted.
- A dead instance cannot sign a later `obs_round`, and replaying its old heartbeats cannot raise that field. The rule therefore cannot fire falsely.
- On a conflict, the receiver gossips `DOPPELGANGER_ALERT{p_X, p_Y}`. The alert is self-authenticating, and both instances halt on it.

Closest precedents: Web3Signer's shared-database lock ([concepts][w3s-sp]) and Horcrux's Raft election among cosigners ([Horcrux][horcrux]). Both put a coordinator in front of the key; here the other committee members act as distributed witnesses, as in ROTE ([ROTE][rote]).

### B.6 Continuous monitoring and pause guard (SG-9)

While ARMED:
- Any own-key signed item that the local guard did not produce means **HALT**. A single double-sign cannot be undone, but halting bounds the damage.
- A monotonic-clock gap of more than 30 s (10 rounds) between ticks, such as a VM suspend, SIGSTOP or a hung disk, means back to **QUERY**. This covers the suspend/wake "time-travel" hole that Lighthouse's lessons-learned note describes ([Hauner][lh-lessons]).
- So does falling more than `GC_DEPTH` (50 rounds) behind the certified frontier.

### B.7 Restore rules

**Snapshot restore: SN-6′, replacing G3 `SN-6` (`docs/G3_STATE_AUTHENTICATION_CONTRACT.md:366-370`) and `RC-4` (`:401-402`).**
1. A restore never writes `consensus:qc_signing:*`, `consensus:vattest:*`, `consensus:vproposed:*`, `consensus:sign_hwm:*`, `consensus:sign_floor:*` or `guard_origin` from any source. `cleared_by_restore` already keeps the local guards (`sync/src/state_sync.rs:698-708`); the new templates join that list.
2. After a restore, `guard_origin` is absent, so the first boot is in AMNESIA mode for **any** key.
   - SYNC runs to the QC-verified tip, then QUERY, then LISTEN.
   - This closes the documented gap for a key that became a validator after the checkpoint (`G3:856-870`): membership is read at the tip, and the gate runs whether or not the restored state records the key.
3. Keep today's refusals (`check_restored_signer`, `core/node/src/main.rs:289-305`; `restored_committee`, `sync/src/state_sync.rs:870-887`) as defence in depth until the S9 witnesses below are green. After that, the operator rule "restore with a fresh key" can relax to "any key; the gate applies".

**Backup restore: BK-1 … BK-5.**
- **BK-1.** `backup_node.sh` stops bundling `node.key` with the DB by default (today: `scripts/backup_node.sh:135-140`). The key is backed up once, encrypted, offline, as `docs/DR_RUNBOOK.md:22-35` already recommends.
- **BK-2.** `restore_node.sh` stops restoring `node.key` by default (today it restores it: `scripts/restore_node.sh:145-163`). It always drops a `GUARD_RESTORED` marker into the datadir.
- **BK-3.** A node that finds `GUARD_RESTORED`, or a missing or mismatched sidecar, boots in AMNESIA mode. The marker is removed only in the transaction that writes the new `guard_origin`.
- **BK-4.** Even without the marker, QUERY catches the rollback wherever it matters.
  - The old instance signed a vertex every round until it died, and at n = 4 each certified vertex is held by at least 2 other members (C.6).
  - Anything older than the retention window (≈ 100 rounds) can no longer conflict, because nothing is signed at or below g.
- **BK-5 (fencing, an operating rule).** Before the restore, the failed machine is powered off, or its disk or `node.key` removed (`mv`, never `rm`, per the repo's own practice). "The process stopped" is not enough. See the Cosmos rule to stop one signer fully before starting the other ([Cosmos KMS][cosmos-kms]).

### B.8 Contract text this replaces

- **G1 SA-4** (`docs/G1_CONSENSUS_CONTRACT.md:143-147`). Change "a restore from backup or a cloned key is undetectable" to: a guard loss that some responding member can witness is detected and repaired by SG-7. Only the cases in section (d) count toward β.
- **G1 RC-3** (`:702-705`). Change "abstain for the rest of the epoch" to "AMNESIA boot (SG-7)". At I ≥ 1000 blocks the old rule costs up to about 100 minutes with zero fault tolerance. When one other validator is also down it halts the chain for good, because the epoch cannot end without blocks.
- **G1 Open question 4** (`:882-884`). This note is the proposed answer.

---

## (c) The math

### C.1 Parameters

| Symbol | Value | Source |
|---|---|---|
| Tick τ | 3 s (default; ≥ 100 ms) | `core/node/src/main.rs:846-851` |
| Rounds per tick | ≤ 1 (PR-2 proposes at most once per tick) | G1 `:436-441` |
| Round time | 3 s healthy; up to 9 s with the leader wait `T_LEADER` = 2 ticks | G1 `:236`, PR-3 |
| n, f, quorum | 4, 1, 3 (equal stake at launch) | G1 SA-1, LA-2 |
| Blocks | ≤ 1 per 2 rounds (one per committed even anchor) | G1 DE |
| Epoch I | Today's pinned default is 20 blocks (`core/executor/src/lib.rs:1175`); G1 recommends ≥ 1000 | G1 `:231` |
| Message loss (stress) | 20% per-message omission, the tier-1 corpus level | `consensus/consensus/src/ordering.rs:2206` |
| Gossip duplicate cache | 60 s (identical bytes are not relayed twice) | `core/node/src/p2p.rs:119` |

### C.2 What production waits

| System | Duty period | Wait before signing | In time | Default |
|---|---|---|---|---|
| Lighthouse | 1 attestation per epoch (32 × 12 s = 6.4 min) | 2–3 epochs | 12.8–19.2 min | opt-in flag ([book][lh-dp]) |
| Teku | same | ≤ 2 epochs | ≤ 12.8 min | off ([Teku][teku-dp]) |
| Nimbus | same | ready once the previous epoch was monitored (`doppelCheck + 1 == epoch`) | about 1–2 epochs (≈ 6–13 min) | on ([doc][nimbus-dp], [code][nimbus-code]) |
| Prysm | same | look-back: participation flags in the head state and in the state one epoch earlier (≈ the last 2–3 epochs); skipped when the local watermark + 2 ≥ the current epoch | ≈ 0 s, but refuses to start while old activity is recent | opt-in ([status.go][prysm-srv]) |
| CometBFT | 1 precommit per block | look back `double_sign_check_height` blocks; panic if its own signature is found | N blocks | 0, meaning off ([toml.go][cmt-toml], [state.go][cmt-state]) |
| Sui | 1 block per round | ask peers for its own last block, needing f+1 stake | 5 s timeout, retried | on ([params][sui-params], [sync][sui-sync]) |
| Solana | votes | refuses to start without the tower if the vote account has votes (`--require-tower`); otherwise rebuilds from on-chain votes | — | flag ([args][agave-args], [validator.rs][agave-val]) |

Why Ethereum waits two epochs, from the Lighthouse FAQ ([book][lh-dp]):
- (1) it skips the current epoch, to avoid a false positive from its own restart;
- (2) a validator may not attest until the end of the next epoch.

That is 2 duty periods plus 1 of slack. AINCORE derives the same way below, but its duty period is 1 round (3 s), not 6.4 minutes.

### C.3 Deriving W (the LISTEN length)

**Minimum.** A live, synced clone produces at least one own vertex per round, plus signer bits in certificates. The floor on W is:

W_min = M (margin above R0, so a dead instance's late messages are ignored) + 1 (the clone's next round) + 2 (a leader wait of up to `T_LEADER` = 2 ticks) = 3 + 1 + 2 = **6 rounds (18 s)**.

**Loss term.** Take the conservative model: only the clone's own vertex counts, and it is missed independently with p = 0.2 per round. The chance of missing a live clone over the rounds that count (W − M) is:

| W (rounds) | Counting rounds W − M | P(miss) = 0.2^(W−M) | At τ = 3 s |
|---|---|---|---|
| 6 | 3 | 8.0 × 10⁻³ | 18 s |
| 10 | 7 | 1.3 × 10⁻⁵ | 30 s |
| **20** | **17** | **1.3 × 10⁻¹²** | **60 s** |

Counting the clone's certificate bits as well (≥ 2 artifacts per round, miss 0.04 per round), W = 20 gives ≈ 10⁻²⁴. Loss is therefore not the binding constraint.

**Choice: W = 20 rounds**, about 3 × W_min. The margin covers a clone that is lagging, for example still catching up or itself in a leader wait, for up to about 10 rounds, while keeping the loss term negligible.

**In seconds:**

| Case | Rounds | Time |
|---|---|---|
| Healthy | 20 × 3 s | **60 s** |
| Degraded (every round has a full leader wait) | 20 × 9 s | 180 s |
| Stall, CONTINUOUS guard | wall-clock cap | 180 s |
| Plus QUERY | — | ≤ 10 s |
| Plus jitter | 0–5 rounds | 0–15 s (mean 7.5 s) |

Expected silence per routine restart: 10 + 60 + 7.5 ≈ **78 s**. Worst case ≈ 10 + 180 + 15 = **205 s**.

### C.4 False positives (halting when there is no other instance)

- **By construction ≈ 0.** A halt needs one of:
  - (i) an own-key signature at round > R0 + 3; or
  - (ii) a presence with `obs_round > boot_round(other) + 3`.

  A dead instance's last signature is at round ≤ R_death + 1 ≤ R0 + 2, given that R0 is within 1 round of the true frontier after SYNC and QUERY (LA-1). Its presence heartbeats cannot claim an `obs_round` it never reached. Byzantine peers can only replay; signatures cannot be forged (SA-3).
- **Late copies are not halts.** Old messages from a dead instance (re-gossip, retries, or a peer's `VERTEX_RESP`) have round ≤ R0 + 3. They are imported and raise the floor.
- **The remaining "false" trigger is a true one.** It is an old instance that is actually still alive. That is exactly the case a halt exists for.
- **The real cost is the silence, not false alarms.** At n = 4, a node in LISTEN counts as one node down. Assume 2 upgrade restarts per validator per month: 96 restarts a year × 78 s ≈ **2.1 h/year** of zero-slack windows. The chain keeps running during them unless a second node is down at the same time.
- **Against the current RC-3** (which applies to discontinuities only):
  - "rest of the epoch" is up to 2·I rounds: 40 rounds (2 min) at today's I = 20, but ≥ 2000 rounds (**≥ 100 min**) at I = 1000;
  - in a stall, where one other node is down, RC-3 never ends, because the epoch needs blocks;
  - the AMNESIA gate costs about 78 s when the network is progressing, or stays quiet only until all members answer.

### C.5 False negatives (a live clone is missed)

| Cause | Probability or condition | Mitigation |
|---|---|---|
| Message loss, clone live and connected | ≤ 1.3 × 10⁻¹² (C.3) | — |
| Two instances start together (e.g., both machines power up after an outage), **without** presence | 1 − (1 − d/J)² for detection latency d and jitter span J (d = 1 round): J = 5 → 36%; J = 20 → 9.8%; J = 60 → 3.3% | This is why jitter alone is not enough |
| The same, **with** presence (B.5) | Detected about M + 1 = 4 rounds (12 s) after both connect to one common honest peer. That is < W = 20, so both halt before arming; the residual is ≈ 0.2^(W−4) ≈ 6.6 × 10⁻¹² | presence heartbeat |
| Clone is suspended, powered off or partitioned during LISTEN and signs later | Not detectable by any listen-based scheme: a silent process cannot be told apart from an absent one (Chandra–Toueg [CT96][ct96]) | Section (d), rules O-1 to O-3; continuous monitoring halts at the first sighting |
| A selective network partition hides the clone from this node only | Requires an adversarial network | Out of model |

### C.6 How many QUERY responders are enough (n = 4, f = 1, equal stake)

- **Own certified vertex.** It carries at least 3 attestations, and PR-4 self-attests, so at least 2 *other* members A hold it durably (in `vattest` and `vslot`). For responders R among the 3 others:
  - |R| = 2 gives |R ∩ A| ≥ 1. The vertex is found unless that single holder is Byzantine and withholds it. This is Sui's f+1 rule.
  - |R| = 3 gives |R ∩ A| ≥ 2, so at least one honest holder: always found.
- **Own uncertified vertex**, one that reached only some peers. There is no intersection guarantee. It is covered by `prop_floor ≥ R0 + 1` whenever |R| < 3.
  - In a stall this can cost liveness. That is deliberate. The codebase's own rule, at `consensus/consensus/src/dag.rs:490-495`, is that stalling is never slashed and a reused round is. The alternative is a 100% slash from a proof held by an honest node that was merely offline during QUERY.
- **Own attestation for author a's slot.** The authoritative holder is a itself (`vcollect`), or a's certificate. Silent authors get `att_floor[a] ≥ R0 + 1`.
- **QC votes.** After SYNC every height ≤ tip already has a QC, so `qc_floor ≥ tip` costs nothing.
- **Retention bounds what QUERY has to find.**
  - Peers keep guard, slot and certificate rows only above `g − RETAIN_SLACK`, about GC_DEPTH + RETAIN_SLACK = 100 rounds below the frontier (≈ 5 min at 3 s) (G1 GC-1, GC-3).
  - Older signatures of a dead instance cannot conflict with anything new: nothing is attested or proposed at round ≤ g (AT-1, PR-1), and `qc_floor ≥ tip`.
  - So the dangerous window is exactly "restore or restart within about 5 minutes of the old instance's last signature". That is the window QUERY covers.
  - A DB backup taken on the runbook's 6–12 h cadence (`docs/DR_RUNBOOK.md:31-36`) is thousands of rounds stale, far below g. QUERY then only raises `alarm:guard_rollback` from the synced chain (QC bitmaps and committed vertices); safety comes from the g floor.
- **Residual.** A Byzantine member that withholds this key's signatures and later publishes them. Together with an amnesiac validator that is **2 faults** (> f), so it is beyond the fault bound by definition. It is covered by rule O-4 below.

---

## (d) What stays undetectable, and the operating rules

The research consensus:
- Casper FFG's accountable safety says that any safety failure implicates ≥ 1/3 of stake through evidence ([Buterin & Griffith][casper]).
- BFT protocol forensics identifies culprits from that evidence, but does not ask why they signed ([Sheng et al.][forensics]).
- Twins models "loss of internal state" as a Byzantine behaviour, by running two copies of one identity ([Bano et al.][twins]).

So the protocol cannot tell a malicious equivocator from an honest node that forgot. The evidence is identical and the slash is 100%. Protection has to be local and operational.

**What remains undetectable (U) or unrecoverable:**
- **U-1: a copy of the key that is not running during LISTEN** (powered off, suspended, or partitioned) and signs later: a standby started by a script, a VM snapshot resumed, or a machine reconnected after a network cut. No listen-based scheme can see a silent process ([CT96][ct96]). Continuous monitoring (SG-9) halts both copies at the first sighting, but the first conflicting signature may already exist.
- **U-2: a copy running old software without the gate**, or with it disabled.
- **U-3: signatures held only by a Byzantine or non-responding member.** A 2-fault case (C.6).
- **U-4: a double-sign that already happened.** It cannot be undone; detection only bounds how long it continues.
- **U-5 (limit on detection, not a new hole): an outage of the fsync guarantee itself.** A disk or controller that acknowledges fsync without persisting it, which is a risk on the NAS's spinning disk if a write cache is on. This is covered by SA-4 plus hardware configuration. Note that Solana does **not** fsync its tower (the code says `sync_all()` hurts performance, [tower_storage.rs][agave-tower]). AINCORE should not copy that.

**Operating rules (O), written for the founder:**
- **O-1: exactly one live copy of `node.key`.** The only other copy is an encrypted offline backup, per `docs/DR_RUNBOOK.md:22-35`. No hot or warm standby holds the key. Every client above calls doppelganger protection best-effort and forbids redundant instances ([Lighthouse][lh-dp], [Nimbus][nimbus-dp], [tmkms][tmkms]). Polkadot names duplicated keys as the leading cause of accidental equivocation ([Polkadot][dot-off]).
- **O-2: fenced failover, in this order.**
  1. Power off the old machine, or pull its network cable or disk, and confirm it physically.
  2. Move the key (`mv`, never `cp`).
  3. Start the new machine. The gate runs by itself.

  "systemctl stop succeeded" is not fencing. Aptos and Cosmos both require the old signer to be fully stopped first ([Aptos][aptos-upg], [Cosmos][cosmos-kms]).
- **O-3: no auto-start on a machine that is not the key's current home.** A spare machine's systemd unit stays disabled. After a power outage exactly one machine per key may come back as a validator. This is the simultaneous-start case in C.5.
- **O-4: never restore or migrate two validators at the same time.** A node in AMNESIA counts as the one allowed fault until it is ARMED.
- **O-5: a HALTED doppelganger is an incident, not a glitch.** Do not restart the node, and never use `--accept-amnesia-risk` for it. Find the other copy first. This is Lighthouse's instruction ([book][lh-dp]).
- **O-6: planned moves use export/import (B.3), not backup/restore.** Backups are for disasters, and a restore always takes the AMNESIA path.
- **O-7: never "fix" a node by deleting its database while it holds a validator key.** The FATAL message at `core/node/src/main.rs:491` currently suggests `rm -rf` on the DB (F4). CometBFT labels the equivalent reset "unsafe" ([reset.go][cmt-reset]).

**Why this matters in practice.** In 2021, 75 validators at Staked were slashed after the client's slashing protection was disabled and nodes restarted in error ([The Block][staked]). In 2023, 20 Launchnodes/Lido validators were slashed during an unplanned fallback between signers ([Lido post-mortem][lido]). Both are operator-path failures of the kind O-1 to O-6 target. The accounts come from secondary and post-mortem sources and were not independently re-verified here.

---

## (e) Code touchpoints (no edits made)

### E.1 Hazards in the current tree found while reading

| # | Where | What | Severity for signing safety |
|---|---|---|---|
| F1 | `consensus/consensus/src/dag.rs:944` (sign), `:954-955` (add and broadcast), `:957-960` (`latest_proposed_round` put, result ignored with `let _ =`) | The V3 live producer persists its proposal guard **after** broadcasting. A crash in between means the next boot can propose the same round again, which is a slashable twin. G1 PR-4 fixes this for V4 only. `latest_proposed_round` also stores the *current* round (`:1466-1468`, `:3157-3159`), not "proposed", so it is not a true high-water mark | High while V3 is live |
| F2 | `scripts/backup_node.sh:135-140`, `scripts/restore_node.sh:145-163`, `docs/DR_RUNBOOK.md:97-112` | The DR path packs `node.key` together with the DB, restores both by default, and documents "restore the SAME validator … ChainSyncs only the small delta". That is exactly the rolled-back guard with a live key. Nothing at boot detects it: `check_restored_signer` (`core/node/src/main.rs:289-305`) only sees G3 checkpoint restores (`sys:restored_by`) | High |
| F3 | `core/node/src/main.rs:463` | The DB path is per port, while `node.key` is per datadir. A port change starts an empty `qc_signing` guard (already noted at G1 `:28`) | Medium |
| F4 | `core/node/src/main.rs:491` | The FATAL help text suggests `rm -rf {db_path}` | Medium (operator trap) |
| F5 | `core/node/src/p2p.rs:64` | The libp2p identity is random on every boot, so there is no duplicate-peer signal. Presence must be explicit (B.5) | Informational |
| F6 | `consensus/consensus/src/dag.rs:2172-2181` | For a received vertex whose author is this node, the key check uses the local key and accepts it. This is the natural hook for SG-9: an own-author vertex not in the local guard means a doppelganger | Hook point |

### E.2 Where each rule lives

| Rule | File:line | Change (described, not made) |
|---|---|---|
| SG-1 durable before release (V4) | `consensus/consensus/src/vcert.rs:370-427` (`stage_attestation`, put at `:420-421`), `:437-474` (`attest_slot_in`, `attest_slot`); `consensus/consensus/src/qc_producer.rs:207-232` (`with_durable_qc`), `:333-335` (guard puts) | Already correct. Add the SG-2 high-water max-merge to the same staged view |
| SG-1 (V3 fix) | `consensus/consensus/src/dag.rs:944-960` | Write a per-round proposal row durably, before `add_vertex` and `broadcast_vertex`. Treat a write error as "do not broadcast" |
| SG-2 high-water marks / SG-3 floor / SG-4 monotonicity | New templates in the G1 key table (`docs/G1_CONSENSUS_CONTRACT.md:280-301`); checks in `vcert.rs:331-367` (`prepare`) and before `:410` (the new-signature branch); `qc_producer.rs:298-331` (before `sign_raw`); PR-4's proposal transaction (G1 `:447-455`) | Refuse at or below the floor unless the exact row exists; max-merge the high-water marks |
| Floor rises at GC | G1 GC-3 (`docs/G1_CONSENSUS_CONTRACT.md:664-667`) | Put `sign_floor ≥ g − RETAIN_SLACK` in the same deletion batch; the high-water and floor rows are exempt from range deletes |
| Key classes | `common/storage/src/class.rs:283` (`qc_signing` is Local), `:174` | Classify the new `sign_hwm`, `sign_floor` and `guard_origin` templates as Local |
| Never restored | `sync/src/state_sync.rs:698-708` (`cleared_by_restore`) | Keep the new templates along with `qc_signing`, `vattest` and `latest_proposed_round` |
| SG-5 guard identity and sidecar | `core/node/src/main.rs:367-445` (key load), `:463` (DB path), `:482-495` (open); G1 `guard_origin` (`:297`), RC-3 (`:702-705`) | Read and write `node.key.guard`; compare it with `guard_origin`; decide CONTINUOUS or AMNESIA before `DagConsensus::new` (`dag.rs:138`) |
| SG-6 interchange | New `guard export` / `guard import` subcommands (the node binary, or `core/cli`) | EIP-3076 rules I-1 to I-5 and X-1 to X-3 |
| SG-7 boot gate | `core/node/src/main.rs:787-790` (after `check_restored_signer`), consensus loop `:885-900`; `dag.rs:708` (`try_create_vertex` entry); G1 PR-2 "guard continuity holds" (`:436-441`), AT-1 (`:369-378`) | A `SigningGate` state shared by the producer, the attester and the QC producer; nothing signs unless ARMED |
| QUERY protocol | `chain_sync::handle_message` in `sync/src/lib.rs` (per repo practice, serving-side sync logic lives there); G1 wire table (`docs/G1_CONSENSUS_CONTRACT.md:268-280`) | New `SIGNER_STATUS_REQ/RESP` over `secure_connect`; budget it like `CERT_REQ` |
| LISTEN / SG-9 monitoring | `dag.rs:2705-2735` (`handle_message`: `DAG_VERTEX`, `QC_VOTE`, `EQUIV_PROOF`), `:1152` (`add_vertex`), `:2172-2181` (own-author branch), `:2655` (`handle_remote_qc_vote`); the V4 certificate ingest (G1 CE-3) | Any own-key item not in the guard: import it if at or below R0 + 3, halt otherwise |
| SG-8 presence | New `SIGNER_PRESENCE:` / `DOPPELGANGER_ALERT:` prefixes in `dag.rs:2705` `handle_message`; gossip via `core/node/src/p2p.rs` | Non-consensus domain; never slashable |
| Pause guard | Consensus loop `core/node/src/main.rs:885-900` | A monotonic gap over 30 s sends the gate back to QUERY |
| HALTED exit | Any gate transition; systemd unit (not in the repo; lives on the hosts) | Exit code 42; `RestartPreventExitStatus=42` |
| SN-6′ (snapshot) | `core/node/src/main.rs:705-721` (restore before genesis), `:289-305`; `sync/src/state_sync.rs:870-906`; G3 `:366-370`, `:401-402`, `:856-870` | After a restore: AMNESIA mode for any key; keep the existing refusals until the witnesses are green |
| BK-1 to BK-5 (backup) | `scripts/backup_node.sh:135-140`; `scripts/restore_node.sh:19-24`, `:145-163`; `docs/DR_RUNBOOK.md:97-112` | Separate the key from DB backups; add a `GUARD_RESTORED` marker; rewrite the runbook's "restore the SAME validator" section as the fenced procedure in O-2 |
| Contract text | G1 SA-4 `:143-147`, RC-3 `:702-705`, open question 4 `:882-884`, S9 row (k) `:862` | Replace per B.8; extend witness (k) as below |

### E.3 Witnesses that would prove it

Proposed extensions of G1 S9 (k). Each needs a mutation that is observed to turn red.

| Witness | Scenario | Pass condition | Mutation that must turn it red |
|---|---|---|---|
| k1 | Wiped guard under a live key | QUERY imports rows; resumes after W; never signs a conflicting slot | Skip QUERY |
| k2 | Backup restore after the old instance signed 100 more rounds | `alarm:guard_rollback` is written; floor ≥ those rounds | Treat a matching sidecar as proof of continuity |
| k3 | A live clone is started | Both instances halt; no conflicting signature leaves either process | Halt criterion without M |
| k4 | Two instances start within 1 round | Presence conflict halts both before ARMED | Drop presence |
| k5 | Stall: the network needs this node and one other node is down | CONTINUOUS resumes after 180 s; AMNESIA stays quiet unless all members answered | — |
| k6 | A Byzantine responder replays old items and sends forged ones | Floor rises; no halt; forged items rejected | Criterion at R0 + 0 (the false positive must show red) |
| k7 | SIGSTOP for 60 s, then SIGCONT | Re-quarantine | No pause guard |
| k8 | `--port` change | AMNESIA path | No sidecar |

---

## Sources

**Ethereum**
- [eth-spec]: Ethereum consensus-specs, phase0 honest validator, "How to avoid slashing" and "Protection best practices": https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing
- [eip3076]: EIP-3076, Slashing Protection Interchange Format: https://eips.ethereum.org/EIPS/eip-3076
- [lh-dp]: Lighthouse Book, Doppelganger Protection: https://lighthouse-book.sigmaprime.io/validator-doppelganger.html (source: https://github.com/sigp/lighthouse/blob/stable/book/src/validator_doppelganger.md)
- [lh-lessons]: P. Hauner, "Doppelganger Detection: Lessons Learned": https://hackmd.io/Szjk_d1gTrWGuUsLojmoqA
- [teku-dp]: Teku, Detect doppelgangers: https://docs.teku.consensys.io/how-to/prevent-slashing/detect-doppelgangers
- [nimbus-dp]: Nimbus guide, Doppelganger detection: https://nimbus.guide/doppelganger-detection.html
- [nimbus-code]: `validator_pool.nim` (`doppelgangerReady`): https://github.com/status-im/nimbus-eth2/blob/stable/beacon_chain/validators/validator_pool.nim
- [prysm-sp]: Prysm, Import and export slashing protection history: https://prysm.offchainlabs.com/docs/backup-and-migration/slashing-protection/
- Prysm flag reference: https://prysm.offchainlabs.com/docs/prysm-usage/parameters
- [prysm-srv]: Prysm beacon-side `CheckDoppelGanger`: https://github.com/OffchainLabs/prysm/blob/develop/beacon-chain/rpc/prysm/v1alpha1/validator/status.go
- [prysm-cli]: Prysm validator-side watermark request: https://github.com/OffchainLabs/prysm/blob/develop/validator/client/doppelganger.go
- [w3s-sp]: Web3Signer, Slashing protection: https://docs.web3signer.consensys.io/concepts/slashing-protection
- [w3s-conf]: Web3Signer, Configure slashing protection: https://docs.web3signer.consensys.io/how-to/configure-slashing-protection
- [w3s-cl]: Web3Signer CHANGELOG (low watermark; "do not sign below watermark"; high watermark): https://github.com/Consensys/web3signer/blob/master/CHANGELOG.md
- [w3s-696]: Web3Signer, high-watermark feature request: https://github.com/Consensys/web3signer/issues/696

**CometBFT and Cosmos**
- [cmt-file]: CometBFT `privval/file.go` (`CheckHRS`, `signVote`, `saveSigned`): https://github.com/cometbft/cometbft/blob/v0.38.x/privval/file.go
- [cmt-tmp]: CometBFT `libs/tempfile/tempfile.go` (O_SYNC, then rename): https://github.com/cometbft/cometbft/blob/v0.38.x/libs/tempfile/tempfile.go
- [cmt-toml]: CometBFT `config/toml.go` (`double_sign_check_height`): https://github.com/cometbft/cometbft/blob/v0.38.x/config/toml.go
- [cmt-state]: CometBFT `consensus/state.go` (`checkDoubleSigningRisk`): https://github.com/cometbft/cometbft/blob/v0.38.x/consensus/state.go
- [cmt-reset]: CometBFT `unsafe-reset-priv-validator`: https://github.com/cometbft/cometbft/blob/v0.38.x/cmd/cometbft/commands/reset.go
- [cosmos-kms]: Cosmos docs, Migrate from TMKMS: https://docs.cosmos.network/sdk/latest/kms/migrate-from-tmkms
- [tmkms]: iqlusion tmkms: https://github.com/iqlusioninc/tmkms
- [horcrux]: Strangelove Horcrux: https://github.com/strangelove-ventures/horcrux

**Aptos**
- [aptos-sd]: `SafetyData`: https://github.com/aptos-labs/aptos-core/blob/main/consensus/consensus-types/src/safety_data.rs
- [aptos-2c]: `safety_rules_2chain.rs` (sign, `set_safety_data`, return): https://github.com/aptos-labs/aptos-core/blob/main/consensus/safety-rules/src/safety_rules_2chain.rs
- Epoch reset: https://github.com/aptos-labs/aptos-core/blob/main/consensus/safety-rules/src/safety_rules.rs
- Storage syncs before returning: https://github.com/aptos-labs/aptos-core/blob/main/consensus/safety-rules/src/persistent_safety_storage.rs
- [aptos-yaml]: validator config (`secure-data.json`): https://github.com/aptos-labs/aptos-core/blob/main/docker/compose/aptos-node/validator.yaml
- [aptos-upg]: Aptos, Upgrade Nodes (copy `consensus_db` + `secure-data.json`; one validator at a time): https://aptos.dev/network/nodes/validator-node/modify-nodes/update-validator-node

**Sui**
- [sui-params]: Sui consensus `parameters.rs` (`sync_last_known_own_block_timeout`, 5 s): https://github.com/MystenLabs/sui/blob/main/consensus/config/src/parameters.rs
- [sui-sync]: Sui `synchronizer.rs` (`start_fetch_own_last_block_task`, f+1): https://github.com/MystenLabs/sui/blob/main/consensus/core/src/synchronizer.rs
- [sui-core]: Sui `core.rs` (`set_last_known_proposed_round`): https://github.com/MystenLabs/sui/blob/main/consensus/core/src/core.rs
- Enabled at `boot_counter == 0`: https://github.com/MystenLabs/sui/blob/main/consensus/core/src/authority_node.rs
- [sui-tasks]: Sui validator tasks (deleting `consensus_db`): https://github.com/MystenLabs/sui/blob/main/docs/content/operators/validator/validator-tasks.mdx
- Sui failover discussion (sit out the epoch): https://github.com/MystenLabs/sui/issues/17522

**Solana / Agave**
- [agave-args]: `--require-tower`: https://github.com/anza-xyz/agave/blob/master/validator/src/commands/run/args.rs
- [agave-val]: `post_process_restored_tower`: https://github.com/anza-xyz/agave/blob/master/core/src/validator.rs
- [agave-tower]: `tower_storage.rs` (no fsync): https://github.com/anza-xyz/agave/blob/master/core/src/consensus/tower_storage.rs
- Agave failover guide: https://docs.anza.xyz/operations/guides/validator-failover

**Polkadot**
- [dot-off]: Polkadot, Offenses and Slashes (equivocation, min((3x/n)², 1), duplicate keys): https://docs.polkadot.com/node-infrastructure/run-a-validator/staking-mechanics/offenses-and-slashes/
- [grandpa-vr]: finality-grandpa `voting_round.rs` (`env.prevoted` before `outgoing.push`): https://github.com/paritytech/finality-grandpa/blob/master/src/voter/voting_round.rs
- Substrate `environment.rs` (`write_voter_set_state`): https://github.com/paritytech/polkadot-sdk/blob/master/substrate/client/consensus/grandpa/src/environment.rs

**Research**
- [casper]: V. Buterin, V. Griffith, "Casper the Friendly Finality Gadget", 2017 (Theorem 1, Accountable Safety): https://arxiv.org/abs/1710.09437
- [forensics]: P. Sheng, G. Wang, K. Nayak, S. Kannan, P. Viswanath, "BFT Protocol Forensics", ACM CCS 2021: https://arxiv.org/abs/2010.06785
- [twins]: S. Bano et al., "Twins: BFT Systems Made Robust": https://arxiv.org/abs/2004.10617
- [rote]: S. Matetic et al., "ROTE: Rollback Protection for Trusted Execution", USENIX Security 2017: https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic
- M. Aguilera, W. Chen, S. Toueg, "Failure detection and consensus in the crash-recovery model", Distributed Computing 13 (2000): https://link.springer.com/article/10.1007/s004460050070
- [ct96]: T. Chandra, S. Toueg, "Unreliable failure detectors for reliable distributed systems", JACM 43(2), 1996: https://dl.acm.org/doi/10.1145/226643.226647

**Incidents**
- [staked]: The Block, 75 validators slashed (Staked): https://www.theblock.co/post/93730/eth2-validators-slashed-staked-bug
- [lido]: Lido, Launchnodes slashing post-mortem: https://blog.lido.fi/post-mortem-launchnodes-slashing-incident/

[eth-spec]: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing
[eip3076]: https://eips.ethereum.org/EIPS/eip-3076
[lh-dp]: https://lighthouse-book.sigmaprime.io/validator-doppelganger.html
[lh-lessons]: https://hackmd.io/Szjk_d1gTrWGuUsLojmoqA
[teku-dp]: https://docs.teku.consensys.io/how-to/prevent-slashing/detect-doppelgangers
[nimbus-dp]: https://nimbus.guide/doppelganger-detection.html
[nimbus-code]: https://github.com/status-im/nimbus-eth2/blob/stable/beacon_chain/validators/validator_pool.nim
[prysm-sp]: https://prysm.offchainlabs.com/docs/backup-and-migration/slashing-protection/
[prysm-srv]: https://github.com/OffchainLabs/prysm/blob/develop/beacon-chain/rpc/prysm/v1alpha1/validator/status.go
[prysm-cli]: https://github.com/OffchainLabs/prysm/blob/develop/validator/client/doppelganger.go
[w3s-sp]: https://docs.web3signer.consensys.io/concepts/slashing-protection
[w3s-conf]: https://docs.web3signer.consensys.io/how-to/configure-slashing-protection
[w3s-cl]: https://github.com/Consensys/web3signer/blob/master/CHANGELOG.md
[w3s-696]: https://github.com/Consensys/web3signer/issues/696
[cmt-file]: https://github.com/cometbft/cometbft/blob/v0.38.x/privval/file.go
[cmt-tmp]: https://github.com/cometbft/cometbft/blob/v0.38.x/libs/tempfile/tempfile.go
[cmt-toml]: https://github.com/cometbft/cometbft/blob/v0.38.x/config/toml.go
[cmt-state]: https://github.com/cometbft/cometbft/blob/v0.38.x/consensus/state.go
[cmt-reset]: https://github.com/cometbft/cometbft/blob/v0.38.x/cmd/cometbft/commands/reset.go
[cosmos-kms]: https://docs.cosmos.network/sdk/latest/kms/migrate-from-tmkms
[tmkms]: https://github.com/iqlusioninc/tmkms
[horcrux]: https://github.com/strangelove-ventures/horcrux
[aptos-sd]: https://github.com/aptos-labs/aptos-core/blob/main/consensus/consensus-types/src/safety_data.rs
[aptos-2c]: https://github.com/aptos-labs/aptos-core/blob/main/consensus/safety-rules/src/safety_rules_2chain.rs
[aptos-yaml]: https://github.com/aptos-labs/aptos-core/blob/main/docker/compose/aptos-node/validator.yaml
[aptos-upg]: https://aptos.dev/network/nodes/validator-node/modify-nodes/update-validator-node
[sui-params]: https://github.com/MystenLabs/sui/blob/main/consensus/config/src/parameters.rs
[sui-sync]: https://github.com/MystenLabs/sui/blob/main/consensus/core/src/synchronizer.rs
[sui-core]: https://github.com/MystenLabs/sui/blob/main/consensus/core/src/core.rs
[sui-tasks]: https://github.com/MystenLabs/sui/blob/main/docs/content/operators/validator/validator-tasks.mdx
[agave-args]: https://github.com/anza-xyz/agave/blob/master/validator/src/commands/run/args.rs
[agave-val]: https://github.com/anza-xyz/agave/blob/master/core/src/validator.rs
[agave-tower]: https://github.com/anza-xyz/agave/blob/master/core/src/consensus/tower_storage.rs
[dot-off]: https://docs.polkadot.com/node-infrastructure/run-a-validator/staking-mechanics/offenses-and-slashes/
[grandpa-vr]: https://github.com/paritytech/finality-grandpa/blob/master/src/voter/voting_round.rs
[casper]: https://arxiv.org/abs/1710.09437
[forensics]: https://arxiv.org/abs/2010.06785
[twins]: https://arxiv.org/abs/2004.10617
[rote]: https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic
[ct96]: https://dl.acm.org/doi/10.1145/226643.226647
[staked]: https://www.theblock.co/post/93730/eth2-validators-slashed-staked-bug
[lido]: https://blog.lido.fi/post-mortem-launchnodes-slashing-incident/

### Verification notes and limits

- **Read at source:**
  - code: Prysm, Nimbus, CometBFT, Aptos, Sui, Agave, finality-grandpa;
  - specs: the Ethereum honest-validator spec, EIP-3076, Casper FFG.
- **Read through fetch summaries:** vendor documentation for Teku, Web3Signer, Cosmos, Aptos upgrade and Polkadot.
- **Not fetched:** the Lido and Staked post-mortems returned 403 or a redirect. Their one-line summaries come from search results and press coverage.
- **Nothing measured:** no AINCORE code was run.
  - Every AINCORE number is derived from the constants cited, not measured.
  - The 20% loss figure is the repo's stress model, not a measured network rate.
  - W and the query timeout should be validated on the NAS and the Pi (G1 S10).
- **Not copied from any production chain:**
  - the presence heartbeat (B.5);
  - the per-author attestation floor.

  Both are AINCORE-specific and flagged as such.
