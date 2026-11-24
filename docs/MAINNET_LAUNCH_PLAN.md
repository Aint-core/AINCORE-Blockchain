# Mainnet launch plan

Updated: 2026-10-23. Owner: AINCORE maintainer. Status: NOT CLEARED FOR MAINNET.

This is the execution plan for the existing [G0-G7 release
contract](PRODUCTION_READINESS_GOAL.md#ordered-release-gates), not a replacement
protocol or an expanding feature wishlist. The deliverable is an identified,
reviewed release candidate with bounded claims and an explicit launch decision.
Neither zero bugs nor Ethereum-equivalent security is a pass criterion we can
establish.

## Scope and operating rules

- Freeze launch scope before the release candidate. Inventory the actual
  reachable RPCs, Move entry functions, transaction types and network protocols;
  merely calling a reachable feature "optional" does not remove its risk.
- Core scope includes consensus/finality, deterministic execution, native
  transfers and fees, staking/economics, authenticated state/rejoin, networking,
  operator recovery and release artifacts. Any additional reachable feature
  must have evidence or an enforced, tested exclusion before launch.
- Heavy compilation and fault tests run on NAS in isolated workspaces; Pi is a
  separate bounded lab target. No Rust build on the Mac. Serialize heavy jobs.
- Never stop/restart/deploy live services, erase a datadir, reuse a live signing
  key, change genesis or activate protocol rules under this plan. These require
  separate, explicit approval. Preserve old data, failed reports and user edits.
- Retain evidence for unchanged code. A patch reopens affected checks and the
  final candidate regression, not every historical investigation. New features
  and cosmetic improvements wait until after launch unless already in scope.
- Use durable bounded jobs; read results on request or at an agreed completion
  check. No new recurring notifications or automatic retry of a failed gate.

## Verified starting point

Runtime candidate: `7b1ae83537f39957a45dbad053338a118fc5251c`.
Harness/evidence checkpoint: `c85ea78`. Do not mistake these two identities for
the same source tree or claim that the final launch revision has been selected.

| Evidence | Current conclusion | Reference |
| --- | --- | --- |
| 62 node tests and x86_64/aarch64 release builds | PASS for the shutdown candidate, not the full workspace | [Candidate audit](TWO_HOST_LAB_AUDIT_20261020.md#candidate-verification-2026-10-22) |
| Five Pi shutdown/restart/replay cycles | PASS within this finite experiment; original data and identity retained | [Report](evidence/20261022/pi-shutdown.json) |
| Fresh transfer, forged signature, duplicate submission | PASS for the recorded transaction; not sustained application load | [Report](evidence/20261022/transaction.json) |
| Quorum loss and recovery on four lab validators | PASS for recorded scenarios and sampled identities | [Report](evidence/20261022/quorum-recovery.json) |
| Full regression, mandatory witnesses, vectors, lint, deployable builds | Historical reports record successful stages and 131 witnesses. `e1a8799` finished FAIL on actual process exits; shared build output reproduced stale artifact selection. Fresh isolated candidate evidence is required; these logs do not clear the candidate. | [Security report](evidence/20261022/shutdown-security-gate.json), [build isolation audit](BUILD_ISOLATION_AUDIT_20261023.md) |
| Failure exit codes and clean shutdown control | PASS on `1943b4e`, actual Linux x86_64 and ARM64 processes: occupied listener=1, clean=0, flush denied=1 | [NAS](evidence/20261022/process-exit-fixed-x86.json), [Pi](evidence/20261022/process-exit-fixed-arm.json) |
| Observer backup/recovery guards | PASS for added controls, 12 existing fixture checks, real genesis-only and populated-history observer restore on Pi; not validator recovery | [Operations audit](OPERATIONS_RECOVERY_AUDIT_20261022.md) |
| Fixed-runtime lab progression, transaction and quorum recovery | PASS for the recorded finite runs; 79 harness controls pass. Runtime `1943b4e` has the same Rust source as `e1a8799`. | [Operations audit](OPERATIONS_RECOVERY_AUDIT_20261022.md#runtime-candidate-lab-checks) |
| Fresh runtime packaging | Node-only startup failure reproduced and repaired; extracted ARM package starts and exits 0, 90 harness controls pass. Hosted pipeline not yet executed. | [Packaging audit](RELEASE_PACKAGING_AUDIT_20261022.md) |
| Independent audit, separated operators, final deployment/upgrade approval | NOT ESTABLISHED by these lab reports | G7 decision record required |

The four lab processes occupy two hosts at one site. Node RPC verifies their
QCs; that is not a separate cryptographic implementation or evidence of four
independent operators. The historical "Initial state" table in the goal document
and older audits are not a current inventory of unfixed bugs.

Completed NAS job: user unit `aincore-shutdown-fullgate-20261022.service`.
Source: `/home/alpha/aincore-shutdown-gate-20261022`.
Reports: `target/hardening-regression-20261022T053633Z-415702/`.
Limits: one CPU, 2 GiB RAM, 1 GiB swap, six hours maximum.

Failed candidate job: `aincore-final-candidate-20261022.service`, source
`/home/alpha/aincore-release-candidate-20261022` at `e1a8799`.
Its regression started 2026-10-22 11:30:58 UTC, reports under
`target/hardening-regression-20261022T113058Z-489674/` and `target/candidate-result/`.
It ended 2026-10-22 16:58:06 UTC, `stage=process-exits`, exit 1. Cross-checkout
shared-target reuse was reproduced independently on 2026-10-23. The runner now
isolates output per run and passes nine controls; the full fresh candidate
retest is still required. See the build isolation audit above.
Subsequent operational-script changes have separate controls and do not change
the candidate's Rust source. Do not attribute a runtime result to untested code.

## Ordered work and acceptance

### 1. Finish the current candidate gate

Inspect `result.txt`, stage logs and `security-gate.json`. Completion requires
`stage=complete`, `exit_code=0`, successful required witnesses with exact named
test matches, and no unexplained missing stages. A running unit's `Result=success`
or `ExecMainStatus=0` is not completion. A missing result is incomplete.

If a stage fails, retain it, reproduce the exact failure under the same resource
limits, repair its cause and test both the rejecting and accepting cases. Do not
reduce assertions, erase ignored-witness obligations, or restart the run blindly.
The current stage sequence is in `scripts/hardening_regression.sh`.

Done when: one complete report identifies the source, toolchain, commands and
outcomes. For any later runtime change this result remains historical evidence,
not automatic clearance of the changed binary.

### 2. Close the launch-scope defect and coverage ledger

Map G0-G5 contract obligations to exact executable witnesses and the candidate
reports. Start with `scripts/release_security_witnesses.json`, the G1/G3/G4/G5
contracts, and existing crash/replay tests; do not replace them with a new audit
number or repeat already closed findings without a new reproduction.

The next concrete items found during planning are:

| ID | Evidence / limitation | Closure action |
| --- | --- | --- |
| EXIT-1 | REPRODUCED on `7b1ae83`: denying writes to a fresh observer DB causes a real RocksDB flush error, but the process exits 0. [Failed report](evidence/20261022/process-exit-baseline.json). No funds/corruption conclusion follows. | CLOSED for this scenario on `1943b4e`: NAS and Pi actual processes return 1 after the injected flush failure, without a false drain-complete log. See reports above. |
| EXIT-2 | REPRODUCED on the same binary: an occupied listener produces `AddrInUse` and exit 0. Clean shutdown control exits 0 and flushes successfully. | CLOSED for this scenario on `1943b4e`: busy P2P returns 1, clean shutdown returns 0 on both architectures. 62 node tests, strict clippy and both builds passed. |
| SOAK-1 | Legacy Phase 2 script has no certified-state or transaction progression assertion. A control also reproduces the old two-host check accepting advancing status with a stale QC. | Two-host checker now samples before/after QCs, progression on every member, cross-node commitments and retained common history; 14 controls and three real candidate samples pass. Legacy output explicitly denies readiness. Full G6 transaction/resource workload remains pending. |
| BUILD-1 | Node-only release packaging failed fresh startup; hosted compiler differed from the measured NAS baseline. The original hosted matrix omitted Linux ARM64. | Package now includes required public runtime files and a real startup gate; compiler selection aligned to measured 1.95.0. Local ARM smoke PASS, 90 harness controls PASS. The RC workflow now requires native Linux x86-64, Linux ARM64 and macOS ARM64 packages, then attests and verifies the three archives before uploading release assets. Hosted execution and independent verification of a tagged AINCORE release remain OPEN. [Verification procedure](RELEASE_PACKAGE.md#verify-before-running). [Audit](RELEASE_PACKAGING_AUDIT_20261022.md). |
| BUILD-2 | Shared output reused a stale binary despite corrected source; reproduced with two minimal Cargo crates on the installed toolchain. | Fresh per-run target/build directories, explicit artifact handoff, early real-process probes and source-change checks added; nine runner controls PASS. Full isolated native/ARM candidate retest remains OPEN. [Audit](BUILD_ISOLATION_AUDIT_20261023.md). |
| OPS-1 | Reproduced unsafe hot-copy acceptance, busy-lock acceptance, premature destination mutation and empty-directory nesting in the DR tools. | Operational fixes pass controls and real genesis-only/populated-history observer restores, including a historical receipt, balance, nonce and certified commitments. [Audit](OPERATIONS_RECOVERY_AUDIT_20261022.md). Validator reactivation and recovery beyond retention remain OPEN; observer restore does not close this whole row. |

These are code observations or evidence gaps, not reproduced consensus
failures. Classify severity after reproduction. Every resolved defect needs a
named regression; any launch-scope critical/high finding remains a blocker.

Done when: every G0-G5 obligation has a current witness/review reference or an
explicit unresolved row. No unreviewed exclusion or failed mandatory witness is
counted as a pass. Claims of completed gates require more than a test total.

### 3. Rehearse operation and recovery on disposable infrastructure

Use existing lab binaries, unique test-only identities and recorded artifacts.
Build on the two-host transaction and fault harnesses; do not change live nodes.
Exercise real process crash/restart, one unavailable validator while quorum
remains, loss of quorum and healing, restart during an epoch transition, late
rejoin beyond retained history, and authenticated recovery from a pinned anchor.

For each common certified height checked, compare block/state/receipt/finality
identities. Verify balances, nonce, fees and receipts after replay/recovery, not
only height and health. Preserve a conflicting-root negative control.

Follow [DR_RUNBOOK.md](DR_RUNBOOK.md): observer backups use a new identity on
restore; validator recovery fences the old signer and preserves the prescribed
guard-continuity rules. Never restore an old validator database with its key to
simulate a normal restart. Such a rollback is a separate adverse test, not an
approved operating procedure. Exercise upgrade rejection and the chosen
coordinated activation path without rewinding signing state. Select new-network
launch versus migration explicitly; this plan authorizes neither genesis action.

Done when: all scoped drills pass on the identified candidate, recovery times
and limitations are recorded, and another operator can follow the runbook.
Power-loss behavior is not proved by SIGTERM; any physical interruption test
needs disposable hardware/data and separate permission.

### 4. Produce and verify the release candidate

Package from a clean pinned source and reviewed dependencies. Record compiler,
lockfile, stdlib/genesis identity, source revision, artifact hashes and build
provenance. A SHA-256 checksum proves integrity relative to its trusted source,
not who produced an artifact. Confirm provenance and verification instructions.
Record the tag and source commit approved by the release operators. The signing workflow requires artifact attestation support for the repository. GitHub currently supports public repositories on current plans and private or internal repositories on Enterprise Cloud. Complete online and offline verification of each tagged archive using the [operator procedure](RELEASE_PACKAGE.md#verify-before-running). Record hosted job IDs, archive digests and independent verification results. [GitHub eligibility](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

Do not claim a SLSA level or bit-for-bit reproducibility without testing it.

Fresh-machine install/join checks must use the distributed artifact, not a
developer's existing `target/` directory. Test every advertised OS/architecture;
omit unsupported targets explicitly. Exercise wrong genesis, wrong artifact,
missing prerequisites, unavailable peers and the documented recovery path.
Public RPC must have tested resource limits and no externally exposed operator
credentials. Audit install commands for destructive defaults.

Done when: all supported targets install, join and verify the expected chain,
checksums/provenance are verifiable, secrets scanning and dependency review are
recorded, and the operator instructions match the shipped candidate.

### 5. Run a measured no-value release-candidate testnet

Planned acceptance window: 72 uninterrupted hours **and** at least three complete
committee epochs on the frozen candidate. This is a project-defined minimum
observation window, not a research theorem or a claim that three days proves
security. Record the topology, epoch interval and expected duration first.

Before starting, measure a bounded baseline and record numeric admission rate,
latency/recovery budgets, memory/disk growth limits and sampling cadence. These
must fit the intended launch configuration and be fixed before judging the run;
do not invent a TPS promise or relax a deadline after seeing a failure.

The workload must include successful BCS transactions, deliberate execution
aborts, invalid signatures/nonces, repeated submissions, fee/reward/supply
reconciliation, and every launch-enabled application path. Include abusive
public traffic and one faulty member within the stated consensus assumptions.
Collect finality/state agreement, durable transaction effects, queue/backlog and
resource measurements throughout. Sampling gaps are unknown intervals, not
uptime. Never call stalled empty-block health checks a transaction-load pass.

Done when: required scenarios and numeric budgets pass; no conflicting certified
state, duplicate effect, unexpected process failure or unresolved critical/high
finding occurs. Root-cause every failure. After a relevant runtime/protocol fix,
rerun its checks and the candidate acceptance window. Cosmetic changes do not
restart this clock. A pass clears only the stated G6 scope, not G7 by itself.

### 6. Independent review and mainnet decision

Give a reviewer independent of implementation the frozen source, G0-G5 contracts,
original failing witnesses, fixes, failed and passing reports, build provenance,
operating topology, key/recovery rules and published limitations. A second AI
summary or another self-review is not sufficient independent sign-off. Arrange
reviewer availability in parallel; do not wait for the end to discover it is
unavailable. No external purchase, disclosure of private code/keys, or booking is
authorized by this plan.

Document validator operators, stake, power/network/host failure domains and how
they meet the protocol assumptions. Review key custody and fencing, archive
availability, alert ownership, incident response and upgrade coordination.
There is no global "blockchain certification" implied here: the maintainer makes
the launch decision on recorded technical and operational evidence.

Done when: G0-G6 are evidenced, independent findings have been retested, no
launch-scope critical/high issue remains, other risks have explicit ownership,
and the user approves the exact genesis/validator set/version/activation plan.
Only that approval permits live deployment or public-value operation.

## Tracking and immediate next action

| Work | State | Responsible party |
| --- | --- | --- |
| Plan and closure criteria | Written; no permission to launch implied | Implementation agent + maintainer |
| Current full NAS gate | `e1a8799` FAIL; shared-cache cause reproduced, isolation repair tested. Require fresh candidate run and exact artifact attribution. | Implementation agent |
| EXIT-1 / EXIT-2 reproduction and repair | Scoped PASS on `1943b4e`, actual NAS and Pi processes | Implementation agent |
| Evidence mapping and real recovery/load acceptance | PENDING, reuse existing witnesses and harnesses | Implementation agent |
| Supported platform/feature scope and launch topology | Decision needed before candidate acceptance | Maintainer, with measured recommendations |
| Independent review and final approval | PENDING, external dependency | Maintainer + independent reviewer |

Each closure record must carry: task ID, source/artifact identity, command,
environment/limits, start/end, expected/observed result, evidence path, residual
limits and reviewer. Use PASS (scoped), FAIL, INCOMPLETE or NEEDS DECISION. Missing
evidence is never PASS. Preserve the original failed run beside its successful
retest. Do not sum overlapping test subsets or invent a completion percentage.

The current job has a six-hour execution cap, not a six-hour mainnet ETA. The
launch date depends on its result, the listed repairs, operational exercises and
independent review. Passing closed obligations is a stopping condition; no new
feature is required merely to keep development going.

## Primary references

- [NIST SSDF 1.1, PW.8 and RV](https://csrc.nist.gov/pubs/sp/800/218/final): scoped
  executable testing, recorded findings and root-cause remediation. These guide
  the workflow; they do not certify this blockchain.
- [SLSA 1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements):
  bind release artifacts to their build provenance and verification procedure.
- [Rust Termination](https://doc.rust-lang.org/std/process/trait.Termination.html):
  the main return value determines the process status; logging an error does not
  itself make a normally returning unit-valued main fail.
- [G1 consensus contract](G1_CONSENSUS_CONTRACT.md),
  [G3 state contract](G3_STATE_AUTHENTICATION_CONTRACT.md),
  [G4 network contract](G4_NETWORK_CONTRACT.md),
  [G5 economics contract](G5_ECONOMICS_CONTRACT.md): reconcile historical sections
  with current code and executed evidence; papers and old status tables alone
  are not a completion record.
