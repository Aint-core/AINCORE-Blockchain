# Two-host lab audit, 2026-10-20

Scope: read-only review of the disposable NAS/Pi run, its launcher configuration,
and relevant networking code. This is not a complete protocol security audit.
No live service or firewall changes were made during this review.

## Findings

1. **Resource-isolation gap (high operational priority).** Pi reports cgroup
   controllers `cpuset cpu io pids`, without `memory`. Although systemd accepts
   MemoryMax=512M, the test has no demonstrated enforced memory ceiling on Pi.
   Do not run memory-pressure/fuzz workloads there until enforcement is verified.
   Configured properties alone are not sufficient acceptance evidence.

2. **Self-dial in test launcher (medium).** Every validator was given all four
   addresses, including its own. NAS logs contain LocalPeerId errors at startup.
   This is a test-configuration defect, not evidence of a consensus defect.
   Future launcher must exclude its own endpoint and test the generated topology.

3. **Unreachable outbound route (medium, cause unresolved).** Pi repeatedly timed
   out dialing NAS TCP 9601/9602 while NAS was listening on those ports. NAS UFW
   is active, but its rules are root-readable and current SSH cannot use
   passwordless sudo. Firewall filtering is a hypothesis, not a confirmed cause.
   Nodes nevertheless established committee sessions and made progress.
   `core/node/src/p2p.rs` retries unresolved bootnode addresses independently of
   the connected-member loop. A session established in the other direction does
   not by itself prove that the original advertised address is reachable.
   Inspect firewall rules and packet path before changing retry logic.

4. **Evidence gap (high release priority).** The smoke checker compared certified
   commitments at heights 1 through 18 across all four nodes using node RPC QC
   verification. Shutdown logs on sampled NAS/Pi nodes show block 1200, but this
   is not a comparison of all 1200 commitments, independent signature verification,
   or transaction correctness testing. Valid/forged/replayed transaction coverage
   remains outstanding. Four validators on two hosts are only two physical
   failure domains, not four independent operators.

5. **Lifecycle classification (medium).** All four units report Result=timeout
   with ExecMainStatus=0 after RuntimeMaxSec=2h. This is the configured stop, not
   an unexplained process crash, but exit 0 alone is not a full gate PASS.
   First-origin initialization remains in the transient unit environment. Do not
   blindly restart those units; subsequent starts must use recovery configuration
   and preserve keys, genesis, and database.

## Ordered remediation and acceptance

- Read the NAS rules without modifying them; verify Pi source address and route.
  Any necessary allow rule should be restricted to the Pi and designated test
  TCP ports, with rollback recorded. Never disable the firewall globally.
- Replace ad-hoc launch with a reviewed, reproducible launcher: explicit version
  and binary hashes, self-excluded peers, genesis hash checks, port-conflict
  checks, verified resource-controller prerequisites, and first-start/restart
  separation. Add unit tests before launching it.
- Re-run bidirectional connectivity checks, then compare all sampled certified
  commitments across architectures. Preserve a machine-readable result.
- Test valid transfer execution and balances, forged signatures, replay after
  finality, restart durability, quorum loss, and recovery. Failure must fail the
  gate; merely sending a request must never count as execution success.
- Require independent review and operational evidence before release approval.

## Primary references and limits

- [NIST SP 800-218 SSDF](https://csrc.nist.gov/pubs/sp/800/218/final):
  use review, executable security tests, root-cause analysis, and regression
  evidence. This audit does not assert SSDF certification or compliance.
- [libp2p AutoNAT](https://docs.libp2p.io/concepts/nat/autonat/):
  reachability must be tested rather than inferred from advertised addresses.
  This does not establish that NAT caused this LAN timeout.
- [Bullshark: DAG BFT Protocols Made Practical](https://arxiv.org/abs/2201.05677):
  protocol safety/liveness arguments depend on explicit assumptions. An inspired
  implementation does not inherit the paper's proof; fault schedules and actual
  implementation invariants need separate validation.

Verdict: the short cross-architecture consensus smoke passed; infrastructure and
release acceptance remain incomplete. No claim of bug-free or mainnet readiness.

## Remediation evidence, 2026-10-21 (Asia/Jakarta)

- NAS kernel logs confirmed UFW BLOCK for Pi source 192.168.18.66 to NAS
  TCP 9601/9602. A source/destination/interface-scoped rule was added; both
  ports passed an actual Pi TCP connection test. Firewall remains enabled.
- Recovery launcher excludes each node's own endpoint and explicitly disables
  first-origin initialization. Three configuration regression tests pass.
- The same four databases recovered beyond block 1200 without replacing genesis
  or keys. All four advanced 1203 -> 1207 with three committee sessions each.
  RPC-verified commitments matched at heights 1-18, 1200, 1201, and 1207.
- First transaction harness attempt failed before broadcast because its capture
  proxy lacked the CLI's GET /get_network_info endpoint. Fixed the harness,
  not the blockchain. Retained the failed result.
- Valid test transfers executed successfully at heights 1238 and 1263; each
  recipient received exactly 10^18 quanta. Invalid Ed25519 signatures were
  explicitly rejected with -32010. Replays were explicitly rejected as duplicate
  transactions; recipient balance and sender nonce remained unchanged through
  three subsequent blocks. This tests exact-payload replay, not every replay
  variant or restart-cleared dedup behavior.
- Three additional regression tests ensure busy/unrelated RPC errors cannot
  masquerade as successful signature/replay rejection.
- The block 1263 hash, state root, receipts root, and finality digest match across
  both NAS nodes and both Pi nodes, with available/verified QC responses.
  QC verification remains through node RPC, not an independent implementation.
- Final stricter transaction report on NAS:
  `/home/alpha/aincore-lab-20261020/transaction-gate-1792516759571508283.json`.
- Recovery run is limited to 30 minutes, not configured as a permanent service.
  Pi memory-controller gap remains unresolved; this is not a memory-stress test.
  Live NAS services and archived Pi keys/databases were not changed.

## Pi memory isolation repair, 2026-10-21

User explicitly authorized Pi boot configuration repair and reboot. Kernel has
CONFIG_MEMCG=y. Firmware prepends cgroup_disable=memory; the Raspberry Pi
maintainer documents the downstream cgroup_enable=memory override in
https://github.com/raspberrypi/linux/issues/6980
(see maintainer discussion dated August 4, 2025).
Only cgroup_enable=memory was appended to /boot/firmware/cmdline.txt.
The original is preserved at /boot/firmware/cmdline.txt.before-aincore-20261021,
SHA256 589438adc3b61239772c6c30fee7b4aaf00f80c4ae5f90a936a8f2659ea799c9.
Rollback restores that backup and requires another authorized reboot.

Post-reboot boot ID: 8df53d1c-33e1-4eee-9762-733cc44deafa. The v2 controller
list now includes memory. A disposable systemd user unit with MemoryMax=32M
and MemorySwapMax=0 attempted a 64 MiB allocation: Result=oom-kill, exit signal
9, MemoryPeak=33554432, as expected. A separate 8 MiB allocation under the same
limit exited 0 with memory peak 11.3M. These are small isolation tests, not a
blockchain stress benchmark. Old r3/r4/observer services remained inactive and
disabled; NAS was not rebooted. Recovery launcher now refuses to start without
the memory controller, with a regression test for that precondition.

## Shutdown abort reproduced, 2026-10-21

Release-blocking finding: both Pi lab validators reported SIGABRT (6) after
printing "Node exited cleanly". A repeat without the debugger exited zero,
so the failure is intermittent. A health-gated GDB reproduction captured:

- API thread: Actix ServerInner drop -> RocksDB DBImpl destructor ->
  PeriodicTaskScheduler::Unregister -> Mutex::Lock -> abort.
- Main thread: libc exit -> RocksDB PosixEnv destructor -> JoinThreads.

Evidence: Pi `/home/pi/aincore-lab-20261020/shutdown-ready.log`, copied to
Mac `/tmp/aincore-shutdown-backtrace-20261021.log`. GDB's own exit status was
zero despite the inferior abort: it is NOT a passing node exit status.
An earlier debugger attempt sent SIGTERM before readiness and is inconclusive.
The matching upstream example also drops RocksDB from a detached thread during
process exit: https://github.com/facebook/rocksdb/issues/11349.

Candidate fix owns/joins the API OS thread, routes shutdown through the shared
flag, disables competing Actix signal handling, and waits for graceful server
stop. Removed the premature clean-exit claim. No consensus/genesis changes.
Validation is pending: NAS unit `aincore-shutdown-fix-test-20261021.service`
tests the candidate in `/home/alpha/aincore-shutdown-fix-20261021`, bounded to
1 CPU, 2 GiB RAM, 1 GiB swap and two hours. No Mac Rust build, no deployment.
ARM64 process-level stop/restart regression must follow before closure.

Recovery gate `/tmp/aincore-recovery-fault-1792554845804510000.json` remains
failed: replay after restart was rejected without balance/nonce change, and
two NAS validators stayed at certified height 1518 through a 30-second no-quorum
observation after 30 seconds settling. Recovery sampling then hit an RPC
startup connection refusal. This is not a full passing recovery gate.
Harness now retries only curl connection failure, records termination status,
fails closed on nonzero/unknown exit, and recreates collected transient lab
units without changing data. Pi node2 was restored after debugger completion.

## Candidate verification, 2026-10-22

Code commit: `7b1ae83` (API-thread shutdown ordering). The first candidate passed
the previous 61 node tests but failed the new actual-HTTP shutdown test: awaiting
Actix's stop acknowledgement without polling the Server deadlocked. The corrected
candidate polls both concurrently. The failed run remains in `candidate.log`.

NAS `/home/alpha/aincore-shutdown-fix-20261021/build-result.txt` now records
`stage=complete`, `exit_code=0`. Latest node result: 62 passed, 0 failed,
0 ignored. Both x86_64 and aarch64 release builds completed. Source hashes match
the local committed Rust files. Binary SHA256:

- x86_64: `3a777d89c2f0f289a6f1097ff6180dfa03c1b53f05eefd22f89a9c09537163c3`
- aarch64: `9ea933d682dee4a582e88a3efa42a43e0635efc8febc731ca87cc6fb30c79f86`

Pi process regression passed five cycles, all exit 0, retaining tip 1765 and the
successful transaction receipt/certificate at 1263. Every replay was rejected
with admission error -32010 (used sequence); balance and nonce remained equal
before/after replay and across cycles. Key/genesis hashes remained unchanged.
This was one validator alone, so it proves restart preservation, not liveness.
Report: `/home/pi/aincore-lab-20261020/shutdown-probe-1792646905723107887.json`.
The previous probe report `shutdown-probe-1792646778189463289.json` is failed:
the harness mistakenly treated JSON-RPC `error:null` as an error. The parser was
fixed and four parser controls added; it was not a consensus failure.

Four candidate validators were then started with the original lab data and
genesis, bounded to 30 minutes. Every artifact is hash-pinned before launch.
The launcher refuses listening-port conflicts but permits old TCP TIME_WAIT
entries. RemainAfterExit retains process exit evidence; the fault gate signals
only its own Pi main processes and verifies their termination before measuring
the no-quorum interval. Running binary hashes are checked through `/proc/PID/exe`.

Fresh transaction test passed on the candidate: block 1772, transaction
`37c60103e41657621290611c29f4ab375f19e7f79204593f2df3f2988d2438b0`, execution
success, recipient delta exactly 10^18 base units, forged signature rejected,
duplicate rejected, balance/nonce stable after further blocks.
Report: `/home/alpha/aincore-lab-20261020/transaction-gate-1792647145258411101.json`.
Quorum-loss/recovery outcome and broad release gate are recorded separately;
do not infer them from these passing targeted results.

Quorum-loss/recovery subsequently PASSED on the same binaries. All four nodes
advanced to 1777 after rejection of the old replay (sender next sequence 3).
Pi nodes 2 and 3 both exited normally: ExecMainCode=1, ExecMainStatus=0,
Result=success, MainPID=0. After 30 seconds settling, the NAS pair's certified
height remained 1778 for the 30-second observation. After both Pi nodes restarted,
all four reached 1781. Certificate identities matched at 1263, 1778 and 1781.
Report: `/tmp/aincore-recovery-fault-1792647305314837000.json`.
Small evidence reports are preserved in `docs/evidence/20261022/` (shutdown,
transaction, quorum recovery). These are bounded lab checks, not an independent
cryptographic verifier or an exhaustive adversarial network test.

The nine-package regression, required witnesses, identity vectors, strict clippy
and release builds have been launched from clean commit `7b1ae83` in
`/home/alpha/aincore-shutdown-gate-20261022`. NAS user unit:
`aincore-shutdown-fullgate-20261022.service`, one CPU, 2 GiB RAM, 1 GiB swap,
six-hour maximum. This full run is PENDING until its final result is inspected.
No live NAS service was restarted, no Mac build ran, and no genesis was reset.

Post-heal smoke also passed: every node moved from height 1790 to 1794 and
finalized round 3608 to 3616; each had three authenticated committee sessions.
Certificate identities matched at heights 1-18, 1778, 1779 and 1794. This is
sampling, not verification of every historical block. Local Python harness
controls passed 20 tests (16 lab controls plus four launcher controls).
The fresh transaction at 1772 was also checked on all four nodes: four matching
certificate identities and four successful receipts bound to that block hash.
