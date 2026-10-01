# Recovery after a certificate conflict (G1 CE-3)

Operators follow this procedure when validators halt on `alarm:vcert_conflict`. The tool is
`cert_recovery` (built with the node: `target/release/cert_recovery`). It runs on a stopped
validator's database, `{datadir}/validator_{port}.db`; a running node holds the database lock,
so the tool cannot open it.

## What happened

Two vertex certificates exist for one slot (epoch, round, author) on different digests. An
honest member attests one digest per slot, guarded on disk (AT-1), so more than a third of
the committee's stake signed both. The BFT assumption is broken.

What each node did (G1 CE-3, G5 amendment A3):

- It wrote `alarm:vcert_conflict:{E}:{r}:{author}` holding both certificates.
- It wrote the evidence row `sys:equiv_cert_v4:{author}:{E}:{r}` in the same transaction.
- It halted ordering: no block is placed, no finality vote is signed, no synced block is
  adopted. The halt survives a restart.
- It relayed both certificates once, so every honest node that holds either one halts too
  and keeps the evidence.

No finalized block is lost. Finality stops at the last block with a QC.

## Procedure

1. **Do not restart, wipe or restore any validator** until step 5 says so. The halt and the
   evidence are on disk. Restoring a validator from a backup can make it sign twice (G1: never
   restore a validator from backup); the only restore this runbook uses is state sync, in
   step 5.
2. **Stop every validator and collect** from each one, with
   `cert_recovery inspect --db DB`:
   - each alarmed slot (epoch, round, author) and its two digests;
   - the slot's certificate row, and which of its digests this node ordered;
   - the latest height, and the latest height that has a QC, with its block hash.
3. **Check finality.** Do two different blocks at one height both carry valid QCs? If so,
   finality itself was broken. Stop here: this needs social recovery, a new genesis from a
   state the operators agree on, and this runbook does not cover it.
4. **Pick the canonical certificate** for the slot, by the same rule on every node:
   - the digest some node ordered, if one did;
   - otherwise the lower digest (hex order).

   `cert_recovery choose DIGEST_A DIGEST_B [ORDERED ...]` applies the rule to the digests the
   nodes reported as ordered. Two different ordered digests mean the nodes' orders already
   diverged: go to step 3's social recovery. Record which one was picked and why.

   Export that certificate from a node that holds it, and copy the file to every node:
   `cert_recovery export --db DB --epoch E --round R --author A --digest D --out cert.json`.
5. **Pin the canonical certificate on every validator:**
   `cert_recovery pin --db DB --cert cert.json`. In one transaction it:
   - checks that the certificate verifies under the slot's epoch committee, this chain id and
     this genesis;
   - replaces the slot's certificate row (`consensus:vcert:v1:{E}:{r}:{author}`) with it;
   - takes the certified role from the slot's other digest (its body stays);
   - deletes the slot's `alarm:vcert_conflict:*` row;
   - keeps the `sys:equiv_cert_v4:*` evidence row.

   It refuses, writing nothing, a certificate that does not verify, and a node that ordered the
   other digest. That node's committed sequence already holds the other vertex: restore it by
   state sync from a checkpoint at or below the last block with a QC, never from a backup
   (step 1). Pin every alarmed slot; the tool reports the alarms left.

   Witnesses: `the_recovery_tool_pins_the_canonical_certificate_on_every_node` and
   `a_certificate_conflict_is_recorded_as_evidence_against_both_signers`.
6. **Restart every validator.** The evidence row is carried in the next vertices. Every
   node's block holds it, and the executor convicts exactly the members whose bits are set
   in both certificates:
   - they are jailed for good;
   - their stake moves into unbonding;
   - the fraction is 100 % at once when they hold a third of the committee (SL-4).
7. **Check:**
   - every node holds the evidence in the same block;
   - the convicted members are jailed;
   - finality advances.

   Convicted members leave the next committee. If the remaining stake cannot reach a quorum,
   the chain cannot continue, and step 3's social recovery applies.

## Why the chain halts instead of going on

A node that orders with one certificate while another node orders with the other forks the
DAG's order. Halting stops the divergence where it is seen. Relaying the certificates gives
an attacker no new power: a coalition able to make two certificates can halt the chain
anyway, by withholding its votes.
