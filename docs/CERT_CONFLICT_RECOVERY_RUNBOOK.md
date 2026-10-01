# Recovery after a certificate conflict (G1 CE-3)

Operators follow this procedure when validators halt on `alarm:vcert_conflict`. It is a
genesis blocker until the tool in step 5 exists (G5 contract, Open).

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

1. **Do not restart, wipe or restore any validator.** The halt and the evidence are on disk.
   Restoring a validator from a backup can make it sign twice (G1: never restore a validator
   from backup).
2. **Collect** from every validator:
   - the alarm rows, which hold both certificates (epoch, round, author, digests, signer
     bitmaps);
   - the latest height that has a QC, and its block hash.
3. **Check finality.** Do two different blocks at one height both carry valid QCs? If so,
   finality itself was broken. Stop here: this needs social recovery, a new genesis from a
   state the operators agree on, and this runbook does not cover it.
4. **Pick the canonical certificate** for the slot, by the same rule on every node:
   - the certificate whose digest is in the committed sequence of the latest QC'd block, if
     one is;
   - otherwise the certificate with the lower digest (hex order).

   Record which one was picked and why.
5. **Stop every validator, and apply the recovery tool on each one:**
   - replace the slot's certificate row (`consensus:vcert:v1:{E}:{r}:{author}`) with the
     canonical one;
   - delete the `alarm:vcert_conflict:*` rows;
   - keep the `sys:equiv_cert_v4:*` evidence rows.

   **Status: this tool does not exist yet.** It is required before genesis. The witness
   `a_certificate_conflict_is_recorded_as_evidence_against_both_signers` performs the
   alarm-clearing part in process. Without the certificate replacement, nodes that held
   different certificates could order differently after restart.
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
