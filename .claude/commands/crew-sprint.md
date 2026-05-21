# /crew-sprint

Jalankan full sprint workflow dengan semua departemen.

## Instructions

Kamu adalah ORCHESTRATOR. Spawn agents berikut secara sequential:

### Step 1 — PM Agent
Spawn agent dengan role dari `.claude/crew/agents/pm.md`.
Task: Buat sprint plan berdasarkan: $ARGUMENTS (atau roadmap saat ini kalau kosong).
Baca ROADMAP.md dan docs/PHASE2_AUDIT_FIX_REPORT.md dulu.

### Step 2 — Threat Modeler (parallel dengan Security Lead)
Spawn agent dengan role dari `.claude/crew/agents/security.md`.
Task: Update STRIDE threat model untuk Phase 3 scope (H-02 gossip, C-02 bridge multisig, C-03 VDF).
Baca consensus/consensus/src/dag.rs, da/src/lib.rs, depin/bridge-rust/src.

### Step 3 — Code Auditor  
Spawn agent dengan role dari `.claude/crew/agents/auditor.md`.
Task: Audit modul yang relevan dengan sprint plan dari Step 1.
Gunakan findings dari Step 2 sebagai context.

### Step 4 — QA Validation
Run: cargo test --workspace, cargo clippy --workspace --all-targets, cargo build --release -p node.
Report: test count, clippy delta vs 274 baseline, build status.

### Step 5 — CTO Synthesis
Synthesize semua output dari Step 1-4 menjadi sprint report.
Format: Executive summary, findings table, metrics, known limitations, recommendations.
Save ke docs/SPRINT_REPORT_PHASE3.md.

## Output
Laporan final ke user dengan summary tiap departemen.
