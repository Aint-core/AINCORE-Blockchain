# /crew-audit

Jalankan focused security audit.

## Instructions

$ARGUMENTS = modul yang mau diaudit (optional). Kalau kosong, audit default modules.

Default modules:
- consensus/consensus/src/dag.rs
- core/executor/src/lib.rs  
- core/mempool/src/lib.rs
- da/src/lib.rs
- common/crypto/src/lib.rs

### Step 1 — Security Lead
Spawn agent dengan role dari `.claude/crew/agents/security.md`.
Task: Security review pada modul yang ditentukan.
Baca setiap file lengkap. Cari: string contract drift, lock ordering, integer overflow, missing validation.

### Step 2 — Code Auditor
Spawn agent dengan role dari `.claude/crew/agents/auditor.md`.
Task: Deep code audit dengan checklist lengkap.
Context: gunakan findings dari Step 1.

### Step 3 — Report
Compile findings dari kedua agents.
Format output: findings table sorted by severity + detailed findings.

## Output
Security audit report dengan semua findings, severity, file:line, dan rekomendasi.
