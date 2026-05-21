# /crew-dev

Jalankan implementation task dengan Blockchain Developer agent.

## Instructions

$ARGUMENTS = deskripsi task yang mau diimplementasi
Contoh:
- "fix H-02 gossip wiring untuk downtime attestations"
- "implement C-03 Pietrzak VDF sebagai gantinya dummy VDF"
- "add property-based tests untuk BFT quorum math"

### Step 1 — Read Context
Baca finding yang relevan dari:
- docs/PHASE2_AUDIT_FIX_REPORT.md
- docs/phase2-panic-audit.md
- Identify file:line yang perlu diubah

### Step 2 — Blockchain Developer Agent
Spawn agent dengan role dari `.claude/crew/agents/developer.md`.
Task: Implementasi $ARGUMENTS.

Developer harus:
1. Baca current code
2. Implement fix/feature
3. Tulis tests
4. Verify cargo test green

### Step 3 — QA Validation
Setelah dev selesai:
- cargo test --workspace (harus >= 274 tests, 0 fail)
- cargo clippy (tidak ada new warnings)
- cargo build --release -p node

## Output
Implementation summary + test results + diff ringkasan.
