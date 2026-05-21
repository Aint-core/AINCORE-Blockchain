# /crew-research

Jalankan research workflow untuk topik tertentu.

## Instructions

$ARGUMENTS = topik yang mau diriset

Contoh:
- "Pietrzak VDF implementation Rust"
- "HotStuff-2 vs Bullshark consensus comparison"
- "NIST ML-DSA Dilithium5 production deployment"
- "Celestia DA integration untuk sovereign chain"

### Step 1 — Researcher Agent
Spawn agent dengan role dari `.claude/crew/agents/researcher.md`.
Task: Research mendalam tentang $ARGUMENTS.

Research process:
1. State of the art
2. Kelebihan/kekurangan untuk AINCORE
3. Implementation approach yang direkomendasikan
4. Effort estimate (dev-days)
5. References

### Step 2 — Tech Writer
Buat peneliti menjadi dokumen yang bersih dan bisa dibaca.
Tambahkan TL;DR di atas.
Save ke docs/research_[topic].md

## Output
Research report siap pakai untuk engineering decision.
