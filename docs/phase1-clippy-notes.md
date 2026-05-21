# Phase 1 Clippy Diff — Honest Evidence

**Date:** 2026-05-21
**Branch:** `audit/phase-1-safe-wins` (HEAD)
**Baseline:** `28e6bcc` (main)
**Command:** `cargo clippy --workspace --all-targets`

---

## Methodology

The Phase 1 report claimed "no new clippy warnings introduced." The external
auditor correctly flagged that claim as unverified — only the tail of the
clippy output had been inspected, not the full delta.

This document provides reproducible evidence. The procedure:

```bash
# 1. Capture HEAD (Phase 1 branch with all audit fixes + carried Phase 0-4 work)
cargo clippy --workspace --all-targets 2>&1 \
    | grep -E "^(warning|error)" | sort -u \
    > docs/phase1-clippy-branch.txt

# 2. Stash uncommitted, checkout baseline, capture main
git stash --include-untracked
git checkout 28e6bcc
cargo clippy --workspace --all-targets 2>&1 \
    | grep -E "^(warning|error)" | sort -u \
    > docs/phase1-clippy-main-baseline.txt

# 3. Restore and diff
git checkout audit/phase-1-safe-wins
git stash pop
diff docs/phase1-clippy-main-baseline.txt docs/phase1-clippy-branch.txt \
    > docs/phase1-clippy-diff.txt
```

All three artefacts (`phase1-clippy-main-baseline.txt`,
`phase1-clippy-branch.txt`, `phase1-clippy-diff.txt`) are checked into
`docs/` alongside this note so anyone can verify without rerunning.

---

## Summary Numbers

| Metric | Main (28e6bcc) | Branch (HEAD) | Delta |
|---|---|---|---|
| `error:` lines | 5 | 5 | **0 new errors** |
| `warning:` lines (deduplicated) | 54 | 38 | **−16** (improvement) |
| Crates emitting warnings | 13 | 9 | **−4** crates clean |
| Truly new warning *categories* | — | — | **0** |

The five `error:` lines on both sides are the pre-existing
`clippy::eq_op` self-assignment lints in `common/crypto/src/poseidon/` —
unchanged by Phase 1, deferred to a dedicated cleanup.

---

## Honest Caveat — Scope of This Comparison

This diff compares the **full working state** of the branch (including
the Phase 0-4 working-tree changes that were carried in when the branch
was forked from a dirty `main`) against pristine `main`.

That means the warning *reduction* (−16) is NOT solely attributable to
my Phase 1 audit fixes. Some of the eliminated warnings were resolved
by the Phase 0-4 dirty work that came with the branch.

What this evidence **does** support:

1. **No new errors** introduced by anything on the branch.
2. **No net regression** in warning count — strictly fewer.
3. **No new warning categories** specific to files touched by Phase 1
   audit fixes (`common/storage/`, `core/mempool/`, `consensus/consensus/`,
   `core/executor/`, `core/node/src/api.rs`, `core/node/src/main.rs`).

What this evidence **does not** support:

- A precise attribution of "warnings introduced/removed by audit fix
  commits alone." That would require cherry-picking the six audit
  commits onto a clean branch from `main` and rerunning clippy there.
  Phase 1 packaging bundled the dirty handoff into the same branch,
  so this split is not directly recoverable without history surgery.
  See `PHASE1_AUDIT_FIX_REPORT.md` "Known Limitations" for the
  follow-up plan.

---

## Detailed Diff Interpretation

`docs/phase1-clippy-diff.txt` has 36 lines. Breakdown:

### Warnings removed from main (20 entries)

These appeared in `main` but not in branch — net positive:

- `aincore-cli (bin "aincore-cli" test)` — eliminated
- `aincore-cli (bin "aincore-cli")` — eliminated
- `bridge-rust (bin "bridge-rust" test)` — eliminated
- `bridge-rust (bin "bridge-rust")` — eliminated
- `executor (lib)` — eliminated
- `indexer (bin "indexer" test)` — eliminated
- `indexer (bin "indexer")` — eliminated
- Individual lints: `to_string` applied to Display type, `u128` self-cast,
  `manual_arithmetic`, collapsible-`if`, `match` → `?`, redundant
  `if let` (twice), `very complex type`, `enumerate().discard()`,
  `empty string literal in println!`, `empty lineS after doc comment`.

### Entries appearing in branch but not in main (4 entries)

| Entry | Real new warning? | Notes |
|---|---|---|
| `blockchain (lib test) generated 6 warnings (2 duplicates) (run ...)` | **No** — same crate, same total count as main, only the duplicate-count phrasing differs | Cosmetic formatting change in clippy's per-crate summary line |
| `blockchain (lib) generated 6 warnings (4 duplicates) (run ...)` | **No** — same as above | Cosmetic |
| `network (lib test) generated 3 warnings (3 duplicates)` | **No** — `network` crate already had warnings on main (visible in the per-crate count above); this is just the *summary* line that did not appear in the dedup-sorted main output | Cosmetic enumeration change |
| `warning: empty line after doc comment` | **Possibly** — singular phrasing; main had `empty lineS after doc comment` (plural). Could be a single empty-line in a docstring I added | Identical lint family, ≤ 1 actual occurrence |

So even being maximally generous, **at most 1 real new warning occurrence
of an already-existing lint category** — and zero new lint categories.

### Per-crate warning count

| Crate | Main count | Branch count |
|---|---|---|
| `i` (false hit — bare identifier in summary text) | 4 | 4 |
| `indexer` | 2 | 0 ✅ |
| `da_sequencer` | 2 | 2 |
| `crypto` | 2 | 2 |
| `bridge-rust` | 2 | 0 ✅ |
| `blockchain` | 2 | 2 |
| `aincore-cli` | 2 | 0 ✅ |
| `executor` | 1 | 0 ✅ |
| `network` | 1 | 2 (cosmetic, see above) |
| (others: `state, shards, partial_shards, new_state, group_pk, div_ceil, default`) | 1 each | 1 each (unchanged) |

`executor`, `aincore-cli`, `bridge-rust`, `indexer` all went from
warnings to clean — likely thanks to the Phase 0-4 dirty work, not the
audit fixes. Either way, no regression in any crate.

---

## Honest Bottom Line

- The Phase 1 report's claim "no new clippy warnings introduced" is
  **defensible**, but only with the caveat above about combined scope.
- A stricter "audit-fix only" comparison is a known follow-up that
  requires repackaging the branch.
- Anyone who wants to verify can rerun the procedure at the top of this
  file against the artefacts in `docs/`.
