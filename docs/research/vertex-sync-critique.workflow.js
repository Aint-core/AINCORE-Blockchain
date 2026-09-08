export const meta = {
  name: 'aincore-vertex-sync-critique',
  description: 'Adversarial critique of docs/DAG_VERTEX_SYNC_DESIGN.md v3: Part I (Stage 1) and Part II (Stages 2-4) attacked by separate critic sets, every hole verified by two refuters, before any code',
  phases: [
    { title: 'Break', detail: 'Part I: four lenses. Part II: four lenses. Independent critics, each reads the design and the 16 invariants.' },
    { title: 'Verify', detail: 'refute-by-default, two verifiers per claimed hole' },
    { title: 'Verdict', detail: 'separate verdicts for Part I and Part II' },
  ],
}

const REPO = '/Users/macbookpro/Documents/AINCORE-Blockchain'
const DESIGN = `${REPO}/docs/DAG_VERTEX_SYNC_DESIGN.md`
const CATALOG = `${REPO}/docs/research/D-failure-catalog.json`

const CONTEXT = `
AINCORE is a sovereign Rust L1 at ${REPO}, branch audit/mainnet-hardening, HEAD 3208d29.
The DESIGN under attack is ${DESIGN} (v3). Read it in full first. The 16 invariants it
must satisfy, each from a real failure in a prior review round, are at ${CATALOG}. Read
them. Research inputs are in ${REPO}/docs/research/.

History you must assume repeats: four code fixes and two design drafts for this exact
problem all failed independent review — v1 with 9 confirmed holes, v2 with 21. Every
failure was a defect the author introduced, and the author is the same each time. v2's
five worst holes were ONE root cause (arrival-order anchor selection under equivocation)
that the author had explicitly claimed was "unaffected". Assume v3 contains a claim of the
same kind. Your value is what the author cannot see.

v3 is split: Part I (Stage 1, sections 3-4) is meant to be shippable ALONE, with no
messages, no WANTED, no shadow. Part II (Stages 2-4, sections 5-8) depends on Part I. You
are assigned to one part; stay inside it, but if a Part I hole is what breaks your Part II
claim, say so explicitly.

Verify every AINCORE file:line the design cites against the actual code at HEAD before
relying on it. Report only holes you can state as a concrete attack or failure sequence
with the design section and the code line. Vague concerns are not findings.
`

const CRITIQUE_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['holes'],
  properties: { holes: { type: 'array', maxItems: 8, items: {
    type: 'object', additionalProperties: false,
    required: ['title', 'severity', 'confidence', 'attack', 'which_invariant', 'design_section', 'design_fix', 'part'],
    properties: {
      title: { type: 'string' },
      severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM'] },
      confidence: { type: 'integer', minimum: 1, maximum: 10 },
      attack: { type: 'string' },
      which_invariant: { type: 'string' },
      design_section: { type: 'string' },
      design_fix: { type: 'string' },
      part: { type: 'string', enum: ['I', 'II'] },
    } } } },
}
const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['refuted', 'reason'],
  properties: { refuted: { type: 'boolean' }, reason: { type: 'string' } },
}

const PART_I = [
  ['I-walk-termination', `PART I. R1 now uses resolve_walk = walk_history with floor 0 (section 3), edge checks INSIDE the walk (parent.round == child.round-1, parent.author in validator_set_at(parent.round)), and a cache with Resolved/Unresolved{blocked_on} verdicts re-walked on admission, on sync settlement, and every tick while R4 fails. Read ordering.rs walk_history (:683-714), commit_one_anchor (:720-748), and dag.rs try_create_vertex (:529-585). Attack: can a poison vertex or an attacker chain still become Resolved on any honest node? Can a stale Resolved cache entry survive a prune or a committed_set window eviction and lie? Is the per-tick re-walk of round-(r-1) candidates bounded as claimed, or can an attacker make it O(cone) x n every tick forever? Can two honest nodes reach DIFFERENT verdicts for the same vertex from the same bytes (the walk consults local dag - trace exactly when that is deterministic and when it is not)?`],
  ['I-quorum-and-skip', `PART I. R4 computes parent_quorum_met over the CITED list and refuses to propose below > 2/3; R4' makes a vertex anchor-eligible only with > 2/3 present-parent stake and defers otherwise (section 3.1, 3.3). Read ordering.rs try_commit step 1 (:554-567) and step 2 (:583-597), direct_quorum_met (:650-676), the B4b comment (:505-523), and the three test_b4b_* tests (:1655-1808). Attack: find a sequence where two honest nodes commit DIFFERENT anchor sequences, or where the ancestry skip fires on one node and not another. Consider: a node that resolves > 2/3 but a DIFFERENT > 2/3 than its peers; leader rounds where the leader vertex is present on some nodes and not others; R4' evaluated on present-parent stake that differs per node; stake changes between validator_set_at(round-1) and the current set used for quorum; n=4 with exactly one honest vertex lost. Does deferral ever become permanent for an honest leader?`],
  ['I-admission-determinism', `PART I. v2's R2 was rejected because admission depended on local state. v3 keeps at ingress only: the existing 12 checks, non-empty parents at round > 1, and membership via validator_set_at(vertex.round) (sections 3.2, 3.3). Read dag.rs add_vertex ingress (:947-1090) and the validator set write sites in core/executor/src/lib.rs (:2532-2580, :866-912) and dag.rs get_validator_set_with_stake (:3024-3063). Attack: is validator_set_at(round) itself deterministic and available on every node at the moment ingress needs it (a node that has not yet executed the block that changed the set)? Can the same bytes still be admitted on one node and rejected on another through ANY remaining check (timestamp drift dag.rs:980-991, round jump :964, current-set reads that remain)? What does a node do with a vertex whose round's set snapshot it does not have yet? Can the snapshot rows be griefed or made to disagree?`],
  ['I-tests-and-exit', `PART I. Walk every Part I row of section 10 (rows 1-8) and the Stage 1 exit criterion in section 4. For each test: could it PASS with its named mutation applied? (The author has shipped such tests three times.) Is the burn-in criterion "byte-identical committed sequences and identical anchor_hash per height" actually observable with the RPCs at HEAD (core/node/src/api_local.rs), and does it detect the v1 silent-exclusion failure? Is anything Part I claims to close actually left open, and is anything in Part I secretly dependent on Part II?`],
]

const PART_II = [
  ['II-equivocation-E1E2', `PART II, THE PART THAT FAILED TWICE. Section 6: leader_vertex_hash returns ALL twins in dag ∪ shadow (E1); a leader round is decided by direct votes keyed on (author, round) - commit at the twin with > 2/3 votes, skip if the walked >= 2/3-stake r+1 set has <= 1/3 total votes for any twin, else defer (E2); step 2 never decides a twinned round by visited; NO exclusion rule; one compact+parents shadow per (author, round). Read ordering.rs try_commit fully (:527-620), leader_vertex_hash (:634-647), direct_quorum_met (:650-676), and dag.rs equivocation branch (:1143-1168). Attack E2 with every delivery split the offender can choose at n=4 and n=7, with the offender as leader of r AND of r+2, with twins that cite DIFFERENT parent sets, with the offender's own r+1 vote, and with nodes at different cursor positions. Can two honest nodes commit different anchor_hash for r? Can E2 defer forever? Does "skip if <= 1/3" ever skip a round some node already committed directly? Is the shadow's compact+parents form sufficient for every walk that needs it (find_causal_history ordering.rs:964-990 reads payload?).`],
  ['II-wanted-bounds', `PART II. Sections 5.2, 5.4, 5.5: Tier A (> 1/3 witness stake), Tier B (observable form, from the author only, <= MAX_PARENTS per (X,r), one frame/16 ticks), probe; budgets 256 + 256 with per-author quota 4; TTL 64 receiver ticks; no entries for round > current+2; per-request deadline 2 ticks; per-peer in-flight 2; separate pools 12/4. Read common/network/src/lib.rs timeouts (:17-18, :207-233, :638-670) and dag.rs MAX_ROUND_JUMP (:946-970). Attack every bound: which one can a single validator key, or an unauthenticated TCP peer, inflate or starve? Can Tier A be filled with attacker-witnessed entries (the offender's own vertices are witnesses)? Can the 2-tick deadline be too short on the real 3 s tick / 150 ms WAN and starve honest fetches? Quantify worst-case bytes, requests/s, and CPU on a Raspberry Pi validator.`],
  ['II-fetch-liveness', `PART II. Sections 5.1, 5.3, 5.5, 7: trigger = proposer walk collecting ALL missing hashes; fetch over direct TCP through handle_message with validator_set_at; release on admission or sync settlement. Read sync/src/lib.rs (:625-699, :1200-1248), dag.rs reload_chain_tip (:2843-2884, :2998-3011), the boot loops (:211-373). Attack liveness: find a sequence (packet loss, restart, partition heal, offender withholding, n=4 and n=100) where an honest validator never regains > 2/3 resolved parents, or where WANTED entries are created and expire without ever being requested, or where a fetched body is admitted but its dependents are never re-walked. Does the Stage 1 tick re-walk and Part II release interact badly (double walks, missed walks)?`],
  ['II-invariants-and-tests', `PART II. Walk I2, I3, I4, I5, I6, I7, I8, I9, I10, I13, I14 in ${CATALOG} against section 9, and every Part II row of section 10 (rows 8-17). For each invariant: does the cited element GUARANTEE it, or merely assert it? For each test: could it pass with its mutation applied? Pay special attention to the two leader_equivocation tests and phantom_proof: do they actually distinguish E2 from v2's broken design? Report any invariant claimed satisfied that is not, and any test that cannot fail.`],
]

const ALL = [...PART_I.map((l) => ['I', ...l]), ...PART_II.map((l) => ['II', ...l])]

phase('Break')
log(`Eight lenses: ${PART_I.length} on Part I, ${PART_II.length} on Part II`)
const critiques = await parallel(ALL.map(([part, key, lens]) => () =>
  agent(`${CONTEXT}\n\nYOU ARE ASSIGNED PART ${part}.\n\nYOUR LENS: ${lens}\n\nBREAK IT. Set part="${part}" on every hole. Refuse to report vague concerns.`,
    { label: `critic:${key}`, phase: 'Break', schema: CRITIQUE_SCHEMA, effort: 'high' })
))
const holes = critiques.filter(Boolean).flatMap((c) => c.holes || [])
log(`${holes.length} candidate holes (${holes.filter((h) => h.part === 'I').length} Part I, ${holes.filter((h) => h.part === 'II').length} Part II); verifying each with two refuters`)

phase('Verify')
const verified = await parallel(holes.map((h) => () =>
  parallel([0, 1].map((li) => () => agent(`${CONTEXT}

Adversarial verifier. REFUTE BY DEFAULT. A critic claims a hole in the DESIGN. Read the
design section it cites and the AINCORE code it relies on.

CLAIMED HOLE (Part ${h.part}): ${h.title} [${h.severity}, critic confidence ${h.confidence}/10]
  section: ${h.design_section}
  attack: ${h.attack}
  invariant: ${h.which_invariant}

${li === 0
  ? 'LENS: is the attack sequence actually possible under the design AS WRITTEN and the code AT HEAD? Does the design already handle it in a section the critic missed? Does the critic misread a file:line?'
  : 'LENS: is the severity right and in scope for its Part? Downgrade if it needs privileges the attacker lacks, or if it is an acknowledged residual in section 12, or if it is a Part II concern reported against Part I.'}

Set refuted=true unless you can confirm the hole is real.`,
    { label: `verify:${h.part}`, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' })
  )).then((vs) => { const v = vs.filter(Boolean); return { hole: h, verifiers: v.length, survived: v.length > 0 && v.filter((x) => x.refuted).length < Math.ceil(v.length / 2) } })
))
const confirmed = verified.filter((v) => v.survived).map((v) => v.hole)
const unverified = verified.filter((v) => v.verifiers === 0).map((v) => v.hole)
log(`${confirmed.length} confirmed (${confirmed.filter((h) => h.part === 'I').length} Part I, ${confirmed.filter((h) => h.part === 'II').length} Part II); ${unverified.length} UNVERIFIED (verifiers died)`)

phase('Verdict')
const fmt = (hs) => hs.length ? hs.map((h, i) => `${i + 1}. [${h.severity} c${h.confidence}] ${h.title}\n   section: ${h.design_section}\n   attack: ${h.attack}\n   invariant: ${h.which_invariant}\n   fix: ${h.design_fix}`).join('\n') : '(none)'
const verdicts = await parallel(['I', 'II'].map((part) => () => agent(`${CONTEXT}

VERDICT FOR PART ${part} ONLY.

CONFIRMED HOLES IN PART ${part} (survived two refuters each):
${fmt(confirmed.filter((h) => h.part === part))}

UNVERIFIED (verifiers died - treat as OPEN, not refuted):
${fmt(unverified.filter((h) => h.part === part))}

Give a plain-text verdict for Part ${part}: IMPLEMENT AS WRITTEN / REVISE (list exact
section edits) / REDESIGN (say what is fundamentally wrong). ${part === 'I'
  ? 'State whether Stage 1 may start, and exactly what its gate must prove.'
  : 'State whether the equivocation rule E2 is sound, and which Stage may start first.'}
Be decisive.`, { label: `verdict:${part}`, phase: 'Verdict', effort: 'high' })))

return {
  holes_found: holes.length,
  holes_confirmed: confirmed.length,
  holes_unverified: unverified.length,
  confirmed_holes: confirmed,
  unverified_holes: unverified,
  verdict_part_I: verdicts[0],
  verdict_part_II: verdicts[1],
}
