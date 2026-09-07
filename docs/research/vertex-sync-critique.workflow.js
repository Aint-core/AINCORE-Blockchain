export const meta = {
  name: 'aincore-vertex-sync-critique',
  description: 'Six-lens adversarial critique of docs/DAG_VERTEX_SYNC_DESIGN.md, each hole verified by two refuters, before any code is written',
  phases: [
    { title: 'Break', detail: 'six independent critics attack the design against the 16 invariants' },
    { title: 'Verify', detail: 'refute-by-default, two verifiers per claimed hole' },
    { title: 'Verdict', detail: 'implement / revise / redesign' },
  ],
}

const REPO = '/Users/macbookpro/Documents/AINCORE-Blockchain'
const DESIGN = `${REPO}/docs/DAG_VERTEX_SYNC_DESIGN.md`
const CATALOG = `${REPO}/docs/research/D-failure-catalog.json`

const CONTEXT = `
AINCORE is a sovereign Rust L1 at ${REPO}, branch audit/mainnet-hardening, HEAD 3208d29.
A DESIGN for DAG vertex synchronization is at ${DESIGN}. Read it in full first.
The 16 invariants it must satisfy, each extracted from a real failure in one of four
prior review rounds, are at ${CATALOG}. Read that too. The other research inputs are
in ${REPO}/docs/research/.

History you must assume repeats: FOUR previous designs for this exact problem passed
their author's own reasoning and failed independent review, every time because of a
defect the design itself introduced. The author of this design was the author of all
four. Your value is finding what the author cannot see.

The design's central claim is NEW and must be attacked hardest: that the malicious
never-existing-parent case is neutralised purely by a CITING-side rule (R1: honest
proposers cite only history-resolved vertices) plus the existing deterministic
leader-skip in ordering.rs, with NO ingress rejection, NO buffer and NO fetch for
that case; and that fetching is reserved for hashes whose citers hold > 1/3 stake
(stake-weighted ImPoA). Verify every AINCORE file:line the design cites against the
actual code at HEAD before relying on it.

RULES: report only holes you can state as a concrete attack or failure sequence,
citing the design section and AINCORE file:line. Vague concerns are not findings.
`

const CRITIQUE_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['holes'],
  properties: { holes: { type: 'array', maxItems: 8, items: {
    type: 'object', additionalProperties: false,
    required: ['title', 'severity', 'confidence', 'attack', 'which_invariant', 'design_section', 'design_fix'],
    properties: {
      title: { type: 'string' },
      severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM'] },
      confidence: { type: 'integer', minimum: 1, maximum: 10 },
      attack: { type: 'string' },
      which_invariant: { type: 'string' },
      design_section: { type: 'string' },
      design_fix: { type: 'string' },
    } } } },
}
const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['refuted', 'reason'],
  properties: { refuted: { type: 'boolean' }, reason: { type: 'string' } },
}

const LENSES = [
  ['r1-malicious', `THE CENTRAL CLAIM (design §3). Trace the never-existing-parent attack through HEAD code with R1 in place. Read dag.rs try_create_vertex (parents = round_index[prev], :529-536), ordering.rs try_commit step 1 and step 2 (:554-600), leader_vertex_hash (:637-647), direct_quorum_met (:650-676), walk_history (:683-714), commit_one_anchor (:720-748), and the three test_b4b_* tests (:1655-1808). Find a sequence where the attacker's vertex or a descendant STILL enters an honest anchor's causal cone, or where the skip is NOT deterministic across nodes (different nodes skip differently -> fork), or where the attacker as leader at an even round causes deferral that never resolves. Consider the attacker holding 1/3 stake exactly, multiple attackers, and the attacker's vertex being cited by an honest node that had not yet evaluated R1 at the moment of citation.`],
  ['impoa-and-fetch', `ImPoA and the fetch (design §5). Can an adversary with <= 1/3 stake make a hash fetch-worthy that no honest node holds (e.g. by equivocating so honest nodes cite different things, or by getting honest nodes to cite an attacker vertex BEFORE R1 marks it unresolved)? Can the WANTED set be filled with 256 entries the attacker controls? Can the attacker make honest nodes send requests at a rate that matters? Can a response that is valid-but-useless (e.g. the vertex at the wrong round, or an equivocating twin) be used to keep a hash WANTED forever or to poison the DAG? Check the 'whom to ask' order: is asking a CITER first exploitable?`],
  ['liveness', `LIVENESS under R1 (design §3 cost, §5, §6). R1 narrows what a node cites. Find a sequence — packet loss, restart, partition heal, n=4 and n=100 — where honest nodes' R1-filtered parent sets diverge enough that parent quorum or direct quorum is never met, or where two honest nodes commit DIFFERENT anchors because their R1 views differ. Note direct_quorum_met counts stake of r+1 vertices PRESENT in the local dag that cite the anchor: can R1 make node A see quorum and node B not, permanently? Does the catch-up floor (dag.rs:2998-3011) interact badly?`],
  ['equivocation-s6', `Equivocation (design §6 row 1, state S6). The design keeps drop-second and adds 'hash with a compact proof in sys:equiv_seen is settled'. Attack: is sys:equiv_seen content identical on every node (it is written locally on detection and via gossiped proofs — can it diverge, and does divergence in the settled predicate fork the commit)? Can an attacker plant a proof for a hash that is NOT an equivocation? What happens to the FIRST vertex A: it is in dag and citable — is A's own history resolved? Can the attacker equivocate at every round to force perpetual fetches? Verify leader_vertex_hash find_map really is unaffected.`],
  ['locks-reentrancy-bounds', `Locks, re-entrancy and bounds (design §5.5, §7). The fetcher takes consensus.write() per vertex; reload_chain_tip sweeps WANTED under a lock it already holds; walk_history returns holes. Find a lock-order inversion or re-entry against the real code (dag.rs:1273-1295 commit loop, dag.rs:2843-2884 reload_chain_tip, main.rs dispatch). Check every bound in the table: is any actually unbounded, sender-inflatable, or measured in the wrong unit? Is 256 WANTED entries safe when each entry's citer set is O(n)? Is the 1 MiB server trim correct against the 1 MiB inbound frame cap and the 10 MiB client read cap (network/src/lib.rs:239, B7)?`],
  ['invariant-audit-and-tests', `Walk EVERY invariant I1-I16 in ${CATALOG} against the design's checklist (§8) and test plan (§9). For each: does the cited design element truly guarantee it, or is the guarantee asserted rather than shown? For each test in §9, would the named mutation actually make it fail, or could the test pass with the mutation applied (the author has shipped such tests twice before)? Report any invariant that is claimed satisfied but is not, and any test that cannot fail.`],
]

phase('Break')
log('Six lenses attacking docs/DAG_VERTEX_SYNC_DESIGN.md')
const critiques = await parallel(LENSES.map(([key, lens]) => () =>
  agent(`${CONTEXT}\n\nYOUR LENS: ${lens}\n\nBREAK IT. Refuse to report vague concerns.`,
    { label: `critic:${key}`, phase: 'Break', schema: CRITIQUE_SCHEMA, effort: 'high' })
))
const holes = critiques.filter(Boolean).flatMap((c) => c.holes || [])
log(`${holes.length} candidate holes; verifying each with two refuters`)

phase('Verify')
const verified = await parallel(holes.map((h) => () =>
  parallel([0, 1].map((li) => () => agent(`${CONTEXT}

Adversarial verifier. REFUTE BY DEFAULT. A critic claims a hole in the DESIGN. Read the
design section it cites and the AINCORE code it relies on.

CLAIMED HOLE: ${h.title} [${h.severity}, critic confidence ${h.confidence}/10]
  section: ${h.design_section}
  attack: ${h.attack}
  invariant: ${h.which_invariant}

${li === 0
  ? 'LENS: is the attack sequence actually possible under the design AS WRITTEN and the code AT HEAD? Does the design already handle it in a section the critic missed?'
  : 'LENS: is the severity right and in scope? Downgrade if it needs privileges the attacker lacks, or if it is an acknowledged residual in design §11.'}

Set refuted=true unless you can confirm the hole is real.`,
    { label: 'verify-hole', phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' })
  )).then((vs) => { const v = vs.filter(Boolean); return { hole: h, survived: v.length > 0 && v.filter((x) => x.refuted).length < Math.ceil(v.length / 2) } })
))
const confirmed = verified.filter((v) => v.survived).map((v) => v.hole)
log(`${confirmed.length} holes confirmed`)

phase('Verdict')
const verdict = await agent(`${CONTEXT}

CONFIRMED HOLES (survived two refuters each):
${confirmed.length ? confirmed.map((h, i) => `${i + 1}. [${h.severity} c${h.confidence}] ${h.title}\n   section: ${h.design_section}\n   attack: ${h.attack}\n   invariant: ${h.which_invariant}\n   fix: ${h.design_fix}`).join('\n') : '(none)'}

Refuted (context only): ${verified.filter((v) => !v.survived).map((v) => v.hole.title).join(' | ') || '(none)'}

Give a plain-text verdict: IMPLEMENT AS WRITTEN / REVISE (list exact section edits) /
REDESIGN (the central claim R1 is broken — say why). Then state which Stage of §10 may
start first and what its gate must prove. Be decisive.`, { label: 'verdict', phase: 'Verdict', effort: 'high' })

return {
  holes_found: holes.length,
  holes_confirmed: confirmed.length,
  confirmed_holes: confirmed,
  verdict,
}
