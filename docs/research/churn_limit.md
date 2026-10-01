# Validator churn limit (G5 Open item, research (d) 10)

Status: decided (CH-1 below). The limit must be in the stdlib before the validator set opens to
independent operators, which precedes public mainnet. Sources were read on 2026-10-02 at each
project's branch head; "live" means queried from the chain's public node.

## What other chains do

| Chain | Mechanism | Constant and value | Source |
|---|---|---|---|
| Ethereum phase0 | One churn limit for activations and exits: `max(4, n_active // 65536)` validators per epoch | `MIN_PER_EPOCH_CHURN_LIMIT` 4, `CHURN_LIMIT_QUOTIENT` 65,536 | consensus-specs `specs/phase0/beacon-chain.md` |
| Ethereum Deneb | Activations capped at 8 validators per epoch (EIP-7514); exits not capped by it | `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT` 8 | `specs/deneb/beacon-chain.md` |
| Ethereum Electra | Churn by balance: `max(128 ETH, total // 65536)`, activations and exits at most 256 ETH per epoch | `MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA`, `MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT` | `specs/electra/beacon-chain.md` |
| Ethereum | Weak-subjectivity period from the churn (at most ~3,532 epochs, ~15.7 d) | `SAFETY_DECAY` 10 % | `specs/*/weak-subjectivity.md` |
| Aptos | Voting power joining in one epoch ≤ limit % of total voting power; checked in join and add_stake; reset each epoch | `voting_power_increase_limit`: code allows (0, 50], default 20, **mainnet live 10**, epoch 7,200 s | aptos-framework `stake.move`, `staking_config.move`; mainnet `0x1::staking_config::StakingConfig` |
| CometBFT | No limit on voting-power change; updates of block H apply at H+2. The skipping light client needs ≥ 1/3 of trusted power to remain, else it bisects | `DefaultTrustLevel` 1/3 | cometbft `types/validator_set.go`, `light/verifier.go` |
| Sui | No per-epoch join limit; a per-validator voting-power cap of 10 % and join thresholds (SIP-39) | `MAX_VOTING_POWER` 1,000 bp | sui-system `voting_power.move`, `validator_set.move` |
| Cosmos SDK | No churn limit: top `MaxValidators` re-picked every EndBlock | `MaxValidators`, `MaxEntries` 7 (not a churn limit) | cosmos-sdk v0.50.10 `x/staking` |
| Polkadot | Full NPoS re-election every era; no churn limit | `SessionsPerEra` 6, `BondingDuration` 28 eras | polkadot-fellows runtimes |

Write-ups: Asgaonkar, "Weak Subjectivity in Eth2.0" (period = D·|V| / (2·churn)); Buterin,
"Rate-limiting entry/exits, not withdrawals" (ethresear.ch 4942) and "Weak subjectivity under
the exit queue model" (5187); Casper FFG §3 (dynasty d+2, no numeric cap); Lamport, Malkhi and
Zhou, "Reconfiguring a State Machine" (α-delayed change, no cap); Sui Lutris §4.2 (a `Ready`
quorum of new validators before handover, no cap).

## What the limit protects here

1. **Not weak subjectivity.** Ethereum needs churn for it because its withdrawal delay is only
   ~27 h. Here unbonding U = 21 d exceeds the checkpoint age (≤ 14 d, `clock_and_deadlines.md`
   §5), every committee hand-off is a quorum certificate of the previous committee (G1 EP-4),
   and light clients verify sequentially. A fork after a checkpoint needs a third of a still
   bonded committee to sign twice, which is slashable while the evidence lands within W.
2. **Takeover speed.** Without a limit, stake bought in one epoch can hold a third of the next
   committee one boundary later (~1.85 h). With an increase cap L per epoch, honest stake
   fixed, the newcomers' share after k epochs is s_k = 1 − (1 + L)^(−k) (each epoch the total
   grows by L). At L = 10 %: 1/3 after 5 epochs (~9 h), 2/3 after 12 epochs (~22 h). That is
   time for operators to see it and respond.
3. **Newcomer liveness.** A committee halts when more than a third of its stake is offline.
   Aptos states this purpose for its limit (stake that "can potentially take down the network if
   corresponding validators are not ready"). With at most 10 % new per epoch, one wave of
   unready joiners cannot halt the chain while the existing members' faults stay under ~23 %.

## CH-1 (decision)

- **Rule.** Within one committee epoch E, the stake added to validators that are, or will be at
  E+1, in the active set (a join, `add_stake`, and a delegation deposit into an open pool, which
  the boundary refresh counts into the validator's weight) may total at most
  `CHURN_INCREASE_BPS` = 1,000 (10 %) of C_E's total stake. A transaction that would exceed it
  aborts (`ECHURN_LIMIT`); it can be retried in a later epoch. The counter resets at every
  boundary.
- **Why 10 %.** Aptos mainnet's live value, on an epoch (2 h) almost equal to ours (~1.85 h);
  it gives the 5- and 12-epoch takeover times above. 20 % (Aptos's default) halves them, and
  under 5 % a planned onboarding of an independent operator with a third of the stake would take
  more than 8 epochs.
- **Exits are not limited.** Leaving lowers the attacker's share only if honest stake leaves,
  which is the honest holders' choice, and exiting stake stays slashable through U (SL-2). The
  top-256 election already removes members at boundaries. Ethereum's exit cap exists for its
  weak-subjectivity bound, which does not bind here (point 1).
- **Genesis stake is not counted:** genesis writes the committee directly, and epoch 0's
  allowance is 10 % of the genesis committee. The founder's onboarding of independent operators
  must be planned at most 10 % of the stake per epoch.
- **State.** `0x1::staking::ChurnState {epoch, base, added}`, in quanta. Genesis writes epoch 0's
  and the executor rewrites it at every boundary (`added` = 0, `base` = C_{E+1}'s stake), like
  the clock (CL-2); Move only counts and refuses. A chain without it (a test fixture) has no
  limit; genesis always writes it (witness `the_genesis_opens_epoch_zeros_churn_allowance`).
- **Where.** In `staking.move` (join, add_stake) and `delegation.move` (deposit), as Aptos does:
  the user learns at once, and the Rust election (`next_committee`) stays a pure function of the
  Move set.

Not adopted: Sui's per-validator voting-power cap (a concentration rule, a separate decision),
and limits in validator count (the committee is already capped at 256 by stake).
