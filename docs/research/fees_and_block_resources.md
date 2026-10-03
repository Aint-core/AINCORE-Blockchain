# Fees and block resources (bug ledger B14, B15)

Status: built 2026-10-03 (B14 body and byte gas, B15 base fee); see the ledger for the commit. Every number below is either
measured, read from the code or the operator guide, or marked **choice** with
its reason.

## What is wrong today

1. **Fees resist nothing (B15).** `MIN_GAS_PRICE` is 1 quanta (10^-18 AIN) per
   gas and nothing raises it. A full block (200M gas) costs its senders
   2 x 10^-10 AIN. One funded key can keep every block full.
2. **Bytes are free (B14).** Gas is the declared `gas_limit`, charged in full;
   no part of it depends on the transaction's size. A 100 KiB transaction pays
   what a 400-byte one does.
3. **Unexecuted transactions are stored for nothing.** The block body is every
   committed payload item (`dag.rs`: `block_txs`). Items over the block gas
   ceiling, items with a wrong nonce and items whose payer cannot pay are not
   executed, pay nothing, and stay in the body that every node keeps for
   100,000 blocks. While this holds, no fee can bound storage.

## Inputs

| Input | Value | Source |
|---|---|---|
| Block interval | 6.78 s | TESTNET-V4, 26,133 s of consensus time over 3,854 blocks (2026-10-03) |
| Rounds per block | 2.2 | V4: 8,496 rounds / 3,854 blocks (anchors every 2 rounds, B5 misses) |
| Block gas ceiling | 200,000,000 | `MAX_BLOCK_GAS_LIMIT` |
| Per-transaction gas cap | 10,000,000 | `MAX_GAS_LIMIT`, bounds Move execution work |
| Wallet gas limit for a transfer | 5,000 (CLI), 10,000 (SDK) | `core/cli/src/main.rs`, `aincore-js/src/transaction.ts` |
| Ed25519 transfer size | ~450 B | JSON with a 32 B key and a 64 B signature, hex |
| ML-DSA-65 transfer size | ~10.5 KB | 1,952 B key and 3,309 B signature, hex |
| Minimum validator disk | 100 GB | `docs/NODE_OPERATOR_GUIDE.md` |
| Blocks a full node keeps | 100,000 | `AINCORE_BLOCK_RETENTION` default |
| Empty-block storage | ~10 KB | S6 measurement (B6) |
| Year-1 emission | 2,498,500 AIN | 1.90 % of the 131,497,918 AIN reserve (V4 `getEconomics`) |
| Blocks per year | 4,654,000 | 31,557,600 s / 6.78 s |

## Design

### 1. The body is what paid (closes item 3)

The block body holds the transactions that executed and paid gas, in order.
`tx_hash`, `receipts_root` and `da_root` are computed over that list. A
transaction that did not execute (over the ceiling, wrong nonce, unaffordable,
below the base fee) leaves the body. It goes back to its proposer's mempool by
the existing loan ledger, or is dropped.

Execution is deterministic, so every node builds the same body from the same
committed sequence. A node that syncs the block executes exactly its body,
every transaction of which executed on the producer, so it reaches the same
state.

Precedent: Ethereum blocks carry only valid transactions. Aptos commits only
kept transactions; discarded ones are not written to the ledger.

### 2. A charge per transaction byte (B14)

A transaction must declare `gas_limit >= intrinsic`, where
`intrinsic = BYTE_GAS * len(raw transaction)`. Move execution gets
`gas_limit - intrinsic`, capped at `MAX_GAS_LIMIT` as now.

Derivation of `BYTE_GAS`:

- **Choice:** blocks may use half of the minimum disk over the retention
  window. The other half is for state, indexes and the operating system.
  That gives 0.5 x 100 GB / 100,000 blocks = 500 KB per block on average.
- A block stores its body more than once (block JSON, transaction index,
  receipts). Write the factor as `c` and the empty-block overhead as `o`
  (~10 KB measured). Then the target body is `T = (500 KB - o) / c`. `c` must
  be measured (B6) before the constant is fixed. For `c = 2`, `T = 245 KB`.
- The EIP-1559 target is half the ceiling, `G_t = 100,000,000`. A target block
  made only of bytes is `T` bytes when `BYTE_GAS = G_t / T`. For `c = 2` that
  is 408 gas per byte.

Consequences:

- An Ed25519 transfer's intrinsic gas is ~180,000, so the wallet defaults
  (5,000 and 10,000) must rise. Wallets get the value from `aincore_estimateGas`,
  which includes the intrinsic charge.
- A 100 KiB transaction needs ~42M gas of bytes, so the per-transaction cap
  applies to the execution part only, not to `gas_limit` as a whole.

### 3. An EIP-1559 base fee (B15)

- State `sys:base_fee` (quanta per gas), in the state root.
- After each block, with `g` the gas the block charged and `G_t` its target:
  - if `g > G_t`: `b += max(1, b * (g - G_t) / G_t / 8)`;
  - if `g < G_t`: `b -= b * (G_t - g) / G_t / 8`;
  - `b` never goes below `b_min`.

  Integer arithmetic as in EIP-1559, with its denominator 8 and elasticity 2.
- A transaction needs `gas_price >= b` when it executes.
  - The mempool checks it against the committed base fee.
  - The stateless check keeps `b_min` as its floor.
  - The executor drops a transaction that falls below (item 1: it leaves the
    body, pays nothing).
- Payment is `gas_limit * gas_price`.
  - `gas_limit * b` is **burned**: EIP-1559's reason, so that a block producer
    cannot pay the base fee to itself (Roughgarden, "Transaction Fee
    Mechanism Design for the Ethereum Blockchain", 2020).
  - The rest, the tip, follows today's rule (the burn percentage, then the
    anchor leader).
- Under sustained full blocks the price grows 1.125x per block, about 2.8x a
  minute at 6.78 s blocks.

Derivation of `b_min`:

- **Choice:** at the floor, filling one block costs one block's year-1
  emission, so spam is never cheaper than what the chain pays to produce the
  space. 2,498,500 / 4,654,000 = 0.537 AIN a block, over 200M gas, gives
  `b_min = 2.68 x 10^9` quanta per gas.
- Without a floor (Ethereum's choice), a spammer starting at 1 quanta would
  need ln(2.68e9) / ln(1.125) = 184 full blocks, about 21 minutes, to reach
  that price.
- At the floor, a 200,000-gas transfer costs 5.4 x 10^-4 AIN.

## Order of work

1. Measure `c` and `o` (B6): what a block writes, per byte of body.
2. Body = what paid (item 1), with its sync, QC and recovery tests.
3. Intrinsic byte gas (B14), with `estimateGas`, the SDK and the CLI.
4. Base fee (B15), with its RPC (`aincore_getGasPrice` returns it).
5. A spam test: one key filling blocks. The price must grow 1.125x per block
   and the body bytes must stay at the target.

Items 2-4 change consensus. They ship with the fresh V5 genesis.
