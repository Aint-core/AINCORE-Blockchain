# Fees and block resources (bug ledger B14, B15, B65)

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

### 4. Writes pay for the state they add (B65)

What was wrong: a resource write cost a flat 500 gas (`MoveTo`), and nothing
charged the bytes a transaction's writes added. One 200M-gas block could add
about 200 MB of state, and the state is never pruned.

Rules:

- Every write to a `State` key (what the state root commits to) pays I/O gas:
  152 a write and 1 per 6 bytes written. Source: Aptos
  `storage_io_per_state_slot_write` (895,680 internal units) and
  `storage_io_per_state_byte_write` (890) over its `add` (5,880).
- Every byte a write adds to the state pays the state byte gas `g`.
  - A new key adds its key, its value and `NEW_KEY_BYTES`, the fixed part of
    the tree's rows for it (measured below).
  - An existing key adds its growth.
  - A delete or a shrink adds nothing and refunds nothing. EIP-3529 removed
    most refunds after GasToken stored state cheaply to sell back.
  - History keys (receipts, indexes) are not state: the body's byte gas pays
    for them (section 2).
- `g` follows demand as the base fee does (section 3), over state bytes, with
  its own target `T`. EIP-4844 runs blob gas the same way, apart from
  execution gas.
  - Over the target, the rise is capped at 1/8 a block: one module is many
    targets.
  - Under the target, `g` falls by `g * (T - added) / T / 8`, never below
    `g_min`.
  - `g` is stored in `sys:state_byte_gas` (state), absent at the floor.
- Move execution is still capped at `MAX_GAS_LIMIT` (10M). The writes are
  charged on top, from what the limit leaves, and the whole limit is capped
  at the block ceiling (200M). EIP-8037 splits the two the same way: execution
  gas capped at `TX_MAX_GAS_LIMIT`, the total far above it.
- The charge's own writes (the nonce, the account a first transaction
  creates) and the object loads are priced before anything runs.
  - A limit that cannot pay for them is refused before the VM, and
    `can_pay` refuses it too, so no block reserves space for it.
  - Once the VM has run, every outcome is charged: a limit that does not
    cover execution and writes aborts, and the fee and nonce stay.
  - Refusing after the VM would give free execution and free block
    reservations (independent review, 2026-10-04).
- `aincore_estimateGas` runs a whole transaction (signature zero-filled at its
  length) against the current state, on the RPC's blocking pool, two at most
  at once. It answers execution, I/O and new bytes at `g x 81/64`, the most
  `g` can reach two blocks on. The CLI and the SDK ask for it; the CLI's
  `--execution-gas` overrides it.

Derivation of `g_min`:

- EIP-8037 (status Review, read 2026-10-03) prices a state byte at 1,530 gas:
  (gas limit / 2 x 2,628,000 blocks a year) / 120 GiB, at a 150M reference
  limit.
- Ethereum's `ADD` costs 3 gas, so a state byte there is worth 510 `ADD`s.
- An `add` costs 1 gas here (`GasSchedule::instruction_cost`), so
  `g_min = 510`.

Derivation of `T`:

- Inputs: minimum disk 100 GB; blocks take half of it (section 2);
  4,654,000 blocks a year.
- **Choice:** the other half holds the OS and indexes (10 GB) and the state
  (40 GB). The state's 40 GB must last four years of growth at the target,
  a typical hardware refresh. That is 10 GB of disk a year.
- Disk bytes per charged byte, at most 3. A new key writes:
  - its flat row (key and value);
  - the tree's preimage row (the key again);
  - its value row (the value again, in hex: 2 bytes a byte);
  - its leaf, and its share of the internal nodes.
  A large value is the worst case: 3 bytes of disk per charged byte.
- `T = 10 GB / 4,654,000 / 3 = 716` charged bytes a block.

Measured: the tree rows a key adds (`measure_tree_bytes_per_key`, 2,000 keys
added to a 20,000-key tree):

| Key bytes | Value bytes | Tree bytes, new key | Before pruning | A rewrite, before pruning | After |
|---|---|---|---|---|---|
| 40 | 50 | 632.0 | 1,360.0 | 1,423.0 | 0 |
| 40 | 1,050 | 2,632.0 | 3,360.0 | 3,423.0 | 0 |
| 240 | 50 | 832.2 | 1,567.8 | 1,406.3 | 0 |
| 110 | 200 | 1,004.4 | 1,736.7 | 1,707.7 | 0 |

A new key's tree rows are `K + 2V + 492` bytes in every row (the preimage
holds the key once more, the value row the value in hex): `NEW_KEY_BYTES =
492`. With its flat row, a new key costs the disk `2K + 3V + 492` for a
charge of `K + V + 492`: at most 3 bytes of disk per charged byte, as the
target assumes. A rewrite's history rows go once the version is pruned; its
I/O gas pays for them meanwhile.

Consequences, at the floor (`g = 510`, base fee `b_min`):

- A transfer that creates the recipient's CoinStore adds 645 charged bytes:
  the 121-byte key, a 32-character value and 492. That is 328,950 gas, about
  8.8 x 10^-4 AIN. The transfer's own bytes cost about 180,000 gas.
- A 4 KB module is stored as 8 KB of hex: about 4.4M gas, about 0.012 AIN.
- One block adds at most 200M / 510 = 392 KB of charged state (1.2 MB of
  disk). Before this change it was about 200 MB.
- Under sustained demand, `g` rises until blocks add `T`: 10 GB of disk a year.
  - From the floor, blocks full at the ceiling add at most
    392 KB x (1 + 1/1.125 + 1/1.125^2 + ...) = 3.5 MB while `g` rises.
  - `g` doubles in 6 blocks, about 40 s.

## Order of work

1. Measure `c` and `o` (B6): what a block writes, per byte of body.
2. Body = what paid (item 1), with its sync, QC and recovery tests.
3. Intrinsic byte gas (B14), with `estimateGas`, the SDK and the CLI.
4. Base fee (B15), with its RPC (`aincore_getGasPrice` returns it).
5. A spam test: one key filling blocks. The price must grow 1.125x per block
   and the body bytes must stay at the target.

Items 2-4 change consensus. They ship with the fresh V5 genesis.
