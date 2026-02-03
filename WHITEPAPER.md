# AINCORE Blockchain - Technical Whitepaper

> **Version:** 3.0 (Production)  
> **Last Updated:** January 2026

---

## 🎯 TL;DR (Ringkasan Singkat)

| Aspek | AINCORE |
|-------|---------|
| **Konsensus** | **DAG-BFT PoS** (Proof of Stake + DAG Structure) |
| **Supply** | 150,000,000 AIN (Fixed Max Supply) |
| **Block Reward** | 36 AIN per block (Halving setiap 4 tahun) |
| **Block Time** | ~1-2 detik |
| **Fair Launch** | ✅ Ya (No Pre-mine, No ICO) |
| **Smart Contract** | Move VM (sama seperti Aptos/Sui) |
| **Unique Feature** | DePIN Mining (Mine dengan IoT/Biometrics) |

---

## 1. Apa itu AINCORE?

AINCORE adalah Layer-1 blockchain yang menggabungkan:

1. **DAG-Based Consensus** - Struktur transaksi berbentuk DAG (Directed Acyclic Graph), bukan linear chain
2. **Proof of Stake (PoS)** - Validator stake token untuk mendapatkan hak mining
3. **DePIN Mining** - Mine cryptocurrency menggunakan data dari IoT devices (smartwatch, breath sensors)
4. **Move Smart Contracts** - VM yang sama dengan Aptos/Sui untuk keamanan maksimal

---

## 2. Mekanisme Konsensus: DAG-BFT

### Bagaimana Kerjanya?

```
Round 1:    [V1] ──────────────────────────────────────┐
                                                        │
Round 2:    [V2] ──┬───────────────────────────────────┤
                   │                                    │
Round 3:    [V3] ──┴─ [V4] ─────────────────────────────┤
                         │                              │
Round 4:    [V5] ────────┴─ [V6] ───────────────────────┴─▶ COMMIT
```

1. **Setiap validator membuat "Vertex"** yang berisi transaksi
2. **Vertex terhubung ke vertex sebelumnya** (parent links)
3. **BFT Quorum (2f+1)** - Butuh mayoritas validator setuju
4. **Ordering Engine** - Setelah quorum tercapai, transaksi di-commit secara deterministik

### Keunggulan vs Linear Chain:
- **Parallel Processing** - Multiple validators bisa propose bersamaan
- **Higher Throughput** - Tidak bottleneck pada satu block producer
- **Faster Finality** - Transaksi final dalam 1-2 detik

---

## 3. Proof of Stake (PoS) - Bukan PoW!

### AINCORE **BUKAN** Proof of Work:
- ❌ Tidak pakai GPU/ASIC mining
- ❌ Tidak ada electricity waste
- ✅ Validator stake AIN untuk participate

### Cara Jadi Validator:

```typescript
// Minimum stake: 1000 AIN
const tx = Transaction.createRegisterValidator(keypair, sequenceNumber);
tx.sign(keypair);
await connection.sendTransaction(tx.toString());
```

### Slashing (Hukuman):
- **Double-Sign** → Stake BURNED 100%
- **Offline** → Penalty per missed round
- **Unbonding Period** → 21 hari untuk withdraw stake

---

## 4. Tokenomics (Ekonomi)

### Supply:

| Metric | Value |
|--------|-------|
| **Max Supply** | 150,000,000 AIN |
| **Genesis Supply** | 0 (Fair Launch!) |
| **Block Reward** | 36 AIN (decreasing) |
| **Halving** | Every 4 years (~2.1M blocks) |

### Halving Schedule:

| Year | Block Reward | Cumulative Supply |
|------|-------------|-------------------|
| 0-4 | 36 AIN | ~75M |
| 4-8 | 18 AIN | ~112M |
| 8-12 | 9 AIN | ~131M |
| 12-16 | 4.5 AIN | ~140M |
| ... | ... | → 150M (asymptotic) |

### Reward Distribution:
- **80%** → Block Proposer (Validator)
- **20%** → DePIN Miners (IoT Devices)

---

## 5. Fair Launch - Apa Artinya?

### ✅ AINCORE adalah Fair Launch:

1. **No Pre-mine** - Tidak ada coin yang di-mine sebelum launch
2. **No ICO/IDO** - Tidak ada private sale
3. **No VC Allocation** - Tidak ada token untuk investor
4. **Equal Opportunity** - Semua orang bisa jadi validator dari block 1

### Bagaimana Dapat Coin Pertama?

| Method | Deskripsi |
|--------|-----------|
| **Staking** | Jadi validator, stake AIN, dapat block reward |
| **DePIN Mining** | Register IoT device, submit breath data, dapat reward |
| **Transfer** | Terima dari orang lain yang sudah punya |
| **Bridge** | Bridge dari chain lain (BTC → AIN-BTC) |

### Genesis Bootstrap:
Untuk bootstrap awal, genesis validator mendapat initial stake untuk memulai chain. Setelah itu, semua coin hanya bisa didapat melalui mining/staking.

---

## 6. DePIN Mining - Yang Bikin Unik!

### Apa itu DePIN?
**D**ecentralized **P**hysical **I**nfrastructure **N**etwork

### Cara Kerja DePIN Mining di AINCORE:

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ IoT Device   │ --→  │   Oracle     │ --→  │  Blockchain  │
│ (Smartwatch) │      │ (BQI Calc)   │      │  (Reward)    │
└──────────────┘      └──────────────┘      └──────────────┘
     │                      │                      │
     ├─ Heart Rate          ├─ Calculate BQI      ├─ Mint AIN
     ├─ SpO2                ├─ Verify Signature   └─ Send to Owner
     └─ Breath Rate         └─ Submit Proof
```

### BQI (Breath Quality Index):
- **Score 0-100** berdasarkan kesehatan pernapasan
- **Higher BQI = More Reward**
- **Formula:** `reward = 0.36 AIN × (BQI / 100)`

### Supported Devices:
1. **Wearables** - Smartwatch, Fitness Band
2. **Stationary** - Air Quality Monitor
3. **Mobile** - Phone App
4. **Desktop** - Computer App
5. **Browser** - Web Extension

---

## 7. Technology Stack

### Core Components:

| Layer | Technology |
|-------|------------|
| **Consensus** | DAG-BFT (Bullshark-inspired) |
| **Execution** | Move VM (Aptos Fork) |
| **Storage** | RocksDB |
| **Networking** | libp2p (Kademlia DHT + Gossipsub) |
| **Cryptography** | Ed25519, SHA-256, Blake3 |
| **Data Availability** | Reed-Solomon Erasure Coding |

### Smart Contract:

```move
module 0x1::my_contract {
    public entry fun transfer(from: &signer, to: address, amount: u64) {
        coin::transfer<AincoreCoin>(from, to, amount);
    }
}
```

AINCORE menggunakan **Move Language** yang sama dengan Aptos/Sui karena:
- **Resource Safety** - Assets tidak bisa di-copy atau destroy sembarangan
- **Formal Verification** - Bisa dibuktikan secara matematis
- **Parallel Execution** - Otomatis detect dan parallelkan transaksi

---

## 8. Cross-Chain Bridge

### BTC Bridge:
```
BTC (Bitcoin) → Lock → Mint AIN-BTC (Wrapped)
AIN-BTC → Burn → Unlock → BTC
```

### EVM Bridge:
```
AIN (AINCORE) → Lock → Mint wAIN (Ethereum/BSC)
wAIN → Burn → Unlock → AIN
```

### Bridge Security:
- **Multi-sig Federation** - Multiple parties harus sign
- **Timelock** - Delay untuk prevent flash attacks
- **Fraud Proofs** - Challenge period untuk dispute

---

## 9. Delegation System (Staking Pools)

### Kenapa Delegation Penting?

| Tanpa Delegation | Dengan Delegation |
|------------------|-------------------|
| Min. stake 1000 AIN | Min. stake **1 AIN** |
| Hanya whale bisa participate | **Semua orang** bisa participate |
| Centralized | **Decentralized** |

---

### Cara Kerja Delegation:

```
┌─────────────────────────────────────────────────────────────┐
│                    VALIDATOR POOL                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Validator: Alice (Commission: 10%)                   │   │
│  │ Self-Stake: 5,000 AIN                               │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ DELEGATORS:                                          │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐             │   │
│  │  │ Bob      │ │ Charlie  │ │ David    │             │   │
│  │  │ 100 AIN  │ │ 500 AIN  │ │ 50 AIN   │             │   │
│  │  └──────────┘ └──────────┘ └──────────┘             │   │
│  │ TOTAL STAKE: 5,650 AIN                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

### Delegation Parameters:

| Parameter | Value |
|-----------|-------|
| **Min Delegation** | 1 AIN |
| **Max Commission** | 30% |
| **Unbonding Period** | 21 hari |
| **Commission Change Notice** | 7 hari |

---

### SDK Usage:

```typescript
// 1. Delegate 100 AIN ke validator
const tx = Transaction.createDelegate(keypair, validatorAddress, 100n * 10n**18n);
tx.sign(keypair);
await connection.sendTransaction(tx.toString());

// 2. Check delegation status
const info = await connection.getDelegation(myAddress, validatorAddress);
console.log(`Delegated: ${info.amount}, Pending Rewards: ${info.pendingRewards}`);

// 3. Claim rewards
const claimTx = Transaction.createClaimRewards(keypair, validatorAddress);
await connection.sendTransaction(claimTx.toString());

// 4. Undelegate (starts 21-day unbonding)
const undelegateTx = Transaction.createUndelegate(keypair, validatorAddress, 50n * 10n**18n);
await connection.sendTransaction(undelegateTx.toString());

// 5. Withdraw after unbonding period
const withdrawTx = Transaction.createWithdrawUnbonded(keypair, validatorAddress);
await connection.sendTransaction(withdrawTx.toString());
```

---

### Reward Distribution Example:

**Scenario:** Block Reward = 36 AIN, Validator Commission = 10%

| Participant | Stake | Share | Gross | Commission | Net Reward |
|-------------|-------|-------|-------|------------|------------|
| Alice (Validator) | 5,000 | 88.5% | 31.86 | +0.41 | **32.27 AIN** |
| Bob | 100 | 1.77% | 0.64 | -0.06 | **0.57 AIN** |
| Charlie | 500 | 8.85% | 3.19 | -0.32 | **2.87 AIN** |
| David | 50 | 0.88% | 0.32 | -0.03 | **0.29 AIN** |

---

### Staking Options:

| Type | Min Stake | Run Node? | Rewards |
|------|-----------|-----------|---------|
| **Solo Validator** | 1000 AIN | ✅ Yes | Full block reward |
| **Delegation** | 1 AIN | ❌ No | Proportional (minus commission) |

---

### DePIN Mining:
- **No pools needed** - Each device mines independently
- **Reward goes to device owner** - Direct to wallet

---

## 10. Comparison dengan Blockchain Lain

| Feature | AINCORE | Bitcoin | Ethereum | Solana | Aptos |
|---------|---------|---------|----------|--------|-------|
| Consensus | DAG-BFT PoS | PoW | PoS | PoH+PoS | BFT PoS |
| TPS | ~10,000 | 7 | 30 | 65,000 | 160,000 |
| Finality | 1-2s | 60min | 15min | 400ms | 1s |
| Smart Contract | Move | Script | Solidity | Rust | Move |
| Mining | DePIN | ASIC | Staking | Staking | Staking |
| Fair Launch | ✅ | ✅ | ❌ | ❌ | ❌ |

---

## 11. FAQ

### Q: Apakah ini PoW atau PoS?
**A:** PoS (Proof of Stake) dengan struktur DAG. Tidak ada GPU/ASIC mining.

### Q: Bagaimana dapat coin pertama?
**A:** 
1. Jadi validator (stake + run node)
2. DePIN mining (pasang IoT device)
3. Terima transfer dari orang lain
4. Bridge dari chain lain

### Q: Apakah Fair Launch?
**A:** Ya! Tidak ada pre-mine, ICO, atau alokasi khusus.

### Q: Berapa minimum stake?
**A:** 1000 AIN untuk jadi validator.

### Q: Apa bedanya dengan Aptos/Sui?
**A:** 
- Aptos/Sui fokus ke high TPS saja
- AINCORE punya **DePIN Mining** - mine dengan IoT devices
- AINCORE punya **BTC Bridge** - bisa wrap Bitcoin

### Q: Apakah ada staking pool?
**A:** Ya, bisa delegate stake ke validator lain.

---

## 12. Links & Resources

- **GitHub:** [AINCORE-Blockchain](https://github.com/...)
- **SDK:** `aincore-js` (npm package)
- **Explorer:** Coming Soon
- **Faucet:** Coming Soon (Testnet)

---

> **Built with ❤️ for decentralized future**
