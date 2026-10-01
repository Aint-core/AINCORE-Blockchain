# AINCORE Blockchain - Technical Whitepaper

> **Version:** 3.0 (Production)  
> **Last Updated:** January 2026

---

## 🎯 TL;DR (Ringkasan Singkat)

| Aspek | AINCORE |
|-------|---------|
| **Konsensus** | **DAG-BFT PoS** (Proof of Stake + DAG Structure) |
| **Supply** | 150,000,000 AIN (Fixed Max Supply) |
| **Emisi** | 1,90 %/tahun dari sisa cadangan, dibayar tiap periode reward menurut waktu konsensus |
| **Block Time** | Diukur pada kandidat rilis sebelum genesis (belum dipublikasikan) |
| **Fair Launch** | ✅ Ya (tanpa dana developer, tanpa ICO; genesis hanya berisi stake validator genesis dan cadangan treasury) |
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
- **Finality per blok** - Setiap blok final dengan satu quorum certificate; waktunya diukur sebelum genesis

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
- **Double-sign (equivocation)** → dipotong sebesar `(3 × porsi stake yang curang bersamaan)²`, minimal 1 %, 100 % jika ≥ 1/3 stake curang bersamaan (syarat minimum serangan apa pun). Validator di-jail permanen. Stake milik operator menanggung lebih dulu, baru delegator.
- **Offline** → tidak dipotong (hanya dideteksi)
- **Unbonding Period** → 21 hari waktu konsensus, dihitung dari akhir epoch komite terakhir

---

## 4. Tokenomics (Ekonomi)

### Supply:

| Metric | Value |
|--------|-------|
| **Max Supply** | 150,000,000 AIN |
| **Genesis Supply** | ~1.050.000 AIN (0,7 %): stake validator genesis dan cadangan treasury |
| **Emisi** | 1,90 %/tahun dari sisa cadangan (150 juta dikurangi semua yang sudah dicetak) |

### Kurva Emisi:

Tiap periode reward (20 blok) mencetak `sisa × λ × Δτ`, dengan λ = −ln(0,981) per tahun dan Δτ = waktu konsensus sejak payout terakhir. Karena dihitung dari waktu, bukan jumlah blok, kecepatan blok tidak mengubah kurva.

| Setelah | Bagian cadangan yang sudah dicetak |
|---------|------------------------------------|
| 1 tahun | 1,9 % |
| 10 tahun | 17,5 % |
| ~36 tahun | 50 % |
| 100 tahun | 85,3 % |

### Reward Distribution:
- Emisi dibagi ke anggota komite epoch itu menurut stake (dibatasi 1/50 dari total).
- Bagian tiap validator dibagi lagi: bagian stake sendiri + komisi → validator; sisanya → delegator menurut poin.
- **Fee transaksi:** 20 % ke anchor leader, 80 % ke komite menurut stake, 10 % dibakar (default).
- **DePIN:** 0 % untuk saat ini, sampai distribusinya tersambung.

---

## 5. Fair Launch - Apa Artinya?

### ✅ AINCORE adalah Fair Launch:

1. **Tanpa dana developer** - Genesis hanya berisi stake validator genesis dan cadangan treasury (~0,7 %); 99,3 % dicetak sebagai emisi
2. **No ICO/IDO** - Tidak ada private sale
3. **No VC Allocation** - Tidak ada token untuk investor
4. **Validator terbuka** - Siapa pun dengan stake minimum 1.000 AIN bisa mendaftar; komite setiap epoch adalah 256 validator dengan stake terbesar

### Bagaimana Dapat Coin Pertama?

| Method | Deskripsi |
|--------|-----------|
| **Staking** | Jadi validator (atau delegasi), stake AIN, dapat bagian emisi tiap periode reward |
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
- **Formula (belum aktif: DePIN mendapat 0 % emisi saat ini):** `reward = 0.36 AIN × (BQI / 100)`

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
| **Unbonding Period** | 21 hari waktu konsensus |
| **Commission Change Notice** | 7 hari; kenaikan maks. 5 poin persen sekali umumkan; penurunan langsung berlaku |

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

**Contoh:** emisi satu periode reward (20 blok) untuk validator ini dan pool-nya = 36 AIN (angka ilustrasi; tidak ada block reward tetap), komisi validator 10%

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
| **Solo Validator** | 1000 AIN | ✅ Yes | Bagian emisi komite menurut bobot, tiap periode reward |
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
| TPS | belum diukur | 7 | 30 | 65,000 | 160,000 |
| Finality | belum diukur | 60min | 15min | 400ms | 1s |
| Smart Contract | Move | Script | Solidity | Rust | Move |
| Mining | Staking (DePIN 0 % saat ini) | ASIC | Staking | Staking | Staking |
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
