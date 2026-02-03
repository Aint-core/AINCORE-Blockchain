# AINCORE Consensus Deep Dive

> **Understanding DAG-based consensus with Bullshark ordering**

---

## Overview

AINCORE menggunakan consensus protocol yang terinspirasi dari Narwhal (Meta) dengan Bullshark ordering (Aptos). Berbeda dengan blockchain tradisional yang linear, AINCORE menggunakan DAG (Directed Acyclic Graph).

---

## DAG vs Linear Blockchain

### Traditional (Linear)
```
[Block 1] → [Block 2] → [Block 3] → [Block 4]
```
- Satu block per round
- Sequential processing
- Limited throughput

### AINCORE (DAG)
```
Round 4:   [A4]─────[B4]─────[C4]
             ╲       │       ╱
Round 3:   [A3]─────[B3]─────[C3]
             ╲       │       ╱
Round 2:   [A2]─────[B2]─────[C2]
             ╲       │       ╱
Round 1:   [A1]─────[B1]─────[C1]
              ╲      │      ╱
               [GENESIS]
```
- Multiple vertices per round
- Parallel processing
- High throughput

---

## Core Components

### 1. Vertex

Unit dasar dalam DAG. Setiap validator membuat 1 vertex per round.

```rust
pub struct Vertex {
    pub hash: String,           // SHA-256(content)
    pub round: u64,             // Consensus round number
    pub author: String,         // Validator address
    pub payload: Vec<String>,   // Transactions
    pub parents: Vec<String>,   // Parent vertex hashes
    pub timestamp: u64,         // Unix timestamp
    pub signature: String,      // Ed25519 signature
}
```

### 2. DAG (Directed Acyclic Graph)

Struktur data yang menyimpan semua vertices.

```rust
pub struct DagConsensus {
    pub dag: HashMap<String, Vertex>,      // hash → Vertex
    pub round_index: HashMap<u64, Vec<String>>, // round → hashes
    pub current_round: u64,
    pub ordering_engine: OrderingEngine,
}
```

### 3. Ordering Engine (Bullshark)

Mengubah DAG menjadi urutan linear yang disepakati semua node.

---

## Consensus Flow

### Step 1: Create Vertex

```rust
pub fn try_create_vertex(&mut self) {
    // 1. Get parents from previous round
    let parents = self.get_parents_from_round(self.current_round - 1);
    
    // 2. Check BFT quorum
    if parents.len() < self.get_bft_quorum() {
        return; // Wait for more parents
    }
    
    // 3. Get transactions from mempool
    let txs = self.mempool.lock().get_batch(1000);
    
    // 4. Create vertex
    let vertex = Vertex {
        hash: compute_hash(...),
        round: self.current_round,
        author: self.node_id.clone(),
        payload: txs,
        parents: parents,
        timestamp: now(),
        signature: sign(...),
    };
    
    // 5. Add to local DAG
    self.dag.insert(vertex.hash.clone(), vertex.clone());
    
    // 6. Broadcast to peers
    self.broadcast_vertex(&vertex);
    
    // 7. Try to commit (Bullshark)
    self.try_commit();
}
```

### Step 2: Receive Vertex

```rust
pub fn handle_incoming_vertex(&mut self, vertex: Vertex) {
    // 1. Validate vertex
    if !self.validate_vertex(&vertex) {
        return;
    }
    
    // 2. Add to DAG
    self.dag.insert(vertex.hash.clone(), vertex.clone());
    self.round_index
        .entry(vertex.round)
        .or_default()
        .push(vertex.hash.clone());
    
    // 3. Try to commit
    self.try_commit();
}
```

### Step 3: Bullshark Ordering

```rust
pub fn try_commit(&mut self, round: u64) -> Option<Vec<String>> {
    // 1. Check if this is an anchor round (odd)
    if round % 2 == 0 {
        return None;
    }
    
    // 2. Get leader for this round
    let leader = self.get_leader(round);
    
    // 3. Check if leader vertex has enough support
    let leader_vertex = self.get_vertex_by_author(round, &leader)?;
    let support = self.count_children_support(round + 1, &leader_vertex);
    
    if support < self.get_bft_quorum() {
        return None;
    }
    
    // 4. This vertex is an ANCHOR - commit its causal history
    let committed = self.get_causal_history(&leader_vertex);
    
    // 5. Execute committed transactions
    for hash in &committed {
        self.execute_vertex(hash);
    }
    
    Some(committed)
}
```

---

## BFT Quorum

Byzantine Fault Tolerance dengan formula 2f+1:

```
n = total validators
f = (n - 1) / 3     // Max Byzantine nodes tolerable
quorum = 2f + 1     // Required votes

Examples:
n=4:  f=1, quorum=3 (tolerate 1 Byzantine)
n=7:  f=2, quorum=5 (tolerate 2 Byzantine)
n=10: f=3, quorum=7 (tolerate 3 Byzantine)
```

---

## Leader Election

Leader election menggunakan round-robin deterministik:

```rust
pub fn get_leader(&self, round: u64) -> String {
    let validators = self.get_validator_set();
    let leader_idx = (round as usize) % validators.len();
    validators[leader_idx].clone()
}
```

---

## Checkpoint & Recovery

AINCORE menyimpan checkpoint setiap 100 rounds untuk fast recovery:

```rust
// Save checkpoint
if round % 100 == 0 {
    let vertices = self.get_vertices_since(round - 100);
    let checkpoint_data = serde_json::to_string(&vertices)?;
    self.storage.put_checkpoint(round, checkpoint_data);
}

// Recovery on startup
let checkpoint_round = storage.get_latest_checkpoint_round();
let vertices = storage.get_checkpoint_data(checkpoint_round);
for v in vertices {
    self.dag.insert(v.hash.clone(), v);
}
```

---

## View Change

Jika leader tidak produce vertex:

```rust
pub fn handle_timeout(&mut self) {
    self.increment_view();
    
    if self.current_view > 3 {
        // Skip this round, advance to next
        self.current_round += 1;
        self.current_view = 0;
    }
}
```

---

## Performance

| Metric | Value |
|--------|-------|
| Block Time | ~3 seconds |
| TPS (single node) | ~1,000 |
| TPS (10 nodes) | ~5,000 |
| Finality | 2 rounds (~6s) |
| Byzantine Tolerance | 33% |

---

## Key Files

| File | Purpose |
|------|---------|
| `consensus/consensus/src/dag.rs` | DAG structure & vertex creation |
| `consensus/consensus/src/ordering.rs` | Bullshark ordering |
| `consensus/blockchain/src/lib.rs` | Block & Vertex types |

---

## References

- [Narwhal Paper](https://arxiv.org/abs/2105.11827)
- [Bullshark Paper](https://arxiv.org/abs/2201.05677)
- [Aptos Consensus](https://aptoslabs.com/technology)
