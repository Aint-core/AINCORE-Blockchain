# AINCORE Cryptography Module Guide

> **Understanding and using AINCORE's cryptographic primitives**

---

## Overview

Modul `common/crypto` menyediakan semua primitif kriptografi yang dibutuhkan AINCORE:

| Category | Modules |
|----------|---------|
| Signatures | Ed25519, ECDSA, BLS, Multi-sig, Threshold |
| Hashing | SHA-256, Poseidon (ZK-friendly) |
| ZK Proofs | STARK, SNARK |
| Utilities | VDF, MPC, Accumulator |

---

## Module Structure

```
common/crypto/src/
├── lib.rs              # Main exports & core functions
├── ecdsa.rs            # ECDSA (EVM compatible)
├── multi_sig.rs        # Multi-signature schemes
├── transport.rs        # Encrypted transport (ChaCha20)
├── bls/                # BLS aggregate signatures
├── threshold/          # Threshold signatures (FROST)
├── poseidon/           # ZK-friendly hash
├── zkp/                # STARK/SNARK provers
├── accumulator/        # Merkle accumulator
├── mpc/                # Multi-party computation
├── vdf/                # Verifiable delay function
├── bridges/            # Cross-chain verification
├── rollup/             # L2 proof verification
├── recursive/          # Recursive proofs
└── account_abstraction/ # ERC-4337 support
```

---

## Core Functions

### Hashing

```rust
use crypto::{hash, hash_hex};

// SHA-256 hash → Vec<u8>
let data = b"Hello AINCORE!";
let hash_bytes = hash(data);
assert_eq!(hash_bytes.len(), 32);

// SHA-256 hash → hex string
let hash_string = hash_hex(data);
assert_eq!(hash_string.len(), 64);
```

### Ed25519 Signatures

```rust
use crypto::{Signer, SigningKey, VerifyingKey, verify_signature};
use rand::rngs::OsRng;

// Generate keypair
let signing_key = SigningKey::generate(&mut OsRng);
let verifying_key = signing_key.verifying_key();

// Sign message
let message = b"transaction data";
let signature = signing_key.sign(message);

// Verify signature
let is_valid = verifying_key.verify(message, &signature).is_ok();

// Or use the convenience function
let result = verify_signature(
    &verifying_key.to_bytes(),
    message,
    &signature.to_bytes(),
)?;
```

### Address Derivation

```rust
use crypto::derive_address;

// Derive address from public key
// Address = hex(SHA256(pubkey)[0..16])
let pubkey = [0u8; 32]; // Your public key bytes
let address = derive_address(&pubkey)?;
assert_eq!(address.len(), 32); // 16 bytes = 32 hex chars
```

---

## ECDSA (EVM Compatible)

```rust
use crypto::ecdsa::{ECDSACrypto, ECDSAError};

let crypto = ECDSACrypto::new();

// Sign message
let private_key = [1u8; 32]; // Your private key
let message = b"Hello, Ethereum!";
let signature = crypto.sign(&private_key, message)?;

// Recover address from signature
let recovered_address = crypto.recover_address(&signature, message)?;

// Verify signature
let is_valid = crypto.verify(&signature, message, &expected_address)?;
```

---

## BLS Signatures

Aggregate signatures untuk efisiensi consensus.

```rust
use crypto::bls::{BLSEngine, BLSError};

let engine = BLSEngine::new();

// Generate keypair
let (sk1, pk1) = engine.keygen();
let (sk2, pk2) = engine.keygen();

// Sign message
let message = b"vote for block 123";
let sig1 = engine.sign(&sk1, message);
let sig2 = engine.sign(&sk2, message);

// Aggregate signatures
let agg_sig = engine.aggregate(&[sig1, sig2]);
let agg_pk = engine.aggregate_public_keys(&[pk1, pk2]);

// Verify aggregated signature
let is_valid = engine.verify(&agg_pk, message, &agg_sig)?;
```

---

## Threshold Signatures (FROST)

Signatures yang membutuhkan t-of-n participants.

```rust
use crypto::threshold::threshold_bls::{
    FrostParticipant, 
    aggregate_frost
};

// Setup: 2-of-3 threshold
let threshold = 2;
let total = 3;

// Each participant generates their share
let participant1 = FrostParticipant::new(1, threshold, total);
let participant2 = FrostParticipant::new(2, threshold, total);

// Sign message
let message = b"multisig transaction";
let share1 = participant1.sign(message);
let share2 = participant2.sign(message);

// Aggregate (need threshold shares)
let signature = aggregate_frost(&[share1, share2])?;
```

---

## Multi-Signature

```rust
use crypto::multi_sig::{MultiSigVerifier, SignatureScheme};

// Detect signature scheme
let sig_bytes = [/* signature bytes */];
let scheme = MultiSigVerifier::detect_scheme(&sig_bytes)?;

match scheme {
    SignatureScheme::Ed25519 => println!("Standard Ed25519"),
    SignatureScheme::Dilithium => println!("Post-quantum Dilithium"),
    SignatureScheme::BLS => println!("BLS signature"),
    SignatureScheme::ECDSA => println!("EVM-compatible ECDSA"),
}

// Verify based on scheme
let is_valid = MultiSigVerifier::verify(&sig_bytes, message, &pubkey)?;
```

---

## ZK Proofs (STARK)

```rust
use crypto::zkp::{STARKProver, STARKError};

// Create prover
let prover = STARKProver::new();

// Generate proof for computation
let inputs = vec![1u64, 2, 3, 5, 8, 13]; // Fibonacci sequence
let proof = prover.prove_fibonacci(inputs.len())?;

// Verify proof
let is_valid = prover.verify(&proof)?;
```

### Merkle Proof Verification

```rust
use crypto::zkp::merkle_prover::MerkleProver;

let prover = MerkleProver::new();

// Prove merkle inclusion
let leaf = hash(b"my data");
let path = vec![/* sibling hashes */];
let root = compute_merkle_root(...);

let proof = prover.prove_inclusion(&leaf, &path, &root)?;
let is_valid = prover.verify(&proof)?;
```

---

## Poseidon Hash (ZK-friendly)

```rust
use crypto::poseidon::{PoseidonHasher, poseidon_hash};

// Hash inputs
let inputs = vec![1u64, 2, 3];
let hash = poseidon_hash(&inputs);

// Use hasher for multiple operations
let mut hasher = PoseidonHasher::new();
hasher.update(&[1, 2, 3]);
hasher.update(&[4, 5, 6]);
let result = hasher.finalize();
```

---

## VDF (Verifiable Delay Function)

Time-locked computation untuk randomness.

```rust
use crypto::vdf::{VDFEngine, VDFError};

let engine = VDFEngine::new();

// Compute VDF (takes time)
let input = b"seed";
let iterations = 1000000;
let (output, proof) = engine.compute(input, iterations)?;

// Verify instantly
let is_valid = engine.verify(input, &output, &proof, iterations)?;
```

---

## MPC (Shamir Secret Sharing)

```rust
use crypto::mpc::{MPCProtocol, MPCError};

let mpc = MPCProtocol::new();

// Split secret into shares
let secret = b"my secret key";
let threshold = 3;
let total_shares = 5;

let shares = mpc.split_secret(secret, threshold, total_shares)?;

// Reconstruct with threshold shares
let reconstructed = mpc.reconstruct(&shares[0..3])?;
assert_eq!(reconstructed, secret);
```

---

## Merkle Accumulator

```rust
use crypto::accumulator::{Accumulator, AccumulatorError};

let mut acc = Accumulator::new();

// Add elements
acc.add(hash(b"tx1"));
acc.add(hash(b"tx2"));
acc.add(hash(b"tx3"));

// Get root
let root = acc.root();

// Generate proof
let proof = acc.prove(1)?; // Proof for tx2

// Verify inclusion
let is_valid = acc.verify(&hash(b"tx2"), &proof, &root)?;
```

---

## Encrypted Transport

```rust
use crypto::transport::{encrypt, decrypt};

let key = [0u8; 32]; // 256-bit key
let plaintext = b"secret message";

// Encrypt
let ciphertext = encrypt(&key, plaintext)?;

// Decrypt
let decrypted = decrypt(&key, &ciphertext)?;
assert_eq!(decrypted, plaintext);
```

---

## Best Practices

1. **Never reuse nonces** - Always use fresh random nonces
2. **Secure key storage** - Use keystore module for sensitive keys
3. **Constant-time operations** - Use constant-time comparison for secrets
4. **Validate inputs** - Always validate key/signature lengths
5. **Handle errors** - Don't ignore cryptographic errors

---

## Performance

| Operation | Time (avg) |
|-----------|------------|
| SHA-256 (1KB) | 2 μs |
| Ed25519 sign | 50 μs |
| Ed25519 verify | 120 μs |
| BLS sign | 1.5 ms |
| BLS verify | 2.5 ms |
| STARK prove | 500 ms |
| STARK verify | 10 ms |

---

## References

- [Ed25519 Paper](https://ed25519.cr.yp.to/)
- [BLS Signatures](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html)
- [Winterfell STARK](https://github.com/facebook/winterfell)
- [Poseidon Hash](https://www.poseidon-hash.info/)
