// STARK Benchmarks - Week 7: Performance Measurement
//
// Comprehensive benchmarking suite for STARK proofs
// Measures: proving time, verification time, proof size

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto::zkp::{fibonacci_prover::FibonacciProver, merkle_prover::MerkleProver, stark_proof::*};
use winterfell::Prover;

// ========== Fibonacci Benchmarks ==========

fn bench_fibonacci_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("fibonacci_proving");

    for steps in [8, 16, 32, 64].iter() {
        group.bench_with_input(BenchmarkId::new("default", steps), steps, |b, &steps| {
            b.iter(|| {
                let prover = FibonacciProver::new();
                let (trace, _) = prover.prepare(steps);
                black_box(prover.prove(trace).unwrap())
            });
        });

        group.bench_with_input(BenchmarkId::new("optimized", steps), steps, |b, &steps| {
            b.iter(|| {
                let prover = FibonacciProver::new_optimized();
                let (trace, _) = prover.prepare(steps);
                black_box(prover.prove(trace).unwrap())
            });
        });
    }

    group.finish();
}

fn bench_fibonacci_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("fibonacci_verification");

    for steps in [8, 16, 32].iter() {
        // Pre-generate proof
        let proof_bytes = generate_fibonacci_proof(*steps).unwrap();
        let expected = match steps {
            8 => 21,
            16 => 987,
            32 => 2178309,
            _ => 0,
        };

        group.bench_with_input(BenchmarkId::from_parameter(steps), steps, |b, _| {
            b.iter(|| black_box(verify_fibonacci_proof(&proof_bytes, expected).unwrap()));
        });
    }

    group.finish();
}

fn bench_fibonacci_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("fibonacci_proof_size");

    for steps in [8, 16, 32].iter() {
        group.bench_with_input(BenchmarkId::new("default", steps), steps, |b, &steps| {
            b.iter(|| {
                let proof = generate_fibonacci_proof(steps).unwrap();
                black_box(proof.len())
            });
        });
    }

    group.finish();
}

// ========== Merkle Benchmarks ==========

fn bench_merkle_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proving");

    let leaf = 100;
    let path = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let path_bits = vec![false; 8];

    group.bench_function("default", |b| {
        b.iter(|| {
            let prover = MerkleProver::new();
            let (trace, _) = prover.prepare(leaf, path.clone(), path_bits.clone());
            black_box(prover.prove(trace).unwrap())
        });
    });

    group.bench_function("optimized", |b| {
        b.iter(|| {
            let prover = MerkleProver::new_optimized();
            let (trace, _) = prover.prepare(leaf, path.clone(), path_bits.clone());
            black_box(prover.prove(trace).unwrap())
        });
    });

    group.finish();
}

fn bench_merkle_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_verification");

    let leaf = 100;
    let path = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let path_bits = vec![false; 8];

    // Pre-generate proof
    let proof_bytes = generate_merkle_proof(leaf, path, path_bits).unwrap();
    let expected_root = 136; // Pre-calculated

    group.bench_function("verify", |b| {
        b.iter(|| black_box(verify_merkle_proof(&proof_bytes, expected_root).unwrap()));
    });

    group.finish();
}

// ========== Batch Benchmarks ==========

fn bench_batch_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_proving");

    group.bench_function("fibonacci_batch_3", |b| {
        b.iter(|| black_box(generate_fibonacci_batch_proof(vec![8, 16, 32]).unwrap()));
    });

    group.bench_function("merkle_batch_2", |b| {
        b.iter(|| {
            let proofs = vec![
                (100, vec![1, 2, 3, 4, 5, 6, 7, 8], vec![false; 8]),
                (200, vec![10, 20, 30, 40, 50, 60, 70, 80], vec![true; 8]),
            ];
            black_box(generate_merkle_batch_proof(proofs).unwrap())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fibonacci_proving,
    bench_fibonacci_verification,
    bench_fibonacci_proof_size,
    bench_merkle_proving,
    bench_merkle_verification,
    bench_batch_proving,
);

criterion_main!(benches);
