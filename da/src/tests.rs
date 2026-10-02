use super::*;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 256) as u8).collect()
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Pins the encoding. The DA root is in the block header hash, so a silent
/// change (a new matrix in the Reed-Solomon crate, a tree or domain edit)
/// would fork the chain. The expected values come from `da/reference/da_ref.py`,
/// an independent implementation of the module-doc construction.
#[test]
fn golden_roots_match_an_independent_implementation() {
    let cases = [
        (
            0,
            1,
            1,
            "627670dc0ad6858e4a8290cab1ea460007edb5bdd9453e358c6ae33ca808ac47",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        ),
        (
            1,
            1,
            1,
            "4242cbc3c34686faa320a9a7aab32f1e6950a280dda3d0e1e4e70a36eee79aac",
            "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879",
        ),
        (
            1000,
            2,
            500,
            "5e239cd2126ac20e5269ad09fc9247575b29dd6ed682ea7c9075f7a96dd2fd98",
            "655d195453cee7d86fa06789fe69e4fcc0fbff5b348af5b2878cf6826a7248da",
        ),
        (
            70000,
            128,
            547,
            "16ab6fb91bd951f3b64dbee681b732787d7f8727ab56c0244104efa1a0780b0a",
            "767071e9d5ae98f7519a5fc7cd2e7f3c176cfb46caf6fc0ec438db7911d24e58",
        ),
        // Wide enough shards for the column-parallel encode on any core count.
        (
            600000,
            128,
            4688,
            "14b780e8c2c83a5cb39ca6d6b94adc1c4e406f74bb5869325d786e57a7cb96b8",
            "0a0c9044e73c11a246137a96a110028dacf3c2b39f926da7cc9c8bdff425d549",
        ),
    ];
    for (len, k, size, root, last_shard) in cases {
        let ext = Extended::new(&pattern(len));
        let layout = Layout {
            body_len: len as u64,
            data_shards: k,
            shard_size: size,
        };
        assert_eq!(ext.layout(), layout, "layout of {len} bytes");
        assert_eq!(ext.root(), root, "DA root of {len} bytes");
        assert_eq!(
            sha(ext.shards.last().unwrap()),
            last_shard,
            "last parity shard of {len} bytes"
        );
        assert_eq!(da_root(&pattern(len)), root);
    }
}

/// The column-parallel encode writes the same bytes as one encode of the
/// whole shards, at every width the split can produce.
#[test]
fn the_parallel_encode_equals_one_whole_encode() {
    for len in [65_536, 600_000, 786_432 + 13] {
        let body = pattern(len);
        let ext = Extended::new(&body);
        let mut whole = ext.shards.clone();
        let k = ext.layout().data_shards as usize;
        for parity in &mut whole[k..] {
            parity.fill(0);
        }
        codec(k).encode(&mut whole).unwrap();
        assert!(whole == ext.shards, "{len} bytes");
    }
}

#[test]
fn a_remembered_root_is_the_root_of_that_body() {
    let a = pattern(3_000);
    let mut b = a.clone();
    b[2_999] ^= 1;
    let root_a = da_root(&a);
    assert_eq!(da_root(&a), root_a, "a repeat");
    assert_eq!(root_a, Extended::new(&a).root());
    assert_ne!(da_root(&b), root_a, "a body one bit apart");
    assert_eq!(da_root(&b), Extended::new(&b).root());
    for len in 0..(2 * REMEMBERED_ROOTS) {
        da_root(&pattern(len)); // push `a` out of the memory
    }
    assert_eq!(da_root(&a), root_a, "recomputed after eviction");
}

#[test]
fn the_layout_covers_the_body_with_the_fewest_shards_up_to_the_cap() {
    for len in [
        0,
        1,
        511,
        512,
        513,
        1024,
        65_535,
        65_536,
        65_537,
        786_432,
        6_000_000,
        u64::MAX,
    ] {
        let l = Layout::of(len);
        assert!((1..=MAX_DATA_SHARDS).contains(&l.data_shards), "{len}");
        assert!(l.shard_size >= 1, "{len}");
        assert!(l.total_shards() <= 256, "{len}");
        assert!(
            l.data_shards as u128 * l.shard_size as u128 >= len as u128,
            "{len}: the shards hold the body"
        );
        if l.data_shards < MAX_DATA_SHARDS {
            assert!(
                l.shard_size <= SHARD_TARGET_BYTES,
                "{len}: below the cap, shards keep the target size"
            );
            assert!(
                (l.data_shards - 1) * SHARD_TARGET_BYTES < len.max(1),
                "{len}: no more shards than the body needs"
            );
        }
    }
}

#[test]
fn every_shard_of_every_body_verifies_against_its_root() {
    for len in [0, 1, 700, 5_000, 70_000] {
        let ext = Extended::new(&pattern(len));
        let total = ext.layout().total_shards();
        for index in 0..total {
            let sample = ext.sample(index).expect("an index below the total");
            assert_eq!(
                verify_sample(&ext.root(), &sample),
                Ok(()),
                "{len} bytes, shard {index}"
            );
        }
        assert!(ext.sample(total).is_none());
        assert!(ext.sample(u64::MAX).is_none());
    }
}

#[test]
fn a_tampered_sample_is_refused() {
    let ext = Extended::new(&pattern(5_000));
    let root = ext.root();
    let good = ext.sample(13).unwrap();

    let mut shard = hex::decode(&good.shard).unwrap();
    shard[0] ^= 1;
    let flipped = Sample {
        shard: hex::encode(shard),
        ..good.clone()
    };
    assert_eq!(
        verify_sample(&root, &flipped),
        Err(SampleError::RootMismatch)
    );

    // Another index's shard and proof, relabelled.
    let other = ext.sample(12).unwrap();
    let relabelled = Sample { index: 13, ..other };
    assert!(verify_sample(&root, &relabelled).is_err());

    // The same shard claimed at a different index of the same tree.
    let moved = Sample {
        index: 12,
        ..good.clone()
    };
    assert!(verify_sample(&root, &moved).is_err());

    let mut short = good.clone();
    short.proof.pop();
    assert_eq!(verify_sample(&root, &short), Err(SampleError::BadProof));

    let mut long = good.clone();
    long.proof.push("00".repeat(32));
    assert_eq!(verify_sample(&root, &long), Err(SampleError::BadProof));

    let mut too_long = good.clone();
    too_long.proof = vec!["00".repeat(32); MAX_PROOF_LEN + 1];
    assert_eq!(verify_sample(&root, &too_long), Err(SampleError::BadProof));

    // A different length changes the layout, and the root binds the length.
    let resized = Sample {
        body_len: 4_999,
        ..good.clone()
    };
    assert!(verify_sample(&root, &resized).is_err());

    let other_body = Extended::new(&pattern(5_001)).root();
    assert_eq!(
        verify_sample(&other_body, &good),
        Err(SampleError::RootMismatch)
    );

    assert_eq!(verify_sample("zz", &good), Err(SampleError::BadRoot));
    assert_eq!(
        verify_sample(&"g".repeat(64), &good),
        Err(SampleError::BadRoot)
    );
    assert_eq!(verify_sample(&root, &good), Ok(()), "control");
}

/// Hostile lengths and indices are refused without a panic or a large
/// allocation.
#[test]
fn hostile_samples_are_refused_cheaply() {
    let root = da_root(b"x");
    let hostile = |body_len, index, shard: &str| Sample {
        body_len,
        index,
        shard: shard.into(),
        proof: vec![],
    };
    assert_eq!(
        verify_sample(&root, &hostile(u64::MAX, u64::MAX, "00")),
        Err(SampleError::IndexOutOfRange)
    );
    assert_eq!(
        verify_sample(&root, &hostile(u64::MAX, 0, "00")),
        Err(SampleError::BadShard)
    );
    assert_eq!(
        verify_sample(&root, &hostile(1, 2, "00")),
        Err(SampleError::IndexOutOfRange)
    );
    assert_eq!(
        verify_sample(&root, &hostile(1, 0, "0")),
        Err(SampleError::BadShard)
    );
    assert_eq!(
        verify_sample(&root, &hostile(1, 0, "zz")),
        Err(SampleError::BadShard)
    );
    assert_eq!(
        verify_sample(&root, &hostile(1, 0, "78")),
        Err(SampleError::BadProof),
        "a two-leaf tree needs one sibling"
    );
}

#[test]
fn any_half_of_the_shards_recovers_the_body() {
    let body = pattern(5_000);
    let ext = Extended::new(&body);
    let root = ext.root();
    let k = ext.layout().data_shards as usize;
    let all: Vec<Vec<u8>> = ext.shards.clone();
    let keep = |chosen: &dyn Fn(usize) -> bool| -> Vec<Option<Vec<u8>>> {
        all.iter()
            .enumerate()
            .map(|(i, s)| chosen(i).then(|| s.clone()))
            .collect()
    };
    let patterns: [(&str, Box<dyn Fn(usize) -> bool>); 4] = [
        ("data only", Box::new(move |i| i < k)),
        ("parity only", Box::new(move |i| i >= k)),
        ("even indices", Box::new(|i| i % 2 == 0)),
        ("a spread", Box::new(move |i| (i * 7) % (2 * k) < k)),
    ];
    for (name, chosen) in &patterns {
        let shards = keep(chosen.as_ref());
        assert_eq!(shards.iter().flatten().count(), k, "{name} keeps exactly k");
        assert_eq!(
            recover(&root, 5_000, shards).as_deref(),
            Some(&body[..]),
            "{name}"
        );
    }

    let mut too_few = keep(&|i| i < k);
    too_few[0] = None;
    assert_eq!(
        recover(&root, 5_000, too_few),
        None,
        "k - 1 shards are not enough"
    );

    let mut wrong = keep(&|i| i >= k);
    wrong[k].as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        recover(&root, 5_000, wrong),
        None,
        "a wrong shard does not extend back to the root"
    );

    let mut short = keep(&|i| i < k);
    short[0].as_mut().unwrap().pop();
    assert_eq!(
        recover(&root, 5_000, short),
        None,
        "a shard of the wrong size"
    );

    assert_eq!(
        recover(&root, 4_999, keep(&|i| i < k)),
        None,
        "another length"
    );
}

/// RFC 6962 paths verify under RFC 9162's algorithm for every tree size a
/// layout can produce, powers of two or not, and only at their own index.
#[test]
fn inclusion_paths_verify_for_every_tree_size() {
    for n in 1..=256usize {
        let leaves: Vec<Hash> = (0..n).map(|i| leaf_hash(i as u64, &[i as u8])).collect();
        let root = tree_root(&leaves);
        for m in 0..n {
            let path = inclusion_path(m, &leaves);
            assert_eq!(
                root_from_path(m as u64, n as u64, leaves[m], &path),
                Some(root),
                "n={n} m={m}"
            );
            assert!(path.len() <= MAX_PROOF_LEN);
            if n > 1 {
                let other = (m + 1) % n;
                assert_ne!(
                    root_from_path(other as u64, n as u64, leaves[m], &path),
                    Some(root),
                    "n={n} m={m}"
                );
            }
        }
        assert_eq!(root_from_path(n as u64, n as u64, leaves[0], &[]), None);
    }
}

/// Encoding cost on the host it runs on: `cargo test -p da --release --
/// --ignored --nocapture encode_cost`.
#[test]
#[ignore = "a measurement, not a check"]
fn encode_cost() {
    for len in [65_536usize, 786_432, 2 * 786_432, 6_291_456] {
        let body = pattern(len);
        let _ = Extended::new(&body); // codec built outside the timing
        let runs = 5;
        let start = std::time::Instant::now();
        for _ in 0..runs {
            std::hint::black_box(Extended::new(std::hint::black_box(&body)));
        }
        let per = start.elapsed() / runs;
        let l = Layout::of(len as u64);
        println!(
            "encode_cost len={len} k={} shard={} per_block={:.2?} MB/s={:.1}",
            l.data_shards,
            l.shard_size,
            per,
            len as f64 / per.as_secs_f64() / 1e6
        );
    }
}

#[derive(Deserialize)]
struct Vectors {
    valid: Vec<ValidVector>,
    invalid: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct ValidVector {
    da_root: String,
    sample: Sample,
}

#[derive(Deserialize)]
struct InvalidVector {
    name: String,
    da_root: String,
    sample: Sample,
    error: String,
}

/// The vectors the SDK verifier also checks (`aincore-js/test_da_sample.ts`),
/// made by the independent reference (`da/reference/da_vectors.py`). This
/// crate builds every valid sample byte for byte, accepts it, and refuses every
/// invalid one with the named error.
#[test]
fn shared_vectors_from_the_independent_reference() {
    let v: Vectors = serde_json::from_str(include_str!("../vectors/da_vectors.json")).unwrap();
    assert!(
        v.valid.len() >= 12 && v.invalid.len() >= 12,
        "positive control"
    );
    for t in &v.valid {
        let ext = Extended::new(&pattern(t.sample.body_len as usize));
        assert_eq!(ext.root(), t.da_root);
        assert_eq!(ext.sample(t.sample.index).as_ref(), Some(&t.sample));
        assert_eq!(verify_sample(&t.da_root, &t.sample), Ok(()));
    }
    for t in &v.invalid {
        let err = verify_sample(&t.da_root, &t.sample).expect_err(&t.name);
        assert_eq!(format!("{err:?}"), t.error, "{}", t.name);
    }
}
