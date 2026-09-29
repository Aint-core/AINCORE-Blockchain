use super::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn temp_db(name: &str) -> Arc<StateDB> {
    let path = std::env::temp_dir().join(format!(
        "aincore_state_commit_{}_{}",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    Arc::new(StateDB::open(path.to_str().unwrap()).unwrap())
}

fn k(i: usize) -> String {
    format!("obj:k{i}")
}

fn some(v: &str) -> Option<Vec<u8>> {
    Some(v.as_bytes().to_vec())
}

/// Apply and commit one version; returns the root.
fn commit(
    db: &Arc<StateDB>,
    version: Version,
    changes: Vec<(String, Option<Vec<u8>>)>,
) -> RootHash {
    let applied = apply(db, version, changes).unwrap();
    db.write_batch(applied.batch).unwrap();
    applied.root
}

/// Root of a fresh tree holding exactly `model`, built in one version.
fn from_scratch(name: &str, model: &BTreeMap<String, Vec<u8>>) -> RootHash {
    let db = temp_db(name);
    commit(
        &db,
        0,
        model
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect(),
    )
}

fn root_node_rows(db: &StateDB, version: Version) -> Vec<String> {
    let mut rows = Vec::new();
    for row in db.db.prefix_iterator(NODE.as_bytes()) {
        let (key, _) = row.unwrap();
        if !key.starts_with(NODE.as_bytes()) {
            break;
        }
        let nk: NodeKey = borsh::from_slice(&hex::decode(&key[NODE.len()..]).unwrap()).unwrap();
        if nk.version() == version && nk.nibble_path().is_empty() {
            rows.push(String::from_utf8(key.to_vec()).unwrap());
        }
    }
    rows
}

// ---- apply: sequencing, overwrite, diff, class, duplicates (CM-1, CM-7) ----

#[test]
fn versions_are_sequenced_and_a_missing_parent_root_refuses() {
    let db = temp_db("sequence");
    assert!(
        apply(&db, 1, vec![(k(1), some("a"))]).is_err(),
        "no version 0 yet"
    );
    commit(&db, 0, vec![(k(1), some("a"))]);
    assert!(
        apply(&db, 0, vec![(k(1), some("b"))]).is_err(),
        "re-applying 0"
    );
    assert!(apply(&db, 2, vec![(k(1), some("b"))]).is_err(), "gap");
    commit(&db, 1, vec![(k(1), some("b"))]);
    assert_eq!(latest_version(&db).unwrap(), Some(1), "positive control");

    // P4/P5: with the parent root gone, jmt alone would silently compute a
    // root over the change set only.
    let rows = root_node_rows(&db, 1);
    assert_eq!(
        rows.len(),
        1,
        "positive control: found the root of version 1"
    );
    db.delete(&rows[0]).unwrap();
    let err = apply(&db, 2, vec![(k(2), some("c"))])
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("missing"), "{err}");
}

#[test]
fn an_existing_tree_node_is_never_overwritten() {
    let db = temp_db("overwrite");
    commit(&db, 0, vec![(k(1), some("a"))]);
    commit(&db, 1, vec![(k(1), some("b"))]);
    // P9: rewind the marker and try to write version 1 again, differently.
    db.put(LATEST, "0").unwrap();
    let err = apply(&db, 1, vec![(k(1), some("zzz"))])
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("overwrite"), "{err}");
}

/// Leftover rows from a failed restore must never become the base of a new
/// genesis: the diff would read them and silently drop real changes.
#[test]
fn genesis_refuses_a_dirty_tree_namespace() {
    let db = temp_db("dirty_genesis");
    db.put(&val_key(&key_hash(&k(1)), 7), "vdeadbeef").unwrap();
    let err = apply(&db, 0, vec![(k(1), some("a"))])
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("empty tree namespace"), "{err}");
    let clean = temp_db("clean_genesis");
    assert!(
        apply(&clean, 0, vec![(k(1), some("a"))]).is_ok(),
        "positive control"
    );
}

#[test]
fn unchanged_values_and_absent_deletes_are_not_changes() {
    let db = temp_db("diff");
    let r0 = commit(&db, 0, vec![(k(1), some("a")), (k(2), None)]);
    let applied = apply(&db, 1, vec![(k(1), some("a")), (k(3), None)]).unwrap();
    assert_eq!(applied.changed, 0);
    assert_eq!(applied.root, r0, "root carried forward");
    db.write_batch(applied.batch).unwrap();
    let applied = apply(&db, 2, vec![(k(1), some("changed"))]).unwrap();
    assert_eq!(applied.changed, 1, "positive control: a real change counts");
    assert_ne!(applied.root, r0);
}

#[test]
fn only_state_keys_are_committed() {
    let db = temp_db("class");
    for key in ["latest_height", "consensus:qc:1", "peer:x", "no:such"] {
        assert!(
            apply(&db, 0, vec![(key.to_string(), some("x"))]).is_err(),
            "{key}"
        );
    }
    assert!(
        apply(&db, 0, vec![(k(1), some("x"))]).is_ok(),
        "positive control"
    );
}

/// With duplicates, "last write wins" would make the root depend on order.
#[test]
fn a_duplicate_key_in_one_change_set_is_refused() {
    let db = temp_db("dupes");
    let err = apply(&db, 0, vec![(k(1), some("a")), (k(1), some("b"))])
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("duplicate"), "{err}");
}

#[test]
fn deleting_every_key_then_reinserting_works() {
    let db = temp_db("empty_again");
    let r0 = commit(&db, 0, vec![(k(1), some("a")), (k(2), some("b"))]);
    let empty = commit(&db, 1, vec![(k(1), None), (k(2), None)]);
    assert_ne!(empty, r0);
    let (value, proof) = prove(&db, &k(1), 1).unwrap();
    assert_eq!(value, None);
    verify(empty, &k(1), None, &proof).unwrap();
    let r2 = commit(&db, 2, vec![(k(1), some("a")), (k(2), some("b"))]);
    assert_eq!(r2, r0, "the same state has the same root");
}

/// DT-2: after any random sequence the incremental root equals a
/// from-scratch root over the same state (history independence).
#[test]
fn incremental_root_equals_from_scratch() {
    let mut rng = StdRng::seed_from_u64(0x6733);
    let db = temp_db("differential");
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut checked = 0;
    for version in 0..40u64 {
        let mut last: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
        for _ in 0..rng.gen_range(0..12) {
            let key = k(rng.gen_range(0..60));
            let value = if rng.gen_bool(0.25) {
                None
            } else {
                Some(format!("v{}", rng.gen::<u32>()).into_bytes())
            };
            last.insert(key, value);
        }
        for (key, value) in &last {
            match value {
                Some(v) => model.insert(key.clone(), v.clone()),
                None => model.remove(key),
            };
        }
        let root = commit(&db, version, last.into_iter().collect());
        if !model.is_empty() {
            assert_eq!(
                root,
                from_scratch(&format!("scratch_{version}"), &model),
                "version {version}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 30,
        "positive control: {checked} versions compared"
    );
}

/// S2 will run `apply` on the block transaction's staged view, where reads
/// see the block's own earlier writes. It must match the base path.
#[test]
fn apply_inside_a_block_transaction_matches_the_base_path() {
    let base = temp_db("staged_base");
    let staged = temp_db("staged_view");
    let changes = |v: usize| vec![(k(v), some(&format!("x{v}"))), (k(v + 1), None)];
    for version in 0..5u64 {
        let expected = commit(&base, version, changes(version as usize));
        let got = staged
            .block_transaction(|view| {
                let applied = apply(&view, version, changes(version as usize))
                    .map_err(|e| storage::StorageError::DatabaseOperation(e.to_string()))?;
                view.write_batch(applied.batch)?;
                Ok(applied.root)
            })
            .unwrap();
        assert_eq!(got, expected, "version {version}");
    }
}

// ---- proofs (PF) ----

#[test]
fn proofs_verify_and_every_tampering_fails() {
    let db = temp_db("proofs");
    let r0 = commit(
        &db,
        0,
        (0..20).map(|i| (k(i), some(&format!("v{i}")))).collect(),
    );
    let r1 = commit(&db, 1, vec![(k(3), some("new")), (k(4), None)]);

    let (value, proof) = prove(&db, &k(3), 1).unwrap();
    assert_eq!(value.as_deref(), Some(b"new".as_ref()));
    verify(r1, &k(3), Some(b"new"), &proof).expect("inclusion");
    assert!(
        verify(r1, &k(3), Some(b"old"), &proof).is_err(),
        "wrong value"
    );
    assert!(
        verify(r0, &k(3), Some(b"new"), &proof).is_err(),
        "wrong root"
    );
    assert!(
        verify(r1, &k(5), Some(b"new"), &proof).is_err(),
        "wrong key"
    );

    let (value, proof) = prove(&db, &k(4), 1).unwrap();
    assert_eq!(value, None, "deleted");
    verify(r1, &k(4), None, &proof).expect("exclusion after delete");
    assert!(verify(r1, &k(4), Some(b"v4"), &proof).is_err());

    let (value, proof) = prove(&db, "obj:never", 1).unwrap();
    assert_eq!(value, None);
    verify(r1, "obj:never", None, &proof).expect("exclusion of a never-written key");

    let (value, proof) = prove(&db, &k(3), 0).unwrap();
    assert_eq!(value.as_deref(), Some(b"v3".as_ref()), "history is kept");
    verify(r0, &k(3), Some(b"v3"), &proof).expect("proof at the older version");
}

#[test]
fn an_empty_value_is_not_a_deletion() {
    let db = temp_db("empty_value");
    let r = commit(&db, 0, vec![(k(1), Some(Vec::new()))]);
    let (value, proof) = prove(&db, &k(1), 0).unwrap();
    assert_eq!(value, Some(Vec::new()));
    verify(r, &k(1), Some(b""), &proof).unwrap();
    assert!(verify(r, &k(1), None, &proof).is_err());
}

/// Local corruption, or a future pruning bug, must not turn the proof RPC or
/// snapshot serving into a crash: jmt unwraps reader results internally.
#[test]
fn a_missing_tree_node_is_an_error_not_a_panic() {
    let db = temp_db("corrupt");
    commit(&db, 0, (0..40).map(|i| (k(i), some("v"))).collect());
    let mut removed = 0;
    for row in db.db.prefix_iterator(NODE.as_bytes()) {
        let (key, _) = row.unwrap();
        if !key.starts_with(NODE.as_bytes()) {
            break;
        }
        let nk: NodeKey = borsh::from_slice(&hex::decode(&key[NODE.len()..]).unwrap()).unwrap();
        if !nk.nibble_path().is_empty() {
            db.delete(std::str::from_utf8(&key).unwrap()).unwrap();
            removed += 1;
        }
    }
    assert!(removed > 0, "positive control: nodes were removed");
    let mut failures = 0;
    for i in 0..40 {
        if prove(&db, &k(i), 0).is_err() {
            failures += 1;
        }
    }
    assert!(failures > 0, "positive control: corruption was reached");
    assert!(chunk(&db, 0, None, 50).is_err());
}

// ---- snapshot restore (SN-2) ----

fn server(tag: &str, n: usize) -> (Arc<StateDB>, RootHash) {
    let db = temp_db(&format!("server_{tag}_{n}"));
    let r = commit(
        &db,
        0,
        (0..n)
            .map(|i| (k(i), some(&format!("value-{i}"))))
            .collect(),
    );
    (db, r)
}

/// Pull every chunk of `version` from `server` into `restore`.
fn pull_all(server: &Arc<StateDB>, version: Version, restore: &mut Restore, size: usize) -> usize {
    let mut after = None;
    let mut total = 0;
    while let Some((entries, proof)) = chunk(server, version, after, size).unwrap() {
        after = entries.last().map(|(key, _)| key_hash(key));
        total += restore.add_chunk(entries, proof).unwrap().len();
    }
    total
}

#[test]
fn restore_rebuilds_the_exact_tree_in_chunks() {
    let (srv, root) = server("ok", 150);
    let client = temp_db("client_ok");
    let mut restore = Restore::begin(client.clone(), 0, root).unwrap();
    assert_eq!(
        pull_all(&srv, 0, &mut restore, 37),
        150,
        "positive control: every leaf arrived"
    );
    client.write_batch(restore.finish().unwrap()).unwrap();
    assert_eq!(super::root(&client, 0).unwrap(), root);
    assert_eq!(latest_version(&client).unwrap(), Some(0));
    let (value, proof) = prove(&client, &k(77), 0).unwrap();
    verify(root, &k(77), value.as_deref(), &proof).unwrap();
    assert_eq!(value.as_deref(), Some(b"value-77".as_ref()));
}

/// A node restored at h > 0 must then follow the chain exactly like a node
/// that replayed from genesis.
#[test]
fn a_node_restored_at_a_later_version_keeps_up_with_the_chain() {
    let srv = temp_db("server_later");
    for v in 0..=7u64 {
        commit(
            &srv,
            v,
            vec![
                (k(100 + v as usize), some(&format!("s{v}"))),
                (k(0), some(&format!("c{v}"))),
            ],
        );
    }
    let root7 = super::root(&srv, 7).unwrap();
    let client = temp_db("client_later");
    let mut restore = Restore::begin(client.clone(), 7, root7).unwrap();
    assert_eq!(
        pull_all(&srv, 7, &mut restore, 3),
        9,
        "8 per-version keys plus k0"
    );
    client.write_batch(restore.finish().unwrap()).unwrap();
    for v in 8..=12u64 {
        let changes = || {
            vec![
                (k(v as usize), some("n")),
                (k(1), None),
                (k(0), some(&format!("c{v}"))),
            ]
        };
        assert_eq!(
            commit(&client, v, changes()),
            commit(&srv, v, changes()),
            "version {v}"
        );
    }
}

/// P6: `jmt` accepts a partial restore; ours must not.
#[test]
fn a_partial_restore_is_refused() {
    let (srv, root) = server("partial", 150);
    let client = temp_db("client_partial");
    let mut restore = Restore::begin(client.clone(), 0, root).unwrap();
    let (entries, proof) = chunk(&srv, 0, None, 37).unwrap().unwrap();
    restore.add_chunk(entries, proof).unwrap();
    let Err(err) = restore.finish() else {
        panic!("partial restore must fail")
    };
    assert!(err.to_string().contains("expected"), "{err}");
    assert_eq!(
        latest_version(&client).unwrap(),
        None,
        "not marked complete"
    );
}

/// A peer answering "nothing" must not crash the joiner (jmt asserts on an
/// empty finish).
#[test]
fn finishing_with_no_chunk_is_an_error_not_a_panic() {
    let (_srv, root) = server("nothing", 10);
    let restore = Restore::begin(temp_db("client_nothing"), 0, root).unwrap();
    let Err(err) = restore.finish() else {
        panic!("finishing with nothing must fail")
    };
    assert!(err.to_string().contains("no snapshot chunk"), "{err}");
}

/// After one refused chunk the session is poisoned: later calls fail cleanly
/// instead of panicking or persisting forged rows. `wipe_tree` then lets a
/// clean restore succeed.
#[test]
fn a_refused_chunk_poisons_the_session_and_wipe_recovers() {
    let (srv, root) = server("poison", 60);
    let client = temp_db("client_poison");
    let (entries, proof) = chunk(&srv, 0, None, 20).unwrap().unwrap();

    let mut restore = Restore::begin(client.clone(), 0, root).unwrap();
    let mut forged = entries.clone();
    forged[0].1 = b"forged".to_vec();
    assert!(restore.add_chunk(forged, proof.clone()).is_err());
    let err = restore
        .add_chunk(entries.clone(), proof.clone())
        .expect_err("poisoned");
    assert!(err.to_string().contains("poisoned"), "{err}");
    assert!(
        restore.finish().is_err(),
        "a poisoned finish must not succeed"
    );

    client.write_batch(wipe_tree(&client).unwrap()).unwrap();
    assert!(tree_namespace_empty(&client).unwrap(), "wipe left nothing");
    let mut restore = Restore::begin(client.clone(), 0, root).unwrap();
    assert_eq!(pull_all(&srv, 0, &mut restore, 20), 60);
    client.write_batch(restore.finish().unwrap()).unwrap();
    assert_eq!(
        super::root(&client, 0).unwrap(),
        root,
        "clean retry succeeds"
    );
}

/// P7: restoring version 10 into a store that still holds an older tree
/// (versions 0..=3) panics inside `jmt`. Ours refuses before `jmt` runs.
#[test]
fn restore_refuses_a_non_empty_tree_namespace() {
    let srv = temp_db("server_dirty");
    for v in 0..=10 {
        commit(&srv, v, vec![(k(v as usize), some(&format!("s{v}")))]);
    }
    let root = super::root(&srv, 10).unwrap();
    let client = temp_db("client_dirty");
    for v in 0..=3 {
        commit(&client, v, vec![(k(900 + v as usize), some("old"))]);
    }
    let err = Restore::begin(client, 10, root).err().expect("must refuse");
    assert!(err.to_string().contains("empty tree namespace"), "{err}");
    assert!(
        Restore::begin(temp_db("client_clean"), 10, root).is_ok(),
        "positive control: a clean store may restore"
    );
}

/// A key whose hash lands in the same position (so the ordering check
/// passes) but differs from the leaf: only the proof check can refuse it.
fn same_position_key(entries: &Entries, i: usize) -> String {
    let lo = key_hash(&entries[i - 1].0);
    let hi = key_hash(&entries[i + 1].0);
    (0..1_000_000)
        .map(|n| format!("obj:forged{n}"))
        .find(|key| {
            let kh = key_hash(key);
            kh > lo && kh < hi
        })
        .expect("a key between the neighbours")
}

#[test]
fn forged_or_foreign_chunks_are_refused() {
    let (srv, root) = server("forge", 60);
    let (entries, proof) = chunk(&srv, 0, None, 20).unwrap().unwrap();

    let mut tampered = entries.clone();
    tampered[5].1 = b"forged".to_vec();
    let mut r = Restore::begin(temp_db("forge_value"), 0, root).unwrap();
    assert!(
        r.add_chunk(tampered, proof.clone()).is_err(),
        "tampered value"
    );

    let mut renamed = entries.clone();
    renamed[5].0 = same_position_key(&entries, 5);
    let mut r = Restore::begin(temp_db("forge_key"), 0, root).unwrap();
    let err = r
        .add_chunk(renamed, proof.clone())
        .expect_err("renamed key");
    assert!(
        !err.to_string().contains("out of order"),
        "must be refused by the proof, not the ordering check: {err}"
    );

    let mut foreign = entries.clone();
    foreign[5].0 = "latest_height".to_string();
    let mut r = Restore::begin(temp_db("forge_class"), 0, root).unwrap();
    assert!(
        r.add_chunk(foreign, proof.clone()).is_err(),
        "non-state key"
    );

    let mut r = Restore::begin(temp_db("forge_ok"), 0, root).unwrap();
    assert!(
        r.add_chunk(entries, proof).is_ok(),
        "positive control: the honest chunk passes"
    );
}

/// A malicious server can build a tree that holds non-state keys (for
/// example a node secret or a chain-data marker), with range proofs that
/// verify against the root it commits to. Only the class check stops the
/// joiner from installing those keys.
#[test]
fn a_consistent_tree_with_non_state_keys_is_refused() {
    let srv = temp_db("server_evil");
    let evil = vec![
        (k(1), some("fine")),
        ("sys:da:signing_key_enc_v1".to_string(), some("attacker")),
        ("latest_height".to_string(), some("999999")),
    ];
    let applied = apply_checked(&srv, 0, evil, false).unwrap();
    srv.write_batch(applied.batch).unwrap();
    let (entries, proof) = chunk(&srv, 0, None, 10).unwrap().unwrap();
    assert_eq!(
        entries.len(),
        3,
        "positive control: the evil tree is served whole"
    );
    let mut r = Restore::begin(temp_db("client_evil"), 0, applied.root).unwrap();
    let err = r.add_chunk(entries, proof).expect_err("must refuse");
    assert!(err.to_string().contains("non-state key"), "{err}");
}

/// A server whose preimage row lies must refuse to serve it, not hand every
/// client a chunk that poisons their restore.
#[test]
fn chunk_refuses_a_corrupt_preimage_and_reports_the_end_as_none() {
    let (srv, _root) = server("preimage", 5);
    let kh = key_hash(&k(3));
    srv.put(&pre_key(&kh), &k(4)).unwrap();
    let err = chunk(&srv, 0, None, 10).expect_err("corrupt preimage");
    assert!(err.to_string().contains("corrupt preimage"), "{err}");

    let (clean, _) = server("end", 5);
    let (entries, _) = chunk(&clean, 0, None, 10).unwrap().unwrap();
    let last = key_hash(&entries.last().unwrap().0);
    assert!(
        chunk(&clean, 0, Some(last), 10).unwrap().is_none(),
        "end of stream"
    );
    assert!(chunk(&clean, 0, None, MAX_CHUNK + 1).is_err(), "size cap");
}

/// Golden vector: the root of a fixed state must never drift. Any change to
/// key hashing, leaf or value encoding breaks proofs clients already verify
/// (the same vector will pin the JS verifier, PF-4).
#[test]
fn golden_root_for_a_fixed_state() {
    let db = temp_db("golden");
    let state: Vec<(String, Option<Vec<u8>>)> = vec![
        ("sys:chain_id".into(), some("AINCORE-LOCALTEST-4V-HEAD")),
        (
            "sys:total_supply".into(),
            some("40081273249273785698770128"),
        ),
        (
            "obj:dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42".into(),
            some("{}"),
        ),
        ("total_burned".into(), some("0")),
    ];
    let in_memory: BTreeMap<String, Vec<u8>> = state
        .iter()
        .map(|(k, v)| (k.clone(), v.clone().unwrap()))
        .collect();
    let root = commit(&db, 0, state);
    assert_eq!(hex::encode(root.0), GOLDEN_ROOT);
    // TA-1: the in-memory genesis root is the same root, without a database.
    assert_eq!(genesis_root(&in_memory).unwrap(), root);
    let mut not_state = in_memory.clone();
    not_state.insert("latest_height".into(), b"0".to_vec());
    assert!(genesis_root(&not_state).is_err(), "only state keys");
    assert_eq!(
        hex::encode(key_hash("sys:chain_id").0),
        hex::encode(<Sha256 as sha2::Digest>::digest(b"sys:chain_id")),
        "KeyHash is plain SHA-256 of the key bytes"
    );
}

/// Computed by this implementation on 2026-09-29, and reproduced
/// independently by the S1 reviewer, both with jmt's MockTreeStore and with a
/// hand-written sparse Merkle tree using no jmt code. S4's JS verifier must
/// reproduce it too.
const GOLDEN_ROOT: &str = "1a7348397287235bc3d21611cdb45c0cf3cb29ad93b83d858cf0094027136520";

/// `begin` reserves nothing, so two restores can start on one database. The
/// restore writer's overwrite refusal (CM-7) makes the second one fail
/// instead of silently interleaving tree rows.
#[test]
fn two_restores_into_one_database_cannot_interleave() {
    let (srv, root) = server("twice", 40);
    let client = temp_db("client_twice");
    let mut a = Restore::begin(client.clone(), 0, root).unwrap();
    let mut b = Restore::begin(client.clone(), 0, root).unwrap();
    let (entries, proof) = chunk(&srv, 0, None, 40).unwrap().unwrap();
    a.add_chunk(entries.clone(), proof.clone()).unwrap();
    client.write_batch(a.finish().unwrap()).unwrap();
    let second = b
        .add_chunk(entries, proof)
        .and_then(|_| b.finish().map(|_| ()));
    let err = second.expect_err("the second restore must not overwrite the first");
    assert!(err.to_string().contains("overwrite"), "{err}");
}

/// RC-1: the three height markers must agree, or the node refuses to boot.
#[test]
fn boot_check_refuses_disagreeing_heights_and_a_half_done_restore() {
    let fresh = temp_db("boot_fresh");
    let err = boot_check(&fresh).expect_err("no tree after genesis");
    assert!(err.to_string().contains("no state tree"), "{err}");

    let db = temp_db("boot");
    commit(&db, 0, vec![(k(1), some("a"))]);
    boot_check(&db).expect("genesis seeded, no block yet");
    commit(&db, 1, vec![(k(1), some("b"))]);
    db.put("sys:last_executed_height", "1").unwrap();
    db.put("latest_height", "1").unwrap();
    boot_check(&db).expect("positive control: consistent markers boot");

    // Heights agree with each other, the tree lags behind both: only the
    // tree check can see it.
    db.put("sys:last_executed_height", "2").unwrap();
    db.put("latest_height", "2").unwrap();
    let err = boot_check(&db).expect_err("tree behind the executed height");
    assert!(
        err.to_string().contains("state tree is at version"),
        "{err}"
    );
    db.put("sys:last_executed_height", "1").unwrap();
    db.put("latest_height", "1").unwrap();
    boot_check(&db).expect("positive control: consistent again");
    db.put("latest_height", "7").unwrap();
    assert!(boot_check(&db).is_err(), "chain height disagrees");
    db.put("latest_height", "1").unwrap();
    db.put("sys:restore_in_progress", "{}").unwrap();
    let err = boot_check(&db).expect_err("half-done restore");
    assert!(err.to_string().contains("restore"), "{err}");
    db.delete("sys:restore_in_progress").unwrap();
    boot_check(&db).expect("positive control: consistent again");

    // Executed blocks but no chain height (found by the S2 review).
    db.delete("latest_height").unwrap();
    let err = boot_check(&db).expect_err("latest_height missing");
    assert!(
        err.to_string().contains("latest_height is missing"),
        "{err}"
    );
    db.put("latest_height", "1").unwrap();

    // The latest root node is gone: refused at boot, not at the next block.
    let rows = root_node_rows(&db, 1);
    assert_eq!(
        rows.len(),
        1,
        "positive control: version 1 has one root row"
    );
    db.delete(&rows[0]).unwrap();
    let err = boot_check(&db).expect_err("root node missing");
    assert!(
        err.to_string().contains("root node of tree version 1"),
        "{err}"
    );
}

// ---- PF-4: the shared proof vectors (Rust and JS verifiers) ----

/// The vector file both verifiers read. Regenerated from real trees here and
/// pinned byte for byte: a change to key hashing, value hashing, node hashing
/// or the wire format breaks this test before it breaks a client.
const PF_VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../state_proof/vectors/pf_vectors.json"
);

fn pf_vectors() -> serde_json::Value {
    use serde_json::json;
    let db = temp_db("pf_vectors");
    // Version 0: the golden genesis-like state plus a few more keys.
    let mut v0: Vec<(String, Option<Vec<u8>>)> = vec![
        ("sys:chain_id".into(), some("AINCORE-LOCALTEST-4V-HEAD")),
        (
            "sys:total_supply".into(),
            some("40081273249273785698770128"),
        ),
        (
            "obj:dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42".into(),
            some("{}"),
        ),
        ("total_burned".into(), some("0")),
        ("sys:config:burn_percentage".into(), some("10")),
        ("sys:config:epoch_block_interval".into(), some("20")),
        ("sys:config:federation_addr".into(), some("")),
    ];
    for i in 0..24 {
        v0.push((k(i), some(&format!("value-{i}"))));
    }
    commit(&db, 0, v0);
    // Version 1: one update, one delete (the deleted key's proof is an
    // exclusion proof at v1 and an inclusion proof at v0).
    commit(
        &db,
        1,
        vec![
            (
                "sys:total_supply".into(),
                some("40081273249273785698770000"),
            ),
            (k(3), None),
        ],
    );
    let mut vectors = Vec::new();
    let mut emit = |name: &str, version: Version, key: &str| {
        let root = root(&db, version).unwrap();
        let (value, proof) = wire_proof(&db, key, version).unwrap();
        let value = value.map(|v| String::from_utf8(v).unwrap());
        let valid = json!({
            "name": name, "valid": true, "root": hex::encode(root.0), "key": key,
            "value": value, "proof": proof,
        });
        vectors.push(valid.clone());
        (valid, root)
    };
    let (inc, _) = emit("inclusion: sys:chain_id at v0", 0, "sys:chain_id");
    emit(
        "inclusion: an empty value at v0",
        0,
        "sys:config:federation_addr",
    );
    emit("inclusion: an updated value at v1", 1, "sys:total_supply");
    emit("inclusion: a deleted key at the version before", 0, &k(3));
    let (del, _) = emit("exclusion: a deleted key", 1, &k(3));
    let (abs, _) = emit("exclusion: a key never written", 1, "sys:never_written");
    // Both exclusion shapes: another key's leaf on the path, and an empty
    // subtree (no leaf at all).
    let (mut with_leaf, mut empty) = (0, 0);
    for i in 0..10_000 {
        let key = format!("sys:absent:{i}");
        let has_leaf = wire_proof(&db, &key, 1).unwrap().1.leaf.is_some();
        if has_leaf && with_leaf < 3 {
            with_leaf += 1;
            emit(
                &format!("exclusion: absent key {i}, another leaf on its path"),
                1,
                &key,
            );
        } else if !has_leaf && empty < 3 {
            empty += 1;
            emit(
                &format!("exclusion: absent key {i}, an empty subtree"),
                1,
                &key,
            );
        }
        if with_leaf == 3 && empty == 3 {
            break;
        }
    }
    assert_eq!((with_leaf, empty), (3, 3), "both exclusion shapes found");
    let near = vectors
        .iter()
        .find(|v| {
            v["valid"] == json!(true) && v["value"].is_null() && !v["proof"]["leaf"].is_null()
        })
        .cloned()
        .unwrap();
    // The value of the key whose leaf sits on `near`'s path.
    let neighbour_value = {
        let leaf_key = near["proof"]["leaf"]["key_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let mut found = None;
        for version in [1u64, 0] {
            for key in (0..24).map(k).chain([
                "sys:chain_id".to_string(),
                "sys:total_supply".to_string(),
                "total_burned".to_string(),
                "sys:config:burn_percentage".to_string(),
                "sys:config:epoch_block_interval".to_string(),
                "sys:config:federation_addr".to_string(),
                "obj:dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42".to_string(),
            ]) {
                if found.is_none() && hex::encode(key_hash(&key).0) == leaf_key {
                    found = prove(&db, &key, version).unwrap().0;
                }
            }
        }
        String::from_utf8(found.expect("the neighbour is a known key")).unwrap()
    };
    let empty = vectors
        .iter()
        .find(|v| v["valid"] == json!(true) && v["proof"]["leaf"].is_null())
        .cloned()
        .unwrap();
    // Invalid variants of the valid proofs above.
    let mut bad = |name: &str, base: &serde_json::Value, f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = base.clone();
        v["name"] = json!(name);
        v["valid"] = json!(false);
        f(&mut v);
        vectors.push(v);
    };
    bad("invalid: wrong value", &inc, &|v| {
        v["value"] = json!("AINCORE-MAINNET-1")
    });
    bad("invalid: another key", &inc, &|v| {
        v["key"] = json!("sys:total_supply")
    });
    bad("invalid: another root", &inc, &|v| {
        v["root"] = json!("00".repeat(32))
    });
    bad("invalid: claims absence of a present key", &inc, &|v| {
        v["value"] = json!(null)
    });
    bad("invalid: a sibling flipped", &inc, &|v| {
        let s = v["proof"]["siblings"][0].as_str().unwrap().to_string();
        let flipped = format!("{}{}", if &s[..1] == "0" { "1" } else { "0" }, &s[1..]);
        v["proof"]["siblings"][0] = json!(flipped);
    });
    bad("invalid: a sibling added", &inc, &|v| {
        v["proof"]["siblings"]
            .as_array_mut()
            .unwrap()
            .push(json!("00".repeat(32)));
    });
    bad("invalid: a sibling removed", &inc, &|v| {
        v["proof"]["siblings"].as_array_mut().unwrap().pop();
    });
    bad("invalid: claims a value for a deleted key", &del, &|v| {
        v["value"] = json!("value-3")
    });
    bad("invalid: claims a value for an absent key", &abs, &|v| {
        v["value"] = json!("x")
    });
    bad("invalid: a malformed sibling", &inc, &|v| {
        v["proof"]["siblings"][0] = json!("zz")
    });
    bad(
        "invalid: claims a value in an empty subtree",
        &empty,
        &|v| v["value"] = json!("x"),
    );
    // The forgery the key check stops: the leaf on an absent key's path is
    // another key's, and claiming that key's value for the absent key would
    // otherwise reach the true root.
    bad(
        "invalid: a neighbour's value claimed on an absent key's path",
        &near,
        &|v| {
            v["value"] = json!(neighbour_value.clone());
        },
    );
    bad(
        "invalid: another key's leaf planted in an empty subtree",
        &empty,
        &|v| {
            v["proof"]["leaf"] = inc["proof"]["leaf"].clone();
        },
    );
    json!({
        "description": "G3 PF-4 state proof vectors. Generated from real Jellyfish Merkle trees by common/state_commit (pf_vectors_are_pinned) and verified by common/state_proof and aincore-js. Values are the exact stored strings.",
        "vectors": vectors,
    })
}

/// PF-4: regenerate the vectors from real trees and compare them with the
/// pinned file. Set AINCORE_WRITE_PF_VECTORS=1 to write the file instead.
#[test]
fn pf_vectors_are_pinned() {
    let generated = serde_json::to_string_pretty(&pf_vectors()).unwrap() + "\n";
    if std::env::var_os("AINCORE_WRITE_PF_VECTORS").is_some() {
        std::fs::write(PF_VECTORS, &generated).unwrap();
    }
    let pinned = std::fs::read_to_string(PF_VECTORS).expect("the pinned vector file");
    assert_eq!(generated, pinned, "the proof vectors changed");
}

// ---- GC-1 pruning, RC-2 and RC-3 (S7) ----

fn count_rows(db: &StateDB, prefix: &str) -> usize {
    db.db
        .prefix_iterator(prefix.as_bytes())
        .map(Result::unwrap)
        .take_while(|(k, _)| k.starts_with(prefix.as_bytes()))
        .count()
}

/// A random history with updates, deletes and empty blocks. Returns the
/// model of the flat state after each version.
fn random_history(db: &Arc<StateDB>, seed: u64, versions: u64) -> Vec<BTreeMap<String, Vec<u8>>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut states = Vec::new();
    for version in 0..versions {
        let mut changes: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
        // Every fourth version is an empty block (its root is carried).
        if version == 0 || version % 4 != 3 {
            for _ in 0..rng.gen_range(1..8) {
                let key = k(rng.gen_range(0..40));
                let value = if version > 0 && rng.gen_bool(0.25) {
                    None
                } else {
                    Some(format!("v{version}-{}", rng.gen::<u16>()).into_bytes())
                };
                changes.insert(key, value);
            }
        }
        if version == 0 {
            changes.retain(|_, v| v.is_some());
        }
        for (key, value) in &changes {
            match value {
                Some(v) => {
                    model.insert(key.clone(), v.clone());
                }
                None => {
                    model.remove(key);
                }
            }
        }
        commit(db, version, changes.into_iter().collect());
        states.push(model.clone());
    }
    states
}

fn assert_version_is_whole(db: &Arc<StateDB>, version: Version, model: &BTreeMap<String, Vec<u8>>) {
    let root = root(db, version).unwrap();
    for i in 0..40 {
        let key = k(i);
        let (value, proof) = prove(db, &key, version).unwrap();
        assert_eq!(value.as_ref(), model.get(&key), "{key} at {version}");
        verify(root, &key, value.as_deref(), &proof).unwrap();
    }
}

/// GC-1 / GC-2: pruning never changes a root, keeps every version at or
/// above the floor whole, and after pruning to the tip leaves exactly the
/// nodes of a fresh tree over the same state (no leak, including the roots
/// empty blocks carry forward).
#[test]
fn pruning_keeps_every_retained_version_whole_and_leaks_nothing() {
    let db = temp_db("prune_whole");
    let states = random_history(&db, 7, 40);
    let roots: Vec<RootHash> = (0..40).map(|v| root(&db, v).unwrap()).collect();
    let stats = prune(&db, 25, &Default::default(), usize::MAX).unwrap();
    assert!(
        stats.nodes > 0 && stats.values > 0,
        "positive control: {stats:?}"
    );
    assert_eq!(floor(&db).unwrap(), 25);
    for version in 25..40u64 {
        assert_eq!(root(&db, version).unwrap(), roots[version as usize]);
        assert_version_is_whole(&db, version, &states[version as usize]);
    }
    // To the tip: exactly a fresh tree's nodes and one value row per key.
    prune(&db, 39, &Default::default(), usize::MAX).unwrap();
    let fresh = temp_db("prune_fresh");
    commit(
        &fresh,
        0,
        states[39]
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect(),
    );
    assert_eq!(root(&fresh, 0).unwrap(), roots[39]);
    assert_eq!(
        count_rows(&db, NODE),
        count_rows(&fresh, NODE),
        "no node leaks"
    );
    assert_version_is_whole(&db, 39, &states[39]);
}

/// GC-1 value rule: each key keeps its newest value row at or below the
/// floor and every newer one, and nothing else.
#[test]
fn pruning_follows_the_value_rule() {
    let db = temp_db("prune_values");
    commit(&db, 0, vec![(k(1), some("a")), (k(2), some("x"))]);
    commit(&db, 1, vec![(k(1), some("b"))]);
    commit(&db, 2, vec![(k(1), some("c")), (k(2), None)]);
    commit(&db, 3, vec![(k(1), some("d"))]);
    prune(&db, 2, &Default::default(), usize::MAX).unwrap();
    // k1: the row at 2 (newest at or below the floor) and at 3. k2 was
    // deleted at the floor and never re-created: no row at all, since an
    // absent key reads the same as a deleted one.
    assert_eq!(count_rows(&db, &val_prefix(&key_hash(&k(1)))), 2);
    assert_eq!(count_rows(&db, &val_prefix(&key_hash(&k(2)))), 0);
    assert_eq!(prove(&db, &k(1), 2).unwrap().0, some("c"));
    assert_eq!(prove(&db, &k(1), 3).unwrap().0, some("d"));
    assert_eq!(prove(&db, &k(2), 2).unwrap().0, None);
    assert_eq!(prove(&db, &k(2), 3).unwrap().0, None);
}

/// SN-4: a pinned version below the floor keeps everything it needs.
#[test]
fn a_pinned_version_survives_pruning() {
    let db = temp_db("prune_pinned");
    let states = random_history(&db, 11, 30);
    let pinned: std::collections::BTreeSet<Version> = [10].into();
    prune(&db, 29, &pinned, usize::MAX).unwrap();
    assert_version_is_whole(&db, 10, &states[10]);
    assert_version_is_whole(&db, 29, &states[29]);
}

/// Bounded work per call: the floor is raised first, and repeated calls
/// converge on the same result as one unbounded call.
#[test]
fn bounded_pruning_converges() {
    let (a, b) = (temp_db("prune_bounded"), temp_db("prune_unbounded"));
    let states = random_history(&a, 5, 30);
    random_history(&b, 5, 30);
    let first = prune(&a, 20, &Default::default(), 3).unwrap();
    assert!(first.more, "the limit was hit");
    assert_eq!(floor(&a).unwrap(), 20, "the floor was raised first");
    while prune(&a, 20, &Default::default(), 3).unwrap().more {}
    prune(&b, 20, &Default::default(), usize::MAX).unwrap();
    assert_eq!(count_rows(&a, NODE), count_rows(&b, NODE));
    assert_eq!(count_rows(&a, VAL), count_rows(&b, VAL));
    assert_version_is_whole(&a, 20, &states[20]);
    // The floor never goes down.
    prune(&a, 5, &Default::default(), usize::MAX).unwrap();
    assert_eq!(floor(&a).unwrap(), 20);
}

/// RC-2: a flat state key edited out-of-band, and one that is not in the
/// tree at all, are both listed; a consistent database lists nothing.
#[test]
fn rc2_lists_every_flat_key_the_tree_disagrees_with() {
    let db = temp_db("rc2");
    let _seed = db.seeding();
    for i in 0..10 {
        db.put(&k(i), &format!("v{i}")).unwrap();
    }
    let v0 = seed_genesis(&db).unwrap();
    db.write_batch(v0.batch).unwrap();
    assert_eq!(audit_flat_vs_tree(&db).unwrap(), Vec::<String>::new());
    db.put(&k(3), "tampered").unwrap();
    db.put("sys:config:base_reward", "999").unwrap();
    let mut divergent = audit_flat_vs_tree(&db).unwrap();
    divergent.sort();
    assert_eq!(divergent, vec![k(3), "sys:config:base_reward".to_string()]);
}

/// RC-3: a self-consistent database whose root is not the network's QC root
/// is refused; the network's root passes.
#[test]
fn rc3_refuses_a_root_that_is_not_the_networks() {
    let db = temp_db("rc3");
    let root = commit(&db, 0, vec![(k(1), some("a"))]);
    audit_root_against_qc(&db, 0, &hex::encode(root.0)).unwrap();
    assert!(audit_root_against_qc(&db, 0, &"00".repeat(32)).is_err());
}

/// SN-4 (S7 review): pins exist at production retention. Epoch boundaries
/// spaced about a quarter window apart over two windows: a handful of
/// versions below the floor, not zero and not every boundary.
#[test]
fn the_pin_schedule_pins_a_few_boundaries_below_the_floor() {
    let pins = pin_schedule(600, 200, 20);
    assert_eq!(
        pins,
        [200, 240, 280, 320, 360, 400, 440, 480, 520, 560, 600].into()
    );
    assert!(pins.iter().all(|v| v % 20 == 0), "epoch boundaries only");
    let below_floor = pins.iter().filter(|v| **v < 400).count();
    assert_eq!(below_floor, 5);
    // Full-mode defaults: 100,000 blocks, 20-block epochs.
    let full = pin_schedule(1_000_000, 100_000, 20);
    assert!(full.len() <= 9, "{}", full.len());
    assert!(
        full.iter().any(|v| *v < 900_000),
        "some pin below the floor"
    );
}

/// GC-1 (S7 review): a deleted key leaves nothing behind once pruned past its
/// deletion: no value rows, no preimage. A key deleted and re-created keeps
/// exactly its live row.
#[test]
fn deleted_keys_leave_no_rows_after_pruning() {
    let db = temp_db("prune_deleted");
    commit(
        &db,
        0,
        vec![(k(1), some("keep")), (k(2), some("a")), (k(4), some("p"))],
    );
    // k4 is deleted, then re-created and live at the tip: its deletion row
    // goes, its preimage stays.
    commit(&db, 1, vec![(k(4), None)]);
    commit(&db, 2, vec![(k(4), some("q"))]);
    let mut version = 3;
    for round in 0..10 {
        commit(&db, version, vec![(k(2), None)]);
        commit(&db, version + 1, vec![(k(2), some(&format!("b{round}")))]);
        version += 2;
    }
    commit(&db, version, vec![(k(2), None)]);
    commit(&db, version + 1, vec![(k(3), some("x"))]);
    commit(&db, version + 2, vec![(k(3), None)]);
    let tip = version + 2;
    prune(&db, tip, &Default::default(), usize::MAX).unwrap();
    assert_eq!(
        count_rows(&db, &val_prefix(&key_hash(&k(2)))),
        0,
        "deleted k2"
    );
    assert_eq!(
        count_rows(&db, &val_prefix(&key_hash(&k(3)))),
        0,
        "deleted k3"
    );
    assert_eq!(count_rows(&db, &val_prefix(&key_hash(&k(1)))), 1, "live k1");
    assert_eq!(
        count_rows(&db, &val_prefix(&key_hash(&k(4)))),
        1,
        "re-created k4"
    );
    assert_eq!(count_rows(&db, PRE), 2, "only the live keys' preimages");
    assert_eq!(prove(&db, &k(4), tip).unwrap().0, some("q"));
    assert_eq!(count_rows(&db, VDEAD), 0);
    assert_eq!(prove(&db, &k(2), tip).unwrap().0, None);
    assert_eq!(prove(&db, &k(1), tip).unwrap().0, some("keep"));
}

/// A pin that still needs a deleted key's older value keeps its deletion row
/// too, so versions at or above the deletion still read the key as absent.
#[test]
fn a_pinned_value_keeps_the_deletion_row_after_it() {
    let db = temp_db("prune_deleted_pinned");
    commit(&db, 0, vec![(k(1), some("a"))]);
    commit(&db, 1, vec![(k(9), some("filler"))]);
    commit(&db, 2, vec![(k(1), None)]);
    commit(&db, 3, vec![(k(9), some("filler2"))]);
    prune(&db, 3, &[1].into(), usize::MAX).unwrap();
    assert_eq!(prove(&db, &k(1), 1).unwrap().0, some("a"), "the pin");
    assert_eq!(prove(&db, &k(1), 3).unwrap().0, None, "still absent after");
    // A snapshot served at the pin names k1, so its preimage stays, and so
    // does the deletion row that bounds the pinned value's life.
    assert_eq!(count_rows(&db, &pre_key(&key_hash(&k(1)))), 1, "preimage");
    assert_eq!(count_rows(&db, VDEAD), 1, "deletion row");
    // Once the pin goes, so does everything of k1.
    prune(&db, 3, &Default::default(), usize::MAX).unwrap();
    assert_eq!(count_rows(&db, &val_prefix(&key_hash(&k(1)))), 0);
    assert_eq!(count_rows(&db, &pre_key(&key_hash(&k(1)))), 0);
    assert_eq!(count_rows(&db, VDEAD), 0);
}

/// SN-4: a server offers exactly what pruning keeps: the floor to the tip,
/// and the pins below the floor.
#[test]
fn servable_versions_are_what_pruning_keeps() {
    let db = temp_db("servable");
    assert!(!servable(&db, 0, Some(10)).unwrap(), "no tree yet");
    for v in 0..=40 {
        commit(&db, v, vec![(k((v % 3) as usize), some(&format!("x{v}")))]);
    }
    // Interval 20 is the default; keep 10 pins multiples of 20 from 20.
    let pins = pin_schedule(40, 10, epoch_interval(&db));
    assert_eq!(pins, [20, 40].into());
    prune(&db, 30, &pins, usize::MAX).unwrap();
    for (version, keep, expected) in [
        (30, Some(10), true),
        (40, Some(10), true),
        (41, Some(10), false),
        (20, Some(10), true),
        (25, Some(10), false),
        (29, Some(10), false),
        (20, None, false),
    ] {
        assert_eq!(
            servable(&db, version, keep).unwrap(),
            expected,
            "{version} {keep:?}"
        );
    }
    for version in [20u64, 30, 40] {
        prove(&db, &k(1), version).expect("a servable version is whole");
    }
}

/// GC-1 race: a key re-created while prune decides to drop its preimage
/// keeps the preimage. The re-creation runs on another thread between
/// prune's checks and its writes, as the executor writes: `apply` and its
/// batch in one transaction. The deletion pass is one transaction too, so
/// the two serialize on the writer gate.
#[test]
fn a_key_recreated_during_pruning_keeps_its_preimage() {
    let db = temp_db("prune_race");
    commit(&db, 0, vec![(k(1), some("a")), (k(9), some("x"))]);
    commit(&db, 1, vec![(k(1), None)]);
    commit(&db, 2, vec![(k(9), some("y"))]);
    let writer: std::sync::Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> =
        Default::default();
    let handle = std::sync::Arc::clone(&writer);
    let for_thread = std::sync::Arc::clone(&db);
    BEFORE_DEAD_WRITE.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            let db = for_thread;
            *handle.lock().unwrap() = Some(std::thread::spawn(move || {
                db.transaction(|view| {
                    let applied = apply(&view, 3, vec![(k(1), some("back"))])
                        .map_err(|e| storage::StorageError::DatabaseOperation(e.to_string()))?;
                    view.write_batch(applied.batch)
                })
                .unwrap();
            }));
            std::thread::sleep(std::time::Duration::from_millis(200));
        }));
    });
    prune(&db, 2, &Default::default(), usize::MAX).unwrap();
    writer.lock().unwrap().take().unwrap().join().unwrap();
    assert_eq!(prove(&db, &k(1), 3).unwrap().0, some("back"));
    assert_eq!(
        count_rows(&db, &pre_key(&key_hash(&k(1)))),
        1,
        "the re-created key keeps its preimage"
    );
    assert_eq!(count_rows(&db, VDEAD), 0, "the old deletion row went");
}

