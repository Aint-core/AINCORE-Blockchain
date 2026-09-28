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
    let root = commit(&db, 0, state);
    assert_eq!(hex::encode(root.0), GOLDEN_ROOT);
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
    boot_check(&fresh).expect("an empty database boots");

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
}
