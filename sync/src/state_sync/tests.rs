//! G3 S6 witnesses (SN-2, SN-4): a restore from untrusted peers completes
//! against the checkpoint root, whatever the peers do, or refuses.

use super::*;
use consensus::qc::{build_qc, validator_set_hash, FinalityVote, ValidatorInfo};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

const CHAIN: &str = "AINCORE-TEST-S6";
/// The servers' history runs to TIP; the checkpoint is at H.
const TIP: u64 = 12;
const H: u64 = 10;
/// Leaves per chunk in these tests, so a restore takes several chunks.
const SMALL_CHUNK: usize = 7;
const MEMBER: [u8; 32] = [7; 32];
const IDENTITY: &str = "1d";

fn temp_db(name: &str) -> Arc<StateDB> {
    let path = std::env::temp_dir().join(format!(
        "s6_{name}_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&path);
    Arc::new(StateDB::open(path.to_str().unwrap()).unwrap())
}

fn obj(i: u64) -> String {
    format!("obj:{i:064x}")
}

fn committee() -> Vec<ValidatorInfo> {
    let bls = crypto::bls::BLSEngine::consensus();
    vec![ValidatorInfo {
        address: format!("{:064x}", 1),
        stake: 100,
        ed25519_public_key: "00".repeat(32),
        bls_public_key: hex::encode(bls.pubkey_raw(&MEMBER)),
        bls_pop: hex::encode(bls.prove_possession_raw(&MEMBER)),
    }]
}

/// One server's chain: a tree over versions `0..=TIP` (keys rewritten, one
/// deleted) and, at `H`, the block and a QC over it signed with `signer`.
struct Chain {
    db: Arc<StateDB>,
    cp: Checkpoint,
    /// The consensus state at `H`.
    state: BTreeMap<String, Vec<u8>>,
}

/// This node's own genesis rows, as `RestorePlan::genesis` carries them.
fn genesis() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("sys:chain_id".to_string(), CHAIN.to_string()),
        (
            "genesis:validator_set:v1".to_string(),
            serde_json::to_string(&committee()).unwrap(),
        ),
        (
            "sys:config:epoch_block_interval".to_string(),
            "5".to_string(),
        ),
        ("genesis_version".to_string(), "s6-test".to_string()),
    ])
}

fn chain(name: &str, signer: [u8; 32]) -> Chain {
    chain_as(name, signer, CHAIN)
}

/// A chain whose state names `state_chain` while its QC signs for CHAIN.
fn chain_as(name: &str, signer: [u8; 32], state_chain: &str) -> Chain {
    let db = temp_db(name);
    let members = committee();
    let mut state: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut at_h = BTreeMap::new();
    let mut root_h = None;
    for version in 0..=TIP {
        let changes: Vec<(String, Option<Vec<u8>>)> = if version == 0 {
            let mut v0 = vec![
                (
                    "sys:chain_id".to_string(),
                    Some(state_chain.as_bytes().to_vec()),
                ),
                (
                    "sys:config:epoch_block_interval".to_string(),
                    Some(b"5".to_vec()),
                ),
                (
                    "genesis:validator_set:v1".to_string(),
                    Some(serde_json::to_vec(&members).unwrap()),
                ),
            ];
            v0.extend((0..40).map(|i| (obj(i), Some(format!("v{i}").into_bytes()))));
            v0
        } else if version == 4 {
            vec![(obj(39), None)]
        } else {
            vec![(obj(version % 7), Some(format!("r{version}").into_bytes()))]
        };
        for (key, value) in &changes {
            match value {
                Some(v) => state.insert(key.clone(), v.clone()),
                None => state.remove(key),
            };
        }
        let applied = state_commit::apply(&db, version, changes).unwrap();
        db.write_batch(applied.batch).unwrap();
        if version == H {
            at_h = state.clone();
            root_h = Some(hex::encode(applied.root.0));
        }
    }
    let root = root_h.unwrap();
    let block = Block::new_with_roots_at(
        H,
        2 * H,
        "00".repeat(32),
        vec![],
        "proposer".into(),
        root.clone(),
        "dd".repeat(32),
        1_000,
        vec![],
        "aa".repeat(32),
        vec![],
    );
    let vote = FinalityVote {
        chain_id: CHAIN.into(),
        epoch: 0,
        finalized_round: 2 * H + 2,
        anchor_round: block.header.round,
        anchor_hash: block.anchor_hash.clone(),
        block_height: H,
        block_hash: block.header.hash.clone(),
        state_root: root.clone(),
        receipts_root: block.header.receipts_root.clone(),
        finality_digest: "ee".repeat(32),
        validator_set_hash: validator_set_hash(&members),
    };
    let signature = crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &signer);
    let qc = build_qc(&vote, &members, &[0], &[signature]).unwrap();
    db.put(
        &format!("block_{H}"),
        &serde_json::to_string(&block).unwrap(),
    )
    .unwrap();
    db.put(
        &format!("consensus:qc:{H}"),
        &serde_json::to_string(&qc).unwrap(),
    )
    .unwrap();
    Chain {
        db,
        cp: Checkpoint {
            height: H,
            block_hash: block.header.hash,
            state_root: root,
        },
        state: at_h,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Behaviour {
    Honest,
    /// Rewrites a value in its second chunk.
    Forge,
    /// Says the stream is over at its third chunk.
    EndEarly,
    /// Drops the last leaf of its second chunk.
    DropLast,
    /// Prunes the checkpoint version after serving one chunk.
    PruneAfterFirst,
    /// Stops answering after one chunk.
    DiesAfterFirst,
}

struct Peer {
    sync: ChainSync,
    db: Arc<StateDB>,
    behaviour: Behaviour,
    chunks: usize,
}

fn peer(chain: &Chain, behaviour: Behaviour) -> Peer {
    Peer {
        sync: ChainSync::new(
            "server".into(),
            0,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::clone(&chain.db),
        ),
        db: Arc::clone(&chain.db),
        behaviour,
        chunks: 0,
    }
}

fn serve(peer: &mut Peer, msg: &str) -> Result<String, String> {
    let Some(json) = msg.strip_prefix(CHUNK_REQ) else {
        return peer.sync.handle_message(msg).ok_or("no answer".into());
    };
    if peer.behaviour == Behaviour::DiesAfterFirst && peer.chunks >= 1 {
        return Err("connection reset".into());
    }
    if peer.behaviour == Behaviour::PruneAfterFirst && peer.chunks == 1 {
        state_commit::prune(&peer.db, TIP, &Default::default(), usize::MAX).unwrap();
    }
    let mut request: ChunkRequest = serde_json::from_str(json).unwrap();
    request.max = SMALL_CHUNK;
    let reply = peer
        .sync
        .handle_message(&format!(
            "{CHUNK_REQ}{}",
            serde_json::to_string(&request).unwrap()
        ))
        .ok_or("no answer")?;
    peer.chunks += 1;
    let mut resp: ChunkResponse =
        serde_json::from_str(reply.strip_prefix(CHUNK_RESP).unwrap()).unwrap();
    match peer.behaviour {
        Behaviour::Forge if peer.chunks == 2 => resp.entries[0].1 = hex::encode(b"forged"),
        Behaviour::EndEarly if peer.chunks == 3 => {
            resp = ChunkResponse {
                done: true,
                ..Default::default()
            }
        }
        Behaviour::DropLast if peer.chunks == 2 => {
            resp.entries.pop();
        }
        _ => {}
    }
    Ok(format!(
        "{CHUNK_RESP}{}",
        serde_json::to_string(&resp).unwrap()
    ))
}

fn plan<'a>(
    cp: &'a Checkpoint,
    genesis: &'a BTreeMap<String, String>,
    replace_existing: bool,
) -> RestorePlan<'a> {
    RestorePlan {
        checkpoint: cp,
        genesis,
        genesis_identity: IDENTITY,
        replace_existing,
    }
}

async fn run(
    client: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    peers: &mut [Peer],
) -> Result<Restored, String> {
    let n = peers.len();
    restore_state(client, plan, n, |i, msg| {
        let reply = serve(&mut peers[i], &msg);
        async move { reply }
    })
    .await
}

fn flat_state(db: &StateDB) -> BTreeMap<String, Vec<u8>> {
    db.db
        .iterator(IteratorMode::Start)
        .map(Result::unwrap)
        .filter(|(k, _)| classify(k) == Some(KeyClass::State))
        .map(|(k, v)| (String::from_utf8(k.to_vec()).unwrap(), v.to_vec()))
        .collect()
}

fn count(db: &StateDB, prefix: &str) -> usize {
    db.db
        .iterator(IteratorMode::Start)
        .map(Result::unwrap)
        .filter(|(k, _)| k.starts_with(prefix.as_bytes()))
        .count()
}

/// The datadir boots as a node at `H` holding exactly the checkpoint's state.
fn assert_restored(client: &Arc<StateDB>, chain: &Chain) {
    assert_eq!(client.get(RESTORE_MARKER).unwrap(), None, "marker removed");
    state_commit::boot_check(client).expect("RC-1");
    assert!(
        state_commit::audit_flat_vs_tree(client).unwrap().is_empty(),
        "RC-2"
    );
    assert_eq!(flat_state(client), chain.state, "exactly the state at H");
    assert_eq!(
        hex::encode(state_commit::root(client, H).unwrap().0),
        chain.cp.state_root
    );
    assert_eq!(state_commit::floor(client).unwrap(), H);
    let (value, _) = state_commit::wire_proof(client, &obj(3), H).unwrap();
    assert_eq!(
        value.as_deref(),
        chain.state.get(&obj(3)).map(Vec::as_slice)
    );
    let h = H.to_string();
    for key in [
        "latest_height",
        "sys:last_executed_height",
        "consensus:last_adopted_height",
        "consensus:qc:latest_height",
    ] {
        assert_eq!(
            client.get(key).unwrap().as_deref(),
            Some(h.as_str()),
            "{key}"
        );
    }
    assert_eq!(
        client.get("latest_block_hash").unwrap().as_deref(),
        Some(chain.cp.block_hash.as_str())
    );
    assert!(client.get(&format!("block_{H}")).unwrap().is_some());
    assert_eq!(
        client.get("genesis_identity").unwrap().as_deref(),
        Some(IDENTITY)
    );
    assert_eq!(
        client.get("genesis_version").unwrap().as_deref(),
        Some("s6-test"),
        "genesis rows outside the state"
    );
    let anchor_round = (2 * H).to_string();
    for (key, value) in [
        ("consensus:finality_digest", "ee".repeat(32)),
        ("consensus:last_anchor_round", anchor_round.clone()),
        ("consensus:last_anchor_hash", "aa".repeat(32)),
        ("consensus:finalized_round", (2 * H + 2).to_string()),
        ("consensus:qc:latest_round", anchor_round),
    ] {
        assert_eq!(
            client.get(key).unwrap().as_deref(),
            Some(value.as_str()),
            "{key}"
        );
    }
}

fn stored_qc(chain: &Chain) -> QuorumCertificate {
    serde_json::from_str(&chain.db.get(&format!("consensus:qc:{H}")).unwrap().unwrap()).unwrap()
}

fn stored_block(chain: &Chain) -> Block {
    serde_json::from_str(&chain.db.get(&format!("block_{H}")).unwrap().unwrap()).unwrap()
}

#[tokio::test]
async fn a_node_restores_from_honest_peers() {
    let g = genesis();
    let a = chain("honest_a", MEMBER);
    let b = chain("honest_b", MEMBER);
    let client = temp_db("honest_client");
    let mut peers = [peer(&a, Behaviour::Honest), peer(&b, Behaviour::Honest)];
    let done = run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_eq!(done.leaves, a.state.len());
    assert_eq!(done.restarts, 0);
    assert!(peers[0].chunks > 3, "several chunks: {}", peers[0].chunks);
    assert_restored(&client, &a);

    // The QC check wants the epoch the restored state records for H, even
    // from a committee member's valid signature.
    let good = stored_qc(&a);
    let members = committee();
    let mut vote = good.finality_vote();
    vote.epoch = 1;
    let signature = crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &MEMBER);
    let other_epoch = build_qc(&vote, &members, &[0], &[signature]).unwrap();
    let plan = plan(&a.cp, &g, false);
    let err = verify_restored_qc(&client, &plan, std::slice::from_ref(&other_epoch)).unwrap_err();
    assert!(err.contains("epoch"), "{err}");
    assert_eq!(
        verify_restored_qc(&client, &plan, &[other_epoch, good.clone()]),
        Ok(good)
    );
}

/// The block and QC a peer offers must be the checkpoint's, field by field.
#[test]
fn the_anchor_must_be_the_checkpoints_block_and_its_qc() {
    let a = chain("anchor_a", MEMBER);
    let block = stored_block(&a);
    let qc = stored_qc(&a);
    assert_eq!(check_anchor(&a.cp, &block, &qc), Ok(()));
    let other_cp = [
        Checkpoint {
            height: H + 1,
            ..a.cp.clone()
        },
        Checkpoint {
            block_hash: "11".repeat(32),
            ..a.cp.clone()
        },
        Checkpoint {
            state_root: "11".repeat(32),
            ..a.cp.clone()
        },
    ];
    for cp in &other_cp {
        assert!(check_anchor(cp, &block, &qc).is_err(), "{cp:?}");
    }
    let mut body = block.clone();
    body.transactions.push("{}".into());
    assert!(
        check_anchor(&a.cp, &body, &qc).is_err(),
        "a body the header does not commit to"
    );
    let wrong_qcs: [fn(&mut QuorumCertificate); 6] = [
        |q| q.block_height += 1,
        |q| q.block_hash = "11".repeat(32),
        |q| q.state_root = "11".repeat(32),
        |q| q.receipts_root = "11".repeat(32),
        |q| q.anchor_round += 1,
        |q| q.anchor_hash = "11".repeat(32),
    ];
    for (i, wrong) in wrong_qcs.iter().enumerate() {
        let mut q = qc.clone();
        wrong(&mut q);
        assert!(check_anchor(&a.cp, &block, &q).is_err(), "QC field {i}");
    }
}

/// SN-2 step 3: a forged chunk is refused, and the restore completes
/// against the checkpoint root from another peer.
#[tokio::test]
async fn a_forged_chunk_is_refused_and_the_restore_completes_elsewhere() {
    let g = genesis();
    let a = chain("forge_a", MEMBER);
    let b = chain("forge_b", MEMBER);
    let client = temp_db("forge_client");
    let mut peers = [peer(&a, Behaviour::Forge), peer(&b, Behaviour::Honest)];
    let done = run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_eq!(done.restarts, 1);
    assert_restored(&client, &a);
}

/// SN-4 witness: a truncated stream (one that ends early, or a chunk short
/// of its last leaf) never completes a restore.
#[tokio::test]
async fn a_truncated_stream_restarts_the_restore() {
    let g = genesis();
    let a = chain("trunc_a", MEMBER);
    let b = chain("trunc_b", MEMBER);
    let c = chain("trunc_c", MEMBER);
    let client = temp_db("trunc_client");
    let mut peers = [
        peer(&a, Behaviour::EndEarly),
        peer(&b, Behaviour::DropLast),
        peer(&c, Behaviour::Honest),
    ];
    let done = run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_eq!(done.restarts, 2, "one for each short stream");
    assert_restored(&client, &a);
}

/// SN-4 witness: a peer that prunes the version mid-restore stops serving
/// it, and the restore carries on from another peer at the same cursor.
#[tokio::test]
async fn a_peer_that_prunes_mid_restore_is_left_behind() {
    let g = genesis();
    let a = chain("prune_a", MEMBER);
    let b = chain("prune_b", MEMBER);
    let client = temp_db("prune_client");
    let mut peers = [
        peer(&a, Behaviour::PruneAfterFirst),
        peer(&b, Behaviour::Honest),
    ];
    let done = run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_eq!(done.restarts, 0, "no restart, only another peer");
    assert_eq!(peers[0].chunks, 2, "it served once, then refused");
    assert_restored(&client, &a);
}

/// SN-2 step 5 / RC-1: an interrupted restore leaves a datadir that refuses
/// to boot, and a later restore completes it.
#[tokio::test]
async fn an_interrupted_restore_refuses_to_boot_and_restores_again() {
    let g = genesis();
    let a = chain("crash_a", MEMBER);
    let client = temp_db("crash_client");
    let mut dying = [peer(&a, Behaviour::DiesAfterFirst)];
    let err = run(&client, &plan(&a.cp, &g, false), &mut dying)
        .await
        .unwrap_err();
    assert!(err.contains("no peer serves"), "{err}");
    assert!(client.get(RESTORE_MARKER).unwrap().is_some());
    assert_eq!(flat_state(&client).len(), SMALL_CHUNK, "a partial state");
    let boot = state_commit::boot_check(&client).unwrap_err();
    assert!(boot.to_string().contains("restore is incomplete"), "{boot}");

    let mut honest = [peer(&a, Behaviour::Honest)];
    run(&client, &plan(&a.cp, &g, false), &mut honest)
        .await
        .unwrap();
    assert_restored(&client, &a);
}

/// SN-4 witness: a long-offline node's datadir, with stale flat state, is
/// replaced only when asked. Its signing guards and proposal round stay
/// (SN-6); its old state and chain data go.
#[tokio::test]
async fn a_long_offline_datadir_is_replaced_only_when_asked() {
    let g = genesis();
    let a = chain("offline_a", MEMBER);
    let client = temp_db("offline_client");
    let stale = obj(999);
    let guard = format!(
        "consensus:qc_signing:v1:{}:{}:height:3",
        "ab".repeat(32),
        "cd".repeat(48)
    );
    let old_vertex = format!("vertex:{}", "ef".repeat(32));
    {
        let _seed = client.seeding();
        client.put(&stale, "old").unwrap();
        client.put("genesis_initialized", "true").unwrap();
        client.put("latest_height", "3").unwrap();
        client.put(&guard, "signed").unwrap();
        client.put("latest_proposed_round", "77").unwrap();
        client.put(&old_vertex, "{}").unwrap();
    }
    let mut peers = [peer(&a, Behaviour::Honest)];
    let err = run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("already holds a chain"), "{err}");
    assert_eq!(client.get(&stale).unwrap().as_deref(), Some("old"));
    assert_eq!(client.get(RESTORE_MARKER).unwrap(), None);

    run(&client, &plan(&a.cp, &g, true), &mut peers)
        .await
        .unwrap();
    assert_restored(&client, &a);
    assert_eq!(client.get(&stale).unwrap(), None, "stale state is gone");
    assert_eq!(client.get(&old_vertex).unwrap(), None, "old chain data too");
    assert_eq!(client.get(&guard).unwrap().as_deref(), Some("signed"));
    assert_eq!(
        client.get("latest_proposed_round").unwrap().as_deref(),
        Some("77")
    );
}

/// A checkpoint no peer can back, or one whose state its own committee did
/// not sign, or from another chain, restores nothing.
#[tokio::test]
async fn a_checkpoint_that_does_not_hold_restores_nothing() {
    let g = genesis();
    let a = chain("cp_a", MEMBER);
    let client = temp_db("cp_client");
    let mut peers = [peer(&a, Behaviour::Honest)];

    let wrong_root = Checkpoint {
        state_root: "11".repeat(32),
        ..a.cp.clone()
    };
    let err = run(&client, &plan(&wrong_root, &g, false), &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("no peer holds"), "{err}");
    assert_eq!(client.get(RESTORE_MARKER).unwrap(), None);
    let wrong_block = Checkpoint {
        block_hash: "11".repeat(32),
        ..a.cp.clone()
    };
    let err = run(&client, &plan(&wrong_block, &g, false), &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("no peer holds"), "{err}");

    // This node's genesis names another chain, or another genesis committee.
    for (key, value) in [
        ("sys:chain_id", "AINCORE-OTHER".to_string()),
        (
            "genesis:validator_set:v1",
            serde_json::to_string(&Vec::<ValidatorInfo>::new()).unwrap(),
        ),
        ("sys:config:epoch_block_interval", "6".to_string()),
    ] {
        let mut other = genesis();
        other.insert(key.to_string(), value);
        let err = run(&client, &plan(&a.cp, &other, false), &mut peers)
            .await
            .unwrap_err();
        assert!(err.contains("inconsistent") && err.contains(key), "{err}");
    }
    // The state names another chain, though its QC signs for this one.
    let elsewhere = chain_as("cp_elsewhere", MEMBER, "AINCORE-ELSEWHERE");
    let mut far = [peer(&elsewhere, Behaviour::Honest)];
    let err = run(&client, &plan(&elsewhere.cp, &g, false), &mut far)
        .await
        .unwrap_err();
    assert!(err.contains("AINCORE-ELSEWHERE"), "{err}");

    // Signed by a key outside the committee its own state records.
    let forged = chain("cp_outsider", [9; 32]);
    let mut peers = [peer(&forged, Behaviour::Honest)];
    let err = run(&client, &plan(&forged.cp, &g, false), &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("inconsistent"), "{err}");
    for (what, prefix) in [
        ("marker", RESTORE_MARKER),
        ("tree", "jmt:"),
        ("state", "obj:"),
    ] {
        assert_eq!(count(&client, prefix), 0, "{what} left behind");
    }
}

#[test]
fn the_server_serves_only_what_it_retains() {
    let a = chain("serve_a", MEMBER);
    let sync = peer(&a, Behaviour::Honest).sync;
    let ask = |version: u64, after: Option<String>| {
        sync.handle_state_chunk(ChunkRequest {
            version,
            after,
            max: 100_000,
        })
    };
    let first = ask(H, None);
    assert!(first.error.is_none() && !first.done);
    assert_eq!(first.entries.len(), a.state.len(), "all of a small state");
    assert!(first.entries.len() <= MAX_CHUNK_ENTRIES);
    assert_eq!(
        ask(TIP + 1, None).error.as_deref(),
        Some("version not retained")
    );
    assert_eq!(
        ask(H, Some("zz".into())).error.as_deref(),
        Some("malformed cursor")
    );
    let last = state_commit::key_hash(&first.entries.last().unwrap().0);
    let end = ask(H, Some(hex::encode(last.0)));
    assert!(end.done && end.entries.is_empty() && end.error.is_none());
    state_commit::prune(&a.db, TIP, &Default::default(), usize::MAX).unwrap();
    assert_eq!(ask(H, None).error.as_deref(), Some("version not retained"));
    assert!(ask(TIP, None).error.is_none(), "the floor is still served");
}

#[test]
fn checkpoints_parse_strictly() {
    let block = "ab".repeat(32);
    let root = "CD".repeat(32);
    let cp: Checkpoint = format!("10:{block}:{root}").parse().unwrap();
    assert_eq!(cp.height, 10);
    assert_eq!(cp.state_root, "cd".repeat(32), "lowercased");
    for bad in [
        format!("0:{block}:{root}"),
        format!("x:{block}:{root}"),
        format!("10:{block}"),
        format!("10:{block}:{root}:extra"),
        format!("10:{}:{root}", "ab".repeat(31)),
        format!("10:{block}:{}", "zz".repeat(32)),
    ] {
        assert!(bad.parse::<Checkpoint>().is_err(), "{bad}");
    }
}

/// SN-3: a restored node imports the next block through the normal path
/// (`process_blocks`), onto the restored tree, and reaches the producer's
/// root. The producer is itself a node that imported blocks 1 and 2.
#[test]
fn a_restored_node_follows_the_chain() {
    let g = genesis();
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let pk = hex::encode(key.verifying_key().to_bytes());
    let producer = ChainSync::new(
        "producer".into(),
        0,
        Arc::new(Mutex::new(HashMap::new())),
        temp_db("follow_producer"),
    );
    {
        let _seed = producer.storage.seeding();
        for (k, v) in &g {
            if classify(k.as_bytes()) == Some(KeyClass::State) {
                producer.storage.put(k, v).unwrap();
            }
        }
        producer
            .storage
            .put(
                "sys:validators",
                &serde_json::to_string(&vec![(proposer.clone(), 100u64)]).unwrap(),
            )
            .unwrap();
        let account = storage::object::Object::new(
            proposer.clone(),
            storage::object::Owner::Address(proposer.clone()),
            serde_json::json!({ "public_key": pk, "sequence_number": 0 })
                .to_string()
                .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        producer.storage.put_object(&account).unwrap();
    }
    let v0 = state_commit::seed_genesis(&producer.storage).unwrap();
    producer.storage.write_batch(v0.batch).unwrap();
    let executor = executor::Executor::new(Arc::clone(&producer.storage));
    let empty_block = |height: u64, prev: String| {
        let root = hex::encode(state_commit::root(&producer.storage, height - 1).unwrap().0);
        let mut block = Block::new_with_roots(
            height,
            height,
            prev,
            vec![],
            proposer.clone(),
            root,
            executor.receipts_root_for_block(&[]),
        );
        block.header.hash = blockchain::calculate_header_hash(&block.header);
        block.sign_proposer(&key, &proposer);
        block
    };
    let one = empty_block(1, "genesis".into());
    assert_eq!(producer.process_blocks(vec![one.clone()], 0), 1);
    let two = empty_block(2, one.header.hash.clone());
    assert_eq!(producer.process_blocks(vec![two.clone()], 1), 2);

    // The checkpoint is block 1, with a QC from the genesis committee.
    let vote = FinalityVote {
        chain_id: CHAIN.into(),
        epoch: 0,
        finalized_round: 3,
        anchor_round: one.header.round,
        anchor_hash: one.anchor_hash.clone(),
        block_height: 1,
        block_hash: one.header.hash.clone(),
        state_root: one.header.state_root.clone(),
        receipts_root: one.header.receipts_root.clone(),
        finality_digest: "ee".repeat(32),
        validator_set_hash: validator_set_hash(&committee()),
    };
    let signature = crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &MEMBER);
    let qc = build_qc(&vote, &committee(), &[0], &[signature]).unwrap();
    producer
        .storage
        .put("consensus:qc:1", &serde_json::to_string(&qc).unwrap())
        .unwrap();
    let cp = Checkpoint {
        height: 1,
        block_hash: one.header.hash.clone(),
        state_root: one.header.state_root.clone(),
    };

    let client = ChainSync::new(
        "client".into(),
        0,
        Arc::new(Mutex::new(HashMap::new())),
        temp_db("follow_client"),
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let restored = runtime
        .block_on(restore_state(
            &client.storage,
            &plan(&cp, &g, false),
            1,
            |_, msg| {
                let reply = producer.handle_message(&msg).ok_or("no answer".to_string());
                async move { reply }
            },
        ))
        .unwrap();
    assert_eq!(restored.height, 1);
    assert_eq!(client.process_blocks(vec![two], 1), 2, "block 2 imports");
    assert_eq!(
        state_commit::root(&client.storage, 2).unwrap(),
        state_commit::root(&producer.storage, 2).unwrap()
    );
    assert!(state_commit::audit_flat_vs_tree(&client.storage)
        .unwrap()
        .is_empty());
}

/// S6b: every request the restore sends is one the node's TCP handler routes
/// to chain_sync (`ChainSync::serves`, which main.rs uses), and nothing else.
#[test]
fn the_node_routes_the_restore_requests_to_chain_sync() {
    for msg in [
        "GET_HEIGHT",
        "GET_FINALITY",
        "SYNC_REQ:{}",
        "VERTEX_REQ:{}",
        "STATE_ANCHOR_REQ:{}",
        "STATE_CHUNK_REQ:{}",
    ] {
        assert!(ChainSync::serves(msg), "{msg}");
    }
    for msg in [
        "TX:{}",
        "DAG_VERTEX:{}",
        "QC_VOTE:{}",
        "STATE_CHUNK_RESP:{}",
        "STATE_ANCHOR_RESP:{}",
        "HEIGHT:1",
    ] {
        assert!(!ChainSync::serves(msg), "{msg}");
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A node's TCP server for `chain`, routing by `ChainSync::serves` as the
/// node does. Returns its port once it accepts connections.
async fn spawn_server(chain: &Chain) -> u16 {
    let server = Arc::new(peer(chain, Behaviour::Honest).sync);
    let port = free_port();
    let server_key = crypto::SigningKey::from_bytes(&[5; 32]);
    let server_id = crypto::derive_address(server_key.verifying_key().as_bytes()).unwrap();
    tokio::spawn(network::start_server(
        port,
        server_id,
        Arc::new(Mutex::new(HashMap::new())),
        Arc::clone(&chain.db),
        Arc::new(server_key),
        move |msg: String| {
            if ChainSync::serves(&msg) {
                server.handle_message(&msg)
            } else {
                None
            }
        },
    ));
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    port
}

/// S6b: a restore over the node's real encrypted TCP transport. A peer that
/// is down is skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_restores_over_the_encrypted_transport() {
    let g = genesis();
    let a = chain("tcp_a", MEMBER);
    let port = spawn_server(&a).await;
    let down = ("127.0.0.1".to_string(), free_port());
    let client = temp_db("tcp_client");
    let done = restore_over_tcp(
        &client,
        &plan(&a.cp, &g, false),
        &[down, ("127.0.0.1".to_string(), port)],
        0,
    )
    .await
    .unwrap();
    assert_eq!(done.leaves, a.state.len());
    assert_restored(&client, &a);
}

/// S6b: a connection the server dropped is reopened on the next request,
/// never reused. Here the server drops it for exceeding its message rate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_connection_is_reopened() {
    let a = chain("tcp_drop", MEMBER);
    let port = spawn_server(&a).await;
    let connections = Connections::default();
    let key = crypto::SigningKey::from_bytes(&[6; 32]);
    let ask = |msg: &'static str| ask_over_tcp(&connections, 0, "127.0.0.1", port, 0, &key, msg);
    assert_eq!(ask("GET_HEIGHT").await.unwrap(), "HEIGHT:0");
    let mut dropped = false;
    for _ in 0..200 {
        if ask("GET_HEIGHT").await.is_err() {
            dropped = true;
            break;
        }
    }
    assert!(
        dropped,
        "positive control: the server drops a flooding connection"
    );
    assert!(
        connections.lock().await.is_empty(),
        "the dead connection is gone"
    );
    assert_eq!(
        ask("GET_HEIGHT").await.unwrap(),
        "HEIGHT:0",
        "a new one works"
    );
}
