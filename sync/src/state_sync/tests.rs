//! G3 S6 witnesses (SN-2, SN-4): a restore from untrusted peers completes
//! against the checkpoint root, whatever the peers do, or refuses.

use super::*;
use consensus::qc::{build_qc, validator_set_hash, FinalityVote, ValidatorInfo};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

const CHAIN: &str = "AINCORE-TEST-S6";
/// The servers' history runs to TIP; the checkpoint is at H.
const TIP: u64 = 12;
const H: u64 = 10;
/// Leaves per chunk in these tests, so a restore takes several chunks.
const SMALL_CHUNK: usize = 7;
const MEMBER: [u8; 32] = [7; 32];
const IDENTITY: &str = "1d";
/// The anchor block's proposer.
const PROPOSER: [u8; 32] = [77; 32];

fn proposer() -> (crypto::SigningKey, String) {
    let key = crypto::SigningKey::from_bytes(&PROPOSER);
    let address = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    (key, address)
}

/// The proposer's account, as the state stores it.
fn proposer_account() -> (String, Vec<u8>) {
    let (key, address) = proposer();
    let pk = hex::encode(key.verifying_key().to_bytes());
    let account = storage::object::Object::new(
        address.clone(),
        storage::object::Owner::Address(address.clone()),
        serde_json::json!({ "public_key": pk, "sequence_number": 0 })
            .to_string()
            .into_bytes(),
        "0x1::account::AccountData".to_string(),
    );
    (
        format!("obj:{address}"),
        serde_json::to_vec(&account).unwrap(),
    )
}

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

fn committee_of(seed: [u8; 32], address: u64) -> Vec<ValidatorInfo> {
    let bls = crypto::bls::BLSEngine::consensus();
    vec![ValidatorInfo {
        address: format!("{address:064x}"),
        stake: 100,
        ed25519_public_key: "00".repeat(32),
        bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
        bls_pop: hex::encode(bls.prove_possession_raw(&seed)),
    }]
}

/// The genesis committee.
fn committee() -> Vec<ValidatorInfo> {
    committee_of(MEMBER, 1)
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

/// One server's chain: a tree over versions `0..=TIP` (keys rewritten, one
/// deleted) and, at `H`, the block and a QC over it.
struct Chain {
    db: Arc<StateDB>,
    cp: Checkpoint,
    /// The consensus state at `H`.
    state: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone)]
struct Spec {
    /// Signs the QC at H.
    signer: [u8; 32],
    /// The chain id the state names.
    state_chain: &'static str,
    /// More leaves, at version 0.
    extra: Vec<(String, Vec<u8>)>,
    /// A second epoch from height 5, whose committee is this seed's.
    epoch_one: Option<[u8; 32]>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            signer: MEMBER,
            state_chain: CHAIN,
            extra: Vec::new(),
            epoch_one: None,
        }
    }
}

fn chain(name: &str, signer: [u8; 32]) -> Chain {
    chain_with(
        name,
        Spec {
            signer,
            ..Spec::default()
        },
    )
}

/// A chain whose state names `state_chain` while its QC signs for CHAIN.
fn chain_as(name: &str, signer: [u8; 32], state_chain: &'static str) -> Chain {
    chain_with(
        name,
        Spec {
            signer,
            state_chain,
            ..Spec::default()
        },
    )
}

fn chain_with(name: &str, spec: Spec) -> Chain {
    let db = temp_db(name);
    let members = committee();
    let (epoch, signing) = match spec.epoch_one {
        Some(seed) => (1, committee_of(seed, 2)),
        None => (0, members.clone()),
    };
    let mut state: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut at_h = BTreeMap::new();
    let mut root_h = None;
    for version in 0..=TIP {
        let changes: Vec<(String, Option<Vec<u8>>)> = if version == 0 {
            let mut v0 = vec![
                (
                    "sys:chain_id".to_string(),
                    Some(spec.state_chain.as_bytes().to_vec()),
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
            if spec.epoch_one.is_some() {
                v0.push(("consensus:epoch".into(), Some(b"1".to_vec())));
                v0.push(("consensus:epoch_start_height:1".into(), Some(b"5".to_vec())));
                v0.push((
                    "sys:validator_set:epoch:1".into(),
                    Some(serde_json::to_vec(&signing).unwrap()),
                ));
            }
            v0.extend((0..40).map(|i| (obj(i), Some(format!("v{i}").into_bytes()))));
            let (account_key, account) = proposer_account();
            v0.push((account_key, Some(account)));
            v0.extend(spec.extra.iter().map(|(k, v)| (k.clone(), Some(v.clone()))));
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
    let (proposer_key, proposer_address) = proposer();
    let mut block = Block::new_with_roots_at(
        H,
        2 * H,
        "00".repeat(32),
        vec![],
        proposer_address.clone(),
        root.clone(),
        "dd".repeat(32),
        1_000,
        vec![],
        "aa".repeat(32),
        vec![],
    );
    block.sign_proposer(&proposer_key, &proposer_address);
    let vote = FinalityVote {
        chain_id: CHAIN.into(),
        epoch,
        finalized_round: 2 * H + 2,
        anchor_round: block.header.round,
        anchor_hash: block.anchor_hash.clone(),
        block_height: H,
        block_hash: block.header.hash.clone(),
        state_root: root.clone(),
        receipts_root: block.header.receipts_root.clone(),
        finality_digest: "ee".repeat(32),
        validator_set_hash: validator_set_hash(&signing),
    };
    let signature =
        crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &spec.signer);
    let qc = build_qc(&vote, &signing, &[0], &[signature]).unwrap();
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
    /// Flips a byte in every value part it serves.
    ForgePart,
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
    if msg.starts_with(VALUE_REQ) && peer.behaviour == Behaviour::ForgePart {
        let reply = peer.sync.handle_message(msg).ok_or("no answer")?;
        let mut part: ValueResponse =
            serde_json::from_str(reply.strip_prefix(VALUE_RESP).unwrap()).unwrap();
        let mut data = hex::decode(&part.data).unwrap();
        if let Some(byte) = data.first_mut() {
            *byte ^= 1;
        }
        part.data = hex::encode(data);
        return Ok(format!(
            "{VALUE_RESP}{}",
            serde_json::to_string(&part).unwrap()
        ));
    }
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
        Behaviour::Forge if peer.chunks == 2 => {
            if let Some(entry) = resp.entries.first_mut() {
                entry.value = hex::encode(b"forged");
                entry.len = 6;
            }
        }
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

fn fast() -> Patience {
    Patience {
        max_failures: 6,
        backoff_start: Duration::ZERO,
        backoff_max: Duration::ZERO,
        request_timeout: Duration::from_secs(10),
        min_bytes_per_sec: 1,
        deadline: Duration::from_secs(120),
    }
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
        local_signer: None,
        patience: fast(),
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

async fn run_with(
    client: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    n: usize,
    mut f: impl FnMut(usize, &str) -> Result<String, String>,
) -> Result<Restored, String> {
    restore_state(client, plan, n, |i, msg| {
        let reply = f(i, &msg);
        async move { reply }
    })
    .await
}

fn chunk_reply(resp: &ChunkResponse) -> Result<String, String> {
    Ok(format!(
        "{CHUNK_RESP}{}",
        serde_json::to_string(resp).unwrap()
    ))
}

fn busy() -> Result<String, String> {
    chunk_reply(&ChunkResponse {
        error: Some("busy".into()),
        ..Default::default()
    })
}

fn flat_state(db: &StateDB) -> BTreeMap<String, Vec<u8>> {
    db.db
        .iterator(IteratorMode::Start)
        .map(Result::unwrap)
        .filter(|(k, _)| classify(k) == Some(KeyClass::State))
        .map(|(k, v)| (String::from_utf8(k.to_vec()).unwrap(), v.to_vec()))
        .collect()
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
        StateDB::BLOCK_PRUNE_CURSOR_KEY,
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
    assert_eq!(
        client.get("genesis_identity").unwrap().as_deref(),
        Some(IDENTITY)
    );
    assert_eq!(
        client.get("genesis_initialized").unwrap().as_deref(),
        Some("true"),
        "genesis reopens instead of refusing a datadir that holds state"
    );
    assert_eq!(
        client.get("genesis_version").unwrap().as_deref(),
        Some("s6-test"),
        "genesis rows outside the state"
    );
    assert_eq!(
        client.get(RESTORED_CHECKPOINT).unwrap(),
        Some(chain.cp.to_string())
    );
    assert_eq!(client.get("sync:halt_reason").unwrap(), None);
    let anchor_round = (2 * H).to_string();
    for (key, value) in [
        ("consensus:finality_digest", "ee".repeat(32)),
        ("consensus:last_anchor_round", anchor_round.clone()),
        ("consensus:last_anchor_hash", "aa".repeat(32)),
        ("consensus:finalized_round", (2 * H + 2).to_string()),
        ("consensus:qc:latest_round", anchor_round.clone()),
    ] {
        assert_eq!(
            client.get(key).unwrap().as_deref(),
            Some(value.as_str()),
            "{key}"
        );
    }
    // The QC indexes a later certificate is checked against
    // (`qc_producer::store_certificate`): pointer and body agree.
    let qc = client.get(&format!("consensus:qc:{H}")).unwrap().unwrap();
    assert_eq!(
        client.get("consensus:qc:latest").unwrap().as_ref(),
        Some(&qc)
    );
    assert_eq!(
        client
            .get(&format!("consensus:qc_by_round:{anchor_round}"))
            .unwrap()
            .as_ref(),
        Some(&qc)
    );
    // The stored block is the one its QC certifies.
    let block: Block =
        serde_json::from_str(&client.get(&format!("block_{H}")).unwrap().unwrap()).unwrap();
    let qc: QuorumCertificate = serde_json::from_str(&qc).unwrap();
    assert_eq!(block.header.hash, qc.block_hash);
    assert_eq!(block.anchor_hash, qc.anchor_hash);
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
    assert!(
        peers[0].chunks > 1 && peers[1].chunks > 1,
        "round robin: {} and {}",
        peers[0].chunks,
        peers[1].chunks
    );
    assert_restored(&client, &a);

    // The QC check wants the epoch the restored state records for H, even
    // from a committee member's valid signature.
    let good = stored_qc(&a);
    let block = stored_block(&a);
    let mut vote = good.finality_vote();
    vote.epoch = 1;
    let signature = crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &MEMBER);
    let other_epoch = build_qc(&vote, &committee(), &[0], &[signature]).unwrap();
    let err = verified_pair(
        &client,
        CHAIN,
        0,
        &committee(),
        &[(block.clone(), other_epoch.clone())],
    )
    .unwrap_err();
    assert!(err.contains("epoch"), "{err}");
    let (_, verified) = verified_pair(
        &client,
        CHAIN,
        0,
        &committee(),
        &[(block.clone(), other_epoch), (block, good.clone())],
    )
    .unwrap();
    assert_eq!(verified, good);
}

/// A checkpoint in a later epoch is checked against that epoch's committee,
/// as the restored state records it.
#[tokio::test]
async fn a_checkpoint_in_a_later_epoch_verifies_under_its_committee() {
    let g = genesis();
    let later = [8u8; 32];
    let a = chain_with(
        "epoch1_a",
        Spec {
            signer: later,
            epoch_one: Some(later),
            ..Spec::default()
        },
    );
    let client = temp_db("epoch1_client");
    let mut peers = [peer(&a, Behaviour::Honest)];
    run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_restored(&client, &a);
    assert_eq!(stored_qc(&a).epoch, 1);
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
    // A header field changed under an unchanged hash (the timestamp feeds
    // BFT time at h+1).
    let mut stale = block.clone();
    stale.header.timestamp += 1;
    assert!(
        check_anchor(&a.cp, &stale, &qc).is_err(),
        "a header its hash does not commit to"
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

/// Review L1: the block stored is the one whose own QC verifies. A peer that
/// sends the real header with a rewritten body field, and a QC rewritten to
/// match whose signature fails, does not get its block stored.
#[tokio::test]
async fn the_block_is_stored_with_its_own_verified_qc() {
    let g = genesis();
    let a = chain("pair_a", MEMBER);
    let b = chain("pair_b", MEMBER);
    let client = temp_db("pair_client");
    let mut honest = peer(&b, Behaviour::Honest);
    let mut byz = peer(&a, Behaviour::Honest);
    let forged = "ab".repeat(32);
    let mut block = stored_block(&a);
    block.anchor_hash = forged.clone();
    let mut qc = stored_qc(&a);
    qc.anchor_hash = forged.clone();
    let byz_anchor = format!(
        "{ANCHOR_RESP}{}",
        serde_json::to_string(&AnchorResponse {
            block: Some(block),
            quorum_certificate: Some(qc)
        })
        .unwrap()
    );
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if i == 0 && msg.starts_with(ANCHOR_REQ) {
            Ok(byz_anchor.clone())
        } else if i == 0 {
            serve(&mut byz, msg)
        } else {
            serve(&mut honest, msg)
        }
    })
    .await
    .expect("the restore completes");
    assert_restored(&client, &a);
    let stored = client.get(&format!("block_{H}")).unwrap().unwrap();
    assert!(!stored.contains(&forged), "the forged block was not stored");
}

/// SN-2 step 3: a forged chunk is refused, its peer is shut out, and the
/// restore completes against the checkpoint root from another peer.
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
    assert_eq!(peers[0].chunks, 2, "never asked again once caught");
    assert_restored(&client, &a);
}

/// Every peer lying ends the restore, with the marker kept.
#[tokio::test]
async fn a_restore_with_only_lying_peers_gives_up() {
    let g = genesis();
    let a = chain("liars_a", MEMBER);
    let b = chain("liars_b", MEMBER);
    let client = temp_db("liars_client");
    let mut peers = [peer(&a, Behaviour::Forge), peer(&b, Behaviour::DropLast)];
    let err = run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("every peer sent a bad state stream"), "{err}");
    assert!(client.get(RESTORE_MARKER).unwrap().is_some());
}

/// Review M1: a forging peer next to an honest peer that is sometimes busy
/// cannot wear the restore down: the forger is shut out after one chunk.
#[tokio::test]
async fn a_forger_cannot_outlast_a_busy_honest_peer() {
    let g = genesis();
    let h = chain("busyforge_h", MEMBER);
    let b = chain("busyforge_b", MEMBER);
    let client = temp_db("busyforge_client");
    let mut honest = peer(&h, Behaviour::Honest);
    let mut forger = peer(&b, Behaviour::Honest);
    let mut honest_asks = 0usize;
    let mut forger_asks = 0usize;
    run_with(&client, &plan(&h.cp, &g, false), 2, |i, msg| {
        if !msg.starts_with(CHUNK_REQ) {
            return serve(if i == 0 { &mut honest } else { &mut forger }, msg);
        }
        if i == 0 {
            honest_asks += 1;
            if honest_asks.is_multiple_of(3) {
                return busy();
            }
            return serve(&mut honest, msg);
        }
        forger_asks += 1;
        let reply = serve(&mut forger, msg)?;
        let mut resp: ChunkResponse =
            serde_json::from_str(reply.strip_prefix(CHUNK_RESP).unwrap()).unwrap();
        if let Some(entry) = resp.entries.first_mut() {
            entry.value = hex::encode(b"forged");
            entry.len = 6;
        }
        chunk_reply(&resp)
    })
    .await
    .unwrap();
    assert_eq!(forger_asks, 1, "shut out after its first chunk");
    assert_restored(&client, &h);
}

/// Review M1: busy answers from the only peer are waited out, not taken as
/// the end of the restore.
#[tokio::test]
async fn busy_answers_are_waited_out() {
    let g = genesis();
    let h = chain("busy_h", MEMBER);
    let client = temp_db("busy_client");
    let mut honest = peer(&h, Behaviour::Honest);
    let mut asks = 0usize;
    run_with(&client, &plan(&h.cp, &g, false), 1, |_, msg| {
        if msg.starts_with(CHUNK_REQ) {
            asks += 1;
            if (2..=5).contains(&asks) {
                return busy();
            }
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert_restored(&client, &h);
}

/// Review M1: a peer that answers one leaf at a time does not own the
/// restore: requests go round robin, so the fast peer carries it.
#[tokio::test]
async fn a_slow_peer_does_not_own_the_restore() {
    let g = genesis();
    let slow = chain("slow_s", MEMBER);
    let fast_chain = chain("slow_f", MEMBER);
    let client = temp_db("slow_client");
    let mut s = peer(&slow, Behaviour::Honest);
    let mut f = peer(&fast_chain, Behaviour::Honest);
    let (mut to_slow, mut to_fast) = (0usize, 0usize);
    run_with(&client, &plan(&slow.cp, &g, false), 2, |i, msg| {
        if msg.starts_with(CHUNK_REQ) {
            if i == 0 {
                to_slow += 1;
                let mut req: ChunkRequest =
                    serde_json::from_str(msg.strip_prefix(CHUNK_REQ).unwrap()).unwrap();
                req.max = 1;
                return chunk_reply(&s.sync.handle_state_chunk(req));
            }
            to_fast += 1;
        }
        serve(if i == 0 { &mut s } else { &mut f }, msg)
    })
    .await
    .unwrap();
    assert!(
        to_fast > 0 && to_slow < slow.state.len(),
        "{to_slow} / {to_fast}"
    );
    assert_restored(&client, &slow);
}

/// SN-4 witness: a truncated stream (one that ends early, or a chunk short
/// of its last leaf) never completes a restore; each liar is shut out.
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
    assert_eq!(peers[0].chunks, 3, "the truncator is never asked again");
    assert_eq!(peers[1].chunks, 2, "the leaf dropper is never asked again");
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
    assert!(peers[0].chunks >= 2, "it served once, then refused");
    assert_restored(&client, &a);
}

/// Review H1 / SN-4: a pinned version older than block retention keeps its
/// block, so it can still be restored from a pruning peer.
#[tokio::test]
async fn a_pinned_version_below_block_retention_restores() {
    let g = genesis();
    let a = chain("pin_a", MEMBER);
    let keep = 1; // The retention floor TIP - keep = 11 lies above H = 10.
    {
        let _seed = a.db.seeding();
        a.db.put("sys:config:epoch_block_interval", "5").unwrap();
    }
    let pins = state_commit::pin_schedule(TIP, keep, state_commit::epoch_interval(&a.db));
    assert!(pins.contains(&H), "{pins:?}");
    consensus::dag::prune_history(&a.db, TIP, Some((keep, 1_000)));
    state_commit::prune(&a.db, TIP - keep, &pins, usize::MAX).unwrap();
    assert!(
        a.db.get(&format!("block_{H}")).unwrap().is_some(),
        "the pin's block"
    );
    assert!(state_commit::servable(&a.db, H, Some(keep)).unwrap());
    let client = temp_db("pin_client");
    let mut server = peer(&a, Behaviour::Honest);
    server.sync = ChainSync::new(
        "server".into(),
        0,
        Arc::new(Mutex::new(HashMap::new())),
        Arc::clone(&a.db),
    )
    .with_retention(Some((keep, 1_000)));
    let mut peers = [server];
    run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
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
/// (SN-6); its old state, chain data and consensus view go, and so does a
/// sync halt raised against the old state.
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
    let attest = format!(
        "consensus:vattest:v1:{}:{}:3:author:{:020}",
        "ab".repeat(32),
        "cd".repeat(48),
        7
    );
    let old_vertex = format!("vertex:{}", "ef".repeat(32));
    let old_index = format!("tx_index:{}", "12".repeat(32));
    {
        let _seed = client.seeding();
        client.put(&stale, "old").unwrap();
        client.put("genesis_initialized", "true").unwrap();
        client.put("latest_height", "3").unwrap();
        client.put(&guard, "signed").unwrap();
        client.put(&attest, "attested").unwrap();
        client.put("latest_proposed_round", "77").unwrap();
        client.put(&old_vertex, "{}").unwrap();
        client.put(&old_index, "3").unwrap();
        client
            .put("sync:halt_reason", "state root mismatch at 3")
            .unwrap();
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
    assert_eq!(
        client.get(&old_vertex).unwrap(),
        None,
        "the old consensus view"
    );
    assert_eq!(client.get(&old_index).unwrap(), None, "the old chain data");
    assert_eq!(client.get(&guard).unwrap().as_deref(), Some("signed"));
    assert_eq!(client.get(&attest).unwrap().as_deref(), Some("attested"));
    assert_eq!(
        client.get("latest_proposed_round").unwrap().as_deref(),
        Some("77")
    );

    // A datadir that holds only a chain height is a chain too.
    let height_only = temp_db("offline_height_only");
    height_only.put("latest_height", "3").unwrap();
    let err = run(&height_only, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("already holds a chain"), "{err}");
}

/// SN-6: a restore refuses a chain where this node's key is a validator,
/// and keeps the marker; an observer's key restores.
#[tokio::test]
async fn a_validator_key_is_not_restored_onto_a_new_datadir() {
    let g = genesis();
    // A validator that joined after the checkpoint epoch's committee formed.
    let joined = "aa".repeat(32);
    let a = chain_with(
        "signer_a",
        Spec {
            extra: vec![(
                "sys:validators".into(),
                serde_json::to_vec(&vec![(joined.clone(), 100u64)]).unwrap(),
            )],
            ..Spec::default()
        },
    );
    let client = temp_db("signer_client");
    let mut peers = [peer(&a, Behaviour::Honest)];
    let member = committee()[0].address.clone();
    for signer in [&member, &joined] {
        let as_validator = RestorePlan {
            local_signer: Some(signer),
            ..plan(&a.cp, &g, false)
        };
        let err = run(&client, &as_validator, &mut peers).await.unwrap_err();
        assert!(err.contains("validator") && err.contains("SN-6"), "{err}");
        assert!(client.get(RESTORE_MARKER).unwrap().is_some());
        assert!(state_commit::boot_check(&client).is_err(), "it cannot boot");
    }
    let observer = "ff".repeat(32);
    let as_observer = RestorePlan {
        local_signer: Some(&observer),
        ..plan(&a.cp, &g, false)
    };
    run(&client, &as_observer, &mut peers).await.unwrap();
    assert_restored(&client, &a);
    assert_eq!(client.get(RESTORED_BY).unwrap(), Some(observer.clone()));

    // Post-fix review LOW 6: replacing a chain where this node signs is
    // refused before anything is cleared.
    let signing = temp_db("signer_replace");
    {
        let _seed = signing.seeding();
        signing.put("genesis_initialized", "true").unwrap();
        signing.put("latest_height", "3").unwrap();
        signing
            .put(
                "sys:validators",
                &serde_json::to_string(&vec![(observer.clone(), 100u64)]).unwrap(),
            )
            .unwrap();
        signing.put(&obj(999), "old").unwrap();
    }
    let replace_as_validator = RestorePlan {
        local_signer: Some(&observer),
        ..plan(&a.cp, &g, true)
    };
    let err = run(&signing, &replace_as_validator, &mut peers)
        .await
        .unwrap_err();
    assert!(err.contains("SN-6"), "{err}");
    assert_eq!(
        signing.get(&obj(999)).unwrap().as_deref(),
        Some("old"),
        "untouched"
    );
    assert_eq!(signing.get(RESTORE_MARKER).unwrap(), None);
}

/// A checkpoint no peer can back restores nothing. One whose state its own
/// committee did not sign, or of another genesis, fails closed: the marker
/// stays and the datadir cannot boot until a good restore completes.
#[tokio::test]
async fn a_checkpoint_that_does_not_hold_restores_nothing() {
    let g = genesis();
    let a = chain("cp_a", MEMBER);
    let client = temp_db("cp_client");
    let mut peers = [peer(&a, Behaviour::Honest)];

    for wrong in [
        Checkpoint {
            state_root: "11".repeat(32),
            ..a.cp.clone()
        },
        Checkpoint {
            block_hash: "11".repeat(32),
            ..a.cp.clone()
        },
    ] {
        let err = run(&client, &plan(&wrong, &g, false), &mut peers)
            .await
            .unwrap_err();
        assert!(err.contains("no peer holds"), "{err}");
        assert_eq!(client.get(RESTORE_MARKER).unwrap(), None, "nothing written");
    }

    // This node's genesis names another chain, another genesis committee or
    // another epoch interval.
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
        assert!(client.get(RESTORE_MARKER).unwrap().is_some(), "fail closed");
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
    let mut outsider = [peer(&forged, Behaviour::Honest)];
    let err = run(&client, &plan(&forged.cp, &g, false), &mut outsider)
        .await
        .unwrap_err();
    assert!(err.contains("inconsistent"), "{err}");
    assert!(client.get(RESTORE_MARKER).unwrap().is_some(), "fail closed");
    assert!(state_commit::boot_check(&client).is_err(), "it cannot boot");

    // A good restore then completes over it.
    run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_restored(&client, &a);
}

#[test]
fn the_server_serves_only_what_it_retains() {
    let a = chain("serve_a", MEMBER);
    let sync = peer(&a, Behaviour::Honest).sync;
    let ask = |version: u64, after: Option<String>| {
        sync.handle_state_chunk(ChunkRequest {
            version,
            after,
            max: 100,
        })
    };
    let first = ask(H, None);
    assert!(first.error.is_none() && !first.done);
    assert_eq!(first.entries.len(), a.state.len(), "all of a small state");
    assert_eq!(
        ask(TIP + 1, None).error.as_deref(),
        Some("version not retained")
    );
    assert_eq!(
        ask(H, Some("zz".into())).error.as_deref(),
        Some("malformed cursor")
    );
    let last = state_commit::key_hash(&first.entries.last().unwrap().key);
    let end = ask(H, Some(hex::encode(last.0)));
    assert!(end.done && end.entries.is_empty() && end.error.is_none());
    // Value parts: the same retention, and the same slots.
    let value = |version: u64| {
        sync.handle_state_value(ValueRequest {
            version,
            key: obj(3),
            offset: 0,
        })
    };
    assert_eq!(
        value(TIP + 1).error.as_deref(),
        Some("version not retained")
    );
    let held: Vec<_> = (0..STATE_SERVE_IN_FLIGHT)
        .map(|_| sync.state_budget.admit(None, 1).expect("a slot"))
        .collect();
    assert_eq!(value(H).error.as_deref(), Some("busy"));
    drop(held);
    state_commit::prune(&a.db, TIP, &Default::default(), usize::MAX).unwrap();
    assert_eq!(ask(H, None).error.as_deref(), Some("version not retained"));
    assert_eq!(value(H).error.as_deref(), Some("version not retained"));
    assert!(ask(TIP, None).error.is_none(), "the floor is still served");
    // Refusals are not charged: many of them leave the budget whole.
    let fresh = peer(&a, Behaviour::Honest).sync;
    for _ in 0..50 {
        let refused = fresh.handle_state_chunk(ChunkRequest {
            version: TIP + 1,
            after: None,
            max: MAX_CHUNK_ENTRIES,
        });
        assert!(refused.error.is_some());
    }
    assert!(fresh
        .state_budget
        .admit(None, 8_000)
        .is_some_and(|a| a.granted > 7_000));
}

/// Review H3: snapshot serving has its own bounded budget: slots and units
/// in flight globally, so a flood is shed.
#[test]
fn the_state_server_sheds_load() {
    let a = chain("shed_a", MEMBER);
    let sync = peer(&a, Behaviour::Honest).sync;
    let ask = || {
        sync.handle_state_chunk(ChunkRequest {
            version: H,
            after: None,
            max: MAX_CHUNK_ENTRIES,
        })
    };
    let held: Vec<_> = (0..STATE_SERVE_IN_FLIGHT)
        .map(|_| sync.state_budget.admit(None, 1).expect("a slot"))
        .collect();
    assert_eq!(ask().error.as_deref(), Some("busy"), "no free slot");
    drop(held);
    assert!(ask().error.is_none());
}

/// Post-fix review HIGH 2: one client cannot starve the others. Its own
/// bucket runs dry long before the global one, and a second client is
/// still served.
#[test]
fn one_client_cannot_starve_the_others() {
    let extra = (100..4_100).map(|i| (obj(i), b"x".to_vec())).collect();
    let a = chain_with(
        "fair_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let sync = peer(&a, Behaviour::Honest).sync;
    let ask = |ip: [u8; 4]| {
        sync.serve_state_chunk(
            ChunkRequest {
                version: H,
                after: None,
                max: MAX_CHUNK_ENTRIES,
            },
            Some(IpAddr::from(ip)),
        )
    };
    let hog = [10, 0, 0, 1];
    let start = Instant::now();
    let mut leaves = 0usize;
    for _ in 0..20 {
        leaves += ask(hog).entries.len();
    }
    // At most a burst, then the per-IP rate, however fast it asks.
    let allowed = STATE_SERVE_UNITS_PER_SEC_PER_IP * (1.0 + start.elapsed().as_secs_f64());
    assert!(
        (leaves as f64) <= allowed,
        "the hog got {leaves} leaves, its share is {allowed}"
    );
    assert!(
        leaves < 20 * MAX_CHUNK_ENTRIES,
        "positive control: it was held back"
    );
    let other = ask([10, 0, 0, 2]);
    assert_eq!(
        other.entries.len(),
        MAX_CHUNK_ENTRIES,
        "another client is served in full: {:?}",
        other.error
    );
    // One request in flight per client.
    let third = IpAddr::from([10, 0, 0, 5]);
    let held = sync.state_budget.admit(Some(third), 1);
    assert!(held.is_some());
    assert_eq!(ask([10, 0, 0, 5]).error.as_deref(), Some("busy"));
    drop(held);
    assert!(ask([10, 0, 0, 5]).error.is_none());
}

/// The per-IP table forgets idle clients when full, and refuses new ones
/// while every client it holds is busy or in debt.
#[test]
fn the_client_table_forgets_idle_clients_only() {
    let budget = StateBudget::default();
    let ip = |i: u32| Some(IpAddr::from(i.to_be_bytes()));
    for i in 0..MAX_TRACKED_IPS as u32 {
        drop(budget.admit(ip(i), 1).expect("room"));
    }
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        budget.admit(ip(1 << 20), 1).is_some(),
        "an idle client forgotten"
    );
    // A client with a request in flight is never forgotten, so it cannot
    // dodge its one-slot limit by being evicted.
    let pinned = StateBudget::default();
    let held = pinned.admit(ip(0), 1).expect("in flight");
    for i in 1..MAX_TRACKED_IPS as u32 {
        drop(pinned.admit(ip(i), 1).expect("room"));
    }
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        pinned.admit(ip(1 << 22), 1).is_some(),
        "the table makes room"
    );
    assert!(pinned.admit(ip(0), 1).is_none(), "still one in flight");
    drop(held);
    let busy = StateBudget::default();
    let held: Vec<_> = (0..MAX_TRACKED_IPS as u32)
        .filter_map(|i| busy.admit(ip(i), 1))
        .collect();
    // Only STATE_SERVE_IN_FLIGHT fit at once globally; the rest are in the
    // table, spent.
    drop(held);
    for i in 0..MAX_TRACKED_IPS as u32 {
        if let Some(a) = busy.admit(ip(i), 1) {
            a.charge_read(1 << 30);
        }
    }
    assert!(busy.admit(ip(1 << 21), 1).is_none(), "every client in debt");
}

/// Post-fix review MEDIUM 3: serving is charged by the bytes it reads, so a
/// client that makes the server re-read a large value (alternating keys to
/// miss the cache) runs out of budget.
#[test]
fn value_reads_are_charged_by_their_bytes() {
    let extra = vec![
        (obj(500), vec![b'p'; 3 << 20]),
        (obj(501), vec![b'q'; 3 << 20]),
        (obj(502), vec![b'r'; 8 << 20]),
    ];
    let a = chain_with(
        "bytes_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let sync = peer(&a, Behaviour::Honest).sync;
    let client = Some(IpAddr::from([10, 0, 0, 3]));
    let start = Instant::now();
    let mut served = 0u64;
    for i in 0..10u64 {
        let part = sync.serve_state_value(
            ValueRequest {
                version: H,
                key: obj(500 + i % 2),
                offset: 0,
            },
            client,
        );
        if part.error.is_none() {
            served += 1;
        }
    }
    // Each miss reads 3 MiB and sends 1 MiB: over 1,000 units, of 2,000 a
    // second (plus one burst) for this client.
    let per_read = ((3 << 20) + (1 << 20)) / UNIT_BYTES;
    let allowed = STATE_SERVE_UNITS_PER_SEC_PER_IP * (1.0 + start.elapsed().as_secs_f64());
    assert!(
        (served * per_read) as f64 <= allowed + per_read as f64,
        "{served} whole-value reads served in {:?}",
        start.elapsed()
    );
    // One read of an 8 MiB value costs more than a client's whole bucket
    // (2,048 units read, 256 sent): it leaves the bucket in debt.
    let heavy = Some(IpAddr::from([10, 0, 0, 4]));
    let read = sync.serve_state_value(
        ValueRequest {
            version: H,
            key: obj(502),
            offset: 0,
        },
        heavy,
    );
    assert!(read.error.is_none(), "{:?}", read.error);
    let balance = sync.state_budget.balance(heavy);
    assert!(balance < -300.0, "in debt: {balance}");
}

/// Post-fix review test gap: the one-value cache answers only for its own
/// version and key.
#[test]
fn the_value_cache_answers_only_for_its_key_and_version() {
    let (p, q) = (vec![b'p'; 2 << 20], vec![b'q'; 2 << 20]);
    let a = chain_with(
        "cache_a",
        Spec {
            extra: vec![(obj(500), p.clone()), (obj(501), q.clone())],
            ..Spec::default()
        },
    );
    // Version TIP rewrites obj(500).
    let sync = peer(&a, Behaviour::Honest).sync;
    let first = |key: u64, version: u64| {
        let part = sync.handle_state_value(ValueRequest {
            version,
            key: obj(key),
            offset: 0,
        });
        assert!(part.error.is_none(), "{:?}", part.error);
        hex::decode(part.data).unwrap()[0]
    };
    for _ in 0..2 {
        assert_eq!(first(500, H), b'p');
        assert_eq!(first(501, H), b'q');
    }
    // obj(5) is "r5" at H and "r12" at TIP: the cache is per version.
    let value = |version: u64| {
        let part = sync.handle_state_value(ValueRequest {
            version,
            key: obj(5),
            offset: 0,
        });
        String::from_utf8(hex::decode(part.data).unwrap()).unwrap()
    };
    for _ in 0..2 {
        assert_eq!(value(H), "r5");
        assert_eq!(value(TIP), "r12");
    }
    assert!(
        sync.handle_state_value(ValueRequest {
            version: H,
            key: obj(502),
            offset: 0
        })
        .error
        .is_some(),
        "an absent key after a cached one"
    );
}

/// Review H2: a value too large for a chunk travels in parts, and a chunk of
/// many medium values shrinks to its byte budget.
#[test]
fn a_chunk_stays_within_its_byte_budget() {
    let big = vec![b'y'; 4 << 20];
    let mut extra: Vec<(String, Vec<u8>)> = (100..140)
        .map(|i| (obj(i), vec![b'm'; 200 << 10]))
        .collect();
    extra.push((obj(500), big.clone()));
    let a = chain_with(
        "budget_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let sync = peer(&a, Behaviour::Honest).sync;
    let chunk = sync.handle_state_chunk(ChunkRequest {
        version: H,
        after: None,
        max: 100,
    });
    assert!(chunk.error.is_none(), "{:?}", chunk.error);
    assert!(chunk.entries.len() < a.state.len(), "shrunk");
    let size: usize = chunk
        .entries
        .iter()
        .map(|e| e.key.len() + e.value.len())
        .sum::<usize>()
        + chunk.proof.len();
    assert!(size <= MAX_CHUNK_BYTES, "{size}");
    // Reading those values is charged by their bytes.
    let reader = Some(IpAddr::from([10, 0, 0, 9]));
    let charged = sync.serve_state_chunk(
        ChunkRequest {
            version: H,
            after: None,
            max: 100,
        },
        reader,
    );
    assert!(charged.error.is_none());
    let balance = sync.state_budget.balance(reader);
    assert!(
        balance < 0.0,
        "8 MiB read costs more than a bucket: {balance}"
    );
    // The big value's parts, from the server alone.
    let mut value = Vec::new();
    while value.len() < big.len() {
        let part = sync.handle_state_value(ValueRequest {
            version: H,
            key: obj(500),
            offset: value.len() as u64,
        });
        assert!(part.error.is_none(), "{:?}", part.error);
        assert_eq!(part.len, big.len() as u64);
        value.extend(hex::decode(part.data).unwrap());
    }
    assert_eq!(value, big);
    assert_eq!(
        sync.handle_state_value(ValueRequest {
            version: H,
            key: obj(500),
            offset: big.len() as u64,
        })
        .error
        .as_deref(),
        Some("offset past the value")
    );
}

/// Review H2: a chain with a leaf larger than a chunk restores; a peer that
/// forges a value part is caught by the proof.
#[tokio::test]
async fn a_leaf_larger_than_a_chunk_restores_in_parts() {
    let g = genesis();
    let spec = Spec {
        extra: vec![(obj(500), vec![b'z'; (5 << 20) + 3])],
        ..Spec::default()
    };
    let a = chain_with("big_a", spec.clone());
    let client = temp_db("big_client");
    let mut peers = [peer(&a, Behaviour::Honest)];
    run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .unwrap();
    assert_restored(&client, &a);

    let b = chain_with("big_b", spec);
    let forger_client = temp_db("big_forger_client");
    let mut forger = [peer(&b, Behaviour::ForgePart)];
    let err = run(&forger_client, &plan(&b.cp, &g, false), &mut forger)
        .await
        .unwrap_err();
    assert!(err.contains("every peer sent a bad state stream"), "{err}");
}

#[test]
fn checkpoints_parse_strictly() {
    let block = "ab".repeat(32);
    let root = "CD".repeat(32);
    let cp: Checkpoint = format!("10:{block}:{root}").parse().unwrap();
    assert_eq!(cp.height, 10);
    assert_eq!(cp.state_root, "cd".repeat(32), "lowercased");
    assert_eq!(cp.to_string().parse::<Checkpoint>(), Ok(cp.clone()));
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

/// A node that builds its chain by importing it, as a follower does: empty
/// blocks from one proposer, over the genesis rows of `genesis()`.
struct Producer {
    sync: ChainSync,
    key: crypto::SigningKey,
    proposer: String,
}

impl Producer {
    fn new(name: &str, retention: Option<(u64, u64)>) -> Self {
        let key = crypto::SigningKey::from_bytes(&[77; 32]);
        let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pk = hex::encode(key.verifying_key().to_bytes());
        let sync = ChainSync::new(
            "producer".into(),
            0,
            Arc::new(Mutex::new(HashMap::new())),
            temp_db(name),
        )
        .with_retention(retention);
        {
            let _seed = sync.storage.seeding();
            for (k, v) in &genesis() {
                if classify(k.as_bytes()) == Some(KeyClass::State) {
                    sync.storage.put(k, v).unwrap();
                }
            }
            sync.storage
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
            sync.storage.put_object(&account).unwrap();
        }
        let v0 = state_commit::seed_genesis(&sync.storage).unwrap();
        sync.storage.write_batch(v0.batch).unwrap();
        Self {
            sync,
            key,
            proposer,
        }
    }

    /// Build and import blocks `1..=n`; returns them.
    fn import(&self, n: u64) -> Vec<Block> {
        let executor = executor::Executor::new(Arc::clone(&self.sync.storage));
        let mut prev = "genesis".to_string();
        let mut blocks = Vec::new();
        for height in 1..=n {
            let root = hex::encode(
                state_commit::root(&self.sync.storage, height - 1)
                    .unwrap()
                    .0,
            );
            let mut block = Block::new_with_roots(
                height,
                height,
                prev.clone(),
                vec![],
                self.proposer.clone(),
                root,
                executor.receipts_root_for_block(&[]),
            );
            block.header.hash = blockchain::calculate_header_hash(&block.header);
            block.sign_proposer(&self.key, &self.proposer);
            assert_eq!(
                self.sync.process_blocks(vec![block.clone()], height - 1),
                height
            );
            prev = block.header.hash.clone();
            blocks.push(block);
        }
        blocks
    }
}

/// G3 GC-1: a node that only imports blocks prunes blocks and state like one
/// that builds them (it used to prune neither), keeping the pinned blocks
/// until their pins expire.
#[test]
fn a_node_that_only_follows_prunes() {
    let producer = Producer::new("follow_prunes", Some((10, 250)));
    producer.import(100);
    let db = &producer.sync.storage;
    assert_eq!(state_commit::floor(db).unwrap(), 90);
    assert!(db.get("block_1").unwrap().is_none(), "old blocks pruned");
    assert!(db.get("block_95").unwrap().is_some());
    assert!(state_commit::root(db, 50).is_err(), "an old version pruned");
    // Pins: multiples of 5 (the genesis interval) over two windows.
    for version in [80, 85, 90, 95, 100] {
        state_commit::prove(db, "sys:chain_id", version).expect("kept");
    }
    for block in [80, 85] {
        assert!(
            db.get(&format!("block_{block}")).unwrap().is_some(),
            "pinned block {block}"
        );
    }
    assert!(db.get("block_84").unwrap().is_none(), "not pinned");
    assert!(db.get("block_75").unwrap().is_none(), "its pin expired");
    assert!(state_commit::audit_flat_vs_tree(db).unwrap().is_empty());
}

/// SN-3: a restored node imports the next block through the normal path
/// (`process_blocks`), onto the restored tree, and reaches the producer's
/// root. The producer is itself a node that imported blocks 1 and 2.
#[test]
fn a_restored_node_follows_the_chain() {
    let g = genesis();
    let producer = Producer::new("follow_producer", None);
    let blocks = producer.import(2);
    let (one, two) = (blocks[0].clone(), blocks[1].clone());
    let producer = producer.sync;

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
        "STATE_VALUE_REQ:{}",
    ] {
        assert!(ChainSync::serves(msg), "{msg}");
    }
    for msg in [
        "TX:{}",
        "DAG_VERTEX:{}",
        "QC_VOTE:{}",
        "STATE_CHUNK_RESP:{}",
        "STATE_ANCHOR_RESP:{}",
        "STATE_VALUE_RESP:{}",
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

/// S6b: a restore over the node's real encrypted TCP transport, with a leaf
/// that travels in parts. A peer that is down is skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_restores_over_the_encrypted_transport() {
    let g = genesis();
    let a = chain_with(
        "tcp_a",
        Spec {
            extra: vec![(obj(500), vec![b't'; 3 << 20])],
            ..Spec::default()
        },
    );
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

/// A peer that claims a leaf larger than a client takes is not followed into
/// the allocation: the request counts as unanswered.
#[tokio::test]
async fn a_claimed_leaf_over_the_limit_is_not_fetched() {
    let g = genesis();
    let a = chain("huge_a", MEMBER);
    let client = temp_db("huge_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let mut value_asks = 0usize;
    let err = run_with(&client, &plan(&a.cp, &g, false), 1, |_, msg| {
        if msg.starts_with(VALUE_REQ) {
            value_asks += 1;
        }
        let reply = serve(&mut honest, msg)?;
        let Some(json) = reply.strip_prefix(CHUNK_RESP) else {
            return Ok(reply);
        };
        let mut resp: ChunkResponse = serde_json::from_str(json).unwrap();
        if let Some(entry) = resp.entries.first_mut() {
            entry.value.clear();
            entry.len = MAX_LEAF_BYTES + 1;
        }
        chunk_reply(&resp)
    })
    .await
    .unwrap_err();
    assert!(err.contains("every peer sent a bad state stream"), "{err}");
    assert_eq!(value_asks, 0, "no part was asked for");
}

/// Post-fix review HIGH 1: a peer that sends value parts shorter than the
/// protocol's part size is caught at once and shut out, without a restart.
#[tokio::test]
async fn a_peer_that_trickles_value_parts_is_shut_out() {
    let g = genesis();
    let spec = Spec {
        extra: vec![(obj(500), vec![b't'; 3 << 20])],
        ..Spec::default()
    };
    let slow = chain_with("trickle_s", spec.clone());
    let honest_chain = chain_with("trickle_h", spec);
    let client = temp_db("trickle_client");
    let mut trickler = peer(&slow, Behaviour::Honest);
    let mut honest = peer(&honest_chain, Behaviour::Honest);
    let mut trickled = 0usize;
    let done = run_with(&client, &plan(&slow.cp, &g, false), 2, |i, msg| {
        if i == 1 {
            // Busy until the trickler had its turn at the big value.
            if trickled == 0 && msg.starts_with(CHUNK_REQ) {
                return busy();
            }
            return serve(&mut honest, msg);
        }
        let reply = serve(&mut trickler, msg)?;
        let Some(json) = reply.strip_prefix(VALUE_RESP) else {
            return Ok(reply);
        };
        trickled += 1;
        let mut part: ValueResponse = serde_json::from_str(json).unwrap();
        part.data.truncate(2);
        Ok(format!(
            "{VALUE_RESP}{}",
            serde_json::to_string(&part).unwrap()
        ))
    })
    .await
    .unwrap();
    assert_eq!(done.restarts, 0, "a protocol lie needs no restart");
    assert_eq!(trickled, 1, "shut out after its one short part");
    assert_restored(&client, &slow);
}

/// Post-fix review HIGH 2: busy answers are waited out, however many, and
/// never end the restore as failures do.
#[tokio::test]
async fn many_busy_answers_do_not_end_the_restore() {
    let g = genesis();
    let h = chain("manybusy_h", MEMBER);
    let client = temp_db("manybusy_client");
    let mut honest = peer(&h, Behaviour::Honest);
    let mut asks = 0usize;
    run_with(&client, &plan(&h.cp, &g, false), 1, |_, msg| {
        if msg.starts_with(CHUNK_REQ) {
            asks += 1;
            if !asks.is_multiple_of(5) {
                return busy();
            }
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert!(asks > 20, "{asks} asks, most of them busy");
    assert_restored(&client, &h);
}

/// Failures are counted in a row: a peer that fails now and then, but
/// delivers in between, never exhausts the restore.
#[tokio::test]
async fn failures_count_only_in_a_row() {
    let g = genesis();
    let h = chain("gaps_h", MEMBER);
    let client = temp_db("gaps_client");
    let mut honest = peer(&h, Behaviour::Honest);
    let mut asks = 0usize;
    let mut failed = 0usize;
    run_with(&client, &plan(&h.cp, &g, false), 1, |_, msg| {
        if msg.starts_with(CHUNK_REQ) {
            asks += 1;
            if asks.is_multiple_of(2) {
                failed += 1;
                return Err("connection reset".into());
            }
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert!(failed > fast().max_failures, "{failed} failures in all");
    assert_restored(&client, &h);
}

/// The anchor is asked for again when no peer had it the first time (a
/// blip), before the restore gives up.
#[tokio::test]
async fn the_anchor_is_asked_for_again() {
    let g = genesis();
    let h = chain("anchor_retry_h", MEMBER);
    let client = temp_db("anchor_retry_client");
    let mut honest = peer(&h, Behaviour::Honest);
    let mut anchor_asks = 0usize;
    run_with(&client, &plan(&h.cp, &g, false), 1, |_, msg| {
        if msg.starts_with(ANCHOR_REQ) {
            anchor_asks += 1;
            if anchor_asks < 3 {
                return Err("down".into());
            }
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert_eq!(anchor_asks, 3);
    assert_restored(&client, &h);
}

/// Post-fix review LOW 7: the honest QC with a block whose proposer
/// signature was forged (outside the header hash) is not the pair stored.
#[tokio::test]
async fn a_block_with_a_forged_proposer_signature_is_not_stored() {
    let g = genesis();
    let a = chain("sig_a", MEMBER);
    let b = chain("sig_b", MEMBER);
    let client = temp_db("sig_client");
    let mut byz = peer(&a, Behaviour::Honest);
    let mut honest = peer(&b, Behaviour::Honest);
    let mut block = stored_block(&a);
    block.proposer_signer = "attacker".into();
    let byz_anchor = format!(
        "{ANCHOR_RESP}{}",
        serde_json::to_string(&AnchorResponse {
            block: Some(block),
            quorum_certificate: Some(stored_qc(&a)),
        })
        .unwrap()
    );
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if i == 0 && msg.starts_with(ANCHOR_REQ) {
            Ok(byz_anchor.clone())
        } else if i == 0 {
            serve(&mut byz, msg)
        } else {
            serve(&mut honest, msg)
        }
    })
    .await
    .unwrap();
    let stored: Block =
        serde_json::from_str(&client.get(&format!("block_{H}")).unwrap().unwrap()).unwrap();
    assert_eq!(stored.proposer_signer, proposer().1);
    assert_restored(&client, &a);
}

/// A server that never answers is left after the request timeout, and the
/// restore completes from another.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_server_times_out() {
    let g = genesis();
    let a = chain("silent_a", MEMBER);
    let port = spawn_server(&a).await;
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = silent.accept().await {
            held.push(socket);
        }
    });
    let client = temp_db("silent_client");
    let patient = RestorePlan {
        patience: Patience {
            request_timeout: Duration::from_millis(300),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    let start = Instant::now();
    restore_over_tcp(
        &client,
        &patient,
        &[
            ("127.0.0.1".to_string(), silent_port),
            ("127.0.0.1".to_string(), port),
        ],
        0,
    )
    .await
    .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "{:?}",
        start.elapsed()
    );
    assert_restored(&client, &a);
}

#[test]
fn the_backoff_doubles_per_round_of_the_peers_up_to_its_cap() {
    let patience = Patience {
        backoff_start: Duration::from_millis(50),
        backoff_max: Duration::from_secs(5),
        ..Patience::default()
    };
    let ms = |failures, peers| patience.backoff(failures, peers).as_millis();
    assert_eq!(ms(0, 1), 50);
    assert_eq!(ms(1, 1), 100);
    assert_eq!(ms(3, 1), 400);
    assert_eq!(ms(3, 2), 100, "a round is one ask of every live peer");
    assert_eq!(ms(3, 0), 400, "no live peer counts as one");
    assert_eq!(ms(20, 1), 5_000, "capped");
    assert_eq!(ms(usize::MAX, 1), 5_000, "no overflow");
}

/// A value part whose stated length differs from its leaf's is a lie.
#[tokio::test]
async fn a_value_part_with_another_length_is_a_lie() {
    let g = genesis();
    let a = chain_with(
        "partlen_a",
        Spec {
            extra: vec![(obj(500), vec![b'l'; 3 << 20])],
            ..Spec::default()
        },
    );
    let client = temp_db("partlen_client");
    let mut liar = peer(&a, Behaviour::Honest);
    let err = run_with(&client, &plan(&a.cp, &g, false), 1, |_, msg| {
        let reply = serve(&mut liar, msg)?;
        let Some(json) = reply.strip_prefix(VALUE_RESP) else {
            return Ok(reply);
        };
        let mut part: ValueResponse = serde_json::from_str(json).unwrap();
        part.len += 1;
        Ok(format!(
            "{VALUE_RESP}{}",
            serde_json::to_string(&part).unwrap()
        ))
    })
    .await
    .unwrap_err();
    assert!(err.contains("every peer sent a bad state stream"), "{err}");
}

/// A peer that was busy once gets its turns back once it delivers.
#[tokio::test]
async fn a_peer_busy_once_gets_its_turns_back() {
    let g = genesis();
    let a = chain("turns_a", MEMBER);
    let b = chain("turns_b", MEMBER);
    let client = temp_db("turns_client");
    let mut first = peer(&a, Behaviour::Honest);
    let mut second = peer(&b, Behaviour::Honest);
    let mut first_asks = 0usize;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if i == 1 {
            return serve(&mut second, msg);
        }
        if msg.starts_with(CHUNK_REQ) {
            first_asks += 1;
            if first_asks == 1 {
                return busy();
            }
        }
        serve(&mut first, msg)
    })
    .await
    .unwrap();
    assert!(first.chunks >= 2, "it served again: {}", first.chunks);
    assert_restored(&client, &a);
}

/// A peer that does not answer loses its turns to one that delivers.
#[tokio::test]
async fn a_silent_peer_loses_its_turns() {
    let g = genesis();
    let a = chain("mute_a", MEMBER);
    let client = temp_db("mute_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let mut silent_asks = 0usize;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if i == 0 {
            if msg.starts_with(CHUNK_REQ) {
                silent_asks += 1;
            }
            return Err("no answer".into());
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert!(
        silent_asks <= 3,
        "passed over more each time: {silent_asks}"
    );
    assert_restored(&client, &a);
}

/// Busy answers are waited out only until the restore's deadline.
#[tokio::test]
async fn a_restore_that_is_only_ever_busy_runs_out_of_time() {
    let g = genesis();
    let a = chain("forever_busy", MEMBER);
    let client = temp_db("forever_busy_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let hurried = RestorePlan {
        patience: Patience {
            deadline: Duration::from_millis(200),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    let err = run_with(&client, &hurried, 1, |_, msg| {
        if msg.starts_with(CHUNK_REQ) {
            std::thread::sleep(Duration::from_millis(5));
            return busy();
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap_err();
    assert!(err.contains("ran out of time"), "{err}");
}

/// A peer that sends a value's parts slower than the minimum rate is left
/// for another, before it finishes.
#[tokio::test]
async fn value_parts_sent_too_slowly_are_given_up_on() {
    let g = genesis();
    let spec = Spec {
        extra: vec![(obj(500), vec![b's'; 3 << 20])],
        ..Spec::default()
    };
    let slow_chain = chain_with("sluggish_s", spec.clone());
    let honest_chain = chain_with("sluggish_h", spec);
    let client = temp_db("sluggish_client");
    let mut slow = peer(&slow_chain, Behaviour::Honest);
    let mut honest = peer(&honest_chain, Behaviour::Honest);
    // Parts the slow peer sent in its current turn, and the most in any.
    let (mut slow_parts, mut most) = (0usize, 0usize);
    let hurried = RestorePlan {
        patience: Patience {
            request_timeout: Duration::from_secs(3),
            min_bytes_per_sec: u64::MAX,
            ..fast()
        },
        ..plan(&slow_chain.cp, &g, false)
    };
    run_with(&client, &hurried, 2, |i, msg| {
        if i == 1 {
            if most == 0 && msg.starts_with(CHUNK_REQ) {
                return busy();
            }
            return serve(&mut honest, msg);
        }
        if msg.starts_with(CHUNK_REQ) {
            slow_parts = 0;
        }
        if msg.starts_with(VALUE_REQ) {
            slow_parts += 1;
            most = most.max(slow_parts);
            std::thread::sleep(Duration::from_secs(2));
        }
        serve(&mut slow, msg)
    })
    .await
    .unwrap();
    assert!(
        (1..3).contains(&most),
        "never let finish the value's three parts: {most}"
    );
    assert_restored(&client, &slow_chain);
}

/// When no pair of the first round verifies, the anchor is asked for again:
/// the peer with the good pair may have missed that round.
#[tokio::test]
async fn the_anchor_is_fetched_again_when_no_qc_verifies() {
    let g = genesis();
    let a = chain("refetch_a", MEMBER);
    let bad = chain("refetch_bad", [9; 32]);
    let client = temp_db("refetch_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let mut outsider = peer(&bad, Behaviour::Honest);
    let mut honest_anchor_asks = 0usize;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if i == 0 {
            if msg.starts_with(ANCHOR_REQ) {
                honest_anchor_asks += 1;
                if honest_anchor_asks == 1 {
                    return Err("blip".into());
                }
            }
            return serve(&mut honest, msg);
        }
        if msg.starts_with(ANCHOR_REQ) {
            // A pair signed outside the committee, for the same checkpoint.
            return serve(&mut outsider, msg);
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert_eq!(honest_anchor_asks, 2, "asked again after the bad QC");
    assert_restored(&client, &a);
}

/// A peer that takes its time to say busy is stalling: it sits out turns
/// like a silent one. An honest server says busy at once.
#[tokio::test]
async fn a_peer_that_stalls_before_saying_busy_loses_its_turns() {
    let g = genesis();
    let a = chain("stall_a", MEMBER);
    let client = temp_db("stall_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let mut stalls = 0usize;
    let hurried = RestorePlan {
        patience: Patience {
            request_timeout: Duration::from_millis(200),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    run_with(&client, &hurried, 2, |i, msg| {
        if i == 0 && msg.starts_with(CHUNK_REQ) {
            stalls += 1;
            std::thread::sleep(Duration::from_millis(60));
            return busy();
        }
        serve(&mut honest, msg)
    })
    .await
    .unwrap();
    assert!(stalls <= 3, "passed over more each time: {stalls}");
    assert_restored(&client, &a);
}

/// A peer that delivers is forgiven: its next failure costs one turn again,
/// not twice its last.
#[tokio::test]
async fn a_peer_that_delivers_is_forgiven() {
    let g = genesis();
    let a = chain("forgive_a", MEMBER);
    let client = temp_db("forgive_client");
    let mut first = peer(&a, Behaviour::Honest);
    let mut second = peer(&a, Behaviour::Honest);
    let mut order: Vec<usize> = Vec::new();
    let mut first_asks = 0usize;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if msg.starts_with(CHUNK_REQ) {
            order.push(i);
        }
        if i == 1 {
            return serve(&mut second, msg);
        }
        if msg.starts_with(CHUNK_REQ) {
            first_asks += 1;
            if first_asks == 1 || first_asks == 3 {
                return Err("dropped".into());
            }
        }
        serve(&mut first, msg)
    })
    .await
    .unwrap();
    // After its second failure (its third ask), the other peer is asked
    // twice before it is back: one sit-out turn, as after its first.
    let third = order
        .iter()
        .enumerate()
        .filter(|(_, p)| **p == 0)
        .nth(2)
        .map(|(at, _)| at)
        .unwrap();
    let before_back = order[third + 1..].iter().take_while(|p| **p == 1).count();
    assert_eq!(before_back, 2, "order: {order:?}");
    assert_restored(&client, &a);
}
