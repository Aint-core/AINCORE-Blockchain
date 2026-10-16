//! G3 S6 witnesses (SN-2, SN-4): a restore from untrusted peers completes
//! against the checkpoint root, whatever the peers do, or refuses.

use super::*;
use consensus::qc::{build_qc, validator_set_hash, FinalityVote, ValidatorInfo};
use std::collections::BTreeMap;
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

/// An account that is no validator.
const OUTSIDER: [u8; 32] = [78; 32];

fn outsider() -> (crypto::SigningKey, String) {
    let key = crypto::SigningKey::from_bytes(&OUTSIDER);
    let address = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    (key, address)
}

/// The proposer's account, as the state stores it.
fn proposer_account() -> (String, Vec<u8>) {
    account(proposer())
}

fn account((key, address): (crypto::SigningKey, String)) -> (String, Vec<u8>) {
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
    let path = storage::test_dir::process_dir().join(format!(
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
        bls_pop: hex::encode(bls.prove_possession_raw(&seed, &[0u8; 32])),
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
    /// The active set (`sys:validators`; on V4 `sys:validator_set:v1`)
    /// besides the proposer.
    validators: Vec<String>,
    /// The checkpoint block's BFT timestamp, in seconds.
    timestamp: u64,
    /// A V4 chain: `genesis:vertex_format` 4, the executor's record of the
    /// next epoch's committee, and a QC at H (an epoch boundary) that binds it.
    v4: bool,
    /// B401: the checkpoint block's transactions (a body of several shards).
    transactions: Vec<String>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            signer: MEMBER,
            state_chain: CHAIN,
            extra: Vec::new(),
            epoch_one: None,
            validators: Vec::new(),
            timestamp: 1_000,
            v4: false,
            transactions: Vec::new(),
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
    let (epoch, mut signing) = match spec.epoch_one {
        Some(seed) => (1, committee_of(seed, 2)),
        None => (0, members.clone()),
    };
    // B472: on V4 a block's signer is a member of its epoch's committee
    // (C_E(h), as sync checks it), so the epoch's member is the anchor's
    // proposer. Epoch 0's committee is the genesis set every client pins:
    // a V4 fixture runs in epoch one.
    if spec.v4 {
        assert!(spec.epoch_one.is_some(), "a V4 fixture runs in epoch one");
        signing[0].address = proposer().1;
    }
    // The live set at H (the anchor block's proposer is in it, as on a real
    // chain), and E+1's committee by the rule every node runs at H.
    let mut live = signing.clone();
    if !live.iter().any(|v| v.address == proposer().1) {
        live.push(ValidatorInfo {
            address: proposer().1,
            stake: 100,
            ed25519_public_key: hex::encode(proposer().0.verifying_key().to_bytes()),
            bls_public_key: String::new(),
            bls_pop: String::new(),
        });
    }
    // B472: and the active set's other validators, outside the committee.
    live.extend(spec.validators.iter().map(|address| ValidatorInfo {
        address: address.clone(),
        stake: 100,
        ed25519_public_key: String::new(),
        bls_public_key: String::new(),
        bls_pop: String::new(),
    }));
    let next = blockchain::committee::next_committee(&signing, &live).0;
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
            let (account_key, proposer) = proposer_account();
            v0.push((account_key, Some(proposer)));
            let (outsider_key, outsider) = account(outsider());
            v0.push((outsider_key, Some(outsider)));
            let mut active: Vec<(String, u64)> = vec![(self::proposer().1, 100)];
            active.extend(spec.validators.iter().map(|v| (v.clone(), 100)));
            v0.push((
                "sys:validators".into(),
                Some(serde_json::to_vec(&active).unwrap()),
            ));
            if spec.v4 {
                v0.push(("genesis:vertex_format".into(), Some(b"4".to_vec())));
                v0.push((
                    "sys:validator_set:v1".into(),
                    Some(serde_json::to_vec(&live).unwrap()),
                ));
                v0.push((
                    format!("sys:validator_set:epoch:{}", epoch + 1),
                    Some(serde_json::to_vec(&next).unwrap()),
                ));
            }
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
    // B398: the anchor is the committed sequence's last vertex (G0), as
    // every block a node builds has it.
    let mut block = Block::new_with_roots_at(
        H,
        2 * H,
        "00".repeat(32),
        spec.transactions.clone(),
        proposer_address.clone(),
        root.clone(),
        "dd".repeat(32),
        spec.timestamp,
        vec!["aa".repeat(32)],
        vec![proposer_address.clone()],
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
        next_validator_set_hash: if spec.v4 {
            validator_set_hash(&next)
        } else {
            String::new()
        },
    };
    let signature = crypto::bls::BLSEngine::consensus()
        .sign_raw(&vote.signing_bytes_under(IDENTITY), &spec.signer);
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
        sync: ChainSync::new(Arc::clone(&chain.db)).with_snapshot_serving(true),
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
        slow_turn: Duration::from_secs(2),
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
    assert_eq!(
        client.get(StateDB::KEPT_PIN_BLOCKS_KEY).unwrap().as_deref(),
        Some("[]"),
        "the old chain's kept pins are forgotten"
    );
    let anchor_round = (2 * H).to_string();
    for (key, value) in [
        ("consensus:finality_digest", "ee".repeat(32)),
        ("consensus:last_anchor_round", anchor_round.clone()),
        ("consensus:last_anchor_hash", "aa".repeat(32)),
        ("consensus:finalized_round", (2 * H + 2).to_string()),
        ("consensus:qc:latest_round", anchor_round.clone()),
        // B82: the ordering cursors, written by the restore.
        ("consensus:gc_floor", anchor_round.clone()),
        ("consensus:next_anchor_round", (2 * H + 3).to_string()),
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

/// A block's own pair with `qc`.
fn pair_of(block: Block, qc: QuorumCertificate) -> Pair {
    Pair {
        proposer_signature: block.proposer_signature.clone(),
        proposer_signer: block.proposer_signer.clone(),
        body: Arc::new(block),
        qc,
    }
}

/// G4 S6: a node restores over the network task's sessions: each peer is
/// dialled once by address, every request runs on that session, and each
/// is charged to the key the server's session layer names.
#[tokio::test]
async fn a_node_restores_over_sessions() {
    let g = genesis();
    let a = chain("sessions_a", MEMBER);
    let client = temp_db("sessions_client");
    let server = Arc::new(peer(&a, Behaviour::Honest).sync);
    let (asks_tx, mut asks) = tokio::sync::mpsc::channel::<network::SyncAsk>(8);
    let (dials_tx, mut dials) = tokio::sync::mpsc::channel::<network::SyncDial>(8);
    let sessions = network::SessionClient {
        asks: asks_tx,
        dials: dials_tx,
        table: Default::default(),
    };
    let dialled = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = Arc::new(Mutex::new(std::collections::BTreeSet::<String>::new()));
    let (task_dialled, task_seen, task_server) =
        (Arc::clone(&dialled), Arc::clone(&seen), Arc::clone(&server));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(dial) = dials.recv() => {
                    task_dialled.lock().unwrap().push(dial.addr.clone());
                    let _ = dial.reply.send(Ok("12D3KooWserver".into()));
                }
                Some(ask) = asks.recv() => {
                    task_seen.lock().unwrap().insert(ask.peer.clone());
                    let answer = task_server
                        .serve_session(&ask.wire, "12D3KooWclient")
                        .ok_or_else(|| "refused".to_string());
                    let _ = ask.reply.send(answer);
                }
                else => break,
            }
        }
    });
    let addr = "/ip4/127.0.0.1/tcp/9102".to_string();
    let done = restore_over_sessions(
        &client,
        &plan(&a.cp, &g, false),
        &sessions,
        std::slice::from_ref(&addr),
    )
    .await
    .unwrap();
    assert_eq!(done.leaves, a.state.len());
    assert_restored(&client, &a);
    assert_eq!(*dialled.lock().unwrap(), vec![addr], "one dial, then reuse");
    assert_eq!(
        seen.lock().unwrap().iter().collect::<Vec<_>>(),
        vec!["12D3KooWserver"],
        "every request on the session the dial opened"
    );
    // Charged to the session's key: its bucket exists (an untracked key reads
    // NaN). Not its level, which refills by the wall clock (B46: on the Pi
    // the restore outlasted the refill).
    assert!(
        !server.state_budget.balance(Some("12D3KooWclient")).is_nan(),
        "charged to the session's key"
    );
    assert!(
        server.state_budget.balance(Some("12D3KooWserver")).is_nan(),
        "and to no other"
    );
}

/// G4 S6: a snapshot request a server cannot take now is told "busy" (its
/// client waits it out); any other request has no busy answer.
#[test]
fn only_snapshot_parts_have_a_busy_answer() {
    let chunk = busy_reply(&format!("{CHUNK_REQ}{{}}")).unwrap();
    let chunk: ChunkResponse =
        serde_json::from_str(chunk.strip_prefix(CHUNK_RESP).unwrap()).unwrap();
    assert_eq!(chunk.error.as_deref(), Some("busy"));
    let value = busy_reply(&format!("{VALUE_REQ}{{}}")).unwrap();
    let value: ValueResponse =
        serde_json::from_str(value.strip_prefix(VALUE_RESP).unwrap()).unwrap();
    assert_eq!(value.error.as_deref(), Some("busy"));
    // B418: a checkpoint's anchor too (it was dropped unanswered).
    let anchor = busy_reply(&format!("{ANCHOR_REQ}{{}}")).unwrap();
    let anchor: AnchorResponse =
        serde_json::from_str(anchor.strip_prefix(ANCHOR_RESP).unwrap()).unwrap();
    assert_eq!(anchor.error.as_deref(), Some("busy"));
    assert_eq!(busy_reply("SYNC_REQ:{}"), None);
    assert_eq!(busy_reply("GET_HEIGHT"), None);
}

/// B418 witness: an anchor request the snapshot budget cannot take now is
/// answered busy, and served once a slot is free. It was answered with an
/// empty anchor, which a client counts as no answer.
#[test]
fn an_anchor_the_budget_cannot_take_is_answered_busy() {
    let a = chain("anchor_shed_a", MEMBER);
    let sync = peer(&a, Behaviour::Honest).sync;
    let ask = || sync.handle_state_anchor(AnchorRequest { height: H });
    let held: Vec<_> = (0..STATE_SERVE_IN_FLIGHT)
        .map(|_| sync.state_budget.admit(None, 1, true).expect("a slot"))
        .collect();
    let refused = ask();
    assert_eq!(refused.error.as_deref(), Some("busy"), "no free slot");
    assert!(refused.block.is_none());
    drop(held);
    let served = ask();
    assert!(served.error.is_none());
    assert!(served.block.is_some(), "positive control: served once free");
}

/// B418 witness: a server answering the checkpoint's anchor busy for more
/// rounds than `max_failures` is waited out within the deadline, and its
/// anchor taken once it answers. A busy anchor was no answer, so a server's
/// spent quota (or slots held by others) ended the restore after
/// `max_failures` rounds.
#[tokio::test]
async fn an_anchor_answered_busy_is_waited_out() {
    let a = chain("anchor_busy_a", MEMBER);
    let server = peer(&a, Behaviour::Honest).sync;
    let patience = fast();
    let busy_rounds = patience.max_failures + 2;
    let busy = format!(
        "{ANCHOR_RESP}{}",
        serde_json::to_string(&AnchorResponse {
            error: Some(BUSY.into()),
            ..Default::default()
        })
        .unwrap()
    );
    let busy_answers = std::cell::Cell::new(0usize);
    let mut ask = |_: usize, msg: String| {
        let reply = if msg.starts_with(ANCHOR_REQ) && busy_answers.get() < busy_rounds {
            busy_answers.set(busy_answers.get() + 1);
            Ok(busy.clone())
        } else {
            server
                .handle_message(&msg)
                .ok_or_else(|| "no answer".to_string())
        };
        async move { reply }
    };
    let mut anchor = AnchorBody::default();
    let pairs = fetch_anchor(&a.cp, 1, &mut ask, &patience, &mut anchor, Instant::now())
        .await
        .expect("the anchor, once the server answers");
    assert_eq!(
        busy_answers.get(),
        busy_rounds,
        "positive control: busy for more than max_failures rounds"
    );
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].qc, stored_qc(&a));
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
    let signature =
        crypto::bls::BLSEngine::consensus().sign_raw(&vote.signing_bytes_under(IDENTITY), &MEMBER);
    let other_epoch = build_qc(&vote, &committee(), &[0], &[signature]).unwrap();
    let err = verified_pair(
        &client,
        CHAIN,
        IDENTITY,
        0,
        &committee(),
        &[pair_of(block.clone(), other_epoch.clone())],
    )
    .unwrap_err();
    assert!(err.contains("epoch"), "{err}");
    let verified = verified_pair(
        &client,
        CHAIN,
        IDENTITY,
        0,
        &committee(),
        &[
            pair_of(block.clone(), other_epoch),
            pair_of(block, good.clone()),
        ],
    )
    .unwrap();
    assert_eq!(verified.qc, good);
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

/// B50 witness: a V4 node restored at an epoch boundary past epoch 0 holds
/// the next epoch's record, as every node that executed the boundary block
/// derived it, and that epoch is active: the next block's QC verifies under
/// it. Before, the restore found no committee for the checkpoint's epoch (its
/// record is not state) and failed after the whole download.
#[tokio::test]
async fn a_v4_restore_at_a_boundary_holds_the_next_epochs_record() {
    let g = genesis();
    let later = [8u8; 32];
    let a = chain_with(
        "v4_boundary_a",
        Spec {
            signer: later,
            epoch_one: Some(later),
            v4: true,
            ..Spec::default()
        },
    );
    let client = temp_db("v4_boundary_client");
    let mut peers = [peer(&a, Behaviour::Honest)];
    run(&client, &plan(&a.cp, &g, false), &mut peers)
        .await
        .expect("a V4 restore at a boundary completes");
    assert_restored(&client, &a);
    let block = stored_block(&a);
    let next = consensus::v4::epoch::read_start_from(&client, 2)
        .unwrap()
        .expect("epoch 2's record is written");
    let committee: Vec<ValidatorInfo> =
        serde_json::from_str(&client.get("sys:validator_set:epoch:2").unwrap().unwrap()).unwrap();
    assert_eq!(next.committee, committee, "the executor's record");
    assert_eq!(next.first_round, block.header.round + 2);
    assert_eq!(next.prev_block_hash, block.header.hash);
    assert_eq!(
        client
            .get(consensus::v4::epoch::EPOCH_ACTIVE_KEY)
            .unwrap()
            .as_deref(),
        Some("2")
    );
    assert_eq!(
        consensus::qc_producer::load_validator_set_for_epoch(&client, 2),
        Some(committee),
        "the next block's QC verifies under epoch 2's committee"
    );
}

/// B61 witness: a replace-restore drops the replaced chain's alarms (kept,
/// they halted ordering on the restored state).
#[tokio::test]
async fn a_replace_restore_clears_the_old_chains_alarms() {
    let g = genesis();
    let a = chain("alarms_a", MEMBER);
    let client = temp_db("alarms_client");
    client
        .put("alarm:decision_conflict:42", "DECISION_CONFLICT: old")
        .unwrap();
    let mut peers = [peer(&a, Behaviour::Honest)];
    run(&client, &plan(&a.cp, &g, true), &mut peers)
        .await
        .unwrap();
    assert_restored(&client, &a);
    assert_eq!(client.get("alarm:decision_conflict:42").unwrap(), None);
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
            quorum_certificate: Some(qc),
            oversized: None,
            error: None,
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

/// B42 witness: the only anchor pair offered until late is a liar's (the
/// honest peer answers its first three anchor asks without one). The
/// restore keeps asking within its deadline and stores the honest pair.
/// Before, it asked once more after the download and failed.
#[tokio::test]
async fn the_anchor_is_asked_for_until_a_pair_verifies() {
    let g = genesis();
    let a = chain("late_a", MEMBER);
    let client = temp_db("late_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let mut byz = peer(&a, Behaviour::Honest);
    // The real block with a QC whose signature is wrong: it names the
    // checkpoint's block, so it passes the checks before the download and
    // fails only against the restored committee.
    let honest_qc = serde_json::to_string(&stored_qc(&a)).unwrap();
    let mut qc = stored_qc(&a);
    qc.aggregate_signature[0] ^= 0xff;
    let byz_anchor = format!(
        "{ANCHOR_RESP}{}",
        serde_json::to_string(&AnchorResponse {
            block: Some(stored_block(&a)),
            quorum_certificate: Some(qc),
            oversized: None,
            error: None,
        })
        .unwrap()
    );
    let mut honest_anchor_asks = 0;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if msg.starts_with(ANCHOR_REQ) {
            if i == 0 {
                return Ok(byz_anchor.clone());
            }
            honest_anchor_asks += 1;
            if honest_anchor_asks <= 3 {
                // Answered, but without a pair: the round returns the
                // liar's pair alone, so only asking again finds this one.
                return Ok(format!(
                    "{ANCHOR_RESP}{}",
                    serde_json::to_string(&AnchorResponse::default()).unwrap()
                ));
            }
            return serve(&mut honest, msg);
        }
        if i == 0 {
            serve(&mut byz, msg)
        } else {
            serve(&mut honest, msg)
        }
    })
    .await
    .expect("the restore completes");
    assert_restored(&client, &a);
    let stored = client.get(&format!("consensus:qc:{H}")).unwrap().unwrap();
    assert_eq!(stored, honest_qc, "the verified QC was stored");
    assert!(
        honest_anchor_asks > 3,
        "positive control: asked past the misses"
    );
}

/// B42 review witness: after the download, a whole `fetch_anchor` (six
/// rounds in the test's patience) finds no pair at all; the restore keeps
/// asking within its deadline instead of throwing the download away.
#[tokio::test]
async fn anchor_rounds_without_a_pair_do_not_end_the_restore() {
    let g = genesis();
    let a = chain("nopair_a", MEMBER);
    let client = temp_db("nopair_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let mut byz = peer(&a, Behaviour::Honest);
    let mut qc = stored_qc(&a);
    qc.aggregate_signature[0] ^= 0xff;
    let anchor = |block: Option<Block>, qc: Option<QuorumCertificate>| {
        Ok(format!(
            "{ANCHOR_RESP}{}",
            serde_json::to_string(&AnchorResponse {
                block,
                quorum_certificate: qc,
                oversized: None,
                error: None,
            })
            .unwrap()
        ))
    };
    let (mut byz_asks, mut honest_asks) = (0, 0);
    let misses = 1 + fast().max_failures + 1;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if msg.starts_with(ANCHOR_REQ) {
            if i == 0 {
                byz_asks += 1;
                // The bad pair once, before the download; nothing after.
                return match byz_asks {
                    1 => anchor(Some(stored_block(&a)), Some(qc.clone())),
                    _ => anchor(None, None),
                };
            }
            honest_asks += 1;
            if honest_asks <= misses {
                return anchor(None, None);
            }
            return serve(&mut honest, msg);
        }
        if i == 0 {
            serve(&mut byz, msg)
        } else {
            serve(&mut honest, msg)
        }
    })
    .await
    .expect("the restore completes");
    assert_restored(&client, &a);
    assert!(honest_asks > misses, "positive control: past the misses");
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
    server.sync = ChainSync::new(Arc::clone(&a.db))
        .with_retention(Some((keep, 1_000)))
        .with_snapshot_serving(true);
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
            validators: vec![joined.clone()],
            ..Spec::default()
        },
    );
    let mut peers = [peer(&a, Behaviour::Honest)];
    let member = committee()[0].address.clone();
    let mut last = None;
    for signer in [&member, &joined] {
        // A fresh datadir each time, so the restored state is what refuses.
        let client = temp_db("signer_client");
        let as_validator = RestorePlan {
            local_signer: Some(signer),
            ..plan(&a.cp, &g, false)
        };
        let err = run(&client, &as_validator, &mut peers).await.unwrap_err();
        assert!(err.contains("validator") && err.contains("SN-6"), "{err}");
        assert!(
            client.get(RESTORE_MARKER).unwrap().is_some(),
            "refused after the restore, the marker kept"
        );
        assert!(state_commit::boot_check(&client).is_err(), "it cannot boot");
        last = Some(client);
    }
    let client = last.unwrap();
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
    // The end of the stream costs nothing: its grant is given back.
    let client = Some("10.0.0.12");
    let end = sync.serve_state_chunk(
        ChunkRequest {
            version: H,
            after: Some(hex::encode(last.0)),
            max: 100,
        },
        client,
    );
    assert!(end.done);
    assert_eq!(
        sync.state_budget.balance(client),
        STATE_SERVE_UNITS_PER_SEC_PER_CLIENT
    );
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
        .map(|_| sync.state_budget.admit(None, 1, true).expect("a slot"))
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
        .admit(None, usize::MAX, false)
        .is_some_and(|a| a.granted as f64 > STATE_SERVE_UNITS_PER_SEC_SHARED - 1_000.0));
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
        .map(|_| sync.state_budget.admit(None, 1, true).expect("a slot"))
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
            Some(IpAddr::from(ip).to_string().as_str()),
        )
    };
    let hog = [10, 0, 0, 1];
    let start = Instant::now();
    let mut leaves = 0usize;
    for _ in 0..20 {
        leaves += ask(hog).entries.len();
    }
    // At most a burst, then the per-IP rate, however fast it asks.
    let allowed = STATE_SERVE_UNITS_PER_SEC_PER_CLIENT * (1.0 + start.elapsed().as_secs_f64());
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
    let third = "10.0.0.5";
    let held = sync.state_budget.admit(Some(third), 1, false);
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
    let ip = |i: u32| IpAddr::from(i.to_be_bytes()).to_string();
    for i in 0..MAX_TRACKED_CLIENTS as u32 {
        drop(budget.admit(Some(&ip(i)), 1, false).expect("room"));
    }
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        budget.admit(Some(&ip(1 << 20)), 1, false).is_some(),
        "an idle client forgotten"
    );
    // A client with a request in flight is never forgotten, so it cannot
    // dodge its one-slot limit by being evicted.
    let pinned = StateBudget::default();
    let held = pinned.admit(Some(&ip(0)), 1, false).expect("in flight");
    for i in 1..MAX_TRACKED_CLIENTS as u32 {
        drop(pinned.admit(Some(&ip(i)), 1, false).expect("room"));
    }
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        pinned.admit(Some(&ip(1 << 22)), 1, false).is_some(),
        "the table makes room"
    );
    assert!(
        pinned.admit(Some(&ip(0)), 1, false).is_none(),
        "still one in flight"
    );
    drop(held);
    // A table of clients all still refilling has no room, whatever the
    // global bucket holds.
    let debt = StateBudget::default();
    {
        let mut st = debt.lock();
        let now = Instant::now();
        for i in 0..MAX_TRACKED_CLIENTS as u32 {
            st.per_client.insert(
                IpAddr::from(i.to_be_bytes()).to_string(),
                Bucket {
                    tokens: -1.0,
                    last: now,
                    in_flight: 0,
                },
            );
        }
    }
    assert!(
        debt.admit(Some(&ip(1 << 21)), 1, false).is_none(),
        "every client in debt"
    );
    assert_eq!(
        debt.lock().per_client.len(),
        MAX_TRACKED_CLIENTS,
        "none forgotten"
    );
    assert_eq!(
        debt.balance(None),
        STATE_SERVE_UNITS_PER_SEC_SHARED,
        "not global"
    );
}

/// A bucket holds one second's worth at most, however long it was idle.
#[test]
fn a_bucket_holds_one_seconds_worth() {
    let budget = StateBudget::default();
    let ip = "10.0.0.1";
    drop(budget.admit(Some(ip), 1, false));
    {
        let mut st = budget.lock();
        let long_ago = Instant::now() - Duration::from_secs(60);
        st.global.last = long_ago;
        st.per_client.get_mut(ip).unwrap().last = long_ago;
    }
    let client = budget.admit(Some(ip), usize::MAX, false).unwrap();
    assert_eq!(
        client.granted,
        STATE_SERVE_UNITS_PER_SEC_PER_CLIENT as usize
    );
    drop(client);
    budget.lock().global.last = Instant::now() - Duration::from_secs(60);
    let global = budget.admit(None, usize::MAX, false).unwrap();
    assert_eq!(global.granted, STATE_SERVE_UNITS_PER_SEC_SHARED as usize);
}

/// Post-fix review MEDIUM 3, as charged since review 3: a part costs its
/// bytes, and reading a value the cache does not hold costs its bytes too,
/// up to one second's worth. A client that makes the server re-read large
/// values (more of them than the cache holds) runs out of budget.
#[test]
fn value_reads_are_charged_by_their_bytes() {
    let mut extra: Vec<(String, Vec<u8>)> =
        (500..506).map(|i| (obj(i), vec![b'p'; 3 << 20])).collect();
    extra.push((obj(510), vec![b'r'; 8 << 20]));
    let a = chain_with(
        "bytes_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let sync = peer(&a, Behaviour::Honest).sync;
    let client = Some("10.0.0.3");
    let start = Instant::now();
    let mut served = 0u64;
    for i in 0..12u64 {
        // Six values in turn, more than the cache holds: every read misses.
        let part = sync.serve_state_value(
            ValueRequest {
                version: H,
                key: obj(500 + i % 6),
                offset: 0,
            },
            client,
        );
        if part.error.is_none() {
            served += 1;
        }
    }
    // Each miss costs its part and the 3 MiB read, of 2,000 units a second
    // (plus one burst) for this client.
    let per_read = PART_UNITS as f64 + ((3 << 20) / UNIT_BYTES) as f64;
    let allowed = STATE_SERVE_UNITS_PER_SEC_PER_CLIENT * (1.0 + start.elapsed().as_secs_f64());
    assert!(
        served as f64 * per_read <= allowed + per_read,
        "{served} whole-value reads served in {:?}",
        start.elapsed()
    );
    assert!(served >= 1, "positive control");
    // Reading an 8 MiB value costs one second's worth on top of its part,
    // for the client and globally: in debt by the part, at most.
    let fresh = peer(&a, Behaviour::Honest).sync;
    let heavy = Some("10.0.0.4");
    let ask = |offset: u64, ip: Option<&str>| {
        fresh.serve_state_value(
            ValueRequest {
                version: H,
                key: obj(510),
                offset,
            },
            ip,
        )
    };
    let first = ask(0, heavy);
    assert!(first.error.is_none(), "{:?}", first.error);
    let cost = PART_UNITS as f64 + STATE_SERVE_UNITS_PER_SEC_PER_CLIENT;
    let client_balance = fresh.state_budget.balance(heavy);
    assert_eq!(client_balance, STATE_SERVE_UNITS_PER_SEC_PER_CLIENT - cost);
    let global_balance = fresh.state_budget.balance(None);
    assert_eq!(
        global_balance,
        STATE_SERVE_UNITS_PER_SEC_SHARED - cost,
        "global"
    );
    // Its next part is cached: the part alone, for any client.
    let reader_ip = "10.0.0.5";
    let reader = Some(reader_ip);
    let next = ask(VALUE_PART_BYTES as u64, reader);
    assert!(next.error.is_none(), "{:?}", next.error);
    assert_eq!(
        fresh.state_budget.balance(reader),
        STATE_SERVE_UNITS_PER_SEC_PER_CLIENT - PART_UNITS as f64
    );
    // A part is let in only when its whole cost fits.
    {
        let mut st = fresh.state_budget.lock();
        let bucket = st.per_client.get_mut(reader_ip).unwrap();
        bucket.tokens = 100.0;
        bucket.last = Instant::now();
    }
    assert_eq!(ask(0, reader).error.as_deref(), Some(BUSY));
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
    let reader = Some("10.0.0.9");
    let charged = sync.serve_state_chunk(
        ChunkRequest {
            version: H,
            after: None,
            max: 100,
        },
        reader,
    );
    assert!(charged.error.is_none());
    // Charged a unit per leaf served (the rest of the grant given back) and
    // the bytes read: the leaves served and the one read past the budget.
    let served = charged.entries.len();
    let (read, _) = state_commit::chunk(&a.db, H, None, served + 1)
        .unwrap()
        .unwrap();
    let read: u64 = read.iter().map(|(_, v)| v.len() as u64).sum();
    let expected = STATE_SERVE_UNITS_PER_SEC_PER_CLIENT
        - served as f64
        - (read.div_ceil(UNIT_BYTES) as f64).min(STATE_SERVE_UNITS_PER_SEC_PER_CLIENT);
    // Exactly: a server that read more (every leaf granted, or the same
    // leaves again) would be charged more.
    assert!(read < 8 << 20, "under the charge's cap: {read}");
    assert_eq!(sync.state_budget.balance(reader), expected);
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
        let sync = ChainSync::new(temp_db(name))
            .with_retention(retention)
            .with_snapshot_serving(true);
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
            // G5 CL-2: the executor's own root for this empty block (the
            // clock, and at a boundary the committee record), found in a
            // discarded transaction.
            let root = crate::dry_run_empty_block_root(&self.sync.storage, height, height);
            let mut block = Block::new_with_roots_at(
                height,
                height,
                prev.clone(),
                vec![],
                self.proposer.clone(),
                root,
                executor.receipts_root_for_block(&[]),
                height,
                Vec::new(),
                vec![],
                String::new(),
                Vec::new(),
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
/// until their pins expire. B371: it prunes only below what it has adopted.
#[test]
fn a_node_that_only_follows_prunes() {
    let producer = Producer::new("follow_prunes", Some((10, 250)));
    // B371: pruning keeps every block above the adoption cursor, which only
    // the DAG's adoption loop moves (after each sync pass). This node runs
    // none, so its cursor is put at the tip, where a follower's adoption that
    // keeps pace leaves it: the window is then the retention alone. Left at
    // 0, the clamp held the window at height 11 and the state floor at 1.
    producer
        .sync
        .storage
        .put("consensus:last_adopted_height", "100")
        .unwrap();
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
        next_validator_set_hash: String::new(),
    };
    let signature =
        crypto::bls::BLSEngine::consensus().sign_raw(&vote.signing_bytes_under(IDENTITY), &MEMBER);
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

    let client = ChainSync::new(temp_db("follow_client"));
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
        "STATE_ANCHOR_REQ:{}",
        "STATE_CHUNK_REQ:{}",
        "STATE_VALUE_REQ:{}",
    ] {
        assert!(ChainSync::serves(msg), "{msg}");
    }
    for msg in [
        "TX:{}",
        // B19: the V3 vertex fetch; V4 pulls over its own signed requests.
        "VERTEX_REQ:{}",
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

/// What a fake network task does with one request.
enum Fake {
    Answer(Result<String, String>),
    /// Never answered (the reply is held, so the asker times out).
    Silent,
}

/// A fake network task: `dial(addr)` is the session a dial opens (or why it
/// fails), `ask(session, wire)` what a request on it gets. Returns the
/// client and the addresses dialled, in order.
fn fake_sessions(
    dial: impl Fn(&str) -> Result<String, String> + Send + 'static,
    mut ask: impl FnMut(&str, &str) -> Fake + Send + 'static,
) -> (network::SessionClient, Arc<Mutex<Vec<String>>>) {
    let (asks_tx, mut asks) = tokio::sync::mpsc::channel::<network::SyncAsk>(8);
    let (dials_tx, mut dials) = tokio::sync::mpsc::channel::<network::SyncDial>(8);
    let dialled = Arc::new(Mutex::new(Vec::new()));
    let task_dialled = Arc::clone(&dialled);
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            tokio::select! {
                Some(d) = dials.recv() => {
                    task_dialled.lock().unwrap().push(d.addr.clone());
                    let _ = d.reply.send(dial(&d.addr));
                }
                Some(a) = asks.recv() => match ask(&a.peer, &a.wire) {
                    Fake::Answer(answer) => {
                        let _ = a.reply.send(answer);
                    }
                    Fake::Silent => held.push(a.reply),
                },
                else => break,
            }
        }
    });
    let client = network::SessionClient {
        asks: asks_tx,
        dials: dials_tx,
        table: Default::default(),
    };
    (client, dialled)
}

/// G4 S6: a restore over sessions with a leaf that travels in parts; a peer
/// whose dial fails is skipped.
#[tokio::test]
async fn a_node_restores_over_sessions_past_a_peer_that_is_down() {
    let g = genesis();
    let a = chain_with(
        "sess_parts_a",
        Spec {
            extra: vec![(obj(500), vec![b't'; 3 << 20])],
            ..Spec::default()
        },
    );
    let server = peer(&a, Behaviour::Honest).sync;
    let (sessions, dialled) = fake_sessions(
        |addr| {
            if addr.ends_with("/tcp/1") {
                Err("connection refused".into())
            } else {
                Ok("up".into())
            }
        },
        move |_, wire| {
            Fake::Answer(
                server
                    .serve_session(wire, "client")
                    .ok_or_else(|| "refused".into()),
            )
        },
    );
    let client = temp_db("sess_parts_client");
    let addrs = [
        "/ip4/127.0.0.1/tcp/1".to_string(),
        "/ip4/127.0.0.1/tcp/2".to_string(),
    ];
    let done = restore_over_sessions(&client, &plan(&a.cp, &g, false), &sessions, &addrs)
        .await
        .unwrap();
    assert_eq!(done.leaves, a.state.len());
    assert_restored(&client, &a);
    assert!(
        dialled.lock().unwrap().contains(&addrs[0]),
        "positive control: the down peer was tried"
    );
}

/// G4 S6: a session whose request failed is dialled again before its next
/// request, never reused as it was (the old connection may be gone).
#[tokio::test]
async fn a_failed_request_redials_its_peer() {
    let g = genesis();
    let a = chain("sess_redial_a", MEMBER);
    let server = peer(&a, Behaviour::Honest).sync;
    let mut asked = 0usize;
    let (sessions, dialled) = fake_sessions(
        |_| Ok("only".into()),
        move |_, wire| {
            asked += 1;
            if asked == 2 {
                return Fake::Answer(Err("stream reset".into()));
            }
            Fake::Answer(
                server
                    .serve_session(wire, "client")
                    .ok_or_else(|| "refused".into()),
            )
        },
    );
    let client = temp_db("sess_redial_client");
    let addr = "/ip4/127.0.0.1/tcp/9102".to_string();
    restore_over_sessions(
        &client,
        &plan(&a.cp, &g, false),
        &sessions,
        std::slice::from_ref(&addr),
    )
    .await
    .unwrap();
    assert_restored(&client, &a);
    assert_eq!(
        *dialled.lock().unwrap(),
        vec![addr.clone(), addr],
        "dialled once, and once more after the failure"
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
            oversized: None,
            error: None,
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
#[tokio::test]
async fn a_silent_server_times_out() {
    let g = genesis();
    let a = chain("silent_a", MEMBER);
    let server = peer(&a, Behaviour::Honest).sync;
    let (sessions, _) = fake_sessions(
        |addr| Ok(addr.rsplit('/').next().unwrap_or_default().to_string()),
        move |session, wire| match session {
            "silent" => Fake::Silent,
            _ => Fake::Answer(
                server
                    .serve_session(wire, "client")
                    .ok_or_else(|| "refused".into()),
            ),
        },
    );
    let client = temp_db("silent_client");
    let patient = RestorePlan {
        patience: Patience {
            request_timeout: Duration::from_millis(300),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    let start = Instant::now();
    let addrs = [
        "/dns4/x/tcp/silent".to_string(),
        "/dns4/x/tcp/honest".to_string(),
    ];
    restore_over_sessions(&client, &patient, &sessions, &addrs)
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
            slow_turn: Duration::from_millis(100),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    run_with(&client, &hurried, 2, |i, msg| {
        if i == 0 && msg.starts_with(CHUNK_REQ) {
            stalls += 1;
            std::thread::sleep(Duration::from_millis(150));
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

// ===================== Review 3 witnesses =====================

fn chunk_fits(entries: &[WireEntry], proof: usize) -> bool {
    let mut budget = ChunkBudget::new(proof);
    entries.iter().all(|e| budget.take(&e.key, e.len))
}

/// The protocol's chunk limits (`ChunkBudget`), at and just over each.
#[test]
fn a_chunk_fits_the_protocol_only_within_every_limit() {
    let leaf = |len: u64| WireEntry {
        key: obj(1),
        value: String::new(),
        len,
    };
    assert!(chunk_fits(&[leaf(MAX_LEAF_BYTES)], 0));
    assert!(!chunk_fits(&[leaf(MAX_LEAF_BYTES + 1)], 0), "a leaf");
    let at_total = [leaf(MAX_LEAF_BYTES), leaf(MAX_LEAF_BYTES)];
    assert!(chunk_fits(&at_total, 0), "the parted total");
    let over_total = [
        leaf(MAX_LEAF_BYTES),
        leaf(MAX_LEAF_BYTES),
        leaf(INLINE_VALUE_BYTES as u64 + 1),
    ];
    assert!(!chunk_fits(&over_total, 0), "over the parted total");
    // Inline: the key, 32 bytes of framing and the hex per leaf, and the
    // proof twice. Fill to the limit with the largest inline leaves.
    let cost = |len: u64| obj(1).len() + 32 + 2 * len as usize;
    let big = INLINE_VALUE_BYTES as u64;
    let (mut entries, mut used) = (Vec::new(), 0);
    while used + cost(big) <= MAX_CHUNK_BYTES {
        entries.push(leaf(big));
        used += cost(big);
    }
    let last = ((MAX_CHUNK_BYTES - used - cost(0)) / 2) as u64;
    entries.push(leaf(last));
    assert!(chunk_fits(&entries, 0), "at the inline limit");
    entries.last_mut().unwrap().len = last + 1;
    assert!(!chunk_fits(&entries, 0), "inline bytes");
    entries.last_mut().unwrap().len = last;
    assert!(!chunk_fits(&entries, 1), "the proof counts");
    entries.last_mut().unwrap().len = last - 1;
    assert!(chunk_fits(&entries, 1));
    // A leaf over the inline size counts toward the parts, not inline.
    let parts = [leaf(big + 1), leaf(big + 1)];
    let mut budget = ChunkBudget::new(0);
    assert!(parts.iter().all(|e| budget.take(&e.key, e.len)));
    assert_eq!(budget.inline, 2 * cost(0));
    assert_eq!(budget.parted, 2 * (big + 1));
}

/// The client checks a chunk's entries before it fetches any part: a value
/// neither whole nor in parts is a lie, and only the values in parts count
/// toward a chunk's total.
#[tokio::test]
async fn a_chunks_entries_are_checked_before_any_part_is_fetched() {
    let whole = |key: u64, value: &[u8], len: u64| WireEntry {
        key: obj(key),
        value: hex::encode(value),
        len,
    };
    let parted = |key: u64, len: u64| WireEntry {
        key: obj(key),
        value: String::new(),
        len,
    };
    let cases = [
        // A small value sent empty.
        (vec![parted(1, 10)], false),
        // A whole value over the inline size.
        (
            vec![whole(
                1,
                &vec![7; INLINE_VALUE_BYTES + 1],
                INLINE_VALUE_BYTES as u64 + 1,
            )],
            false,
        ),
        // A value that is not its stated length.
        (vec![whole(1, b"abc", 4)], false),
        // The parted total exactly, inline bytes besides: parts are asked
        // for (and the ask fails here).
        (
            vec![
                whole(1, &[7; 1000], 1000),
                parted(2, MAX_LEAF_BYTES),
                parted(3, MAX_LEAF_BYTES),
            ],
            true,
        ),
        (
            vec![
                parted(2, MAX_LEAF_BYTES),
                parted(3, MAX_LEAF_BYTES),
                parted(4, INLINE_VALUE_BYTES as u64 + 1),
            ],
            false,
        ),
    ];
    for (entries, fetched) in cases {
        let reply = chunk_reply(&ChunkResponse {
            entries,
            ..Default::default()
        });
        let value_asks = std::cell::Cell::new(0usize);
        let mut ask = |_: usize, msg: String| {
            let r = if msg.starts_with(VALUE_REQ) {
                value_asks.set(value_asks.get() + 1);
                Err("down".to_string())
            } else {
                reply.clone()
            };
            async move { r }
        };
        let got = ask_chunk(&mut ask, 0, H, None, &fast()).await;
        if fetched {
            assert!(matches!(got, Reply::Unanswered(_)));
            assert_eq!(value_asks.get(), 1);
        } else {
            assert!(matches!(got, Reply::Lied(_)));
            assert_eq!(value_asks.get(), 0);
        }
    }
}

/// A turn is too slow only past `slow_turn` and under the minimum rate.
#[test]
fn a_turn_is_judged_by_its_rate_past_the_slow_turn() {
    let slow_turn = Duration::from_secs(2);
    let secs = Duration::from_secs;
    assert!(!too_slow(secs(1), 1.0, slow_turn), "a short turn");
    assert!(too_slow(secs(3), 1.0, slow_turn), "a leaf in 3 s");
    let enough = 3.0 * MIN_TURN_UNITS_PER_SEC;
    assert!(!too_slow(secs(3), enough, slow_turn), "enough for its time");
    assert!(too_slow(secs(3), enough - 1.0, slow_turn), "just under");
}

/// A struck peer sits out twice as many turns at each failure in a row, up
/// to `MAX_SIT_OUT`; a delivery forgives it; when every live peer sits out,
/// the closest is asked and its sit-out ends.
#[test]
fn a_struck_peer_sits_out_twice_as_long_up_to_a_cap() {
    let mut set = PeerSet::new(3, Duration::from_secs(2));
    let mut expected = 1;
    for _ in 0..12 {
        set.strike(0);
        assert_eq!(set.sit_out[0], expected);
        expected = (expected * 2).min(MAX_SIT_OUT);
    }
    assert_eq!(set.sit_out[0], MAX_SIT_OUT);
    set.delivered(0);
    assert_eq!((set.penalty[0], set.sit_out[0]), (0, 0));
    set.exclude(2);
    let turns: Vec<_> = (0..4).map(|_| set.pick().unwrap()).collect();
    assert_eq!(turns, [0, 1, 0, 1], "round robin, the excluded skipped");
    for _ in 0..3 {
        set.strike(0);
    }
    for _ in 0..2 {
        set.strike(1);
    }
    assert_eq!(set.pick(), Some(1), "the closest to its turn");
    assert_eq!(set.sit_out[1], 0, "its sit-out ended");
    set.exclude(0);
    set.exclude(1);
    assert_eq!((set.pick(), set.live()), (None, 0));
}

/// The value cache keeps the most recently used values, as many and as
/// large as its limits allow, and always the last one put.
#[test]
fn the_value_cache_keeps_the_most_recently_used() {
    let mut cache = ValueCache::default();
    let value = |b: u8| Arc::new(vec![b; 16]);
    for v in 0..VALUE_CACHE_ENTRIES as u64 {
        cache.put(v, "k", value(v as u8));
    }
    assert!(cache.get(0, "k").is_some(), "the oldest, now the newest");
    cache.put(99, "k", value(9));
    assert!(cache.get(1, "k").is_none(), "the least recently used went");
    for v in [0, 2, 3, 99] {
        assert!(cache.get(v, "k").is_some(), "{v}");
    }
    assert!(cache.get(0, "other").is_none(), "per key");
    cache.put(7, "big", Arc::new(vec![0; VALUE_CACHE_BYTES + 1]));
    assert_eq!(cache.entries.len(), 1, "the byte limit");
    assert!(cache.get(7, "big").is_some(), "the last one stays");
    cache.put(8, "small", value(1));
    assert_eq!(cache.entries.len(), 1);
    assert!(cache.get(8, "small").is_some());
}

/// B299 witness, and snapshot serving off unless asked for
/// (`AINCORE_SERVE_SNAPSHOTS=1`): a validator's disk serves consensus
/// first. B299: anchors too, for a retained version, a block a batch could
/// not hold never parsed for one (they were always served, any height, so
/// anyone made every node read and parse whole blocks).
#[test]
fn a_node_serves_snapshots_only_when_asked_to() {
    let a = chain("optin_a", MEMBER);
    let chunk = || ChunkRequest {
        version: H,
        after: None,
        max: 10,
    };
    let value = || ValueRequest {
        version: H,
        key: obj(3),
        offset: 0,
    };
    let default = ChainSync::new(Arc::clone(&a.db));
    let off = if std::env::var("AINCORE_SERVE_SNAPSHOTS").is_err() {
        default
    } else {
        default.with_snapshot_serving(false)
    };
    assert_eq!(
        off.handle_state_chunk(chunk()).error.as_deref(),
        Some(NOT_SERVED)
    );
    assert_eq!(
        off.handle_state_value(value()).error.as_deref(),
        Some(NOT_SERVED)
    );
    // B299: and anchors too (every node read, parsed and re-serialized any
    // height's block for anyone).
    assert!(off
        .handle_state_anchor(AnchorRequest { height: H })
        .block
        .is_none());
    let on = off.with_snapshot_serving(true);
    assert!(on.handle_state_chunk(chunk()).error.is_none());
    assert!(on.handle_state_value(value()).error.is_none());
    let anchor = on.handle_state_anchor(AnchorRequest { height: H });
    assert!(anchor.block.is_some() && anchor.quorum_certificate.is_some());
    // B299: a block a batch could not hold is not parsed for an anchor.
    let small = on.with_batch_bytes(64);
    assert!(small
        .handle_state_anchor(AnchorRequest { height: H })
        .block
        .is_none());
    // B324: and, known too large from then on, it is not read again.
    assert!(
        small.oversized_known.lock().unwrap().contains_key(&H),
        "the block too large for a batch was not remembered"
    );
    // B299: and only for a version it retains (any height was answered).
    let fresh = ChainSync::new(Arc::clone(&a.db)).with_snapshot_serving(true);
    assert!(
        fresh
            .handle_state_anchor(AnchorRequest { height: H })
            .block
            .is_some(),
        "vacuous: the anchor is not served while retained"
    );
    state_commit::prune(&a.db, TIP, &Default::default(), usize::MAX).unwrap();
    assert!(
        fresh
            .handle_state_anchor(AnchorRequest { height: H })
            .block
            .is_none(),
        "an anchor answered for a version not retained"
    );
}

/// The node's session layer routes by `serve_session`: chain sync's
/// requests are answered and budgeted by the session's key; anything else
/// is not answered.
#[test]
fn serve_session_budgets_by_the_sessions_key() {
    let a = chain("route_a", MEMBER);
    let sync = peer(&a, Behaviour::Honest).sync;
    let key = "12D3KooWrequester";
    let request = ChunkRequest {
        version: H,
        after: None,
        max: 10,
    };
    let msg = format!("{CHUNK_REQ}{}", serde_json::to_string(&request).unwrap());
    let reply = sync.serve_session(&msg, key).unwrap();
    assert!(reply.starts_with(CHUNK_RESP), "{reply}");
    assert!(
        !sync.state_budget.balance(Some(key)).is_nan(),
        "charged to the session (its bucket exists; its level refills, B46)"
    );
    assert!(
        sync.state_budget.balance(Some("12D3KooWother")).is_nan(),
        "and no other session is tracked"
    );
    assert_eq!(sync.serve_session("TX:{}", key), None);
    assert!(sync.serve_session("GET_HEIGHT", key).is_some());
}

/// SN-6 on what the restored state records: a key in any retained epoch's
/// committee, or in the active set, is a validator. The block's signer may
/// be in the checkpoint epoch's committee or in the active set (on V3; B472:
/// on V4 in the committee only, `a_v4_anchor_signer_is_a_member_of_its_committee`).
#[test]
fn validators_are_what_the_restored_state_records() {
    let a = chain_with(
        "recorded_a",
        Spec {
            epoch_one: Some([8; 32]),
            validators: vec!["ab".repeat(32)],
            ..Spec::default()
        },
    );
    let client = temp_db("recorded_client");
    {
        let _seed = client.seeding();
        for (key, value) in &a.state {
            client.put(key, &String::from_utf8_lossy(value)).unwrap();
        }
    }
    let genesis_member = committee()[0].address.clone();
    let epoch_one = committee_of([8; 32], 2)[0].address.clone();
    for key in [&genesis_member, &epoch_one, &"ab".repeat(32), &proposer().1] {
        assert!(recorded_validator(&client, key), "{key}");
    }
    assert!(!recorded_validator(&client, &outsider().1));
    let signing = committee_of([8; 32], 2);
    assert!(
        signed_by_a_validator(&client, &signing, &epoch_one),
        "committee"
    );
    assert!(
        signed_by_a_validator(&client, &signing, &proposer().1),
        "active"
    );
    assert!(!signed_by_a_validator(&client, &signing, &genesis_member));
}

/// A cursor for `after`: the key hash of `key`, hex.
fn cursor_before(key: &str) -> String {
    hex::encode(state_commit::key_hash(key).0)
}

fn leaf_order(chain: &Chain) -> Vec<String> {
    state_commit::chunk(&chain.db, H, None, state_commit::MAX_CHUNK)
        .unwrap()
        .unwrap()
        .0
        .into_iter()
        .map(|(k, _)| k)
        .collect()
}

/// Review 4: the server keeps room for the proof. Eight 262,090-byte leaves
/// with 68-byte keys fill 4,194,240 of the 4,194,304 inline bytes: they fit
/// only without the proof, so the server sends seven, and the client, which
/// counts the proof, accepts them.
#[test]
fn a_served_chunk_near_the_inline_limit_passes_the_client() {
    let big = 262_090usize;
    let extra = (2_000..2_300).map(|i| (obj(i), vec![b'n'; big])).collect();
    let a = chain_with(
        "nearlimit_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let order = leaf_order(&a);
    let is_big = |k: &String| {
        k.strip_prefix("obj:")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .is_some_and(|i| (2_000..2_300).contains(&i))
    };
    let start = (0..order.len().saturating_sub(8))
        .find(|&j| order[j + 1..=j + 8].iter().all(is_big))
        .expect("a run of eight big leaves");
    let server = peer(&a, Behaviour::Honest).sync;
    let resp = server.handle_state_chunk(ChunkRequest {
        version: H,
        after: Some(cursor_before(&order[start])),
        max: MAX_CHUNK_ENTRIES,
    });
    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert!(chunk_fits(&resp.entries, resp.proof.len() / 2));
    assert_eq!(resp.entries.len(), 7, "the byte limit bound the chunk");
}

/// Review 4: a first leaf past the protocol's limits is refused, never
/// reported as the end of the stream. A 4.2 MB key is past the inline limit
/// on its own.
#[test]
fn a_first_leaf_past_the_limits_is_not_the_end() {
    let huge = format!("obj:{}", "k".repeat(4_200_000));
    let a = chain_with(
        "firstpast_a",
        Spec {
            extra: vec![(huge.clone(), b"v".to_vec())],
            ..Spec::default()
        },
    );
    let order = leaf_order(&a);
    let at = order.iter().position(|k| *k == huge).unwrap();
    let server = peer(&a, Behaviour::Honest).sync;
    let resp = server.handle_state_chunk(ChunkRequest {
        version: H,
        after: (at > 0).then(|| cursor_before(&order[at - 1])),
        max: MAX_CHUNK_ENTRIES,
    });
    assert!(!resp.done, "not the end");
    assert_eq!(
        resp.error.as_deref(),
        Some("a leaf over the protocol's limit")
    );
}

/// Review 3: a block re-signed with any account's key is not stored: the
/// signer must be a validator. The pair a validator signed is the one kept.
#[tokio::test]
async fn a_block_signed_by_a_non_validator_is_not_stored() {
    let g = genesis();
    let a = chain("resign_a", MEMBER);
    let client = temp_db("resign_client");
    let mut byz = peer(&a, Behaviour::Honest);
    let mut honest = peer(&a, Behaviour::Honest);
    let (key, address) = outsider();
    let mut block = stored_block(&a);
    block.sign_proposer(&key, &address);
    let byz_anchor = format!(
        "{ANCHOR_RESP}{}",
        serde_json::to_string(&AnchorResponse {
            block: Some(block.clone()),
            quorum_certificate: Some(stored_qc(&a)),
            oversized: None,
            error: None,
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
    assert!(
        ChainSync::verify_proposer_signature_in(&client, &block).is_ok(),
        "positive control: the outsider's signature itself verifies"
    );
    assert_restored(&client, &a);
}

/// Peers that hold the same pair give one candidate, not one each.
#[tokio::test]
async fn the_same_anchor_from_many_peers_is_one_candidate() {
    let a = chain("dedup_a", MEMBER);
    let mut peers = [
        peer(&a, Behaviour::Honest),
        peer(&a, Behaviour::Honest),
        peer(&a, Behaviour::Honest),
    ];
    let mut ask = |i: usize, msg: String| {
        let r = serve(&mut peers[i], &msg);
        async move { r }
    };
    let pairs = fetch_anchor(
        &a.cp,
        3,
        &mut ask,
        &fast(),
        &mut AnchorBody::default(),
        Instant::now(),
    )
    .await
    .unwrap();
    assert_eq!(pairs.len(), 1);
}

/// Review 3 HIGH 1: a large leaf restores on the per-client path from one
/// server, with production patience, even when every part misses the cache
/// (other clients read as many other values in between): a miss costs at
/// most one second's worth, and a busy part is waited for.
#[tokio::test]
async fn a_large_leaf_restores_on_the_per_client_path_when_every_part_misses() {
    let g = genesis();
    let a = chain_with(
        "perip_big_a",
        Spec {
            extra: vec![(obj(500), vec![b'z'; 8 << 20])],
            ..Spec::default()
        },
    );
    let client = temp_db("perip_big_client");
    let server = peer(&a, Behaviour::Honest).sync;
    let key = "12D3KooWrestorer";
    let patient = RestorePlan {
        patience: Patience {
            deadline: Duration::from_secs(120),
            ..Patience::default()
        },
        ..plan(&a.cp, &g, false)
    };
    let (mut thrashed, mut parts, mut lowest) = (None, 0usize, f64::MAX);
    run_with(&client, &patient, 1, |_, msg| {
        if let Some(json) = msg.strip_prefix(VALUE_REQ) {
            let offset = serde_json::from_str::<ValueRequest>(json).unwrap().offset;
            if thrashed != Some(offset) {
                thrashed = Some(offset);
                for i in 0..VALUE_CACHE_ENTRIES as u8 {
                    let read = server.serve_state_value(
                        ValueRequest {
                            version: H,
                            key: obj(u64::from(i)),
                            offset: 0,
                        },
                        Some(format!("12D3KooWother{i}").as_str()),
                    );
                    assert!(read.error.is_none(), "{:?}", read.error);
                }
            }
        }
        let reply = server.serve_session(msg, key).ok_or("no answer")?;
        if let Some(json) = reply.strip_prefix(VALUE_RESP) {
            let part: ValueResponse = serde_json::from_str(json).unwrap();
            parts += usize::from(part.error.is_none());
            lowest = lowest.min(server.state_budget.balance(Some(key)));
        }
        Ok(reply)
    })
    .await
    .unwrap();
    assert_eq!(parts, 8, "each part once");
    assert!(
        lowest < 0.0,
        "positive control: misses were charged: {lowest}"
    );
    assert_restored(&client, &a);
}

/// Review 3 HIGH 2: a peer that sends valid chunks too slowly for what they
/// hold (a leaf at a time) sits out turns like a failing one.
#[tokio::test]
async fn a_peer_that_trickles_valid_chunks_loses_its_turns() {
    let g = genesis();
    let a = chain("slowvalid_a", MEMBER);
    let client = temp_db("slowvalid_client");
    let hostile = peer(&a, Behaviour::Honest).sync;
    let honest = peer(&a, Behaviour::Honest).sync;
    let judged = RestorePlan {
        patience: Patience {
            slow_turn: Duration::from_millis(300),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    let (mut hostile_turns, mut honest_turns) = (0usize, 0usize);
    run_with(&client, &judged, 2, |i, msg| {
        let Some(json) = msg.strip_prefix(CHUNK_REQ) else {
            return honest.handle_message(msg).ok_or("no answer".into());
        };
        let mut request: ChunkRequest = serde_json::from_str(json).unwrap();
        if i == 0 {
            hostile_turns += 1;
            std::thread::sleep(Duration::from_millis(400));
            request.max = 1;
            return chunk_reply(&hostile.handle_state_chunk(request));
        }
        honest_turns += 1;
        request.max = SMALL_CHUNK;
        chunk_reply(&honest.handle_state_chunk(request))
    })
    .await
    .unwrap();
    assert!(
        hostile_turns <= 3,
        "passed over more each time: {hostile_turns} turns, honest {honest_turns}"
    );
    assert_restored(&client, &a);
}

/// A slow turn that delivers enough for its time keeps the peer's turns:
/// only the rate counts, not the time alone.
#[tokio::test]
async fn a_slow_turn_that_delivers_enough_keeps_its_turns() {
    let g = genesis();
    let extra = (100..160)
        .map(|i| (obj(i), vec![b'd'; INLINE_VALUE_BYTES]))
        .collect();
    let a = chain_with(
        "slowbig_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let client = temp_db("slowbig_client");
    let server = peer(&a, Behaviour::Honest).sync;
    let judged = RestorePlan {
        patience: Patience {
            slow_turn: Duration::from_millis(500),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    let (mut slow_turns, mut fast_turns) = (0usize, 0usize);
    run_with(&client, &judged, 2, |i, msg| {
        let Some(json) = msg.strip_prefix(CHUNK_REQ) else {
            return server.handle_message(msg).ok_or("no answer".into());
        };
        // Whole chunks, bound by bytes: about seven 256 KiB leaves each,
        // over 450 units, so over 250 a second unless a turn takes 1.8 s.
        let reply = chunk_reply(&server.handle_state_chunk(serde_json::from_str(json).unwrap()));
        if i == 0 {
            slow_turns += 1;
            std::thread::sleep(Duration::from_millis(600));
        } else {
            fast_turns += 1;
        }
        reply
    })
    .await
    .unwrap();
    assert!(
        fast_turns <= slow_turns + 1,
        "slow {slow_turns}, fast {fast_turns}"
    );
    assert!(slow_turns >= 4, "positive control: {slow_turns}");
    assert_restored(&client, &a);
}

/// A busy answer given at once is no fault: the peer keeps its turns. Only a
/// slow "busy" costs turns (`a_peer_that_stalls_before_saying_busy..`).
#[tokio::test]
async fn a_peer_that_says_busy_at_once_keeps_its_turns() {
    let g = genesis();
    let extra = (100..400).map(|i| (obj(i), b"x".to_vec())).collect();
    let a = chain_with(
        "fairbusy_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let client = temp_db("fairbusy_client");
    let mut first = peer(&a, Behaviour::Honest);
    let mut second = peer(&a, Behaviour::Honest);
    let (mut first_turns, mut second_turns) = (0usize, 0usize);
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if i == 1 || !msg.starts_with(CHUNK_REQ) {
            second_turns += usize::from(msg.starts_with(CHUNK_REQ));
            return serve(&mut second, msg);
        }
        first_turns += 1;
        if !first_turns.is_multiple_of(2) {
            return busy();
        }
        serve(&mut first, msg)
    })
    .await
    .unwrap();
    assert!(
        second_turns <= first_turns + 1,
        "first {first_turns}, second {second_turns}"
    );
    assert!(first_turns > 10, "positive control: {first_turns}");
    assert_restored(&client, &a);
}

fn polling() -> Patience {
    Patience {
        backoff_start: Duration::from_millis(50),
        backoff_max: Duration::from_secs(5),
        ..fast()
    }
}

/// A value part answered "busy" is asked for again from where the value
/// stands: no part is fetched twice, the wait does not grow from one part to
/// the next, and the request timeout runs from the last part, not the first.
#[tokio::test]
async fn value_parts_wait_out_busy_answers_without_starting_over() {
    let g = genesis();
    let a = chain_with(
        "partbusy_a",
        Spec {
            extra: vec![(obj(500), vec![b'w'; 8 << 20])],
            ..Spec::default()
        },
    );
    let client = temp_db("partbusy_client");
    let mut server = peer(&a, Behaviour::Honest);
    // Eight parts, each after a 600 ms wait (4.8 s): longer than the 3 s
    // timeout in all, which each single part has room to meet on a loaded
    // Pi (B17: at 1 s, a 1 MiB part outlived it there once).
    let polled = RestorePlan {
        patience: Patience {
            backoff_start: Duration::from_millis(300),
            request_timeout: Duration::from_secs(3),
            ..polling()
        },
        ..plan(&a.cp, &g, false)
    };
    let (mut asked, mut served, mut waits) = (Vec::new(), Vec::new(), Vec::new());
    let mut said_busy = Instant::now();
    run_with(&client, &polled, 1, |_, msg| {
        if let Some(json) = msg.strip_prefix(VALUE_REQ) {
            let offset = serde_json::from_str::<ValueRequest>(json).unwrap().offset;
            if !asked.contains(&offset) {
                asked.push(offset);
                said_busy = Instant::now();
                let busy = ValueResponse {
                    error: Some("busy".into()),
                    ..Default::default()
                };
                return Ok(format!(
                    "{VALUE_RESP}{}",
                    serde_json::to_string(&busy).unwrap()
                ));
            }
            served.push(offset);
            waits.push(said_busy.elapsed());
        }
        serve(&mut server, msg)
    })
    .await
    .unwrap();
    let parts: Vec<u64> = (0..8).map(|i| i * VALUE_PART_BYTES as u64).collect();
    assert_eq!(served, parts, "each part once, in order");
    // One step each (600 ms). Growing, the third would wait 2.4 s.
    assert!(
        waits.iter().all(|w| *w < Duration::from_millis(1800)),
        "{waits:?}"
    );
    assert_restored(&client, &a);
}

/// The restore's wait for a busy peer starts over once it delivers: the
/// waits do not grow across a restore.
#[tokio::test]
async fn the_busy_wait_starts_over_after_a_delivery() {
    let g = genesis();
    let a = chain("busyreset_a", MEMBER);
    let client = temp_db("busyreset_client");
    let mut server = peer(&a, Behaviour::Honest);
    let polled = RestorePlan {
        patience: polling(),
        ..plan(&a.cp, &g, false)
    };
    let (mut chunk_asks, mut waits) = (0usize, Vec::new());
    let mut said_busy = Instant::now();
    run_with(&client, &polled, 1, |_, msg| {
        if msg.starts_with(CHUNK_REQ) {
            chunk_asks += 1;
            if !chunk_asks.is_multiple_of(2) {
                said_busy = Instant::now();
                return busy();
            }
            waits.push(said_busy.elapsed());
        }
        serve(&mut server, msg)
    })
    .await
    .unwrap();
    // Busy before each chunk answer: one step each (100 ms). Growing, the
    // fifth would wait 1.6 s.
    assert!(waits.len() >= 7, "positive control: {waits:?}");
    assert!(
        waits.iter().all(|w| *w < Duration::from_millis(600)),
        "{waits:?}"
    );
    assert_restored(&client, &a);
}

/// B145 witness: outsiders draw on the shared units only, so however hard
/// they pull (charged after the fact, into debt), a member's value part (all
/// its units at once) is still admitted: one shared bucket was the only one,
/// and outsiders drained it.
#[test]
fn outsiders_cannot_take_the_members_units() {
    let budget = StateBudget::default();
    for group in 0..8 {
        if let Some(a) = budget.admit(Some(&format!("10.{group}")), 2_000, false) {
            a.charge(2_000 * UNIT_BYTES);
        }
    }
    assert!(
        budget.balance(None) < PART_UNITS as f64,
        "vacuous: the shared units were not drained"
    );
    assert!(
        budget.admit_all(Some("member"), PART_UNITS, true).is_some(),
        "a member's part was refused"
    );
    assert!(
        budget.admit_all(Some("10.99"), PART_UNITS, false).is_none(),
        "an outsider drew on the members' units"
    );
}

/// B159 witness: one kept client pulling (and charged) all it may cannot
/// hold the kept units: another member's value part is still admitted while
/// outsiders hold the shared units in debt.
#[test]
fn one_kept_client_cannot_take_the_kept_units() {
    let budget = StateBudget::default();
    for group in 0..8 {
        if let Some(a) = budget.admit(Some(&format!("10.{group}")), 2_000, false) {
            a.charge(2_000 * UNIT_BYTES);
        }
    }
    for _ in 0..8 {
        if let Some(a) = budget.admit(Some("12D3KooWbyzantine"), 2_000, true) {
            a.charge(2_000 * UNIT_BYTES);
        }
    }
    assert!(
        budget
            .admit_all(Some("12D3KooWhonest"), PART_UNITS, true)
            .is_some(),
        "one member took the members' units"
    );
}

/// B131 witness: the kept slot is a member's or a reserved peer's alone:
/// with every other slot held, an outsider is refused and a member served.
#[test]
fn a_snapshot_slot_is_kept_for_members() {
    let budget = StateBudget::default();
    let held: Vec<_> = (0..STATE_SERVE_IN_FLIGHT - STATE_SERVE_IN_FLIGHT_KEPT)
        .map(|i| {
            budget
                .admit(Some(&format!("10.{i}")), 1, false)
                .expect("an open slot")
        })
        .collect();
    assert!(
        budget.admit(Some("10.99"), 1, false).is_none(),
        "an outsider took the kept slot"
    );
    assert!(
        budget.admit(Some("member"), 1, true).is_some(),
        "a member was kept out"
    );
    drop(held);
}

/// B395 witness: a restore that replaced a chain resumes only under the key
/// it began under. Its first attempt, under a new key, cleared the chain
/// that recorded this node's validator key; a resume under that key then
/// found nothing to refuse it by, and restored it. Under the first key the
/// resume completes.
#[tokio::test]
async fn a_replace_restore_resumes_only_under_its_first_key() {
    let g = genesis();
    let a = chain("resume_key_a", MEMBER);
    let client = temp_db("resume_key_client");
    let validator = "cc".repeat(32);
    let fresh = "ff".repeat(32);
    {
        let _seed = client.seeding();
        client.put("genesis_initialized", "true").unwrap();
        client.put("latest_height", "3").unwrap();
        client
            .put(
                "sys:validators",
                &serde_json::to_string(&vec![(validator.clone(), 100u64)]).unwrap(),
            )
            .unwrap();
        client.put(&obj(999), "old").unwrap();
    }
    let as_validator = RestorePlan {
        local_signer: Some(&validator),
        ..plan(&a.cp, &g, true)
    };
    let as_fresh = RestorePlan {
        local_signer: Some(&fresh),
        ..plan(&a.cp, &g, true)
    };

    // Positive control: the old chain records the validator key.
    let mut peers = [peer(&a, Behaviour::Honest)];
    let err = run(&client, &as_validator, &mut peers).await.unwrap_err();
    assert!(err.contains("SN-6"), "{err}");
    assert_eq!(client.get(RESTORE_MARKER).unwrap(), None);

    // A first attempt under a new key clears the old chain, then fails.
    let mut dying = [peer(&a, Behaviour::DiesAfterFirst)];
    let err = run(&client, &as_fresh, &mut dying).await.unwrap_err();
    assert!(err.contains("no peer serves"), "{err}");
    assert!(client.get(RESTORE_MARKER).unwrap().is_some());
    assert_eq!(
        client.get(&obj(999)).unwrap(),
        None,
        "the old chain cleared"
    );
    assert!(
        !recorded_validator(&client, &validator),
        "nothing left records the validator key"
    );

    // Resumed under the validator key: refused, before anything is asked.
    let mut honest = peer(&a, Behaviour::Honest);
    let mut asks = 0usize;
    let err = run_with(&client, &as_validator, 1, |_, msg| {
        asks += 1;
        serve(&mut honest, msg)
    })
    .await
    .unwrap_err();
    assert!(
        err.contains("began under key") && err.contains("SN-6"),
        "{err}"
    );
    assert_eq!(asks, 0, "nothing asked");
    assert!(
        client.get(RESTORE_MARKER).unwrap().is_some(),
        "still marked"
    );

    // Resumed under the first key: it completes.
    let mut peers = [peer(&a, Behaviour::Honest)];
    run(&client, &as_fresh, &mut peers).await.unwrap();
    assert_restored(&client, &a);
    assert_eq!(client.get(RESTORED_BY).unwrap(), Some(fresh.clone()));
}

/// B395 witness: a replace restore is a guard loss for G1 RC-3. The guard
/// origin and the resume point go, so the next boot abstains afresh; the
/// V4 producer guards (B282) stay, like the attestation guards. The origin
/// stayed while the producer guards went.
#[tokio::test]
async fn a_restore_drops_the_guard_origin_and_keeps_the_producer_guards() {
    const H64: &str = "dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42";
    let proposed = format!("consensus:vproposed:v1:{H64}:{H64}:3:00000000000000153030");
    let proposed_high = format!("consensus:vproposed_high:v1:{H64}:{H64}:3");
    let attest = format!(
        "consensus:vattest:v1:{}:{}:3:author:{:020}",
        "ab".repeat(32),
        "cd".repeat(48),
        7
    );
    let resume = consensus::v4::epoch::GUARD_RESUME_KEY;
    for key in [&proposed, &proposed_high, &attest] {
        assert_eq!(
            classify(key.as_bytes()),
            Some(KeyClass::Local),
            "vacuous: {key}"
        );
    }
    let g = genesis();
    let a = chain("guards_a", MEMBER);
    let client = temp_db("guards_client");
    {
        let _seed = client.seeding();
        client.put("genesis_initialized", "true").unwrap();
        client.put("latest_height", "3").unwrap();
        client
            .put("consensus:guard_origin", "{\"cg\":\"old\"}")
            .unwrap();
        client.put(resume, "5").unwrap();
        client.put(&proposed, "{}").unwrap();
        client.put(&proposed_high, "153030").unwrap();
        client.put(&attest, "attested").unwrap();
    }
    let mut peers = [peer(&a, Behaviour::Honest)];
    run(&client, &plan(&a.cp, &g, true), &mut peers)
        .await
        .unwrap();
    assert_restored(&client, &a);
    assert_eq!(
        client.get("consensus:guard_origin").unwrap(),
        None,
        "continuity is lost"
    );
    assert_eq!(client.get(resume).unwrap(), None, "the old resume point");
    for key in [&proposed, &proposed_high, &attest] {
        assert!(client.get(key).unwrap().is_some(), "{key} kept");
    }
    // RC-3 starts abstaining afresh at the next boot (B405: the level height
    // is observed again in that run), not from the old point.
    consensus::v4::epoch::begin_abstaining(&client).unwrap();
    assert_eq!(consensus::v4::epoch::level_height(&client).unwrap(), None);
}

/// B395 witness: on V4 a key in the executor's record of a later epoch's
/// committee (`sys:validator_set:epoch:{E}`, state) is a validator. E's own
/// record is no state, so a restored state holds none, and a key in no
/// active set was not seen.
#[test]
fn a_v4_validator_is_what_the_restored_state_records() {
    let client = temp_db("v4_recorded_client");
    let later = committee_of([9; 32], 3);
    {
        let _seed = client.seeding();
        client.put(consensus::v4::VERTEX_FORMAT_KEY, "4").unwrap();
        client.put("sys:config:epoch_block_interval", "5").unwrap();
        client.put("consensus:epoch", "2").unwrap();
        client
            .put(
                "genesis:validator_set:v1",
                &serde_json::to_string(&committee()).unwrap(),
            )
            .unwrap();
        client
            .put(
                "sys:validator_set:epoch:2",
                &serde_json::to_string(&later).unwrap(),
            )
            .unwrap();
        client
            .put(
                "sys:validators",
                &serde_json::to_string(&vec![(proposer().1, 100u64)]).unwrap(),
            )
            .unwrap();
    }
    assert!(consensus::v4::is_v4_chain(&client));
    assert!(
        consensus::v4::epoch::committee_of(&client, 2).is_none(),
        "vacuous: epoch 2's own record is held"
    );
    assert!(recorded_validator(&client, &later[0].address), "epoch 2");
    assert!(
        recorded_validator(&client, &committee()[0].address),
        "genesis"
    );
    assert!(recorded_validator(&client, &proposer().1), "the active set");
    assert!(!recorded_validator(&client, &outsider().1));
}

/// B396 witness: a V4 checkpoint past epoch 0 that is no epoch boundary is
/// refused from this node's own genesis, before any request, marker or
/// clear. It was refused after the whole download, with a replaced chain
/// already cleared.
#[tokio::test]
async fn an_inner_v4_checkpoint_is_refused_before_anything_is_asked() {
    let plain = genesis();
    let mut v4 = genesis();
    v4.insert(
        consensus::v4::VERTEX_FORMAT_KEY.to_string(),
        "4".to_string(),
    );
    let client = temp_db("inner_v4_client");
    {
        let _seed = client.seeding();
        client.put("genesis_initialized", "true").unwrap();
        client.put("latest_height", "3").unwrap();
        client.put(&obj(999), "old").unwrap();
    }
    let at = |height| Checkpoint {
        height,
        block_hash: "11".repeat(32),
        state_root: "22".repeat(32),
    };
    // Height 7 is in epoch 1 at an interval of 5.
    let inner = at(7);
    let mut asks = 0usize;
    let err = run_with(&client, &plan(&inner, &v4, true), 1, |_, _| {
        asks += 1;
        Err("down".into())
    })
    .await
    .unwrap_err();
    assert!(err.contains("epoch boundary"), "{err}");
    assert_eq!(asks, 0, "nothing asked");
    assert_eq!(client.get(RESTORE_MARKER).unwrap(), None, "no marker");
    assert_eq!(
        client.get(&obj(999)).unwrap().as_deref(),
        Some("old"),
        "nothing cleared"
    );
    // Positive controls: a boundary, a height in epoch 0, and the inner
    // height on a chain whose genesis is not V4 go on to ask.
    for (cp, genesis) in [(at(10), &v4), (at(3), &v4), (at(7), &plain)] {
        let mut asks = 0usize;
        let err = run_with(&client, &plan(&cp, genesis, true), 1, |_, _| {
            asks += 1;
            Err("down".into())
        })
        .await
        .unwrap_err();
        assert!(err.contains("no peer holds"), "{}: {err}", cp.height);
        assert!(asks > 0, "{}", cp.height);
    }
}

/// B398 witness: a block whose anchor is junk (padded, with its QC padded
/// to match) is refused by the anchor binding before its body is checked
/// against its header (the DA root's Reed-Solomon extension), and so is one
/// whose QC names another anchor round. The extension ran first.
#[test]
fn a_junk_anchor_is_refused_before_the_bodys_roots() {
    let a = chain("junk_anchor_a", MEMBER);
    let checks = || COMMITMENT_CHECKS.with(|n| n.get());
    let mut block = stored_block(&a);
    block.anchor_hash = "ab".repeat(1 << 16);
    let mut qc = stored_qc(&a);
    qc.anchor_hash = block.anchor_hash.clone();
    let before = checks();
    let err = check_anchor(&a.cp, &block, &qc).unwrap_err();
    assert!(err.contains("not its last committed vertex"), "{err}");
    let mut other_round = stored_qc(&a);
    other_round.anchor_round += 1;
    let err = check_anchor(&a.cp, &stored_block(&a), &other_round).unwrap_err();
    assert!(err.contains("QC is not for"), "{err}");
    assert_eq!(checks(), before, "no body was checked against its header");
    assert_eq!(
        check_anchor(&a.cp, &stored_block(&a), &stored_qc(&a)),
        Ok(())
    );
    assert_eq!(checks(), before + 1, "positive control: the real one is");
}

/// The byte cut at which these tests' anchor block is too large for a batch.
const PARTED_BATCH: usize = 256;

/// B397 witness: a server whose block at the checkpoint is too large for an
/// answer names it with its header, proposer's signature and QC, from what
/// it knows after one read (B324), and serves its body in shards. It
/// answered nothing.
#[test]
fn an_anchor_over_a_batch_is_named_with_its_qc() {
    let a = chain("named_anchor_a", MEMBER);
    let server = ChainSync::new(Arc::clone(&a.db))
        .with_snapshot_serving(true)
        .with_batch_bytes(PARTED_BATCH);
    let block = stored_block(&a);
    assert!(
        serde_json::to_string(&block).unwrap().len() > PARTED_BATCH,
        "vacuous: the block fits a batch"
    );
    for ask in 0..2 {
        let answer = server.handle_state_anchor(AnchorRequest { height: H });
        assert!(answer.block.is_none(), "ask {ask}");
        let big = answer.oversized.expect("named");
        assert_eq!(big.height, H);
        assert_eq!(big.header.hash, block.header.hash);
        assert_eq!(big.proposer_signature, block.proposer_signature);
        assert_eq!(big.proposer_signer, block.proposer_signer);
        assert_eq!(answer.quorum_certificate, Some(stored_qc(&a)), "ask {ask}");
    }
    let piece = server.handle_block_shard(crate::ShardRequest {
        height: H,
        index: 0,
        offset: 0,
    });
    assert_eq!(piece.error, None, "its body is served in shards");
}

/// B397 witness: a checkpoint whose block is larger than a sync batch
/// restores: its body comes in shards, each proved under the DA root the
/// checkpoint's hash pins (a peer whose shard does not prove is passed
/// over), and the block stored is the whole one. No node could restore it.
#[tokio::test]
async fn a_checkpoint_block_over_a_batch_restores_through_its_shards() {
    let g = genesis();
    let a = chain("parted_anchor_a", MEMBER);
    let b = chain("parted_anchor_b", MEMBER);
    let client = temp_db("parted_anchor_client");
    let parted = |chain: &Chain| {
        let mut server = peer(chain, Behaviour::Honest);
        server.sync = ChainSync::new(Arc::clone(&chain.db))
            .with_snapshot_serving(true)
            .with_batch_bytes(PARTED_BATCH);
        server
    };
    let (mut liar, mut honest) = (parted(&a), parted(&b));
    let (mut lied, mut pieces) = (0usize, 0usize);
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if !msg.starts_with(crate::SHARD_REQ) {
            return serve(if i == 0 { &mut liar } else { &mut honest }, msg);
        }
        if i == 1 {
            pieces += 1;
            return serve(&mut honest, msg);
        }
        // Every piece the liar serves has a byte flipped.
        lied += 1;
        let reply = serve(&mut liar, msg)?;
        let mut piece: crate::ShardResponse =
            serde_json::from_str(reply.strip_prefix(crate::SHARD_RESP).unwrap()).unwrap();
        let mut data = hex::decode(&piece.data).unwrap();
        if let Some(byte) = data.first_mut() {
            *byte ^= 1;
        }
        piece.data = hex::encode(data);
        Ok(format!(
            "{}{}",
            crate::SHARD_RESP,
            serde_json::to_string(&piece).unwrap()
        ))
    })
    .await
    .expect("the restore completes");
    assert_restored(&client, &a);
    assert!(lied > 0, "positive control: the liar was asked");
    assert!(pieces > 1, "the body came in pieces: {pieces}");
    let stored = client.get(&format!("block_{H}")).unwrap().unwrap();
    assert_eq!(
        stored,
        serde_json::to_string(&stored_block(&b)).unwrap(),
        "the whole block, with the honest peer's signature"
    );
}

/// B401: a checkpoint block whose body is several data shards.
fn parted_spec() -> Spec {
    Spec {
        transactions: vec!["ab".repeat(400); 3],
        ..Spec::default()
    }
}

/// A server whose checkpoint block is too large for its batch.
fn parted_peer(chain: &Chain) -> Peer {
    let mut server = peer(chain, Behaviour::Honest);
    server.sync = ChainSync::new(Arc::clone(&chain.db))
        .with_snapshot_serving(true)
        .with_batch_bytes(PARTED_BATCH);
    server
}

/// B401 witness: the anchor block's shards one peer proved survive its
/// error: the next peer completes the body without being asked for them,
/// and the restore completes. The fetch was one call's own, so the error
/// threw the proved shards away and the next peer was asked for every one.
#[tokio::test]
async fn proved_anchor_shards_survive_a_peer_error() {
    let g = genesis();
    let a = chain_with("survive_a", parted_spec());
    let b = chain_with("survive_b", parted_spec());
    let client = temp_db("survive_client");
    let shards = da::Layout::of(stored_block(&a).body_bytes().len() as u64).data_shards;
    assert!(shards >= 3, "vacuous: a body of {shards} shards");
    let (mut first, mut second) = (parted_peer(&a), parted_peer(&b));
    let mut proved_by_first: Vec<u64> = Vec::new();
    let mut asked_of_second: Vec<u64> = Vec::new();
    let mut dropped = 0usize;
    run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        let Some(json) = msg.strip_prefix(crate::SHARD_REQ) else {
            return serve(if i == 0 { &mut first } else { &mut second }, msg);
        };
        let req: crate::ShardRequest = serde_json::from_str(json).unwrap();
        if i == 1 {
            asked_of_second.push(req.index);
            return serve(&mut second, msg);
        }
        // The first peer's connection drops once it has proved two shards.
        if proved_by_first.len() >= 2 {
            dropped += 1;
            return Err("connection reset".into());
        }
        let reply = serve(&mut first, msg)?;
        let piece: crate::ShardResponse =
            serde_json::from_str(reply.strip_prefix(crate::SHARD_RESP).unwrap()).unwrap();
        if !piece.proof.is_empty() {
            proved_by_first.push(piece.index);
        }
        Ok(reply)
    })
    .await
    .expect("the restore completes");
    assert_restored(&client, &a);
    assert_eq!(
        dropped, 1,
        "positive control: the first peer's turn ended in an error"
    );
    assert_eq!(proved_by_first, [0, 1]);
    assert!(
        asked_of_second.contains(&2),
        "the second peer completed the body: {asked_of_second:?}"
    );
    assert!(
        asked_of_second.iter().all(|i| !proved_by_first.contains(i)),
        "a proved shard was asked for again: {asked_of_second:?}"
    );
}

/// B401 witness: a server busy past a request timeout ends its turn, not
/// the fetch: the restore waits it out, within its deadline, and no piece is
/// fetched twice. The turn failed after one request timeout and the shards
/// it had proved went with it, to be fetched again.
#[tokio::test]
async fn a_busy_shard_server_is_waited_out_without_losing_shards() {
    let g = genesis();
    let a = chain_with("busy_shards_a", parted_spec());
    let client = temp_db("busy_shards_client");
    let mut server = parted_peer(&a);
    let patience = Patience {
        backoff_start: Duration::from_millis(10),
        backoff_max: Duration::from_millis(10),
        request_timeout: Duration::from_millis(100),
        ..fast()
    };
    let patient = RestorePlan {
        patience: patience.clone(),
        ..plan(&a.cp, &g, false)
    };
    let mut busy_from: Option<Instant> = None;
    let mut busy = 0usize;
    let mut served: std::collections::HashMap<(u64, u64), usize> = Default::default();
    run_with(&client, &patient, 1, |_, msg| {
        let Some(json) = msg.strip_prefix(crate::SHARD_REQ) else {
            return serve(&mut server, msg);
        };
        let req: crate::ShardRequest = serde_json::from_str(json).unwrap();
        // Shard 1 is busy for three request timeouts.
        let window = patience.request_timeout * 3;
        if req.index == 1 && busy_from.get_or_insert_with(Instant::now).elapsed() < window {
            busy += 1;
            return Ok(busy_reply(msg).unwrap());
        }
        *served.entry((req.index, req.offset)).or_default() += 1;
        serve(&mut server, msg)
    })
    .await
    .expect("the restore completes");
    assert_restored(&client, &a);
    assert!(busy > 1, "positive control: busy past a request timeout");
    assert!(
        served.keys().any(|(index, _)| *index == 0),
        "positive control: shard 0 came before the busy one"
    );
    assert!(
        served.values().all(|n| *n == 1),
        "no piece was fetched twice: {served:?}"
    );
}

/// B401 witness: two peers that name the parted block under two signatures
/// give two pairs that share one body, checked against its header once and
/// held for later rounds; the whole block is built for a pair on demand.
/// Each pair held its own copy (up to 512 MiB of text each), and each copy's
/// commitments were run.
#[tokio::test]
async fn parted_anchor_pairs_share_one_body() {
    let a = chain_with("shared_body_a", parted_spec());
    let server = parted_peer(&a).sync;
    let mut resigned = server.handle_state_anchor(AnchorRequest { height: H });
    let (key, address) = outsider();
    let mut block = stored_block(&a);
    block.sign_proposer(&key, &address);
    let big = resigned.oversized.as_mut().expect("named");
    big.proposer_signature = block.proposer_signature;
    big.proposer_signer = block.proposer_signer;
    let resigned = format!("{ANCHOR_RESP}{}", serde_json::to_string(&resigned).unwrap());
    let checks = || COMMITMENT_CHECKS.with(|n| n.get());
    let before = checks();
    let shard_asks = std::cell::Cell::new(0usize);
    let mut ask = |i: usize, msg: String| {
        shard_asks.set(shard_asks.get() + usize::from(msg.starts_with(crate::SHARD_REQ)));
        let reply = if i == 1 && msg.starts_with(ANCHOR_REQ) {
            Ok(resigned.clone())
        } else {
            server
                .handle_message(&msg)
                .ok_or_else(|| "no answer".to_string())
        };
        async move { reply }
    };
    let mut anchor = AnchorBody::default();
    let pairs = fetch_anchor(&a.cp, 2, &mut ask, &fast(), &mut anchor, Instant::now())
        .await
        .unwrap();
    assert_eq!(pairs.len(), 2, "two signatures, two pairs");
    assert!(
        Arc::ptr_eq(&pairs[0].body, &pairs[1].body),
        "one body for both"
    );
    assert!(
        anchor
            .body
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, &pairs[0].body)),
        "the one held for later rounds"
    );
    assert_eq!(checks(), before + 1, "the body's commitments ran once");
    // A later round shares it again: no shard is asked for, no check run.
    let fetched = shard_asks.get();
    assert!(fetched > 0, "positive control: the body came in shards");
    let again = fetch_anchor(&a.cp, 2, &mut ask, &fast(), &mut anchor, Instant::now())
        .await
        .unwrap();
    assert!(again.iter().all(|p| Arc::ptr_eq(&p.body, &pairs[0].body)));
    assert_eq!(shard_asks.get(), fetched, "no shard asked for again");
    assert_eq!(checks(), before + 1);
    let honest = pairs
        .iter()
        .find(|p| p.proposer_signer == proposer().1)
        .expect("the proposer's pair")
        .clone();
    let (whole, qc) = honest.into_block();
    assert_eq!(
        serde_json::to_string(&whole).unwrap(),
        serde_json::to_string(&stored_block(&a)).unwrap(),
        "the whole block under the pair's own signature"
    );
    assert_eq!(qc, stored_qc(&a));
}

// ===================== Round 30 witnesses =====================

/// B463 witness support: the part of a `len`-byte value from `offset`, all
/// zeros, as a peer that holds no such value answers.
fn junk_part(len: u64, offset: u64) -> Result<String, String> {
    let part = (len - offset).min(VALUE_PART_BYTES as u64) as usize;
    Ok(format!(
        "{VALUE_RESP}{}",
        serde_json::to_string(&ValueResponse {
            data: hex::encode(vec![0u8; part]),
            len,
            error: None,
        })
        .unwrap()
    ))
}

/// B463 witness: a chunk turn's value parts are paced by the bytes they
/// brought, over the whole turn, never by the length a value claims. Each
/// part here comes 200 ms after its ask (5 MiB/s for whole parts), under a
/// floor of 16 MiB/s past a 150 ms request timeout: the turn ends within two
/// asks. A value claimed 32 MiB long was given 150 ms and 2 s, so eleven
/// parts were asked; ten values claimed one part long were given 150 ms
/// each, from their own start, so all ten were fetched (2 s).
#[tokio::test]
async fn a_chunk_turn_is_paced_by_the_bytes_it_brought() {
    let patience = Patience {
        request_timeout: Duration::from_millis(150),
        min_bytes_per_sec: 16 << 20,
        ..fast()
    };
    let parted = |key: u64, len: u64| WireEntry {
        key: obj(key),
        value: String::new(),
        len,
    };
    let one_part = INLINE_VALUE_BYTES as u64 + 1;
    let cases = [
        ("a value claimed long", vec![parted(1, 32 << 20)]),
        (
            "values claimed one part long",
            (1..=10).map(|k| parted(k, one_part)).collect::<Vec<_>>(),
        ),
    ];
    for (case, entries) in cases {
        let lens: std::collections::HashMap<String, u64> =
            entries.iter().map(|e| (e.key.clone(), e.len)).collect();
        let reply = chunk_reply(&ChunkResponse {
            entries,
            ..Default::default()
        });
        let value_asks = std::cell::Cell::new(0usize);
        let mut ask = |_: usize, msg: String| {
            let r = match msg.strip_prefix(VALUE_REQ) {
                Some(json) => {
                    value_asks.set(value_asks.get() + 1);
                    let req: ValueRequest = serde_json::from_str(json).unwrap();
                    std::thread::sleep(Duration::from_millis(200));
                    junk_part(lens[&req.key], req.offset)
                }
                None => reply.clone(),
            };
            async move { r }
        };
        let got = ask_chunk(&mut ask, 0, H, None, &patience).await;
        assert!(
            matches!(got, Reply::Unanswered(_)),
            "{case}: the turn ran as long as its claims"
        );
        assert!(
            (1..=2).contains(&value_asks.get()),
            "{case}: {} parts asked",
            value_asks.get()
        );
    }
}

/// B463 witness: a peer owes the time a turn held the restore past what it
/// delivered, and sits out a turn for each `slow_turn` of that debt; a
/// delivery forgives it only once its deliveries paid the debt (at
/// `MIN_TURN_UNITS_PER_SEC`). Any delivery forgave it, a quick one-leaf
/// chunk included, so a peer alternating that with a long failed turn sat
/// out one turn a cycle.
#[test]
fn a_failed_turns_time_is_owed_until_deliveries_pay_it() {
    let secs = Duration::from_secs;
    let mut set = PeerSet::new(2, secs(2));
    // 30 s held, nothing brought: 30 s owed, a turn for each 2 s of it.
    set.charge(1, secs(30), 0.0);
    set.strike(1);
    assert_eq!((set.penalty[1], set.sit_out[1]), (1, 15));
    // A quick one-leaf chunk (its leaf pays 4 ms of its 10) pays none of
    // it: no forgiveness.
    set.charge(1, Duration::from_millis(10), 1.0);
    set.delivered(1);
    assert_eq!(
        (set.penalty[1], set.sit_out[1]),
        (1, 15),
        "a small delivery forgave a failed turn"
    );
    // Another failed turn doubles the penalty and adds its time.
    set.charge(1, secs(30), 0.0);
    set.strike(1);
    assert_eq!((set.penalty[1], set.sit_out[1]), (2, 30));
    // 2,000 units in a second pay 8 s, less the second: 7 s each, so the
    // ninth such delivery pays the 60 s owed.
    let mut deliveries = 0;
    while set.penalty[1] > 0 {
        set.charge(1, secs(1), 2_000.0);
        set.delivered(1);
        deliveries += 1;
        assert!(deliveries <= 9, "never forgiven");
    }
    assert_eq!((deliveries, set.sit_out[1]), (9, 0));
    // Control: a peer that owes nothing is forgiven at its first delivery,
    // and a quick turn that brought nothing (a busy answer) adds no debt.
    set.strike(0);
    set.charge(0, Duration::from_millis(10), 0.0);
    set.delivered(0);
    assert_eq!((set.penalty[0], set.sit_out[0]), (0, 0));
}

/// B463 witness: a peer that alternates a turn it holds and brings nothing
/// with (a value claimed long, junk parts at the floor's pace) and a quick
/// one-leaf chunk owes the first turn's time: the one-leaf chunk no longer
/// forgives it, and its stalls come further and further apart while the
/// honest peer carries the restore. Any delivery forgave it, so it stalled
/// once in every three of the honest peer's turns, to the restore's end (up
/// to about 360 times slower at the defaults: past the 24 h deadline for a
/// state over about 475,000 leaves).
#[tokio::test]
async fn a_peer_alternating_stalls_and_single_leaves_loses_its_turns() {
    let g = genesis();
    let a = chain("b463_alternate_a", MEMBER);
    let client = temp_db("b463_alternate_client");
    let honest = peer(&a, Behaviour::Honest).sync;
    let hostile = peer(&a, Behaviour::Honest).sync;
    let judged = RestorePlan {
        patience: Patience {
            request_timeout: Duration::from_millis(600),
            min_bytes_per_sec: 32 << 20,
            slow_turn: Duration::from_millis(200),
            ..fast()
        },
        ..plan(&a.cp, &g, false)
    };
    let claimed = 32u64 << 20;
    let (mut hostile_turns, mut stalls, mut honest_turns) = (0usize, 0usize, 0usize);
    run_with(&client, &judged, 2, |i, msg| {
        let server = if i == 0 { &honest } else { &hostile };
        if let (1, Some(json)) = (i, msg.strip_prefix(VALUE_REQ)) {
            let offset = serde_json::from_str::<ValueRequest>(json).unwrap().offset;
            std::thread::sleep(Duration::from_millis(300));
            return junk_part(claimed, offset);
        }
        let Some(json) = msg.strip_prefix(CHUNK_REQ) else {
            return server.handle_message(msg).ok_or("no answer".into());
        };
        let mut request: ChunkRequest = serde_json::from_str(json).unwrap();
        request.max = 1;
        if i == 0 {
            honest_turns += 1;
        } else {
            hostile_turns += 1;
            if !hostile_turns.is_multiple_of(2) {
                stalls += 1;
                return chunk_reply(&ChunkResponse {
                    entries: vec![WireEntry {
                        key: obj(0),
                        value: String::new(),
                        len: claimed,
                    }],
                    ..Default::default()
                });
            }
        }
        chunk_reply(&server.handle_state_chunk(request))
    })
    .await
    .unwrap();
    assert!(
        stalls <= 6,
        "{stalls} stalls, the honest peer's turns {honest_turns}"
    );
    assert!(
        honest_turns >= 20,
        "positive control: the honest peer carried it ({honest_turns} turns)"
    );
    assert_restored(&client, &a);
}

/// B471 witness: a chunk reads no more bytes than its grant pays for (a
/// unit a `UNIT_BYTES`), but the leaf that ends it: it ends before a leaf
/// whose value takes the read past the grant, parted values included, and
/// is charged what it read. Each value was read whole and a chunk ended only
/// at the protocol's limits (512 MiB parted), charged one client-second.
#[test]
fn a_chunk_reads_no_more_than_its_grant_pays_for() {
    let big = INLINE_VALUE_BYTES + 1;
    let extra = (100..120).map(|i| (obj(i), vec![b'g'; big])).collect();
    let a = chain_with(
        "b471_reads_a",
        Spec {
            extra,
            ..Spec::default()
        },
    );
    let sync = peer(&a, Behaviour::Honest).sync;
    let reader = Some("10.0.0.71");
    let max = 300;
    let chunk = sync.serve_state_chunk(
        ChunkRequest {
            version: H,
            after: None,
            max,
        },
        reader,
    );
    assert!(chunk.error.is_none(), "{:?}", chunk.error);
    let served = chunk.entries.len();
    // What it read: the leaves served and the one that ended the chunk.
    let (visited, _) = state_commit::chunk(&a.db, H, None, served + 1)
        .unwrap()
        .unwrap();
    let read: u64 = visited.iter().map(|(_, v)| v.len() as u64).sum();
    let readable = max as u64 * UNIT_BYTES;
    assert!(
        read <= readable + big as u64,
        "{read} bytes read for a grant of {max} units ({served} leaves of {})",
        a.state.len()
    );
    assert!(
        read > readable && served < a.state.len(),
        "vacuous: the grant did not end the chunk ({read} bytes)"
    );
    assert_eq!(
        sync.state_budget.balance(reader),
        STATE_SERVE_UNITS_PER_SEC_PER_CLIENT - served as f64 - read.div_ceil(UNIT_BYTES) as f64,
        "charged a unit a leaf served and a unit a `UNIT_BYTES` read"
    );
}

/// B472 witness: on V4 the checkpoint block's signer is a member of its
/// epoch's committee, by the rule sync checks a block's signer by
/// (`eligible_proposers`: C_E(h)). The restored active set was accepted
/// too, so a block signed by an active validator outside C_E was stored,
/// and no block-syncing client could take it from the restored node.
#[test]
fn a_v4_anchor_signer_is_a_member_of_its_committee() {
    let client = temp_db("b472_signer_client");
    let members = committee_of([9; 32], 3);
    {
        let _seed = client.seeding();
        client.put(consensus::v4::VERTEX_FORMAT_KEY, "4").unwrap();
        client
            .put(
                "sys:validators",
                &serde_json::to_string(&vec![(proposer().1, 100u64)]).unwrap(),
            )
            .unwrap();
    }
    assert!(consensus::v4::is_v4_chain(&client));
    assert!(
        client
            .get_active_validators()
            .iter()
            .any(|(address, _)| *address == proposer().1),
        "vacuous: the signer is no active validator"
    );
    assert!(
        signed_by_a_validator(&client, &members, &members[0].address),
        "a member of C_E"
    );
    assert!(
        !signed_by_a_validator(&client, &members, &proposer().1),
        "an active validator outside C_E"
    );
}

/// B472 witness, end to end: on V4 the anchor pair an active validator
/// outside C_E re-signed is not the one stored, though it is offered first;
/// the pair C_E's member signed is.
#[tokio::test]
async fn a_v4_anchor_signed_outside_its_committee_is_not_stored() {
    let g = genesis();
    let later = [8u8; 32];
    let a = chain_with(
        "b472_resign_a",
        Spec {
            signer: later,
            epoch_one: Some(later),
            v4: true,
            validators: vec![outsider().1],
            ..Spec::default()
        },
    );
    let client = temp_db("b472_resign_client");
    let mut byz = peer(&a, Behaviour::Honest);
    let mut honest = peer(&a, Behaviour::Honest);
    let (key, address) = outsider();
    let mut block = stored_block(&a);
    block.sign_proposer(&key, &address);
    let byz_anchor = format!(
        "{ANCHOR_RESP}{}",
        serde_json::to_string(&AnchorResponse {
            block: Some(block.clone()),
            quorum_certificate: Some(stored_qc(&a)),
            oversized: None,
            error: None,
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
    assert_eq!(stored.proposer_signer, proposer().1, "the member's pair");
    assert!(
        client
            .get_active_validators()
            .iter()
            .any(|(v, _)| *v == address),
        "vacuous: the re-signer is no active validator"
    );
    assert!(
        ChainSync::verify_proposer_signature_in(&client, &block).is_ok(),
        "positive control: the re-signed block's signature verifies"
    );
    assert_restored(&client, &a);
}

/// B466 witness: a restore's refusals of a peer's text are logged cut and
/// escaped (`loggable`), and the error boot prints carries it cut: a chunk
/// whose key is past the protocol's limits (its refusal names the key), and
/// a peer that refuses every chunk with its own text (logged at each
/// strike, and returned once the restore gives up). Each was printed whole,
/// megabytes a line, line breaks included (a forged log line).
#[tokio::test]
async fn a_peers_text_is_logged_and_returned_cut() {
    let g = genesis();
    let a = chain("b466_cut_a", MEMBER);
    let client = temp_db("b466_cut_client");
    let mut honest = peer(&a, Behaviour::Honest);
    let forged = format!("x\n🚨 [DE-6] a forged alarm line {}", "e".repeat(5 << 20));
    let long_key = WireEntry {
        key: forged.clone(),
        value: hex::encode(b"v"),
        len: 1,
    };
    crate::take_logged();
    let err = run_with(&client, &plan(&a.cp, &g, false), 2, |i, msg| {
        if !msg.starts_with(CHUNK_REQ) {
            return serve(&mut honest, msg);
        }
        if i == 0 {
            return chunk_reply(&ChunkResponse {
                entries: vec![long_key.clone()],
                ..Default::default()
            });
        }
        chunk_reply(&ChunkResponse {
            error: Some(forged.clone()),
            ..Default::default()
        })
    })
    .await
    .unwrap_err();
    let cut = |text: &str| text.chars().count() <= 400 && !text.contains('\n');
    assert!(cut(err.as_str()), "returned whole: {}", err.len());
    assert!(err.contains("x\\n"), "control: the peer's text, escaped: {err}");
    let logged = crate::take_logged();
    for line in &logged {
        assert!(cut(line.as_str()), "logged whole: {} bytes", line.len());
    }
    for what in ["broke the protocol", "gave no answer"] {
        assert!(
            logged.iter().any(|l| l.contains(what) && l.contains("x\\n")),
            "vacuous: no {what} line"
        );
    }
}
