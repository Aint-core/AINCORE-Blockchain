//! Serving bounds against peers outside the committee, on one real node
//! (`start_p2p`) whose sync requests are answered by the test.
//!
//! B30: a requester that never reads its answers cannot make a node hold
//! more than `OPEN_HELD_MAX_BYTES` of them, and the bytes come back when its
//! connection closes or the answers are written. Every request is answered
//! with 9 MiB; a client outside the committee opens eight sync streams and
//! never reads a response (its codec waits forever), so each answer stays
//! in the node's write path until the request times out. Seven fit under
//! the 64 MiB bound; the eighth is refused. Before the bound all eight
//! (72 MiB) were held, and eight per connection on two connections per host
//! from many hosts.
//!
//! B34: free identities on one host share one sync budget.

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncWrite, StreamExt};
use libp2p::{
    core::upgrade, noise, request_response, swarm::SwarmEvent, tcp, yamux, Multiaddr,
    StreamProtocol, Swarm, Transport,
};
use node::sessions::{self, OPEN_HELD_MAX_BYTES};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A sync client that writes requests and never reads an answer.
#[derive(Debug, Clone, Copy, Default)]
struct NeverReads;

#[async_trait]
impl request_response::Codec for NeverReads {
    type Protocol = StreamProtocol;
    type Request = String;
    type Response = String;

    async fn read_request<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<String>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<String>
    where
        T: AsyncRead + Unpin + Send,
    {
        std::future::pending().await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: String,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        sessions::write_frame(io, &req, sessions::SYNC_REQUEST_CAP).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
        _: String,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}

trait SyncCodec:
    request_response::Codec<Protocol = StreamProtocol, Request = String, Response = String>
    + Clone
    + Send
    + 'static
{
}
impl<C> SyncCodec for C where
    C: request_response::Codec<Protocol = StreamProtocol, Request = String, Response = String>
        + Clone
        + Send
        + 'static
{
}

fn new_client<C: SyncCodec>(codec: C) -> Swarm<request_response::Behaviour<C>> {
    client_on(
        codec,
        sessions::SYNC_PROTOCOL,
        libp2p::identity::Keypair::generate_ed25519(),
    )
}

fn client_on<C: SyncCodec>(
    codec: C,
    protocol: &'static str,
    key: libp2p::identity::Keypair,
) -> Swarm<request_response::Behaviour<C>> {
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&key).expect("noise"))
        .multiplex(yamux::Config::default())
        .boxed();
    let behaviour = request_response::Behaviour::with_codec(
        codec,
        [(
            StreamProtocol::new(protocol),
            request_response::ProtocolSupport::Outbound,
        )],
        // Longer than the test: a client never gives a stream up itself.
        request_response::Config::default().with_request_timeout(Duration::from_secs(600)),
    );
    let peer = key.public().to_peer_id();
    Swarm::new(
        transport,
        behaviour,
        peer,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(600)),
    )
}

/// Drive `swarm` until `done` holds, or fail after `within`.
async fn drive_until<C: SyncCodec>(
    swarm: &mut Swarm<request_response::Behaviour<C>>,
    within: Duration,
    what: &str,
    mut done: impl FnMut() -> bool,
) {
    let deadline = tokio::time::Instant::now() + within;
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::select! {
            _ = swarm.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_a_non_reader_holds_are_bounded_and_freed_on_close() {
    const ANSWER: usize = 9 << 20;
    const REQUESTS: usize = 8;
    // Seven answers fit under the bound; the eighth does not.
    const FIT: usize = OPEN_HELD_MAX_BYTES / ANSWER;
    const _: () = assert!(FIT < REQUESTS);
    let node_under_test = start_node("held", ANSWER).await;
    let (target, held, answered) = (
        node_under_test.target.clone(),
        Arc::clone(&node_under_test.held),
        Arc::clone(&node_under_test.answered),
    );
    let mut client = new_client(NeverReads);
    let node = connect(&mut client, &target).await;
    for _ in 0..REQUESTS {
        client
            .behaviour_mut()
            .send_request(&node, "GET_HEIGHT".to_string());
    }
    drive_until(
        &mut client,
        Duration::from_secs(30),
        "every request answered",
        || answered.load(Ordering::SeqCst) == REQUESTS,
    )
    .await;
    // Let the node hand off (or refuse) the last answer.
    let settle = tokio::time::Instant::now() + Duration::from_secs(2);
    drive_until(&mut client, Duration::from_secs(5), "settle", || {
        tokio::time::Instant::now() >= settle
    })
    .await;

    assert_eq!(
        held.load(Ordering::SeqCst),
        FIT * ANSWER,
        "the answers that fit are held, the rest refused"
    );

    // The client goes away: the node frees what it held.
    drop(client);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while held.load(Ordering::SeqCst) != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "held answers were not freed on close: {} bytes",
            held.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// B30 witness, written answers: a client that reads gets its answers whole,
/// and their bytes are freed as they are written, while its connection stays
/// open (its own node: the host's budget, B60, is fresh).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reading_clients_answers_are_freed_as_written() {
    const ANSWER: usize = 9 << 20;
    let node_under_test = start_node("written", ANSWER).await;
    let (target, held) = (
        node_under_test.target.clone(),
        Arc::clone(&node_under_test.held),
    );
    // A client that reads: its answers are written whole and their bytes
    // freed while its connection stays open.
    let mut reader = new_client(sessions::FramedCodec::new(
        sessions::SYNC_REQUEST_CAP,
        sessions::SYNC_RESPONSE_CAP,
    ));
    let node = connect(&mut reader, &target).await;
    for _ in 0..2 {
        reader
            .behaviour_mut()
            .send_request(&node, "GET_HEIGHT".to_string());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut read = 0;
    while read < 2 {
        assert!(tokio::time::Instant::now() < deadline, "answers not read");
        tokio::select! {
            ev = reader.select_next_some() => match ev {
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                }) => {
                    assert_eq!(response.len(), ANSWER);
                    read += 1;
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { error, .. }) => {
                    panic!("a request failed: {error}")
                }
                _ => {}
            },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    drive_until(
        &mut reader,
        Duration::from_secs(10),
        "written answers freed",
        || held.load(Ordering::SeqCst) == 0,
    )
    .await;
    assert!(
        reader.is_connected(&node),
        "freed by the writes, not a close"
    );
}

/// One real node whose sync requests are all answered with `answer` bytes.
struct NodeUnderTest {
    target: Multiaddr,
    book: Arc<std::sync::RwLock<sessions::PeerBook>>,
    held: Arc<AtomicUsize>,
    answered: Arc<AtomicUsize>,
    dir: std::path::PathBuf,
    // The node's network task runs while this is held.
    _tx_out: tokio::sync::mpsc::Sender<network::Outbound>,
}

impl Drop for NodeUnderTest {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start_node(name: &str, answer: usize) -> NodeUnderTest {
    let mut dir = storage::test_dir::process_dir();
    dir.push(format!("aincore_serving_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let storage = Arc::new(storage::StateDB::open(dir.to_str().unwrap()).expect("temp db"));

    // A port for the node's libp2p listener (base port + 100): a pseudo-random
    // one, another on a clash (the listener binds at start, so a port in use
    // fails `start_p2p`; this crate opens no socket of its own, G4 S6).
    let book = Arc::new(std::sync::RwLock::new(sessions::PeerBook::default()));
    let seed = std::process::id() as u64
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64;
    let mut started = None;
    for attempt in 0..32u64 {
        let libp2p_port = 20_000 + (seed.wrapping_add(attempt * 7_919) % 40_000) as u16;
        let (wiring, _client, serves) = sessions::SessionWiring::new(Arc::clone(&book));
        let held = Arc::clone(&wiring.held_open_bytes);
        if let Ok((tx_out, rx_in)) = node::p2p::start_p2p(
            libp2p_port - 100,
            vec![],
            Arc::clone(&storage),
            false,
            false,
            [7; 32],
            wiring,
        )
        .await
        {
            started = Some((libp2p_port, held, serves, tx_out, rx_in));
            break;
        }
    }
    let (libp2p_port, held, mut serves, tx_out, mut rx_in) =
        started.expect("the node starts on a free port");
    tokio::spawn(async move { while rx_in.recv().await.is_some() {} });
    let answered = Arc::new(AtomicUsize::new(0));
    {
        let answered = Arc::clone(&answered);
        tokio::spawn(async move {
            while let Some(serve) = serves.recv().await {
                let _ = serve.reply.send(Some("x".repeat(answer)));
                answered.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    NodeUnderTest {
        target: format!("/ip4/127.0.0.1/tcp/{libp2p_port}").parse().unwrap(),
        book,
        held,
        answered,
        dir,
        _tx_out: tx_out,
    }
}

/// Send `n` requests, at most 8 at a time (the node's open streams per
/// connection), and count the answered and the refused.
async fn ask_in_batches(
    swarm: &mut Swarm<request_response::Behaviour<sessions::FramedCodec>>,
    node: &libp2p::PeerId,
    n: usize,
    stop_at_first_refusal: bool,
) -> (usize, usize) {
    let (mut answered, mut refused) = (0, 0);
    while answered + refused < n {
        let batch = (n - answered - refused).min(8);
        for _ in 0..batch {
            swarm
                .behaviour_mut()
                .send_request(node, "GET_HEIGHT".to_string());
        }
        let mut outcomes = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while outcomes < batch {
            assert!(tokio::time::Instant::now() < deadline, "a batch hung");
            tokio::select! {
                ev = swarm.select_next_some() => match ev {
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Response { .. },
                        ..
                    }) => {
                        answered += 1;
                        outcomes += 1;
                    }
                    SwarmEvent::Behaviour(request_response::Event::OutboundFailure { .. }) => {
                        refused += 1;
                        outcomes += 1;
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        if stop_at_first_refusal && refused > 0 {
            break;
        }
    }
    (answered, refused)
}

/// B34 witness: free identities on one host share one sync budget. One
/// identity spends the host's burst; a second, fresh identity from the same
/// host gets only what the bucket refilled since. Keyed by PeerId (before),
/// the second identity had a full burst of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn free_identities_on_one_host_share_one_sync_budget() {
    const ASKED: usize = 64;
    let node_under_test = start_node("budget", 2).await;
    let reader = || {
        new_client(sessions::FramedCodec::new(
            sessions::SYNC_REQUEST_CAP,
            sessions::SYNC_RESPONSE_CAP,
        ))
    };
    let mut first = reader();
    let node = connect(&mut first, &node_under_test.target).await;
    let (spent, refused) = ask_in_batches(&mut first, &node, 400, true).await;
    assert!(refused > 0, "the host's budget ran out");
    assert!(
        spent >= sessions::SYNC_REQUEST_BURST as usize,
        "positive control: the burst was answered ({spent})"
    );
    let exhausted = std::time::Instant::now();
    drop(first);

    let mut second = reader();
    let node = connect(&mut second, &node_under_test.target).await;
    let (answered, _) = ask_in_batches(&mut second, &node, ASKED, false).await;
    let refill = sessions::SYNC_REQUESTS_PER_SEC * exhausted.elapsed().as_secs_f64();
    assert!(
        refill + 1.0 < ASKED as f64,
        "the test ran too slowly to tell the budgets apart ({refill:.1})"
    );
    assert!(
        (answered as f64) <= refill.ceil() + 1.0,
        "a fresh identity on the same host was answered {answered} times; \
         the host's bucket refilled only {refill:.1}"
    );
}

/// The one outcome of one request.
async fn one_answer<C: SyncCodec>(
    swarm: &mut Swarm<request_response::Behaviour<C>>,
    node: &libp2p::PeerId,
    request: String,
) -> Result<String, request_response::OutboundFailure> {
    swarm.behaviour_mut().send_request(node, request);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no outcome");
        tokio::select! {
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                }) => return Ok(response),
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { error, .. }) => {
                    return Err(error)
                }
                _ => {}
            },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

/// B30 witness: a peer outside the committee cannot open a consensus
/// stream at all (refused at negotiation, before its frame is read). Once
/// the book names it, the connection it opened under the old book is
/// closed, and on a new one its consensus message is acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consensus_streams_open_for_members_only() {
    let node_under_test = start_node("members_only", 2).await;
    let key = libp2p::identity::Keypair::generate_ed25519();
    let consensus_client = |key: &libp2p::identity::Keypair| {
        client_on(
            sessions::FramedCodec::consensus(),
            sessions::CONSENSUS_PROTOCOL,
            key.clone(),
        )
    };
    let mut outsider = consensus_client(&key);
    let node = connect(&mut outsider, &node_under_test.target).await;
    let big = format!("DAG_V4:{}", "x".repeat(700 << 10));
    match one_answer(&mut outsider, &node, big).await {
        Err(request_response::OutboundFailure::UnsupportedProtocols) => {}
        other => {
            panic!("a non-member's consensus stream was not refused at negotiation: {other:?}")
        }
    }

    // The book names the outsider now: the node closes the connection it
    // opened as a non-member (the committee dial runs every 5 s).
    let public = hex::encode(key.public().try_into_ed25519().unwrap().to_bytes());
    let member = blockchain::committee::ValidatorInfo {
        address: "member".into(),
        stake: 1,
        ed25519_public_key: public,
        bls_public_key: String::new(),
        bls_pop: String::new(),
    };
    *node_under_test.book.write().unwrap() = sessions::PeerBook::new(0, &[&[member]]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while outsider.is_connected(&node) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the connection opened as a non-member was not closed"
        );
        tokio::select! {
            _ = outsider.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    drop(outsider);
    let mut member = consensus_client(&key);
    let node = connect(&mut member, &node_under_test.target).await;
    let answer = one_answer(&mut member, &node, "DAG_V4:hello".into()).await;
    assert_eq!(answer.ok().as_deref(), Some(sessions::CONSENSUS_ACK));
}

/// B60 witness: a non-member's answers are charged by their bytes. 2 MiB
/// answers cost 32 more tokens each, so a host's burst of 128 tokens buys a
/// handful of them, not 128 (the request count alone let a few hosts keep
/// every serving thread busy with large answers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_answers_spend_a_hosts_budget_by_their_bytes() {
    let node_under_test = start_node("by_bytes", 2 << 20).await;
    let mut client = new_client(sessions::FramedCodec::new(
        sessions::SYNC_REQUEST_CAP,
        sessions::SYNC_RESPONSE_CAP,
    ));
    let node = connect(&mut client, &node_under_test.target).await;
    let (answered, refused) = ask_in_batches(&mut client, &node, 32, false).await;
    assert!(
        answered <= 2 * 8,
        "{answered} answers of 2 MiB from one burst"
    );
    assert!(refused > 0, "control: the budget ran out");
}

/// B48 witness: the node runs no gossip (a member that stopped reading made
/// every node queue gossipsub messages for it without bound): a gossipsub
/// stream is refused at negotiation, member or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_offers_no_gossip_protocol() {
    let node_under_test = start_node("no_gossip", 2).await;
    for protocol in ["/meshsub/1.1.0", "/meshsub/1.0.0"] {
        let mut client = client_on(
            sessions::FramedCodec::new(1024, 1024),
            protocol,
            libp2p::identity::Keypair::generate_ed25519(),
        );
        let node = connect(&mut client, &node_under_test.target).await;
        match one_answer(&mut client, &node, "x".into()).await {
            Err(request_response::OutboundFailure::UnsupportedProtocols) => {}
            other => panic!("{protocol} was not refused: {other:?}"),
        }
    }
}

/// A member's sync client (the per-host cap on strangers is not what the
/// duplicate tests test) and the node it reaches.
fn member_client(
    node_under_test: &NodeUnderTest,
) -> Swarm<request_response::Behaviour<sessions::FramedCodec>> {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let member = blockchain::committee::ValidatorInfo {
        address: "member".into(),
        stake: 1,
        ed25519_public_key: hex::encode(key.public().try_into_ed25519().unwrap().to_bytes()),
        bls_public_key: String::new(),
        bls_pop: String::new(),
    };
    *node_under_test.book.write().unwrap() = sessions::PeerBook::new(0, &[&[member]]);
    client_on(
        sessions::FramedCodec::new(sessions::SYNC_REQUEST_CAP, sessions::SYNC_RESPONSE_CAP),
        sessions::SYNC_PROTOCOL,
        key,
    )
}

/// The client's connections as it sees them open and close.
#[derive(Default)]
struct Seen {
    opened: Vec<libp2p::swarm::ConnectionId>,
    closed: std::collections::HashSet<libp2p::swarm::ConnectionId>,
}

impl Seen {
    /// Open one more connection to `target`, each its own dial.
    async fn open(
        &mut self,
        client: &mut Swarm<request_response::Behaviour<sessions::FramedCodec>>,
        target: &Multiaddr,
    ) {
        let want = self.opened.len() + 1;
        client
            .dial(
                libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
                    .address(target.clone())
                    .build(),
            )
            .expect("dial");
        self.drive(client, Duration::from_secs(30), |s| s.opened.len() >= want)
            .await;
        assert_eq!(self.opened.len(), want, "a connection opened");
    }

    /// Drive the client until `done` or `within` passes.
    async fn drive(
        &mut self,
        client: &mut Swarm<request_response::Behaviour<sessions::FramedCodec>>,
        within: Duration,
        done: impl Fn(&Self) -> bool,
    ) {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline && !done(self) {
            tokio::select! {
                ev = client.select_next_some() => match ev {
                    SwarmEvent::ConnectionEstablished { connection_id, .. } => {
                        self.opened.push(connection_id)
                    }
                    SwarmEvent::ConnectionClosed { connection_id, .. } => {
                        self.closed.insert(connection_id);
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }
}

/// Rehearsal regression witness (2026-10-03): libp2p dials a peer's
/// addresses together, keeps the first connection that opens and drops the
/// rest, so a node sees several open at once. The one kept used to be
/// closed as a duplicate the moment it opened (the third over a limit of
/// two), and the dialer redialled in a loop. It now survives its dropped
/// siblings. (Each test stays under the node's 20 s idle timeout.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dialers_kept_connection_survives_its_dropped_siblings() {
    let node_under_test = start_node("siblings", 2).await;
    let mut client = member_client(&node_under_test);
    let mut seen = Seen::default();
    for _ in 0..3 {
        seen.open(&mut client, &node_under_test.target).await;
    }
    // The dialer keeps the newest and drops the two others.
    client.close_connection(seen.opened[0]);
    client.close_connection(seen.opened[1]);
    seen.drive(&mut client, Duration::from_secs(8), |_| false)
        .await;
    assert!(
        !seen.closed.contains(&seen.opened[2]),
        "the connection the dialer kept was closed"
    );
}

/// The duplicate rule still holds: three connections that all outlive the
/// grace are trimmed to two, the newest first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_past_the_grace_are_trimmed_to_two() {
    let node_under_test = start_node("trimmed", 2).await;
    let mut client = member_client(&node_under_test);
    let mut seen = Seen::default();
    for _ in 0..3 {
        seen.open(&mut client, &node_under_test.target).await;
    }
    let newest = seen.opened[2];
    seen.drive(&mut client, Duration::from_secs(15), |s| {
        s.closed.contains(&newest)
    })
    .await;
    assert!(seen.closed.contains(&newest), "the newest was not closed");
    let live = seen
        .opened
        .iter()
        .filter(|id| !seen.closed.contains(id))
        .count();
    assert_eq!(live, 2, "trimmed to two: closed {:?}", seen.closed);
}

/// A non-member's sync client: an identity no committee names.
fn stranger_client() -> Swarm<request_response::Behaviour<sessions::FramedCodec>> {
    client_on(
        sessions::FramedCodec::new(sessions::SYNC_REQUEST_CAP, sessions::SYNC_RESPONSE_CAP),
        sessions::SYNC_PROTOCOL,
        libp2p::identity::Keypair::generate_ed25519(),
    )
}

/// B67 witness (rehearsal, 2026-10-04): the per-host cap on non-members
/// counts identities, not connections. An observer's own extra connections
/// (it dials a node's addresses at once and keeps one) are not closed when
/// they open: the one it kept survives its dropped siblings. A third
/// identity from the same host is still refused. Counting connections closed
/// the observer's kept connection at once, and it redialled in a loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_own_connections_are_not_counted_as_new_identities() {
    let node_under_test = start_node("stranger_siblings", 2).await;
    let target = &node_under_test.target;
    let mut observer = stranger_client();
    let mut seen = Seen::default();
    for _ in 0..3 {
        seen.open(&mut observer, target).await;
    }
    observer.close_connection(seen.opened[0]);
    observer.close_connection(seen.opened[1]);
    seen.drive(&mut observer, Duration::from_secs(7), |_| false)
        .await;
    assert!(
        !seen.closed.contains(&seen.opened[2]),
        "the connection the observer kept was closed"
    );

    let mut second = stranger_client();
    let mut second_seen = Seen::default();
    second_seen.open(&mut second, target).await;
    let mut third = stranger_client();
    let mut third_seen = Seen::default();
    third_seen.open(&mut third, target).await;
    third_seen
        .drive(&mut third, Duration::from_secs(5), |s| !s.closed.is_empty())
        .await;
    assert!(
        third_seen.closed.contains(&third_seen.opened[0]),
        "a third identity from one host was admitted"
    );
    second_seen
        .drive(&mut second, Duration::from_millis(500), |_| false)
        .await;
    assert!(
        second_seen.closed.is_empty(),
        "the second identity was refused"
    );
}

/// Dial `target` and wait for the session.
async fn connect<C: SyncCodec>(
    swarm: &mut Swarm<request_response::Behaviour<C>>,
    target: &Multiaddr,
) -> libp2p::PeerId {
    swarm.dial(target.clone()).expect("dial");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no session opened");
        tokio::select! {
            ev = swarm.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                    return peer_id;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}
