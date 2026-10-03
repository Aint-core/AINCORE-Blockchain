//! G4 S1 (NI-1): sessions bound to committee keys.
//!
//! The libp2p identity is the node key, the ed25519 key that signs vertices
//! and blocks. Committee validation already ties a member's address to that
//! key (`address = SHA-256(ed25519 key)`), so the PeerId a Noise session
//! authenticates names a committee member, or no member. `PeerBook` maps
//! PeerIds to the members of C_E and C_{E+1}.
//!
//! Consensus traffic travels on `/aincore/consensus/1`, a request-response
//! protocol that only members may use (Aptos `HandshakeAuthMode::Mutual`, Sui
//! `AllowPublicKeys`: a validator network admits the validator set). Its
//! frames are length-prefixed and the length is checked against the cap
//! before anything is allocated (NI-4). A libp2p signature cannot pass for a
//! consensus one: libp2p signs payloads prefixed `noise-libp2p-static-key:`
//! or `libp2p-pubsub:`, consensus signs 64-character hex hashes and
//! domain-tagged pull requests.

use async_trait::async_trait;
use blockchain::committee::ValidatorInfo;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{identity, request_response, PeerId, StreamProtocol};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// The consensus protocol: `DAG_V4:` and `QC_*` messages between members.
pub const CONSENSUS_PROTOCOL: &str = "/aincore/consensus/1";

/// The largest consensus frame: one maximal V4 wire message plus room for
/// its prefix.
pub const CONSENSUS_REQUEST_CAP: usize = consensus::v4::MAX_WIRE_BYTES + 64;

/// A consensus request is answered with this acknowledgement only.
pub const CONSENSUS_ACK: &str = "ok";

/// The sync protocol: block sync and finality, open to any session (an
/// observer follows the chain over it), each request attributed to the key
/// its session authenticated.
pub const SYNC_PROTOCOL: &str = "/aincore/sync/1";

/// The largest sync request (a `SYNC_REQ` is a few hundred bytes).
pub const SYNC_REQUEST_CAP: usize = 64 << 10;

/// The largest sync answer: what a legacy client read (`SYNC_RESP` blocks
/// stop at `chain_sync::SYNC_RESP_BLOCK_BYTES`).
pub const SYNC_RESPONSE_CAP: usize = 10 << 20;

/// The node's libp2p keypair: its node key.
pub fn local_keypair(node_key: &[u8; 32]) -> identity::Keypair {
    identity::Keypair::ed25519_from_bytes(*node_key)
        .expect("any 32 bytes are an ed25519 secret key")
}

/// The PeerId of the node whose ed25519 public key is `public_key_hex`.
pub fn peer_id_of(public_key_hex: &str) -> Option<PeerId> {
    let bytes = hex::decode(public_key_hex).ok()?;
    let key = identity::ed25519::PublicKey::try_from_bytes(&bytes).ok()?;
    Some(identity::PublicKey::from(key).to_peer_id())
}

/// The committee members of the current epoch and, once it is known, the
/// next one, by the PeerId their node key gives.
#[derive(Debug, Default, Clone)]
pub struct PeerBook {
    epoch: u64,
    by_peer: HashMap<PeerId, String>,
    by_address: HashMap<String, PeerId>,
}

impl PeerBook {
    /// The members of `committees` (C_E, and C_{E+1} when known). A member
    /// whose key is not an ed25519 key is left out: committee validation
    /// refuses one, and this never guesses a PeerId.
    pub fn new(epoch: u64, committees: &[&[ValidatorInfo]]) -> Self {
        let mut book = Self {
            epoch,
            ..Self::default()
        };
        for member in committees.iter().flat_map(|c| c.iter()) {
            if let Some(peer) = peer_id_of(&member.ed25519_public_key) {
                book.by_peer.insert(peer, member.address.clone());
                book.by_address.insert(member.address.clone(), peer);
            }
        }
        book
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The member a session's PeerId names, if any.
    pub fn member_of(&self, peer: &PeerId) -> Option<&str> {
        self.by_peer.get(peer).map(String::as_str)
    }

    /// The PeerId of the member at `address`, if it is one.
    pub fn peer_of(&self, address: &str) -> Option<PeerId> {
        self.by_address.get(address).copied()
    }

    /// Every member's PeerId.
    pub fn peers(&self) -> impl Iterator<Item = &PeerId> {
        self.by_peer.keys()
    }

    pub fn len(&self) -> usize {
        self.by_peer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_peer.is_empty()
    }
}

/// The wire prefixes of consensus messages: what the consensus protocol
/// carries between members.
pub const CONSENSUS_PREFIXES: &[&str] = &["DAG_V4:", "QC_VOTE:", "QC_WANT:", "QC_CERT:"];

/// What only a member may publish: vertices, attestations, certificates and
/// finality votes. A boundary QC and the request for one stay open to any
/// publisher: an observer asks for the QC that activates the next epoch,
/// the QC verifies itself against the committee, and answers are throttled.
pub const MEMBER_ONLY_PREFIXES: &[&str] = &["DAG_V4:", "QC_VOTE:"];

pub fn is_consensus_message(wire: &str) -> bool {
    CONSENSUS_PREFIXES.iter().any(|p| wire.starts_with(p))
}

/// NI-1: a gossip message is admitted unless only a member may publish it
/// and its signed publisher is not a member (or is unknown).
pub fn admit_gossip(book: &PeerBook, publisher: Option<&PeerId>, wire: &str) -> bool {
    !MEMBER_ONLY_PREFIXES.iter().any(|p| wire.starts_with(p))
        || publisher.is_some_and(|p| book.member_of(p).is_some())
}

/// Frames are a u32 big-endian length and that many bytes of UTF-8. The
/// length is checked against the cap before anything is read or allocated.
#[derive(Debug, Clone, Copy)]
pub struct FramedCodec {
    request_cap: usize,
    response_cap: usize,
}

impl FramedCodec {
    pub fn new(request_cap: usize, response_cap: usize) -> Self {
        Self {
            request_cap,
            response_cap,
        }
    }

    /// `/aincore/consensus/1`: a V4 message in, an acknowledgement out.
    pub fn consensus() -> Self {
        Self::new(CONSENSUS_REQUEST_CAP, CONSENSUS_ACK.len())
    }
}

pub async fn read_frame<T: AsyncRead + Unpin + Send>(io: &mut T, cap: usize) -> io::Result<String> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a {len}-byte frame is over the {cap}-byte cap"),
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the frame is not UTF-8"))
}

pub async fn write_frame<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    frame: &str,
    cap: usize,
) -> io::Result<()> {
    if frame.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a {}-byte frame is over the {cap}-byte cap", frame.len()),
        ));
    }
    io.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    io.write_all(frame.as_bytes()).await?;
    io.close().await
}

#[async_trait]
impl request_response::Codec for FramedCodec {
    type Protocol = StreamProtocol;
    type Request = String;
    type Response = String;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<String>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.request_cap).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<String>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.response_cap).await
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
        write_frame(io, &req, self.request_cap).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: String,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res, self.response_cap).await
    }
}

/// The request-response behaviour of `/aincore/consensus/1`.
pub fn consensus_behaviour() -> request_response::Behaviour<FramedCodec> {
    request_response::Behaviour::with_codec(
        FramedCodec::consensus(),
        [(
            StreamProtocol::new(CONSENSUS_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(10))
            .with_max_concurrent_streams(32),
    )
}

/// G4 S1: what the network task shares with the node: the committee book,
/// the session table sync reads, the requests sync asks, and the requests
/// sessions ask it to serve.
pub struct SessionWiring {
    pub book: Arc<RwLock<PeerBook>>,
    pub table: network::SessionTable,
    pub asks: mpsc::Receiver<network::SyncAsk>,
    pub serves: mpsc::Sender<network::SyncServe>,
}

impl SessionWiring {
    /// The wiring, the client sync asks through, and the receiver the node
    /// serves sync requests from.
    pub fn new(
        book: Arc<RwLock<PeerBook>>,
    ) -> (
        Self,
        network::SessionClient,
        mpsc::Receiver<network::SyncServe>,
    ) {
        let table: network::SessionTable = Arc::default();
        let (asks_tx, asks) = mpsc::channel(64);
        let (serves, serves_rx) = mpsc::channel(64);
        (
            Self {
                book,
                table: Arc::clone(&table),
                asks,
                serves,
            },
            network::SessionClient {
                asks: asks_tx,
                table,
            },
            serves_rx,
        )
    }
}

/// NI-2: inbound connections from peers no committee key names, all
/// together (Aptos `MAX_INBOUND_CONNECTIONS` = 50, counting unknown peers
/// only). Members are never counted.
pub const MAX_NON_MEMBER_INBOUND: usize = 50;

/// NI-3: consensus messages a member may send a second, and in a burst.
/// A member sends at most a vertex, a certificate and one attestation per
/// author each round: R = MAX_COMMITTEE + 2 = 258 at the 256-member cap,
/// at most one round per 3 s tick (~86 a second). The burst is 4R and the
/// rate 400 a second (4.6x the average): a choice that leaves room for pull
/// traffic.
pub const MEMBER_MSG_BURST: f64 = 4.0 * (blockchain::committee::MAX_COMMITTEE as f64 + 2.0);
pub const MEMBER_MSGS_PER_SEC: f64 = 400.0;

/// NI-3: sync requests a session may send (Lighthouse's quota for
/// blocks-by-range: 128 per 10 s).
pub const SYNC_REQUESTS_PER_SEC: f64 = 12.8;
pub const SYNC_REQUEST_BURST: f64 = 128.0;

/// NI-3: a token bucket per key, `rate` tokens a second up to `burst`.
/// Spending past it only drops the message; nothing is banned (a key that
/// relays others' traffic must not be punished for it).
#[derive(Debug)]
pub struct Budget<K> {
    rate: f64,
    burst: f64,
    buckets: HashMap<K, (f64, std::time::Instant)>,
}

/// Keys a budget remembers before it forgets the idle ones; an attacker
/// chooses its PeerIds, so the map must stay bounded.
const BUDGET_KEYS: usize = 10_000;

impl<K: std::hash::Hash + Eq + Clone> Budget<K> {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            rate,
            burst,
            buckets: HashMap::new(),
        }
    }

    /// Spend one token of `key` at `now`; false when its bucket is empty.
    pub fn spend(&mut self, key: &K, now: std::time::Instant) -> bool {
        if self.buckets.len() >= BUDGET_KEYS && !self.buckets.contains_key(key) {
            let (rate, burst) = (self.rate, self.burst);
            // A bucket idle long enough is full again: forgetting it is exact.
            self.buckets.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * rate < burst
            });
            if self.buckets.len() >= BUDGET_KEYS {
                return false;
            }
        }
        let (tokens, at) = self.buckets.entry(key.clone()).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * self.rate).min(self.burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// NI-3: what the network task holds for the node while the node is busy
/// (it holds the consensus lock through a block's execution). The swarm
/// never waits on the node: a message past this many bytes is dropped, and
/// the per-tick rebroadcast brings it again. 64 MiB is a choice: ~80
/// maximal vertices, well inside a validator's memory.
pub const INBOX_MAX_BYTES: usize = 64 << 20;

/// NI-3: the messages bound for the node, bounded in bytes.
#[derive(Debug, Default)]
pub struct Inbox {
    queue: std::collections::VecDeque<String>,
    bytes: usize,
    dropped: u64,
}

impl Inbox {
    /// Queue `msg`; false (and dropped) when it would pass the byte bound.
    pub fn push(&mut self, msg: String) -> bool {
        if self.bytes + msg.len() > INBOX_MAX_BYTES {
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                eprintln!(
                    "⚠️ [NI-3] node inbox full ({} bytes): {} messages dropped so far",
                    self.bytes, self.dropped
                );
            }
            return false;
        }
        self.bytes += msg.len();
        self.queue.push_back(msg);
        true
    }

    pub fn pop(&mut self) -> Option<String> {
        let msg = self.queue.pop_front()?;
        self.bytes -= msg.len();
        Some(msg)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// The request-response behaviour of `/aincore/sync/1`.
pub fn sync_behaviour() -> request_response::Behaviour<FramedCodec> {
    request_response::Behaviour::with_codec(
        FramedCodec::new(SYNC_REQUEST_CAP, SYNC_RESPONSE_CAP),
        [(
            StreamProtocol::new(SYNC_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(60))
            .with_max_concurrent_streams(8),
    )
}

/// What a node does with a consensus request from `peer`: deliver it, as
/// the member it names, or refuse it (its response channel is dropped, so
/// the requester sees a failure, never an acknowledgement).
pub fn admit_consensus_request<'a>(book: &'a PeerBook, peer: &PeerId) -> Option<&'a str> {
    book.member_of(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::transport::MemoryTransport;
    use libp2p::core::upgrade;
    use libp2p::futures::StreamExt;
    use libp2p::swarm::{Swarm, SwarmEvent};
    use libp2p::{noise, yamux, Multiaddr, Transport};
    use std::time::Duration;

    fn member(seed: u8) -> (ValidatorInfo, [u8; 32]) {
        let secret = [seed; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public = key.verifying_key().to_bytes();
        let info = ValidatorInfo {
            address: crypto::derive_address(&public).unwrap(),
            stake: 100,
            ed25519_public_key: hex::encode(public),
            bls_public_key: String::new(),
            bls_pop: String::new(),
        };
        (info, secret)
    }

    /// W1: the libp2p identity of a node is its node key, so the PeerId a
    /// session authenticates is the one its committee entry gives.
    #[test]
    fn the_session_identity_is_the_node_key() {
        let (info, secret) = member(7);
        let peer = local_keypair(&secret).public().to_peer_id();
        assert_eq!(peer_id_of(&info.ed25519_public_key), Some(peer));
        // And it does not depend on the boot: the same key, the same PeerId.
        assert_eq!(local_keypair(&secret).public().to_peer_id(), peer);
        assert_ne!(local_keypair(&[8; 32]).public().to_peer_id(), peer);
    }

    /// W2: the book names the members of C_E and C_{E+1} and nobody else;
    /// a member that left is gone after a refresh.
    #[test]
    fn the_book_names_members_of_both_committees_only() {
        let (a, sa) = member(1);
        let (b, sb) = member(2);
        let (c, sc) = member(3);
        let (_, outsider) = member(4);
        let id = |s: &[u8; 32]| local_keypair(s).public().to_peer_id();
        let book = PeerBook::new(5, &[&[a.clone(), b.clone()], std::slice::from_ref(&c)]);
        assert_eq!(book.member_of(&id(&sa)), Some(a.address.as_str()));
        assert_eq!(book.member_of(&id(&sc)), Some(c.address.as_str()));
        assert_eq!(book.member_of(&id(&outsider)), None);
        assert_eq!(book.peer_of(&b.address), Some(id(&sb)));
        assert_eq!(book.len(), 3);
        let next = PeerBook::new(6, &[std::slice::from_ref(&c)]);
        assert_eq!(next.member_of(&id(&sa)), None, "A left");
        assert_eq!(next.epoch(), 6);
        // A malformed key is left out, never guessed.
        let mut bad = a.clone();
        bad.ed25519_public_key = "zz".into();
        assert!(PeerBook::new(1, &[&[bad]]).is_empty());
    }

    /// W6: vertices, attestations, certificates and votes are admitted from
    /// a member publisher only; a boundary QC request or answer from anyone.
    #[test]
    fn consensus_gossip_needs_a_member_publisher() {
        let (a, sa) = member(1);
        let book = PeerBook::new(0, &[&[a]]);
        let member = local_keypair(&sa).public().to_peer_id();
        let stranger = local_keypair(&[9; 32]).public().to_peer_id();
        for wire in ["DAG_V4:{}", "QC_VOTE:{}"] {
            assert!(admit_gossip(&book, Some(&member), wire), "{wire}");
            assert!(!admit_gossip(&book, Some(&stranger), wire), "{wire}");
            assert!(!admit_gossip(&book, None, wire), "{wire}");
        }
        // An observer asks for and is answered a self-verifying boundary QC.
        for wire in ["QC_WANT:7", "QC_CERT:{}", "TX:{}"] {
            assert!(admit_gossip(&book, Some(&stranger), wire), "{wire}");
        }
    }

    /// NI-3: the inbox keeps order, counts bytes exactly, and drops what
    /// would pass its bound rather than block.
    #[test]
    fn the_inbox_is_bounded_in_bytes_and_keeps_order() {
        let mut inbox = Inbox::default();
        assert!(inbox.push("a".into()) && inbox.push("bc".into()));
        assert_eq!(inbox.bytes(), 3);
        assert!(!inbox.push("x".repeat(INBOX_MAX_BYTES)), "past the bound");
        assert_eq!(inbox.pop().as_deref(), Some("a"));
        assert_eq!(inbox.pop().as_deref(), Some("bc"));
        assert!(inbox.is_empty() && inbox.bytes() == 0);
        assert!(
            inbox.push("x".repeat(INBOX_MAX_BYTES)),
            "exactly the bound fits"
        );
    }

    /// NI-3: a budget spends its burst, refuses past it, refills at its
    /// rate, keeps keys apart, and stays bounded however many keys come.
    #[test]
    fn a_budget_refills_at_its_rate_and_stays_bounded() {
        let t0 = std::time::Instant::now();
        let mut b: Budget<u32> = Budget::new(10.0, 5.0);
        assert!((0..5).all(|_| b.spend(&1, t0)), "the burst");
        assert!(!b.spend(&1, t0), "past the burst");
        assert!(b.spend(&2, t0), "another key has its own bucket");
        let later = t0 + std::time::Duration::from_millis(200);
        assert!(b.spend(&1, later) && b.spend(&1, later), "0.2 s at 10/s");
        assert!(!b.spend(&1, later));
        // Bounded: a flood of fresh keys never grows the map past the cap.
        let mut b: Budget<u64> = Budget::new(1.0, 1.0);
        for k in 0..(BUDGET_KEYS as u64 + 500) {
            b.spend(&k, t0);
        }
        assert!(b.buckets.len() <= BUDGET_KEYS);
    }

    /// The member budget is above an honest member's burst at the largest
    /// committee: a vertex, a certificate and an attestation per author.
    #[test]
    fn the_member_budget_covers_an_honest_round() {
        let round = (blockchain::committee::MAX_COMMITTEE + 2) as f64;
        assert!(MEMBER_MSG_BURST >= 4.0 * round);
        assert!(MEMBER_MSGS_PER_SEC >= 4.0 * round / 3.0);
    }

    /// W9: a frame over the cap is refused after its 4-byte length, before
    /// any of it is read; one that is not UTF-8 is refused too.
    #[test]
    fn frames_are_capped_before_they_are_read() {
        let run = |bytes: Vec<u8>, cap: usize| {
            futures::executor::block_on(async move {
                let mut io = libp2p::futures::io::Cursor::new(bytes);
                let r = read_frame(&mut io, cap).await;
                (r, io.position())
            })
        };
        let mut over = (11u32).to_be_bytes().to_vec();
        over.extend(vec![b'a'; 11]);
        let (r, read) = run(over, 10);
        assert!(
            r.is_err() && read == 4,
            "read {read} bytes of an over-cap frame"
        );
        let mut ok = (10u32).to_be_bytes().to_vec();
        ok.extend(vec![b'a'; 10]);
        assert_eq!(run(ok, 10).0.unwrap(), "a".repeat(10));
        let mut bad = (2u32).to_be_bytes().to_vec();
        bad.extend([0xff, 0xfe]);
        assert!(run(bad, 10).0.is_err());
        // A writer refuses to exceed the cap too.
        let mut sink = libp2p::futures::io::Cursor::new(Vec::new());
        assert!(futures::executor::block_on(write_frame(&mut sink, "abc", 2)).is_err());
    }

    fn swarm(key: identity::Keypair) -> Swarm<request_response::Behaviour<FramedCodec>> {
        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&key).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();
        Swarm::new(
            transport,
            consensus_behaviour(),
            key.public().to_peer_id(),
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(30)),
        )
    }

    /// What a server does in this test: the node's own rule.
    enum Seen {
        Delivered(String, String),
        Refused(PeerId),
    }

    /// W3 and W4: over real Noise sessions, a member's consensus request is
    /// acknowledged and delivered as that member; a non-member's is refused
    /// (it gets a failure, not an acknowledgement, and nothing is delivered).
    /// A forged identity cannot be claimed: the session key is the identity.
    #[tokio::test]
    async fn only_a_member_session_is_heard_on_the_consensus_protocol() {
        let (a, sa) = member(1);
        let (_, sb) = member(2);
        let book = PeerBook::new(0, &[std::slice::from_ref(&a)]);
        let mut server = swarm(local_keypair(&sb));
        let addr: Multiaddr = format!("/memory/{}", rand::random::<u64>() | 1)
            .parse()
            .unwrap();
        server.listen_on(addr.clone()).unwrap();
        let server_id = *server.local_peer_id();

        let mut member_client = swarm(local_keypair(&sa));
        let mut stranger = swarm(local_keypair(&[9; 32]));
        for c in [&mut member_client, &mut stranger] {
            c.add_peer_address(server_id, addr.clone());
        }
        member_client
            .behaviour_mut()
            .send_request(&server_id, "DAG_V4:member".into());
        stranger
            .behaviour_mut()
            .send_request(&server_id, "DAG_V4:forged".into());

        let mut seen = Vec::new();
        let (mut member_acked, mut stranger_failed, mut stranger_acked) = (false, false, false);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline
            && !(member_acked && stranger_failed && seen.len() == 2)
        {
            tokio::select! {
                ev = server.select_next_some() => {
                    if let SwarmEvent::Behaviour(request_response::Event::Message {
                        peer,
                        message: request_response::Message::Request { request, channel, .. },
                    }) = ev {
                        match admit_consensus_request(&book, &peer) {
                            Some(who) => {
                                seen.push(Seen::Delivered(who.to_string(), request));
                                let _ = server.behaviour_mut().send_response(channel, CONSENSUS_ACK.into());
                            }
                            None => {
                                seen.push(Seen::Refused(peer));
                                drop(channel);
                            }
                        }
                    }
                }
                ev = member_client.select_next_some() => {
                    if let SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Response { response, .. }, ..
                    }) = ev {
                        member_acked = response == CONSENSUS_ACK;
                    }
                }
                ev = stranger.select_next_some() => match ev {
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Response { .. }, ..
                    }) => stranger_acked = true,
                    SwarmEvent::Behaviour(request_response::Event::OutboundFailure { .. }) => {
                        stranger_failed = true;
                    }
                    _ => {}
                },
            }
        }
        assert!(member_acked, "the member was not acknowledged");
        assert!(
            stranger_failed && !stranger_acked,
            "the stranger was answered"
        );
        let delivered: Vec<(String, String)> = seen
            .iter()
            .filter_map(|s| match s {
                Seen::Delivered(w, r) => Some((w.clone(), r.clone())),
                Seen::Refused(_) => None,
            })
            .collect();
        assert_eq!(
            delivered,
            vec![(a.address.clone(), "DAG_V4:member".to_string())]
        );
        assert!(seen
            .iter()
            .any(|s| matches!(s, Seen::Refused(p) if *p == *stranger.local_peer_id())));
    }
}
