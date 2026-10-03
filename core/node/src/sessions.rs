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
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// The largest sync request. A `SYNC_REQ` is a few hundred bytes; a
/// forwarded transaction batch (`TX_SUBMIT:`, B21) is cut at this size, and
/// one maximal transaction (100 KiB, at most doubled by JSON escaping) fits.
pub const SYNC_REQUEST_CAP: usize = 256 << 10;

/// The largest sync answer (`SYNC_RESP` blocks stop at
/// `chain_sync::SYNC_RESP_BLOCK_BYTES`, 8 MiB, under it).
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

pub fn is_consensus_message(wire: &str) -> bool {
    CONSENSUS_PREFIXES.iter().any(|p| wire.starts_with(p))
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

/// B30: what a frame reserves before its bytes arrive.
const FRAME_CHUNK: usize = 64 << 10;

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
    // B30: the buffer grows with the bytes that arrive, not with the length
    // a peer declares (a 4-byte prefix used to reserve up to the cap).
    let mut buf = Vec::with_capacity(len.min(FRAME_CHUNK));
    io.take(len as u64).read_to_end(&mut buf).await?;
    if buf.len() != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the frame ended early",
        ));
    }
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
            // B30: a connection's unanswered consensus streams hold at most
            // 16 frames (a member keeps a few pushes in flight to a peer).
            .with_max_concurrent_streams(16),
    )
}

/// B30: `/aincore/consensus/1` exists only on connections whose peer a
/// committee key names. libp2p's request-response handler reads a whole
/// request before the behaviour learns who sent it, so a non-member could
/// make this node read 16 frames of up to 776 KiB per connection, on every
/// connection it holds, only for them to be dropped. A connection's handler
/// is chosen when it opens: the request-response handler for a member, one
/// that supports no protocol for anyone else (a stream is refused at
/// negotiation, before a byte of it is read). A connection keeps its handler
/// while its peer's membership changes; `misfiled` names it for the node to
/// close, and the committee dial reconnects a new member.
pub struct MembersOnly {
    inner: request_response::Behaviour<FramedCodec>,
    book: Arc<RwLock<PeerBook>>,
    /// Handlers chosen, until the connection is established or fails.
    chosen: HashMap<libp2p::swarm::ConnectionId, bool>,
    /// Connections with the request-response handler, by peer.
    served: HashMap<PeerId, Vec<libp2p::swarm::ConnectionId>>,
    /// Connections with none.
    refused: HashMap<libp2p::swarm::ConnectionId, PeerId>,
}

impl MembersOnly {
    pub fn new(book: Arc<RwLock<PeerBook>>) -> Self {
        Self {
            inner: consensus_behaviour(),
            book,
            chosen: HashMap::new(),
            served: HashMap::new(),
            refused: HashMap::new(),
        }
    }

    fn is_member(&self, peer: &PeerId) -> bool {
        self.book
            .read()
            .map(|b| b.member_of(peer).is_some())
            .unwrap_or(false)
    }

    /// Connections whose handler no longer fits their peer: a member's
    /// without the protocol, a former member's with it.
    pub fn misfiled(&self) -> Vec<(PeerId, libp2p::swarm::ConnectionId)> {
        let mut out: Vec<(PeerId, libp2p::swarm::ConnectionId)> = self
            .refused
            .iter()
            .filter(|(_, peer)| self.is_member(peer))
            .map(|(id, peer)| (*peer, *id))
            .collect();
        for (peer, ids) in &self.served {
            if !self.is_member(peer) {
                out.extend(ids.iter().map(|id| (*peer, *id)));
            }
        }
        out
    }

    fn handler(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        inner: impl FnOnce(
            &mut request_response::Behaviour<FramedCodec>,
        ) -> Result<
            libp2p::swarm::THandler<request_response::Behaviour<FramedCodec>>,
            libp2p::swarm::ConnectionDenied,
        >,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        use libp2p::swarm::derive_prelude::Either;
        let member = self.is_member(&peer);
        let handler = if member {
            Either::Left(inner(&mut self.inner)?)
        } else {
            Either::Right(libp2p::swarm::dummy::ConnectionHandler)
        };
        self.chosen.insert(connection_id, member);
        Ok(handler)
    }
}

impl std::ops::Deref for MembersOnly {
    type Target = request_response::Behaviour<FramedCodec>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for MembersOnly {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl libp2p::swarm::NetworkBehaviour for MembersOnly {
    type ConnectionHandler = libp2p::swarm::derive_prelude::Either<
        libp2p::swarm::THandler<request_response::Behaviour<FramedCodec>>,
        libp2p::swarm::dummy::ConnectionHandler,
    >;
    type ToSwarm = request_response::Event<String, String>;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<(), libp2p::swarm::ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        self.handler(connection_id, peer, |inner| {
            inner.handle_established_inbound_connection(
                connection_id,
                peer,
                local_addr,
                remote_addr,
            )
        })
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[libp2p::Multiaddr],
        effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<libp2p::Multiaddr>, libp2p::swarm::ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        addr: &libp2p::Multiaddr,
        role_override: libp2p::core::Endpoint,
        port_use: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        self.handler(connection_id, peer, |inner| {
            inner.handle_established_outbound_connection(
                connection_id,
                peer,
                addr,
                role_override,
                port_use,
            )
        })
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished};
        use libp2p::swarm::FromSwarm;
        // The inner behaviour hears only of the connections it has a handler
        // on, with the counts of those alone.
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                if self.chosen.remove(&e.connection_id) == Some(true) {
                    let ids = self.served.entry(e.peer_id).or_default();
                    let other_established = ids.len();
                    ids.push(e.connection_id);
                    self.inner.on_swarm_event(FromSwarm::ConnectionEstablished(
                        ConnectionEstablished {
                            other_established,
                            ..e
                        },
                    ));
                } else {
                    self.refused.insert(e.connection_id, e.peer_id);
                    // Requests queued for this peer while it was dialled
                    // wait for a connection with the protocol; this one has
                    // none, and no dial failure follows: fail them now.
                    let aborted = libp2p::swarm::DialError::Aborted;
                    self.inner
                        .on_swarm_event(FromSwarm::DialFailure(libp2p::swarm::DialFailure {
                            peer_id: Some(e.peer_id),
                            error: &aborted,
                            connection_id: e.connection_id,
                        }));
                }
            }
            FromSwarm::ConnectionClosed(e) => {
                if self.refused.remove(&e.connection_id).is_some() {
                    return;
                }
                let Some(ids) = self.served.get_mut(&e.peer_id) else {
                    return;
                };
                let before = ids.len();
                ids.retain(|id| *id != e.connection_id);
                if ids.len() == before {
                    return;
                }
                let remaining_established = ids.len();
                if ids.is_empty() {
                    self.served.remove(&e.peer_id);
                }
                self.inner
                    .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        remaining_established,
                        ..e
                    }));
            }
            FromSwarm::AddressChange(e) => {
                if self
                    .served
                    .get(&e.peer_id)
                    .is_some_and(|ids| ids.contains(&e.connection_id))
                {
                    self.inner.on_swarm_event(event);
                }
            }
            FromSwarm::DialFailure(e) => {
                self.chosen.remove(&e.connection_id);
                self.inner.on_swarm_event(event);
            }
            FromSwarm::ListenFailure(e) => {
                self.chosen.remove(&e.connection_id);
                self.inner.on_swarm_event(event);
            }
            other => self.inner.on_swarm_event(other),
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        use libp2p::swarm::derive_prelude::Either;
        match event {
            Either::Left(event) => {
                self.inner
                    .on_connection_handler_event(peer_id, connection_id, event)
            }
            Either::Right(never) => match never {},
        }
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>>
    {
        self.inner
            .poll(cx)
            .map(|action| action.map_in(libp2p::swarm::derive_prelude::Either::Left))
    }
}

/// G4 S1: what the network task shares with the node: the committee book,
/// the session table sync reads, the requests sync asks, and the requests
/// sessions ask it to serve.
pub struct SessionWiring {
    pub book: Arc<RwLock<PeerBook>>,
    pub table: network::SessionTable,
    pub asks: mpsc::Receiver<network::SyncAsk>,
    pub dials: mpsc::Receiver<network::SyncDial>,
    pub serves: mpsc::Sender<network::SyncServe>,
    /// B30: the bytes of answers non-members hold unread (a gauge).
    pub held_open_bytes: Arc<AtomicUsize>,
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
        let (dials_tx, dials) = mpsc::channel(16);
        let (serves, serves_rx) = mpsc::channel(64);
        (
            Self {
                book,
                table: Arc::clone(&table),
                asks,
                dials,
                serves,
                held_open_bytes: Arc::default(),
            },
            network::SessionClient {
                asks: asks_tx,
                dials: dials_tx,
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

/// B40: outbound connections to peers no committee key names (Kademlia's
/// bootstrap dials peers others named), all together. The same count as
/// inbound, a choice.
pub const MAX_NON_MEMBER_OUTBOUND: usize = 50;

/// B43: saved peer addresses dialled at boot (members and bootnodes are
/// the only ones saved now; older rows are capped here, a choice).
pub const MAX_SAVED_PEERS: usize = 64;

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

    /// B60: take `tokens` more from `key` after the fact (an answer's size is
    /// known once it is made). The bucket may go below zero, down to
    /// `-burst`, and the key's next requests wait for it to refill.
    pub fn charge(&mut self, key: &K, tokens: f64, now: std::time::Instant) {
        if let Some((held, at)) = self.buckets.get_mut(key) {
            *held = (*held + now.duration_since(*at).as_secs_f64() * self.rate).min(self.burst);
            *at = now;
            *held = (*held - tokens).max(-self.burst);
        }
    }
}

/// B60: a non-member's sync answer costs one more token of its budget for
/// each this many bytes (a choice: at 12.8 tokens a second a host is served
/// ~820 KiB/s; the request count alone let a few hosts keep every serving
/// thread busy with 8 MiB answers).
pub const SYNC_ANSWER_TOKEN_BYTES: usize = 64 << 10;

/// B60: the tokens an answer of `len` bytes costs beyond its request's.
pub fn answer_tokens(len: usize) -> f64 {
    (len / SYNC_ANSWER_TOKEN_BYTES) as f64
}

/// B24: how long a connection may take to finish Noise and yamux. A
/// handshake is ~1.5 round trips; 10 s is a choice far above any honest
/// one. The transport had no timeout: a connection that never finished
/// held a descriptor and a task for good.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// B24: unfinished inbound handshakes held at once, in all (a choice).
pub const MAX_PENDING_INBOUND: u32 = 128;
/// B24: unfinished inbound handshakes from one IP at once (a choice: one
/// host runs a few nodes).
pub const PENDING_PER_IP: usize = 4;
/// B24 (NI-2's IP admission rate): new inbound connections an IP may open,
/// per second and in a burst (choices: a node dials a peer a handful of
/// times per boot).
pub const ADMIT_PER_IP_PER_SEC: f64 = 2.0;
pub const ADMIT_BURST_PER_IP: f64 = 16.0;
/// B56: unfinished handshakes kept for IPs members connected from (a
/// choice: four members reconnecting at once, `PENDING_PER_IP` each). The
/// rest of `MAX_PENDING_INBOUND` is all other IPs': ~28 IPs holding silent
/// handshakes used to fill every slot and keep a restarted member out.
pub const PENDING_KEPT_FOR_MEMBERS: usize = 16;
/// B56: member IPs remembered at most.
pub const MAX_MEMBER_IPS: usize = 1024;

/// B56: the IPs committee members connected from, which the network task
/// adds to and the gate reads.
pub type MemberIps = Arc<RwLock<std::collections::HashSet<std::net::IpAddr>>>;

/// B24: inbound admission before any handshake. Every cap of the network
/// task runs once a connection is established, after the Noise handshake
/// it costs; this gate refuses a connection from an IP that holds
/// `PENDING_PER_IP` unfinished ones or has spent its admission budget,
/// before the handshake starts.
#[derive(Debug)]
pub struct InboundGate {
    pending: HashMap<libp2p::swarm::ConnectionId, std::net::IpAddr>,
    admit: Budget<std::net::IpAddr>,
    member_ips: MemberIps,
}

impl Default for InboundGate {
    fn default() -> Self {
        Self::with_member_ips(MemberIps::default())
    }
}

impl InboundGate {
    /// A gate that keeps `PENDING_KEPT_FOR_MEMBERS` slots for `member_ips`.
    pub fn with_member_ips(member_ips: MemberIps) -> Self {
        Self {
            pending: HashMap::new(),
            admit: Budget::new(ADMIT_PER_IP_PER_SEC, ADMIT_BURST_PER_IP),
            member_ips,
        }
    }
}

fn ip_of(addr: &libp2p::Multiaddr) -> Option<std::net::IpAddr> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.into()),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.into()),
        _ => None,
    })
}

impl libp2p::swarm::NetworkBehaviour for InboundGate {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        _local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<(), libp2p::swarm::ConnectionDenied> {
        let Some(ip) = ip_of(remote_addr) else {
            return Ok(());
        };
        let denied =
            |why: &str| libp2p::swarm::ConnectionDenied::new(io::Error::other(why.to_string()));
        if self.pending.values().filter(|p| **p == ip).count() >= PENDING_PER_IP {
            return Err(denied("too many unfinished handshakes from this IP"));
        }
        // B56: other IPs share all but the slots kept for members'.
        if let Ok(members) = self.member_ips.read() {
            let others = self
                .pending
                .values()
                .filter(|p| !members.contains(p))
                .count();
            let limit = MAX_PENDING_INBOUND as usize - PENDING_KEPT_FOR_MEMBERS;
            if !members.contains(&ip) && others >= limit {
                return Err(denied(
                    "the unfinished handshakes of other IPs are at their bound",
                ));
            }
        }
        if !self.admit.spend(&ip, std::time::Instant::now()) {
            return Err(denied("this IP opens connections too fast"));
        }
        self.pending.insert(connection_id, ip);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        self.pending.remove(&connection_id);
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        if let libp2p::swarm::FromSwarm::ListenFailure(failure) = event {
            self.pending.remove(&failure.connection_id);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>>
    {
        std::task::Poll::Pending
    }
}

/// NI-3: what the network task holds for the node while the node is busy
/// (it holds the consensus lock through a block's execution). The swarm
/// never waits on the node: a message past this many bytes is dropped, and
/// the per-tick rebroadcast brings it again. 64 MiB is a choice: ~80
/// maximal vertices, well inside a validator's memory.
pub const INBOX_MAX_BYTES: usize = 64 << 20;

/// B55: one source's share of the inbox (a choice: a quarter, ~20 maximal
/// vertices). A source is a member's address, or the peer a boundary QC was
/// asked of.
pub const INBOX_SOURCE_MAX_BYTES: usize = INBOX_MAX_BYTES / 4;

/// NI-3 (B55): the messages bound for the node, a queue per source, handed
/// to the node in turn. One FIFO let one member's flood fill the inbox and
/// stand ahead of every other member's messages. A source holds at most
/// `INBOX_SOURCE_MAX_BYTES`; when the whole inbox is full, the longest queue
/// gives up its newest messages to a shorter one's.
#[derive(Debug, Default)]
pub struct Inbox {
    /// Each source's messages, oldest first, and their bytes.
    queues: HashMap<String, (std::collections::VecDeque<String>, usize)>,
    /// The sources with something queued, in turn order.
    turn: std::collections::VecDeque<String>,
    bytes: usize,
    dropped: u64,
}

impl Inbox {
    /// Queue `msg` from `source`; false (and dropped) when it would pass the
    /// source's share, or the whole bound with no longer queue to give way.
    pub fn push(&mut self, source: &str, msg: String) -> bool {
        let len = msg.len();
        let held = self.queues.get(source).map_or(0, |(_, b)| *b);
        if held + len > INBOX_SOURCE_MAX_BYTES {
            return self.refuse();
        }
        while self.bytes + len > INBOX_MAX_BYTES {
            let longest = self
                .queues
                .iter()
                .filter(|(s, _)| s.as_str() != source)
                .max_by_key(|(_, (_, b))| *b)
                .map(|(s, (_, b))| (s.clone(), *b));
            match longest {
                Some((victim, bytes)) if bytes > held + len => self.evict_newest(&victim),
                _ => return self.refuse(),
            }
        }
        let (queue, bytes) = self.queues.entry(source.to_string()).or_default();
        if queue.is_empty() {
            self.turn.push_back(source.to_string());
        }
        queue.push_back(msg);
        *bytes += len;
        self.bytes += len;
        true
    }

    fn evict_newest(&mut self, source: &str) {
        let Some((queue, bytes)) = self.queues.get_mut(source) else {
            return;
        };
        if let Some(msg) = queue.pop_back() {
            *bytes -= msg.len();
            self.bytes -= msg.len();
            self.dropped += 1;
        }
        if queue.is_empty() {
            self.queues.remove(source);
            self.turn.retain(|s| s != source);
        }
    }

    fn refuse(&mut self) -> bool {
        self.dropped += 1;
        if self.dropped.is_power_of_two() {
            eprintln!(
                "⚠️ [NI-3] node inbox full ({} bytes): {} messages dropped so far",
                self.bytes, self.dropped
            );
        }
        false
    }

    /// The next message, from the next source in turn, with its source
    /// (B51: the node holds a source to account for what fails).
    pub fn pop(&mut self) -> Option<(String, String)> {
        let source = self.turn.pop_front()?;
        let (queue, bytes) = self.queues.get_mut(&source)?;
        let msg = queue.pop_front()?;
        *bytes -= msg.len();
        self.bytes -= msg.len();
        if queue.is_empty() {
            self.queues.remove(&source);
        } else {
            self.turn.push_back(source.clone());
        }
        Some((source, msg))
    }

    pub fn is_empty(&self) -> bool {
        self.turn.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// B30: answers handed to non-members and not yet written, all together.
/// A choice: the inbox's bound, six answers at the 10 MiB response cap.
pub const OPEN_HELD_MAX_BYTES: usize = 64 << 20;

/// B30: a requester that stops reading holds every answer it was sent
/// until its request times out (60 s), and free identities on many hosts
/// add up. An answer to a non-member counts from hand-off until it is
/// written or fails; past `OPEN_HELD_MAX_BYTES` a new one is refused.
#[derive(Debug)]
pub struct HeldAnswers<K> {
    held: HashMap<K, usize>,
    bytes: Arc<AtomicUsize>,
}

impl<K: std::hash::Hash + Eq> HeldAnswers<K> {
    pub fn new(bytes: Arc<AtomicUsize>) -> Self {
        bytes.store(0, Ordering::Relaxed);
        Self {
            held: HashMap::new(),
            bytes,
        }
    }

    /// Count `len` bytes for `id`; false (nothing counted) when that would
    /// pass the bound.
    pub fn admit(&mut self, id: K, len: usize) -> bool {
        let now = self.bytes.load(Ordering::Relaxed);
        if now.saturating_add(len) > OPEN_HELD_MAX_BYTES {
            return false;
        }
        let before = self.held.insert(id, len).unwrap_or(0);
        self.bytes.store(now + len - before, Ordering::Relaxed);
        true
    }

    /// `id`'s answer was written, or failed: its bytes are free.
    pub fn release(&mut self, id: &K) {
        if let Some(len) = self.held.remove(id) {
            self.bytes.fetch_sub(len, Ordering::Relaxed);
        }
    }

    pub fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// G4 S6: a sync peer given as `host:port` (its base port, as bootnodes
/// are) is its libp2p address `/ip4|ip6|dns4/host/tcp/(port+100)`; a
/// multiaddr (optionally ending `/p2p/<PeerId>`, which pins its key) is
/// taken as is.
pub fn sync_peer_multiaddr(peer: &str) -> Result<String, String> {
    let peer = peer.trim();
    if peer.starts_with('/') {
        return peer
            .parse::<libp2p::Multiaddr>()
            .map(|a| a.to_string())
            .map_err(|e| format!("{peer}: {e}"));
    }
    let (host, port) = peer
        .rsplit_once(':')
        .ok_or_else(|| format!("{peer}: want host:port or a multiaddr"))?;
    let port = port
        .parse::<u16>()
        .ok()
        .and_then(|p| p.checked_add(100))
        .ok_or_else(|| format!("{peer}: port must be a base port below 65436"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("{peer}: no host"));
    }
    let proto = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => "ip4",
        Ok(std::net::IpAddr::V6(_)) => "ip6",
        Err(_) => "dns4",
    };
    let addr = format!("/{proto}/{host}/tcp/{port}");
    addr.parse::<libp2p::Multiaddr>()
        .map(|a| a.to_string())
        .map_err(|e| format!("{peer}: {e}"))
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

/// B22: an operator's bootnode, given by its base port (`host:port`, or a
/// multiaddr carrying the base port), as the libp2p address it is dialled
/// at (base + 100; a `/p2p/<PeerId>` suffix is kept).
pub fn libp2p_bootnode(given: &str) -> Result<String, String> {
    use libp2p::multiaddr::Protocol;
    let given = given.trim();
    if !given.starts_with('/') {
        return sync_peer_multiaddr(given);
    }
    let addr: libp2p::Multiaddr = given.parse().map_err(|e| format!("{given}: {e}"))?;
    let mut out = libp2p::Multiaddr::empty();
    let mut mapped = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Tcp(port) if !mapped => {
                let port = port
                    .checked_add(100)
                    .ok_or_else(|| format!("{given}: port must be a base port below 65436"))?;
                out.push(Protocol::Tcp(port));
                mapped = true;
            }
            other => out.push(other),
        }
    }
    if mapped {
        Ok(out.to_string())
    } else {
        Err(format!("{given}: no tcp port"))
    }
}

/// B22: whether another host can dial `addr`: not loopback, unspecified,
/// link-local, or on a Docker bridge (172.16.0.0/12, which leaks through
/// identify when nodes run in containers).
pub fn routable_for_others(addr: &libp2p::Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    addr.iter().all(|proto| match proto {
        Protocol::Ip4(ip) => {
            let o = ip.octets();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || (o[0] == 172 && (16..=31).contains(&o[1])))
        }
        Protocol::Ip6(ip) => !(ip.is_loopback() || ip.is_unspecified()),
        _ => true,
    })
}

/// B22: what a node dials at boot. The operator's bootnodes, mapped to their
/// libp2p port; then the addresses saved from earlier sessions, which are
/// libp2p addresses already (mapping them again dialled base + 200) and are
/// kept only when another host could dial them (a peer's loopback address
/// is its own). No address twice.
pub fn boot_dial_list(bootnodes: &[String], saved: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for given in bootnodes {
        match libp2p_bootnode(given) {
            Ok(addr) if !out.contains(&addr) => out.push(addr),
            Ok(_) => {}
            Err(e) => eprintln!("⚠️ bootnode ignored: {e}"),
        }
    }
    for addr in saved {
        let routable = addr
            .parse::<libp2p::Multiaddr>()
            .is_ok_and(|a| routable_for_others(&a));
        if routable && !out.contains(addr) {
            out.push(addr.clone());
        }
    }
    out
}

/// `addr` without a trailing `/p2p/<PeerId>`.
pub fn without_peer(addr: &libp2p::Multiaddr) -> libp2p::Multiaddr {
    let mut addr = addr.clone();
    if matches!(
        addr.iter().last(),
        Some(libp2p::multiaddr::Protocol::P2p(_))
    ) {
        addr.pop();
    }
    addr
}

/// B22: bootnodes given without a PeerId, dialled again until a session
/// this node dialled opens from that address (only a dial proves it: a
/// peer's identify could claim any address, B40). A node that booted before its peers
/// otherwise never reached them: a bootnode is dialled once, and without a
/// PeerId it is in no routing table. Redials back off from
/// `REDIAL_FIRST` doubling to `REDIAL_MAX` (a choice: a member that comes
/// up late is reached within a minute, a dead bootnode costs one dial a
/// minute).
#[derive(Debug, Default)]
pub struct Unresolved(Vec<(libp2p::Multiaddr, std::time::Instant, u32)>);

pub const REDIAL_FIRST: std::time::Duration = std::time::Duration::from_secs(5);
pub const REDIAL_MAX: std::time::Duration = std::time::Duration::from_secs(60);

impl Unresolved {
    /// `dial_list` was dialled at `now` (boot).
    pub fn new(dial_list: &[String], now: std::time::Instant) -> Self {
        Self(
            dial_list
                .iter()
                .filter_map(|a| a.parse::<libp2p::Multiaddr>().ok())
                .filter(|a| !matches!(a.iter().last(), Some(libp2p::multiaddr::Protocol::P2p(_))))
                .map(|a| (a, now + REDIAL_FIRST, 0))
                .collect(),
        )
    }

    /// A dial at `addr` opened a session: that bootnode is resolved.
    /// Returns whether it was one.
    pub fn resolved(&mut self, addr: &libp2p::Multiaddr) -> bool {
        let addr = without_peer(addr);
        let before = self.0.len();
        self.0.retain(|(a, _, _)| *a != addr);
        self.0.len() != before
    }

    /// The bootnodes to dial at `now`; each is then due again after twice
    /// its last wait, at most `REDIAL_MAX`.
    pub fn due(&mut self, now: std::time::Instant) -> Vec<libp2p::Multiaddr> {
        let mut out = Vec::new();
        for (addr, next, tries) in &mut self.0 {
            if *next <= now {
                out.push(addr.clone());
                *tries = tries.saturating_add(1);
                let wait = REDIAL_FIRST
                    .saturating_mul(1 << (*tries).min(16))
                    .min(REDIAL_MAX);
                *next = now + wait;
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
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

    /// G4 S6: restore peers keep their `host:port` form (the base port, as
    /// bootnodes) and may pin a key with a full multiaddr.
    #[test]
    fn a_sync_peer_is_its_libp2p_address() {
        assert_eq!(
            sync_peer_multiaddr("192.168.18.202:9022").unwrap(),
            "/ip4/192.168.18.202/tcp/9122"
        );
        assert_eq!(
            sync_peer_multiaddr("node.example:9002").unwrap(),
            "/dns4/node.example/tcp/9102"
        );
        assert_eq!(
            sync_peer_multiaddr("[::1]:9000").unwrap(),
            "/ip6/::1/tcp/9100"
        );
        let pinned = format!(
            "/ip4/10.0.0.1/tcp/9102/p2p/{}",
            local_keypair(&[3; 32]).public().to_peer_id()
        );
        assert_eq!(sync_peer_multiaddr(&pinned).unwrap(), pinned);
        assert!(sync_peer_multiaddr("10.0.0.1:65436").is_err());
        assert!(sync_peer_multiaddr(":9022").is_err());
        assert!(sync_peer_multiaddr("10.0.0.1").is_err());
    }

    /// NI-3: the inbox keeps order, counts bytes exactly, and drops what
    /// would pass its bound rather than block.
    #[test]
    fn the_inbox_is_bounded_in_bytes_and_keeps_order() {
        let mut inbox = Inbox::default();
        assert!(inbox.push("m", "a".into()) && inbox.push("m", "bc".into()));
        assert_eq!(inbox.bytes(), 3);
        assert!(
            !inbox.push("m", "x".repeat(INBOX_SOURCE_MAX_BYTES)),
            "past the source's share"
        );
        assert_eq!(inbox.pop(), Some(("m".into(), "a".into())));
        assert_eq!(inbox.pop(), Some(("m".into(), "bc".into())));
        assert!(inbox.is_empty() && inbox.bytes() == 0);
        assert!(
            inbox.push("m", "x".repeat(INBOX_SOURCE_MAX_BYTES)),
            "exactly the share fits"
        );
    }

    /// B55 witness: members that flood fill their own shares; an honest
    /// member's message is still taken, and the node gets it in its turn,
    /// not behind the floods. With every share full, the longest queue gives
    /// way to a shorter one.
    #[test]
    fn a_flooding_member_cannot_crowd_out_the_others() {
        let mut inbox = Inbox::default();
        let big = "x".repeat(1 << 20);
        for flooder in ["f1", "f2", "f3", "f4"] {
            while inbox.push(flooder, big.clone()) {}
        }
        assert_eq!(inbox.bytes(), INBOX_MAX_BYTES, "the floods fill the inbox");
        assert!(inbox.push("honest", "vertex".into()), "room is made");
        let mut order = Vec::new();
        while let Some((_, msg)) = inbox.pop() {
            order.push(msg);
            if order.last().map(String::as_str) == Some("vertex") {
                break;
            }
        }
        assert!(
            order.len() <= 5,
            "the honest message came after {} others",
            order.len() - 1
        );
    }

    /// B30: held answers count exactly, refuse past the bound, and free
    /// their bytes once (a second release of one id frees nothing).
    #[test]
    fn held_answers_are_bounded_and_released_once() {
        let gauge = Arc::new(AtomicUsize::new(7));
        let mut held: HeldAnswers<u32> = HeldAnswers::new(Arc::clone(&gauge));
        assert_eq!(held.bytes(), 0, "a new tracker starts the gauge at zero");
        let part = OPEN_HELD_MAX_BYTES / 4;
        assert!(
            (0..4).all(|id| held.admit(id, part)),
            "exactly the bound fits"
        );
        assert!(!held.admit(4, 1), "past the bound");
        assert_eq!(gauge.load(Ordering::Relaxed), OPEN_HELD_MAX_BYTES);
        held.release(&0);
        held.release(&0);
        held.release(&9);
        assert_eq!(held.bytes(), OPEN_HELD_MAX_BYTES - part);
        assert!(held.admit(4, part), "freed bytes are admitted again");
        (1..5).for_each(|id| held.release(&id));
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
    }

    /// B56 witness: with every slot other IPs may use held by silent
    /// handshakes, a new IP is refused and a member's IP is still admitted.
    #[test]
    fn slots_are_kept_for_members_ips() {
        use libp2p::swarm::NetworkBehaviour;
        let members = MemberIps::default();
        let member: std::net::IpAddr = "10.9.9.9".parse().unwrap();
        members.write().unwrap().insert(member);
        let mut gate = InboundGate::with_member_ips(members);
        let local: libp2p::Multiaddr = "/ip4/10.0.0.1/tcp/9101".parse().unwrap();
        let from =
            |ip: String| -> libp2p::Multiaddr { format!("/ip4/{ip}/tcp/40000").parse().unwrap() };
        let (mut ok, mut next) = (0, 0usize);
        for i in 0..64u32 {
            let ip = format!("192.0.2.{i}");
            for _ in 0..PENDING_PER_IP {
                next += 1;
                let id = libp2p::swarm::ConnectionId::new_unchecked(next);
                if gate
                    .handle_pending_inbound_connection(id, &local, &from(ip.clone()))
                    .is_ok()
                {
                    ok += 1;
                }
            }
        }
        assert_eq!(
            ok,
            MAX_PENDING_INBOUND as usize - PENDING_KEPT_FOR_MEMBERS,
            "other IPs' share"
        );
        let id = libp2p::swarm::ConnectionId::new_unchecked(999_999);
        assert!(gate
            .handle_pending_inbound_connection(id, &local, &from("198.51.100.1".into()))
            .is_err());
        let id = libp2p::swarm::ConnectionId::new_unchecked(999_998);
        assert!(
            gate.handle_pending_inbound_connection(id, &local, &from(member.to_string()))
                .is_ok(),
            "a member's IP was kept out"
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
        // B30: a frame that ends before its declared length is refused.
        let mut short = (10u32).to_be_bytes().to_vec();
        short.extend(b"abc");
        assert!(run(short, 10).0.is_err());
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

    /// B22: a bootnode is given by base port and dialled at base + 100,
    /// once; a malformed one is refused.
    #[test]
    fn a_bootnode_is_dialled_at_its_base_port_plus_100() {
        let id = local_keypair(&[3; 32]).public().to_peer_id();
        for (given, dialled) in [
            (
                "/ip4/192.168.18.202/tcp/9411",
                "/ip4/192.168.18.202/tcp/9511".to_string(),
            ),
            (
                "192.168.18.66:9413",
                "/ip4/192.168.18.66/tcp/9513".to_string(),
            ),
            (
                "seed.example:9002",
                "/dns4/seed.example/tcp/9102".to_string(),
            ),
            ("[::1]:9000", "/ip6/::1/tcp/9100".to_string()),
            (
                &format!("/dns4/seed/tcp/9002/p2p/{id}"),
                format!("/dns4/seed/tcp/9102/p2p/{id}"),
            ),
        ] {
            assert_eq!(
                libp2p_bootnode(given).as_deref(),
                Ok(dialled.as_str()),
                "{given}"
            );
        }
        for bad in [
            "/ip4/1.2.3.4/udp/9000",
            "/ip4/1.2.3.4/tcp/65500",
            "nonsense",
        ] {
            assert!(libp2p_bootnode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_addresses_another_host_can_dial_are_routable() {
        let r = |a: &str| routable_for_others(&a.parse().unwrap());
        for yes in [
            "/ip4/192.168.18.66/tcp/9514",
            "/ip4/8.8.8.8/tcp/1",
            "/dns4/seed/tcp/1",
        ] {
            assert!(r(yes), "{yes}");
        }
        for no in [
            "/ip4/127.0.0.1/tcp/9511",
            "/ip4/0.0.0.0/tcp/9511",
            "/ip4/169.254.1.1/tcp/1",
            "/ip4/172.23.0.1/tcp/9032",
            "/ip6/::1/tcp/1",
        ] {
            assert!(!r(no), "{no}");
        }
    }

    /// B22 witness (the rehearsal's restart): saved addresses are libp2p
    /// addresses and are dialled as they are, not at +100 again (d1 dialled
    /// d4 at 9614 and never reached it); a peer's saved loopback address is
    /// dropped; the operator's bootnodes are mapped once, loopback included.
    #[test]
    fn the_boot_dial_list_maps_bootnodes_once_and_keeps_saved_addresses() {
        let id = local_keypair(&[4; 32]).public().to_peer_id();
        let saved = vec![
            format!("/ip4/192.168.18.66/tcp/9514/p2p/{id}"),
            format!("/ip4/127.0.0.1/tcp/9513/p2p/{id}"),
            "/ip4/192.168.18.202/tcp/9512".to_string(),
        ];
        let bootnodes = vec![
            "/ip4/192.168.18.202/tcp/9412".to_string(),
            "127.0.0.1:9000".to_string(),
        ];
        assert_eq!(
            boot_dial_list(&bootnodes, &saved),
            vec![
                "/ip4/192.168.18.202/tcp/9512".to_string(),
                "/ip4/127.0.0.1/tcp/9100".to_string(),
                format!("/ip4/192.168.18.66/tcp/9514/p2p/{id}"),
            ]
        );
    }

    /// B22: a bootnode without a PeerId is redialled, backing off from 5 s
    /// to 60 s, until a dial reaches it or a peer's identify names it (with
    /// or without the PeerId on the address).
    #[test]
    fn a_bootnode_is_redialled_with_backoff_until_reached() {
        use std::time::{Duration, Instant};
        let id = local_keypair(&[5; 32]).public().to_peer_id();
        let list = vec![
            "/ip4/192.168.18.66/tcp/9514".to_string(),
            "/ip4/192.168.18.66/tcp/9513".to_string(),
            format!("/ip4/192.168.18.202/tcp/9512/p2p/{id}"),
        ];
        let t0 = Instant::now();
        let mut due = Unresolved::new(&list, t0);
        assert_eq!(
            due.len(),
            2,
            "a PeerId-pinned address is routed, not redialled"
        );
        assert!(due.due(t0).is_empty(), "dialled at boot");
        let mut at = Vec::new();
        let mut t = t0;
        for _ in 0..240 {
            t += Duration::from_secs(1);
            if !due.due(t).is_empty() {
                at.push((t - t0).as_secs());
            }
        }
        assert_eq!(
            at,
            [5, 15, 35, 75, 135, 195],
            "5 s doubling, capped at 60 s"
        );
        let reached: libp2p::Multiaddr = format!("/ip4/192.168.18.66/tcp/9514/p2p/{id}")
            .parse()
            .unwrap();
        assert!(due.resolved(&reached));
        assert!(!due.resolved(&reached), "once");
        assert_eq!(
            due.due(t + REDIAL_MAX),
            ["/ip4/192.168.18.66/tcp/9513"
                .parse::<libp2p::Multiaddr>()
                .unwrap()]
        );
    }

    /// B24 witness: before any handshake, an IP holding `PENDING_PER_IP`
    /// unfinished connections, or one past its admission burst, is refused;
    /// another IP is not; a finished or failed handshake frees its place.
    #[test]
    fn the_gate_admits_per_ip_before_the_handshake() {
        use libp2p::swarm::{ConnectionId, NetworkBehaviour};
        let mut gate = InboundGate::default();
        let local: Multiaddr = "/ip4/10.0.0.1/tcp/9101".parse().unwrap();
        let from = |ip: &str| -> Multiaddr { format!("/ip4/{ip}/tcp/40000").parse().unwrap() };
        let ids: Vec<ConnectionId> = (0..PENDING_PER_IP + 1)
            .map(|_| ConnectionId::new_unchecked(rand::random::<u32>() as usize))
            .collect();
        for id in &ids[..PENDING_PER_IP] {
            assert!(gate
                .handle_pending_inbound_connection(*id, &local, &from("6.6.6.6"))
                .is_ok());
        }
        assert!(
            gate.handle_pending_inbound_connection(ids[PENDING_PER_IP], &local, &from("6.6.6.6"))
                .is_err(),
            "a fifth unfinished handshake from one IP"
        );
        let other = ConnectionId::new_unchecked(7);
        assert!(gate
            .handle_pending_inbound_connection(other, &local, &from("7.7.7.7"))
            .is_ok());
        let peer = local_keypair(&[1; 32]).public().to_peer_id();
        assert!(gate
            .handle_established_inbound_connection(ids[0], peer, &local, &from("6.6.6.6"))
            .is_ok());
        assert!(
            gate.handle_pending_inbound_connection(ids[PENDING_PER_IP], &local, &from("6.6.6.6"))
                .is_ok(),
            "a finished handshake freed its place"
        );
        // The admission burst: 16 per IP, then refused at once.
        let mut burst = InboundGate::default();
        let admitted = (0..32)
            .filter(|i| {
                let id = ConnectionId::new_unchecked(1000 + i);
                let ok = burst
                    .handle_pending_inbound_connection(id, &local, &from("8.8.8.8"))
                    .is_ok();
                if ok {
                    burst.pending.remove(&id);
                }
                ok
            })
            .count();
        assert_eq!(admitted, ADMIT_BURST_PER_IP as usize);
        // An address without an IP (the memory transport) is not gated.
        assert!(burst
            .handle_pending_inbound_connection(
                ConnectionId::new_unchecked(5),
                &local,
                &"/memory/1".parse().unwrap()
            )
            .is_ok());
    }
}
