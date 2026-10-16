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

/// B200: the largest answer to a height, finality or QC request: a few KB
/// (a height, or one QC: fixed-width hashes, a bitmap of at most 32 bytes, a
/// 96-byte aggregate), so 64 KiB (a choice). Every answer took
/// `SYNC_RESPONSE_CAP`, read on to the 60 s timeout after the asker gave up:
/// a peer answering each GET_HEIGHT with a slow 10 MiB frame held up to 80
/// MiB a session.
pub const SMALL_ANSWER_CAP: usize = 64 << 10;

/// B200: the largest answer to a forwarded batch: `FORWARD_BATCH` verdicts,
/// each a hash or a reason of a few hundred bytes (a choice).
pub const SUBMIT_ANSWER_CAP: usize = 256 << 10;

/// B200: the cap of the answer to `request`, at most `cap`.
pub fn answer_cap(request: &str, cap: usize) -> usize {
    let small = request == "GET_HEIGHT"
        || request == "GET_FINALITY"
        || request.starts_with(consensus::dag::QC_WANT_PREFIX);
    if small {
        cap.min(SMALL_ANSWER_CAP)
    } else if request.starts_with(crate::forward::TX_SUBMIT) {
        cap.min(SUBMIT_ANSWER_CAP)
    } else {
        cap
    }
}

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
    /// B122: the current committee's stake by member address.
    stakes: HashMap<String, u64>,
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
        if let Some(current) = committees.first() {
            for member in current.iter() {
                book.stakes.insert(member.address.clone(), member.stake);
            }
        }
        book
    }

    /// B122: the current committee's stake by member address.
    pub fn stakes(&self) -> &HashMap<String, u64> {
        &self.stakes
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
/// `Q` is the request's type: a `String`, or (B89) an `Arc<str>` for the
/// consensus protocol, whose broadcast hands every member the same bytes
/// (it cloned the wire, up to ~776 KiB, once per member, and the copies
/// lived while slow members read).
pub struct FramedCodec<Q = String> {
    request_cap: usize,
    response_cap: usize,
    /// B200: the cap of the answer to the request this stream sent (each
    /// outbound stream writes its request, then reads the answer, with one
    /// clone of the codec).
    answer_cap: usize,
    request: std::marker::PhantomData<fn() -> Q>,
}

/// B89: the consensus protocol's codec.
pub type ConsensusCodec = FramedCodec<Arc<str>>;

impl<Q> Clone for FramedCodec<Q> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Q> Copy for FramedCodec<Q> {}

impl<Q> std::fmt::Debug for FramedCodec<Q> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedCodec")
            .field("request_cap", &self.request_cap)
            .field("response_cap", &self.response_cap)
            .finish()
    }
}

impl<Q> FramedCodec<Q> {
    pub fn new(request_cap: usize, response_cap: usize) -> Self {
        Self {
            request_cap,
            response_cap,
            answer_cap: response_cap,
            request: std::marker::PhantomData,
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
impl<Q> request_response::Codec for FramedCodec<Q>
where
    Q: From<String> + AsRef<str> + Send + Sync + 'static,
{
    type Protocol = StreamProtocol;
    type Request = Q;
    type Response = String;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Q>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.request_cap).await.map(Q::from)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<String>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.answer_cap).await
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Q) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.answer_cap = answer_cap(req.as_ref(), self.response_cap);
        write_frame(io, req.as_ref(), self.request_cap).await
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
pub fn consensus_behaviour() -> request_response::Behaviour<ConsensusCodec> {
    request_response::Behaviour::with_codec(
        ConsensusCodec::consensus(),
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
    inner: request_response::Behaviour<ConsensusCodec>,
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
            &mut request_response::Behaviour<ConsensusCodec>,
        ) -> Result<
            libp2p::swarm::THandler<request_response::Behaviour<ConsensusCodec>>,
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
    type Target = request_response::Behaviour<ConsensusCodec>;
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
        libp2p::swarm::THandler<request_response::Behaviour<ConsensusCodec>>,
        libp2p::swarm::dummy::ConnectionHandler,
    >;
    type ToSwarm = request_response::Event<Arc<str>, String>;

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

/// B75: the network group of a host, as Bitcoin Core groups peers
/// (`NetGroupManager::GetGroup`, read 2026-10-04): an IPv4 address by its
/// /16, an IPv6 one by its /32; a name, or nothing, stands alone.
pub fn net_group(host: &str) -> String {
    use std::net::IpAddr;
    let group_v4 = |o: [u8; 4]| format!("{}.{}", o[0], o[1]);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => group_v4(v4.octets()),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => group_v4(v4.octets()),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}", s[0], s[1])
            }
        },
        Err(_) => host.to_string(),
    }
}

/// B75: what a full table of inbound non-member connections does with a
/// new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundAdmission<C> {
    Admitted,
    /// Admitted in the place of this connection, which is closed.
    Evicted(C),
    Refused,
}

/// B75: the inbound non-member connections and their network groups. The
/// slots were first come: 25 IPv4 hosts at two identities each held all 50
/// and kept them with a request every 15 s. Full, a newcomer takes the slot
/// of the youngest connection of the group with the most connections, when
/// that group holds at least two more than the newcomer's (Bitcoin Core
/// evicts from the network group with the most connections and keeps the
/// half connected longest, `SelectNodeToEvict`); otherwise it is refused, so
/// filling the slots for good takes as many groups as slots.
#[derive(Debug)]
pub struct NonMemberInbound<C> {
    held: HashMap<C, (String, u64)>,
    next: u64,
}

impl<C> Default for NonMemberInbound<C> {
    fn default() -> Self {
        Self {
            held: HashMap::new(),
            next: 0,
        }
    }
}

impl<C: std::hash::Hash + Eq + Clone> NonMemberInbound<C> {
    pub fn admit(&mut self, id: C, group: &str) -> InboundAdmission<C> {
        let mut admitted = InboundAdmission::Admitted;
        if self.held.len() >= MAX_NON_MEMBER_INBOUND {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for (g, _) in self.held.values() {
                *counts.entry(g.as_str()).or_insert(0) += 1;
            }
            let mine = counts.get(group).copied().unwrap_or(0);
            let Some((largest, most)) = counts
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
                .map(|(g, n)| (g.to_string(), *n))
            else {
                return InboundAdmission::Refused;
            };
            if most < mine + 2 {
                return InboundAdmission::Refused;
            }
            let Some(victim) = self
                .held
                .iter()
                .filter(|(_, (g, _))| *g == largest)
                .max_by_key(|(_, (_, seq))| *seq)
                .map(|(c, _)| c.clone())
            else {
                return InboundAdmission::Refused;
            };
            self.held.remove(&victim);
            admitted = InboundAdmission::Evicted(victim);
        }
        self.held.insert(id, (group.to_string(), self.next));
        self.next += 1;
        admitted
    }

    pub fn remove(&mut self, id: &C) {
        self.held.remove(id);
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

/// B75: peers the operator names (`AINCORE_RESERVED_PEERS`, PeerIds,
/// comma-separated: its own observers and RPC nodes), never counted against
/// the non-member slots.
pub fn reserved_peers_from_env() -> std::collections::HashSet<String> {
    reserved_peers(&std::env::var("AINCORE_RESERVED_PEERS").unwrap_or_default()).0
}

/// The reserved peers a comma-separated list names: PeerIds, or (B132)
/// multiaddrs ending in `/p2p/{PeerId}`, whose IP literals the gate keeps
/// slots for (a PeerId is unknown before the handshake, so a reserved peer
/// given by PeerId alone was kept out with every stranger). Returns the
/// PeerIds and those addresses.
pub fn reserved_peers(list: &str) -> (std::collections::HashSet<String>, Vec<String>) {
    let mut peers = std::collections::HashSet::new();
    let mut addresses = Vec::new();
    for entry in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match entry.parse::<libp2p::Multiaddr>() {
            Ok(addr) => {
                if let Some(libp2p::multiaddr::Protocol::P2p(peer)) = addr.iter().last() {
                    peers.insert(peer.to_string());
                    addresses.push(entry.to_string());
                }
            }
            Err(_) => {
                peers.insert(entry.to_string());
            }
        }
    }
    (peers, addresses)
}

/// B132: the reserved peers' addresses (`reserved_peers`) from the
/// environment.
pub fn reserved_addresses_from_env() -> Vec<String> {
    reserved_peers(&std::env::var("AINCORE_RESERVED_PEERS").unwrap_or_default()).1
}

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

/// B148: an honest member's consensus bytes to one node in a round, at
/// most: its vertex and one retry of it, and the answers to this node's
/// pull requests of a tick (`CLIENT_REQS_PER_TICK`), each at most
/// `MAX_WIRE_BYTES`, and a kibibyte for each of its other messages.
pub const MEMBER_ROUND_BYTES: f64 = ((2 + consensus::v4::pull::CLIENT_REQS_PER_TICK)
    * consensus::v4::MAX_WIRE_BYTES
    + (blockchain::committee::MAX_COMMITTEE + 2) * 1024) as f64;
/// B148: consensus bytes a member may send a second, and in a burst: four
/// rounds' worth, and as many rounds a second as the message budget allows.
/// The message count alone let a member push 400 bodies of 768 KiB a
/// second, each a parse, two serializations, a hash and a signature check
/// (15-25 ms on the Pi), uncounted.
pub const MEMBER_BYTE_BURST: f64 = 4.0 * MEMBER_ROUND_BYTES;
pub const MEMBER_BYTES_PER_SEC: f64 =
    MEMBER_MSGS_PER_SEC / (blockchain::committee::MAX_COMMITTEE as f64 + 2.0) * MEMBER_ROUND_BYTES;

/// NI-3/B148: what a member's consensus push costs: a message, and its
/// bytes.
#[derive(Debug)]
pub struct MemberBudget {
    msgs: Budget<String>,
    bytes: Budget<String>,
}

impl Default for MemberBudget {
    fn default() -> Self {
        Self {
            msgs: Budget::new(MEMBER_MSGS_PER_SEC, MEMBER_MSG_BURST),
            bytes: Budget::new(MEMBER_BYTES_PER_SEC, MEMBER_BYTE_BURST),
        }
    }
}

impl MemberBudget {
    /// Spend a push of `len` bytes from `member` at `now`; false when it
    /// is over either budget.
    pub fn admit(&mut self, member: &str, len: usize, now: std::time::Instant) -> bool {
        let key = member.to_string();
        self.msgs.spend(&key, now) && self.bytes.spend_amount(&key, len as f64, now)
    }
}

/// B157: transactions one forwarding host (or member) may submit to this
/// node a second, on a quota of their own. A batch of 64 cost its sender
/// one token of the sync quota (12.8 a second, shared with block sync,
/// B156) while its signatures cost this node 64 checks. The rate is an
/// observer's full mempool every re-forward period (5,000 / 30 s, ~167 a
/// second) of the smallest transactions (B477: a full pool by bytes for
/// the operator's reserved peers, `RESERVED_TX_SUBMIT_BYTES_PER_SEC`).
pub const TX_SUBMIT_PER_SEC: f64 =
    mempool::MAX_PENDING_TXS as f64 / crate::forward::FORWARD_RETRY_SECS as f64;
/// B172/B183: the quota in bytes, priced by the length alone, so the swarm
/// task reads nothing of a batch before it is charged (counting its
/// transactions parsed the whole request there first, and a refused one
/// for free): `TX_SUBMIT_PER_SEC` signature checks' worth a second at
/// `forward::MIN_WIRE_PER_CHECK` bytes a check, so at most that many
/// checks; the burst is four requests at the cap (a pass's loan to one
/// member), so the largest batch an honest forwarder sends fits it.
pub const TX_SUBMIT_BYTES_PER_SEC: f64 =
    TX_SUBMIT_PER_SEC * crate::forward::MIN_WIRE_PER_CHECK as f64;
pub const TX_SUBMIT_BYTE_BURST: f64 = (4 * SYNC_REQUEST_CAP) as f64;

/// B477: the quota of the operator's reserved peers (B114: its RPC nodes),
/// at B157's rate in the unit the mempool is bounded by since B215: an
/// observer's full mempool by bytes every re-forward period (8 MiB / 30 s,
/// ~280 KB/s). Priced from the smallest transaction, a check's 324 bytes,
/// `TX_SUBMIT_BYTES_PER_SEC` carried ~5 ML-DSA-65 transactions (~10.8 KB
/// each) a second to a member, a full pool of them in ~160 s. A stranger
/// keeps that price: it is what bounds the checks junk buys (B172/B183),
/// and a host's quota at every member carries more than the chain
/// includes (a 200M-gas block holds 500 KB at 400 gas a byte: ~75 KB/s at
/// 6.65 s blocks, under two members' 108 KB/s; ~139 KB/s at 3.59 s, under
/// three members' 162 KB/s).
pub const RESERVED_TX_SUBMIT_BYTES_PER_SEC: f64 =
    mempool::MAX_PENDING_BYTES as f64 / crate::forward::FORWARD_RETRY_SECS as f64;

/// B157: what a `TX_SUBMIT` costs its sender: its bytes (B172), from the
/// reserved peers' quota for them (B477), else the open one.
#[derive(Debug)]
pub struct SubmitBudget {
    open: Budget<String>,
    reserved: Budget<String>,
}

impl Default for SubmitBudget {
    fn default() -> Self {
        Self {
            open: Budget::new(TX_SUBMIT_BYTES_PER_SEC, TX_SUBMIT_BYTE_BURST),
            reserved: Budget::new(RESERVED_TX_SUBMIT_BYTES_PER_SEC, TX_SUBMIT_BYTE_BURST),
        }
    }
}

impl SubmitBudget {
    /// Spend `wire`'s length from `key`'s quota at `now`, a reserved
    /// peer's (`reserved`) or the open one; false when it holds less.
    pub fn admit(
        &mut self,
        key: &str,
        wire: &str,
        reserved: bool,
        now: std::time::Instant,
    ) -> bool {
        let quota = if reserved {
            &mut self.reserved
        } else {
            &mut self.open
        };
        quota.spend_amount(&key.to_string(), wire.len() as f64, now)
    }
}

/// B34/B114/B187: the serving slots a session's request takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServePool {
    /// A member's sync request (B88: members keep to their own).
    Member,
    /// A reserved peer's sync request (B187: they shared the open slots with
    /// every stranger, so a host holding those starved the operator's RPC
    /// nodes of block sync and QC_WANT).
    Reserved,
    /// Anyone else's.
    Open,
    /// A forwarded batch (B31).
    TxSubmit,
    /// A reserved peer's forwarded batch (B114).
    ReservedTxSubmit,
}

/// The pool a request takes its serving slot from.
pub fn serve_pool(tx_submit: bool, member: bool, reserved: bool) -> ServePool {
    match (tx_submit, member, reserved) {
        (true, _, true) => ServePool::ReservedTxSubmit,
        (true, _, false) => ServePool::TxSubmit,
        (false, true, _) => ServePool::Member,
        (false, false, true) => ServePool::Reserved,
        (false, false, false) => ServePool::Open,
    }
}

/// B131/B178: who a snapshot request is charged to, and whether it may take
/// the kept snapshot slot and units (`chain_sync::state_sync`): a reserved
/// peer by its key, kept; a member by its key, not kept: a node whose key a
/// committee records never restores (SN-6, S6 refuses it), so a member has
/// no use for them, and two Byzantine members kept them drained; anyone else
/// by its network group (`group`), when known.
pub fn snapshot_client(
    peer: &str,
    member: bool,
    reserved: bool,
    group: Option<&str>,
) -> (String, bool) {
    let client = match group {
        Some(group) if !member && !reserved => group.to_string(),
        _ => peer.to_string(),
    };
    (client, reserved)
}

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
        self.spend_amount(key, 1.0, now)
    }

    /// B148: spend `amount` tokens of `key` at `now`; false (and nothing
    /// spent) when its bucket holds fewer.
    pub fn spend_amount(&mut self, key: &K, amount: f64, now: std::time::Instant) -> bool {
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
        if *tokens >= amount {
            *tokens -= amount;
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

/// B299: a non-member's answer, built, charged its bytes to `key` (B60)
/// whether the held-answer bound (B30) keeps it or refuses it; true when it
/// may be sent. A refused one was free, though the server had read, parsed
/// and serialized it in full: a stranger whose group's share was held got
/// that work at one token a request.
pub fn charge_then_hold<K: std::hash::Hash + Eq>(
    budget: &mut Budget<String>,
    held: &mut HeldAnswers<K>,
    id: K,
    key: &str,
    group: &str,
    len: usize,
    now: std::time::Instant,
) -> bool {
    budget.charge(&key.to_string(), answer_tokens(len), now);
    held.admit(id, group, len)
}

/// A non-member's sync request being answered: the busy reply its kind has
/// (B30) and its requester's network group (B75), for the held-answer bound.
pub struct OpenServe {
    pub busy: Option<String>,
    pub group: String,
}

/// A sync request being answered off the network task (G4 S1).
struct Serve<C> {
    /// The channel its answer goes out on; `None` once its requester went.
    channel: Option<C>,
    /// The budget key its answer is charged to (B60, B88).
    key: String,
    open: Option<OpenServe>,
}

/// What the network task does with an answer that came (`Serving::answered`).
pub enum Answered<C> {
    /// Send it on the channel.
    Send(C, String),
    /// The held-answer bound refused it: send the busy reply, or drop the
    /// channel when there is none.
    Refused(C, Option<String>),
    /// Nothing to send: no answer, or its requester went.
    Nothing,
}

/// The sync requests the network task is answering, by request id, and who
/// each answer is charged to. B312: an answer is charged its bytes when it
/// comes even if its requester went first. A requester that closed its
/// connection with its requests unanswered had every answer built in full
/// for a token: B60's byte charge (and B88's, for a member) never applied.
pub struct Serving<Id, C> {
    serves: HashMap<Id, Serve<C>>,
}

impl<Id: std::hash::Hash + Eq + Clone, C> Default for Serving<Id, C> {
    fn default() -> Self {
        Self {
            serves: HashMap::new(),
        }
    }
}

impl<Id: std::hash::Hash + Eq + Clone, C> Serving<Id, C> {
    /// A request handed to the serving loop; its answer goes on `channel`,
    /// charged to `key`; `open` for a non-member's.
    pub fn begin(&mut self, id: Id, channel: C, key: String, open: Option<OpenServe>) {
        self.serves.insert(
            id,
            Serve {
                channel: Some(channel),
                key,
                open,
            },
        );
    }

    /// Its requester went (the connection closed) before the answer came:
    /// the channel goes, the charge stays.
    pub fn abandon(&mut self, id: &Id) {
        if let Some(serve) = self.serves.get_mut(id) {
            serve.channel = None;
        }
    }

    /// The answer to `id` came (`None`: there is none). It is charged its
    /// bytes whether it is sent, refused by the held-answer bound (B299)
    /// or its requester went (B312).
    pub fn answered(
        &mut self,
        id: Id,
        answer: Option<String>,
        budget: &mut Budget<String>,
        held: &mut HeldAnswers<Id>,
        now: std::time::Instant,
    ) -> Answered<C> {
        let (Some(serve), Some(answer)) = (self.serves.remove(&id), answer) else {
            return Answered::Nothing;
        };
        let len = answer.len();
        match (serve.channel, serve.open) {
            (Some(channel), Some(open)) => {
                if charge_then_hold(budget, held, id, &serve.key, &open.group, len, now) {
                    Answered::Send(channel, answer)
                } else {
                    Answered::Refused(channel, open.busy)
                }
            }
            (channel, _) => {
                budget.charge(&serve.key, answer_tokens(len), now);
                channel.map_or(Answered::Nothing, |c| Answered::Send(c, answer))
            }
        }
    }

    /// Requests being answered.
    pub fn len(&self) -> usize {
        self.serves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.serves.is_empty()
    }
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
/// B221: a kept IP's own admission rate (choices: twice a stranger's): a
/// kept IP skipped the rate (B111: the shared budget's key map, once full,
/// refused a reconnecting member like a stranger), and a member names the
/// IP it reports, so a host it controls cost every node a Noise handshake
/// (a keygen, two X25519, a signature) as fast as it could reconnect. Its
/// map holds kept IPs only (`MAX_KEPT_IPS`).
pub const ADMIT_KEPT_PER_SEC: f64 = 2.0 * ADMIT_PER_IP_PER_SEC;
pub const ADMIT_KEPT_BURST: f64 = 2.0 * ADMIT_BURST_PER_IP;
/// B56: unfinished handshakes kept for IPs members connected from (a
/// choice: four members reconnecting at once, `PENDING_PER_IP` each). The
/// rest of `MAX_PENDING_INBOUND` is all other IPs': ~28 IPs holding silent
/// handshakes used to fill every slot and keep a restarted member out.
pub const PENDING_KEPT_FOR_MEMBERS: usize = 16;
/// B132: IPs kept per committee member: its latest connection's and its
/// latest identify-reported one (a choice).
pub const MEMBER_IPS_KEPT: usize = 2;
/// B152: a member's kept IP is replaced at most this often (a choice: the
/// handshake timeout, so an IP left behind holds its unfinished handshakes
/// no longer than its successor has been kept). A member rotating the IPs
/// it reports gave each new one its own slots, ~1,300 IPs filled the total
/// in one timeout, and every inbound connection was refused.
pub const KEPT_IP_HOLD: std::time::Duration = HANDSHAKE_TIMEOUT;

/// B152: where a member's kept IP came from. Each source has its own slot:
/// a member reporting two interfaces pushed out the IP it connects from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    /// An authenticated connection's remote address.
    Connected,
    /// An address it reported (identify).
    Reported,
}

/// A member's kept IPs, one per source, each with when it was kept.
#[derive(Debug, Default, Clone)]
struct MemberSlots {
    connected: Option<(std::net::IpAddr, std::time::Instant)>,
    reported: Option<(std::net::IpAddr, std::time::Instant)>,
}
/// B132: IPs kept from the boot list (literals, and its host names resolved).
pub const MAX_BOOT_IPS: usize = 128;
/// B132: kept IPs at most: the boot list's, and the members' of the current
/// and next committees.
pub const MAX_KEPT_IPS: usize =
    2 * MAX_BOOT_IPS + 2 * blockchain::committee::MAX_COMMITTEE * MEMBER_IPS_KEPT;
/// B132: unfinished inbound handshakes at once, in all: the others' share
/// and `PENDING_PER_IP` for every kept IP. Each kept IP has its own slots:
/// with sixteen shared, Byzantine members filled them from their own kept
/// IPs while strangers held the rest, and no honest member could reconnect.
pub const MAX_PENDING_TOTAL: u32 = (MAX_PENDING_INBOUND as usize - PENDING_KEPT_FOR_MEMBERS
    + PENDING_PER_IP * MAX_KEPT_IPS) as u32;
/// B116: unfinished handshakes from one network group (`net_group`: /16
/// IPv4, /32 IPv6) outside the kept IPs, at once (a choice: two hosts'
/// worth; the other IPs' 112 slots then take 14 groups to fill, where 28
/// IPs of one provider's range did).
pub const PENDING_PER_GROUP: usize = 2 * PENDING_PER_IP;

/// B56/B116: the IPs the gate keeps handshake slots for. The operator's
/// bootnodes and saved members' are kept from boot: the set used to start
/// empty and fill only from members' sessions, so at a cold start ~28 IPs
/// holding silent handshakes kept every member out and the chain could not
/// start. A committee member's IP is kept one per member PeerId, replaced
/// when it connects from another and dropped once it leaves the committee:
/// a member could record 32 addresses for good and hold every pending slot
/// from them.
#[derive(Debug, Default)]
pub struct KeptIps {
    boot: std::collections::HashSet<std::net::IpAddr>,
    /// B132: the boot list's host names, resolved (replaced at each lookup).
    resolved: std::collections::HashSet<std::net::IpAddr>,
    members: HashMap<PeerId, MemberSlots>,
    all: std::collections::HashSet<std::net::IpAddr>,
}

impl KeptIps {
    /// The IPs kept from boot (the operator's bootnodes, saved members and
    /// reserved peers given with addresses).
    pub fn with_boot(boot: impl IntoIterator<Item = std::net::IpAddr>) -> Self {
        let mut kept = Self {
            boot: boot.into_iter().take(MAX_BOOT_IPS).collect(),
            ..Self::default()
        };
        kept.rebuild();
        kept
    }

    /// B132: the IPs the boot list's host names resolve to now.
    pub fn set_resolved(&mut self, ips: impl IntoIterator<Item = std::net::IpAddr>) {
        self.resolved = ips.into_iter().take(MAX_BOOT_IPS).collect();
        self.rebuild();
    }

    /// Committee member `peer` connected from, or reported, `ip` at `now`:
    /// kept in that source's slot, unless the slot changed less than
    /// `KEPT_IP_HOLD` ago (B152); `is_member` tells which recorded members
    /// still are (those that left are dropped).
    pub fn record_member(
        &mut self,
        peer: PeerId,
        ip: std::net::IpAddr,
        source: IpSource,
        now: std::time::Instant,
        is_member: impl Fn(&PeerId) -> bool,
    ) {
        self.members.retain(|p, _| is_member(p));
        if self.members.len() < 2 * blockchain::committee::MAX_COMMITTEE
            || self.members.contains_key(&peer)
        {
            let slots = self.members.entry(peer).or_default();
            let slot = match source {
                IpSource::Connected => &mut slots.connected,
                IpSource::Reported => &mut slots.reported,
            };
            match slot {
                Some((held, _)) if *held == ip => {}
                Some((_, since)) if now.saturating_duration_since(*since) < KEPT_IP_HOLD => {}
                _ => *slot = Some((ip, now)),
            }
        }
        self.rebuild();
    }

    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        self.all.contains(ip)
    }

    pub fn len(&self) -> usize {
        self.all.len()
    }

    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    fn rebuild(&mut self) {
        self.all = self
            .boot
            .iter()
            .chain(&self.resolved)
            .chain(self.members.values().flat_map(|slots| {
                slots
                    .connected
                    .iter()
                    .chain(slots.reported.iter())
                    .map(|(ip, _)| ip)
            }))
            .copied()
            .collect();
    }
}

/// B367: committee members' identify reports, each handled at most once a
/// `KEPT_IP_HOLD` unless its addresses changed. identify emits the whole
/// stored report again on every push a peer sends (an empty push merges
/// into it), and each of a report's ~350 addresses rebuilt the kept IPs and
/// refreshed the address book in the swarm task: one member pushing on its
/// connections delayed every other connection's events.
#[derive(Debug, Default)]
pub struct IdentifyGate {
    handled: HashMap<PeerId, (u64, std::time::Instant)>,
}

/// B372: a member's identify reports are handled at most this often,
/// changed or not: one alternating two address lists was handled on every
/// push. A changed report refused within it is not lost: identify keeps the
/// whole report and the member's next one (a push or the periodic identify)
/// carries it.
pub const IDENTIFY_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

impl IdentifyGate {
    /// Whether member `peer`'s report of `addrs` at `now` is handled: its
    /// first, or one `IDENTIFY_EVERY` after the last handled that changed or
    /// comes `KEPT_IP_HOLD` after it. `is_member` drops those that left once
    /// the gate holds two committees' worth.
    pub fn admit(
        &mut self,
        peer: PeerId,
        addrs: &[libp2p::Multiaddr],
        now: std::time::Instant,
        is_member: impl Fn(&PeerId) -> bool,
    ) -> bool {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        addrs.hash(&mut hasher);
        let digest = hasher.finish();
        if !self.handled.contains_key(&peer)
            && self.handled.len() >= 2 * blockchain::committee::MAX_COMMITTEE
        {
            self.handled.retain(|p, _| is_member(p));
        }
        match self.handled.get(&peer) {
            Some((held, at))
                if now.saturating_duration_since(*at) < IDENTIFY_EVERY
                    || (*held == digest && now.saturating_duration_since(*at) < KEPT_IP_HOLD) =>
            {
                false
            }
            _ => {
                self.handled.insert(peer, (digest, now));
                true
            }
        }
    }
}

/// B367: the addresses of a member's report this node keeps: at most
/// `ADDRESSES_PER_PEER` usable ones (`learned_address_ok`, or on this host
/// `learned_address_ok_on_this_host` with an IP literal), in its order.
pub fn usable_reported(
    addrs: Vec<libp2p::Multiaddr>,
    on_this_host: bool,
) -> Vec<libp2p::Multiaddr> {
    addrs
        .into_iter()
        .filter(|addr| {
            if on_this_host {
                ip_of(addr).is_some() && learned_address_ok_on_this_host(addr)
            } else {
                learned_address_ok(addr)
            }
        })
        .take(ADDRESSES_PER_PEER)
        .collect()
}

/// B132: the boot list's host names to resolve (`/dns*` multiaddrs and
/// `host:port`), with their ports. A host name had no kept slots (only IP
/// literals did), and the documented mainnet bootnodes are host names.
pub fn boot_hosts(boot: &[String]) -> Vec<(String, u16)> {
    use libp2p::multiaddr::Protocol;
    let mut out = Vec::new();
    for entry in boot.iter().map(|e| e.trim()) {
        if let Ok(addr) = entry.parse::<libp2p::Multiaddr>() {
            let host = addr.iter().find_map(|p| match p {
                Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => Some(h.to_string()),
                _ => None,
            });
            let port = addr.iter().find_map(|p| match p {
                Protocol::Tcp(port) => Some(port),
                _ => None,
            });
            if let (Some(host), Some(port)) = (host, port) {
                out.push((host, port));
            }
        } else if entry.parse::<std::net::SocketAddr>().is_err() {
            if let Some((host, port)) = entry.rsplit_once(':') {
                if let Ok(port) = port.parse::<u16>() {
                    if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
                        out.push((host.to_string(), port));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// B163: each boot name's last answer. A failed (or empty) lookup keeps
/// the previous one: a resolver hiccup cleared every bootnode's kept slots.
#[derive(Debug, Default)]
pub struct ResolvedNames {
    /// B185: ordered, so the names that keep the boot slots are the same at
    /// every lookup (HashMap order gave them to whichever came first).
    last: std::collections::BTreeMap<(String, u16), Vec<std::net::IpAddr>>,
}

/// B185: the IPs one boot name keeps (a choice: a DNS seed's answer of a
/// few hosts). A name answering 128 rotating IPs held every kept boot slot.
pub const MAX_IPS_PER_NAME: usize = 8;

impl ResolvedNames {
    /// `host:port`'s lookup: `None` when it failed.
    pub fn record(&mut self, host: &str, port: u16, found: Option<Vec<std::net::IpAddr>>) {
        if let Some(mut ips) = found.filter(|ips| !ips.is_empty()) {
            ips.truncate(MAX_IPS_PER_NAME);
            self.last.insert((host.to_string(), port), ips);
        }
    }

    /// The IPs every name resolved to, last time it did, in name order.
    pub fn ips(&self) -> Vec<std::net::IpAddr> {
        self.last.values().flatten().copied().collect()
    }
}

/// B160: whether the peer a connection's remote host (`multiaddr_host`)
/// names runs on this host: a loopback connection. Decided from this node's
/// own connection, never from what the peer reports.
pub fn on_this_host(host: Option<&str>) -> bool {
    host.and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback())
}

/// B146: `learned_address_ok` for a peer on this host (its loopback is
/// fine): an IP literal, no name.
pub fn learned_address_ok_on_this_host(addr: &libp2p::Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    addr.iter()
        .any(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))
        && !addr.iter().any(|p| {
            matches!(
                p,
                Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
            )
        })
}

/// B146: whether an address a peer reported (identify, mDNS) is kept: an IP
/// literal another host can dial. A name a peer reports is never resolved
/// (it could name loopback or a Docker bridge behind the IP filter, or fan
/// out through `/dnsaddr`); only names the operator gave are.
pub fn learned_address_ok(addr: &libp2p::Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    routable_for_others(addr)
        && addr
            .iter()
            .any(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)))
        && !addr.iter().any(|p| {
            matches!(
                p,
                Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
            )
        })
}

/// B116: the IP literals of the boot dial list (bootnodes and saved member
/// addresses, as multiaddrs or `ip:port`); host names are left out (no DNS
/// lookup at boot).
pub fn boot_ips(boot: &[String]) -> Vec<std::net::IpAddr> {
    boot.iter()
        .filter_map(|addr| {
            let addr = addr.trim();
            if let Ok(multiaddr) = addr.parse::<libp2p::Multiaddr>() {
                return ip_of(&multiaddr);
            }
            addr.parse::<std::net::SocketAddr>()
                .map(|s| s.ip())
                .or_else(|_| addr.parse::<std::net::IpAddr>())
                .ok()
        })
        .collect()
}

/// B56: the IPs the gate keeps slots for, which the network task adds to
/// and the gate reads.
pub type MemberIps = Arc<RwLock<KeptIps>>;

/// B24: inbound admission before any handshake. Every cap of the network
/// task runs once a connection is established, after the Noise handshake
/// it costs; this gate refuses a connection from an IP that holds
/// `PENDING_PER_IP` unfinished ones or has spent its admission budget,
/// before the handshake starts.
#[derive(Debug)]
pub struct InboundGate {
    /// Unfinished handshakes: the IP, whether it took a kept IP's slots
    /// (B199: counted in that bucket until it finishes, whatever the kept
    /// set becomes meanwhile), and (B334) its network group, computed once
    /// (empty for a kept IP).
    pending: HashMap<libp2p::swarm::ConnectionId, (std::net::IpAddr, bool, String)>,
    admit: Budget<std::net::IpAddr>,
    /// B221: kept IPs' own admission rate, by exact IP.
    admit_kept: Budget<std::net::IpAddr>,
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
            admit_kept: Budget::new(ADMIT_KEPT_PER_SEC, ADMIT_KEPT_BURST),
            member_ips,
        }
    }
}

/// B187: what a host's connections count under: an IPv6 address by its /64
/// (one host routes 2^64 of them, and each counted as a host of its own), a
/// mapped IPv4 one as IPv4, loopback as itself; as the RPC's limiter keys a
/// client (B74).
pub fn host_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv6Addr};
    match ip {
        IpAddr::V6(v6) if !v6.is_loopback() => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        _ => ip,
    }
}

pub fn ip_of(addr: &libp2p::Multiaddr) -> Option<std::net::IpAddr> {
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
        // B187: per host: an IPv6 one by its /64. B207: a member's kept IP by
        // itself (kept IPs are exact): a host sharing the member's /64 used
        // up the member's own handshake slots. B199: each handshake counts in
        // the bucket it was admitted to (a member that rotated its reported
        // IP moved its unfinished handshakes into the shared slots).
        let key = host_key(ip);
        let kept_ip = self.member_ips.read().is_ok_and(|kept| kept.contains(&ip));
        // B111: a member's IP is not held to the per-IP admission rate (once
        // that budget's key map was full, a reconnecting member's IP could be
        // refused like any stranger's). B221: but to a rate of its own. B334:
        // the rate is checked first, so a refused connect costs no scan of
        // the unfinished handshakes (three ran before it on the swarm task,
        // the last allocating two strings an entry).
        let now = std::time::Instant::now();
        let admitted = if kept_ip {
            self.admit_kept.spend(&ip, now)
        } else {
            self.admit.spend(&key, now)
        };
        if !admitted {
            return Err(denied("this IP opens connections too fast"));
        }
        if self
            .pending
            .values()
            .filter(|(p, kept, _)| {
                if kept_ip {
                    *kept && *p == ip
                } else {
                    !*kept && host_key(*p) == key
                }
            })
            .count()
            >= PENDING_PER_IP
        {
            return Err(denied("too many unfinished handshakes from this IP"));
        }
        // B132: the backstop over all: the others' share and each kept IP's
        // own slots (`connection_limits` holds the same bound).
        if self.pending.len() >= MAX_PENDING_TOTAL as usize {
            return Err(denied("too many unfinished handshakes in all"));
        }
        // B56: other IPs share all but the slots kept for members'; B116:
        // and one network group holds at most PENDING_PER_GROUP of them.
        let group = if kept_ip {
            String::new()
        } else {
            net_group(&ip.to_string())
        };
        if !kept_ip {
            let (others, in_group) = self
                .pending
                .values()
                .filter(|(_, kept, _)| !*kept)
                .fold((0usize, 0usize), |(others, in_group), (_, _, g)| {
                    (others + 1, in_group + usize::from(*g == group))
                });
            let limit = MAX_PENDING_INBOUND as usize - PENDING_KEPT_FOR_MEMBERS;
            if others >= limit {
                return Err(denied(
                    "the unfinished handshakes of other IPs are at their bound",
                ));
            }
            if in_group >= PENDING_PER_GROUP {
                return Err(denied(
                    "too many unfinished handshakes from this network group",
                ));
            }
        }
        self.pending.insert(connection_id, (ip, kept_ip, group));
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

/// B90: the addresses this node dials a peer at by its PeerId (a member, in
/// the committee dial): its bootnodes', the ones a dial reached, and the
/// routable listen addresses a member's session reported (G4: addresses
/// come from the authenticated session or the operator's bootnodes). It
/// replaces Kademlia, which held this table but also stored anyone's
/// records, answered anyone's queries and bootstrapped every 5 minutes by
/// dialling addresses peers supplied; nothing used those.
///
/// B102: the operator's bootnode addresses and those a dial reached are
/// pinned (never pushed out); session-reported ones are a member's only and
/// rotate; a peer's entry is refreshed whenever it is added to, and a full
/// book evicts the least recently refreshed peer with nothing pinned. The
/// first version took any stranger's identify and evicted in insertion
/// order, so churn pushed members out and a dropped link never redialled.
#[derive(Debug, Default)]
pub struct AddressBook {
    entries: HashMap<PeerId, BookEntry>,
    /// Least recently refreshed first.
    order: std::collections::VecDeque<PeerId>,
}

#[derive(Debug, Default)]
struct BookEntry {
    pinned: Vec<libp2p::Multiaddr>,
    learned: Vec<libp2p::Multiaddr>,
}

/// B90: addresses kept per peer, of each kind (a choice: a host's few
/// interfaces and transports).
pub const ADDRESSES_PER_PEER: usize = 8;
/// B90: peers the book holds (a choice: four times the largest committee,
/// `MAX_COMMITTEE`); past it, the least recently refreshed peer with nothing
/// pinned leaves.
pub const MAX_BOOK_PEERS: usize = 1024;

impl AddressBook {
    /// An address a member's session reported: the newest kept.
    pub fn add_address(&mut self, peer: &PeerId, address: libp2p::Multiaddr) {
        self.touch(peer);
        let entry = self.entries.entry(*peer).or_default();
        if entry.pinned.contains(&address) {
            return;
        }
        entry.learned.retain(|a| *a != address);
        if entry.learned.len() >= ADDRESSES_PER_PEER {
            entry.learned.remove(0);
        }
        entry.learned.push(address);
    }

    /// B102: an address the operator named (a bootnode's) or a dial reached:
    /// kept for good.
    pub fn pin_address(&mut self, peer: &PeerId, address: libp2p::Multiaddr) {
        self.touch(peer);
        let entry = self.entries.entry(*peer).or_default();
        entry.learned.retain(|a| *a != address);
        if !entry.pinned.contains(&address) {
            if entry.pinned.len() >= ADDRESSES_PER_PEER {
                entry.pinned.remove(0);
            }
            entry.pinned.push(address);
        }
    }

    /// `peer` becomes the most recently refreshed; a new one in a full book
    /// takes the place of the least recently refreshed peer with nothing
    /// pinned.
    fn touch(&mut self, peer: &PeerId) {
        if self.entries.contains_key(peer) {
            self.order.retain(|p| p != peer);
        } else if self.entries.len() >= MAX_BOOK_PEERS {
            if let Some(at) = self
                .order
                .iter()
                .position(|p| self.entries.get(p).is_none_or(|e| e.pinned.is_empty()))
            {
                if let Some(gone) = self.order.remove(at) {
                    self.entries.remove(&gone);
                }
            }
        }
        self.order.push_back(*peer);
    }

    /// Where `peer` is dialled: its pinned addresses, then the learned ones.
    pub fn addresses_of(&self, peer: &PeerId) -> Vec<libp2p::Multiaddr> {
        self.entries
            .get(peer)
            .map(|e| e.pinned.iter().chain(&e.learned).cloned().collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl libp2p::swarm::NetworkBehaviour for AddressBook {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[libp2p::Multiaddr],
        _effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<libp2p::Multiaddr>, libp2p::swarm::ConnectionDenied> {
        Ok(maybe_peer
            .map(|peer| self.addresses_of(&peer))
            .unwrap_or_default())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
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

    fn on_swarm_event(&mut self, _event: libp2p::swarm::FromSwarm) {}

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

/// B75: the held answers of one network group (`net_group`), at most. A
/// choice: two answers at `SYNC_RESPONSE_CAP` in flight, as a reading
/// client keeps them (one at a time refused an honest pipelined sync); four
/// groups fill the pool, where two hosts that stopped reading filled it.
pub const OPEN_HELD_PER_GROUP_BYTES: usize = 2 * SYNC_RESPONSE_CAP;

/// B30: a requester that stops reading holds every answer it was sent
/// until its request times out (60 s), and free identities on many hosts
/// add up. An answer to a non-member counts from hand-off until it is
/// written or fails; past `OPEN_HELD_MAX_BYTES` a new one is refused, and
/// (B75) past `OPEN_HELD_PER_GROUP_BYTES` for its requester's group.
#[derive(Debug)]
pub struct HeldAnswers<K> {
    held: HashMap<K, (String, usize)>,
    by_group: HashMap<String, usize>,
    bytes: Arc<AtomicUsize>,
}

impl<K: std::hash::Hash + Eq> HeldAnswers<K> {
    pub fn new(bytes: Arc<AtomicUsize>) -> Self {
        bytes.store(0, Ordering::Relaxed);
        Self {
            held: HashMap::new(),
            by_group: HashMap::new(),
            bytes,
        }
    }

    /// Count `len` bytes for `id`, an answer to a requester in `group`;
    /// false (nothing counted) when that would pass either bound.
    pub fn admit(&mut self, id: K, group: &str, len: usize) -> bool {
        self.release(&id);
        let now = self.bytes.load(Ordering::Relaxed);
        let mine = self.by_group.get(group).copied().unwrap_or(0);
        if now.saturating_add(len) > OPEN_HELD_MAX_BYTES
            || mine.saturating_add(len) > OPEN_HELD_PER_GROUP_BYTES
        {
            return false;
        }
        self.held.insert(id, (group.to_string(), len));
        *self.by_group.entry(group.to_string()).or_insert(0) += len;
        self.bytes.store(now + len, Ordering::Relaxed);
        true
    }

    /// `id`'s answer was written, or failed: its bytes are free.
    pub fn release(&mut self, id: &K) {
        if let Some((group, len)) = self.held.remove(id) {
            self.bytes.fetch_sub(len, Ordering::Relaxed);
            if let Some(held) = self.by_group.get_mut(&group) {
                *held = held.saturating_sub(len);
                if *held == 0 {
                    self.by_group.remove(&group);
                }
            }
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
    // B185: a saved row is dialled only as an IP literal: only the
    // operator's own boot list names hosts (a saved name was resolved at boot
    // as if the operator had given it).
    for addr in saved {
        let literal = addr
            .parse::<libp2p::Multiaddr>()
            .is_ok_and(|a| learned_address_ok(&a));
        if literal && !out.contains(addr) {
            out.push(addr.clone());
        }
    }
    out
}

/// B394: the sessions a QC_WANT may ask: the connected members, and apart
/// from them every other connected session (an archive node holds a QC the
/// members pruned with its block, and a book whose members all left holds
/// none at all: a pending vote whose QC formed elsewhere was never retired).
pub fn qc_want_candidates(
    members: impl IntoIterator<Item = PeerId>,
    connected: impl IntoIterator<Item = PeerId>,
) -> QcWantCandidates {
    let mut out = QcWantCandidates::default();
    for peer in members {
        if !out.members.contains(&peer) {
            out.members.push(peer);
        }
    }
    for peer in connected {
        if !out.members.contains(&peer) && !out.others.contains(&peer) {
            out.others.push(peer);
        }
    }
    out
}

/// B402: the two groups a QC_WANT asks, kept apart, so the sessions a
/// stranger can open (50 inbound) never dilute the members' turns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QcWantCandidates {
    pub members: Vec<PeerId>,
    pub others: Vec<PeerId>,
}

/// B198: the members a QC_WANT asks over sync at its `turn`: two of the
/// connected ones, the next two in key order each turn, so every member is
/// asked within `ceil(m / 2)` turns. It asked the first two of the book's
/// hash order every time, which a node waiting at a boundary never rebuilt:
/// two Byzantine members there that never answer held it in its epoch.
/// B402: and one other session, the next in key order each turn (two with
/// no member connected). B394 sorted both groups into one rotation, so 50
/// stranger sessions that never answer stretched a member's turn ~25 times.
pub fn qc_want_peers(candidates: QcWantCandidates, turn: usize) -> Vec<PeerId> {
    let others = if candidates.members.is_empty() { 2 } else { 1 };
    let mut asked = in_turn(candidates.members, turn, 2);
    asked.extend(in_turn(candidates.others, turn, others));
    asked
}

/// The `per_turn` sessions of `peers` asked at `turn`: the next ones in key
/// order, so each is asked within `ceil(len / per_turn)` turns.
fn in_turn(mut peers: Vec<PeerId>, turn: usize, per_turn: usize) -> Vec<PeerId> {
    if peers.is_empty() {
        return peers;
    }
    peers.sort_by_key(|p| p.to_bytes());
    let start = turn.wrapping_mul(per_turn) % peers.len();
    let take = peers.len().min(per_turn);
    peers
        .iter()
        .cycle()
        .skip(start)
        .take(take)
        .copied()
        .collect()
}

/// B222: how long a saved peer address stands unwritten while it is
/// unchanged (a choice: B43 dials the newest rows first, and a member
/// reconnecting rewrote its unchanged row each time).
pub const PEER_ROW_FRESH_SECS: u64 = 3_600;

/// B222: `peer`'s saved row holds `addr`, saved less than
/// `PEER_ROW_FRESH_SECS` before `now_secs`.
pub fn peer_row_is_fresh(
    storage: &storage::StateDB,
    peer: &str,
    addr: &str,
    now_secs: u64,
) -> bool {
    storage
        .get(&format!("peer_addr:{peer}"))
        .ok()
        .flatten()
        .and_then(|row| {
            let (at, saved) = row.split_once(' ')?;
            Some((at.parse::<u64>().ok()?, saved.to_string()))
        })
        .is_some_and(|(at, saved)| {
            saved == addr && now_secs.saturating_sub(at) < PEER_ROW_FRESH_SECS
        })
}

/// Seconds since the epoch (0 if the clock is before it).
pub fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// B186: the key `addr` pins (its trailing `/p2p/<PeerId>`), if any.
pub fn pinned_peer(addr: &libp2p::Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(libp2p::multiaddr::Protocol::P2p(peer)) => Some(peer),
        _ => None,
    }
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
        assert!(part <= OPEN_HELD_PER_GROUP_BYTES);
        let group = |id: u32| format!("10.{id}");
        assert!(
            (0..4).all(|id| held.admit(id, &group(id), part)),
            "exactly the bound fits"
        );
        assert!(!held.admit(4, &group(4), 1), "past the bound");
        assert_eq!(gauge.load(Ordering::Relaxed), OPEN_HELD_MAX_BYTES);
        held.release(&0);
        held.release(&0);
        held.release(&9);
        assert_eq!(held.bytes(), OPEN_HELD_MAX_BYTES - part);
        assert!(
            held.admit(4, &group(4), part),
            "freed bytes are admitted again"
        );
        (1..5).for_each(|id| held.release(&id));
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
    }

    /// B367 witness: a member's identify report is handled at most once a
    /// `KEPT_IP_HOLD` unless its addresses change, and at most
    /// `ADDRESSES_PER_PEER` of them are kept. identify emits the whole report
    /// again on every push (an empty push merges into it), and each of ~350
    /// addresses rebuilt the kept IPs and refreshed the address book in the
    /// swarm task, so one member pushing delayed every connection's events.
    #[test]
    fn a_members_identify_report_is_handled_once_a_hold_unless_changed() {
        let peer = PeerId::random();
        let report: Vec<libp2p::Multiaddr> = (0..350u32)
            .map(|i| {
                format!("/ip4/203.0.{}.{}/tcp/9101", i / 256, i % 256)
                    .parse()
                    .unwrap()
            })
            .collect();
        let member = |_: &PeerId| true;
        let t0 = std::time::Instant::now();
        let mut gate = IdentifyGate::default();
        assert!(gate.admit(peer, &report, t0, member), "a first report");
        let soon = t0 + KEPT_IP_HOLD / 2;
        assert!(
            !gate.admit(peer, &report, soon, member),
            "an unchanged push was handled again"
        );
        let mut changed = report.clone();
        changed.pop();
        assert!(gate.admit(peer, &changed, soon, member), "a changed report");
        assert!(!gate.admit(peer, &changed, soon, member));
        // B372: alternating reports are handled at most once a second.
        let alternate = soon + IDENTIFY_EVERY / 2;
        assert!(
            !gate.admit(peer, &report, alternate, member),
            "an alternating report within a second was handled"
        );
        assert!(gate.admit(peer, &report, soon + IDENTIFY_EVERY, member));
        assert!(gate.admit(peer, &changed, soon + 2 * IDENTIFY_EVERY, member));
        let later = soon + 2 * IDENTIFY_EVERY;
        assert!(!gate.admit(peer, &changed, later + KEPT_IP_HOLD / 2, member));
        assert!(
            gate.admit(peer, &changed, later + KEPT_IP_HOLD, member),
            "a report a hold later"
        );
        let kept = usable_reported(report.clone(), false);
        assert_eq!(kept, report[..ADDRESSES_PER_PEER].to_vec());
    }

    /// B394 witness: a QC_WANT may ask every connected session, the members
    /// first: it asked members only, so a QC they pruned with its block (an
    /// archive node held it) or a book whose members all left kept a pending
    /// vote open for good, and with it the next epoch and pruning.
    #[test]
    fn a_qc_is_asked_of_every_connected_session() {
        let (m1, m2, archive) = (PeerId::random(), PeerId::random(), PeerId::random());
        let asked = qc_want_candidates([m1, m2], [archive, m2, m1]);
        assert_eq!(asked.members, vec![m1, m2]);
        assert_eq!(asked.others, vec![archive]);
        let alone = qc_want_candidates([], [archive]);
        assert_eq!(alone.others, vec![archive]);
        assert_eq!(qc_want_peers(alone, 0), vec![archive]);
        let mut every = std::collections::HashSet::new();
        for turn in 0..2 {
            every.extend(qc_want_peers(asked.clone(), turn));
        }
        assert!(every.contains(&archive), "the archive node was never asked");
    }

    /// B402 witness: strangers outnumbering the members do not stretch a
    /// member's turn: every turn asks two members and one other session.
    /// One rotation over both groups asked a member once per ~13 turns here.
    #[test]
    fn a_member_is_asked_every_turn_however_many_strangers_connect() {
        let members: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        let strangers: Vec<PeerId> = (0..50).map(|_| PeerId::random()).collect();
        let candidates = qc_want_candidates(members.clone(), strangers.clone());
        let mut asked_members = std::collections::HashSet::new();
        let mut asked_strangers = std::collections::HashSet::new();
        for turn in 0..50 {
            let asked = qc_want_peers(candidates.clone(), turn);
            assert_eq!(asked.len(), 3);
            let of_members = asked.iter().filter(|p| members.contains(p)).count();
            assert_eq!(of_members, 2, "turn {turn} asked {of_members} members");
            if turn < 2 {
                asked_members.extend(asked.iter().filter(|p| members.contains(p)).copied());
            }
            asked_strangers.extend(asked.iter().filter(|p| strangers.contains(p)).copied());
        }
        assert_eq!(
            asked_members.len(),
            4,
            "a member waited past ceil(m / 2) turns"
        );
        assert_eq!(asked_strangers.len(), 50, "a stranger was never asked");
        let none = qc_want_candidates([], strangers.clone());
        assert_eq!(qc_want_peers(none, 0).len(), 2);
    }

    /// B90/B102 witness: the address book dials a peer at what it was told,
    /// pinned addresses first, each address once, and holds at most
    /// `MAX_BOOK_PEERS` peers; a full book pushes out the least recently
    /// refreshed peer with nothing pinned, never a pinned one (a bootnode, an
    /// address a dial reached), and a refreshed peer stays.
    #[test]
    fn the_address_book_is_bounded_and_dials_what_it_holds() {
        use libp2p::swarm::NetworkBehaviour;
        let mut book = AddressBook::default();
        let addr = |port: u16| -> libp2p::Multiaddr {
            format!("/ip4/203.0.113.7/tcp/{port}").parse().unwrap()
        };
        let member = PeerId::random();
        let bootnode = PeerId::random();
        book.pin_address(&bootnode, addr(9001));
        for port in 0..(ADDRESSES_PER_PEER as u16 + 3) {
            book.add_address(&member, addr(port));
        }
        book.add_address(&member, addr(10));
        book.pin_address(&member, addr(7000));
        let held = book.addresses_of(&member);
        assert_eq!(held.len(), ADDRESSES_PER_PEER + 1);
        assert_eq!(held[0], addr(7000), "pinned first");
        assert_eq!(
            held.last(),
            Some(&addr(10)),
            "the newest learned last, once"
        );
        let dialled = book
            .handle_pending_outbound_connection(
                libp2p::swarm::ConnectionId::new_unchecked(1),
                Some(member),
                &[],
                libp2p::core::Endpoint::Dialer,
            )
            .unwrap();
        assert_eq!(dialled, held);
        // A stranger flood: unpinned entries come and go, but the pinned
        // bootnode and the member (pinned and refreshed) stay, and so does a
        // peer known only by what it reported, while it keeps reporting
        // (the least recently heard leaves first).
        let early = PeerId::random();
        book.add_address(&early, addr(1));
        let talker = PeerId::random();
        book.add_address(&talker, addr(21));
        for i in 0..(2 * MAX_BOOK_PEERS) {
            book.add_address(&PeerId::random(), addr(1));
            if i == MAX_BOOK_PEERS / 2 {
                book.add_address(&member, addr(11));
            }
            if i % (MAX_BOOK_PEERS / 2) == MAX_BOOK_PEERS / 4 {
                book.add_address(&talker, addr(22));
            }
        }
        assert_eq!(book.len(), MAX_BOOK_PEERS);
        assert_eq!(book.addresses_of(&bootnode), vec![addr(9001)]);
        assert!(book.addresses_of(&member).contains(&addr(7000)));
        assert_eq!(
            book.addresses_of(&talker),
            vec![addr(21), addr(22)],
            "a peer heard from recently was evicted"
        );
        assert!(
            book.addresses_of(&early).is_empty(),
            "an unpinned stranger left"
        );
    }

    /// B75 witness: one network group holds at most its share of the held
    /// answers, whatever is left of the pool; its freed bytes are its own
    /// again.
    #[test]
    fn one_group_cannot_hold_the_whole_pool() {
        let mut held: HeldAnswers<u32> = HeldAnswers::new(Arc::default());
        let answer = SYNC_RESPONSE_CAP;
        assert!(held.admit(0, "203.0", answer), "an answer at the cap fits");
        assert!(held.admit(1, "203.0", answer), "and a second in flight");
        assert!(!held.admit(2, "203.0", answer), "past the group's share");
        assert!(held.admit(3, "198.51", answer), "another group's own share");
        held.release(&0);
        assert!(held.admit(2, "203.0", answer), "freed for its group");
        assert_eq!(held.bytes(), 3 * answer, "answers 1, 2 and 3");
    }

    /// B75 witness: the slots full of a few network groups, a newcomer from
    /// another takes the youngest slot of the largest; one from the largest
    /// group (or a group as large as it but one) is refused; a reserved peer
    /// list parses.
    #[test]
    fn a_full_table_makes_room_for_new_network_groups() {
        assert_eq!(net_group("203.0.113.7"), "203.0");
        assert_eq!(net_group("::ffff:203.0.113.7"), "203.0");
        assert_eq!(net_group("2001:db8:1:2::1"), "2001:db8");
        assert_eq!(net_group("seed.example"), "seed.example");
        let mut slots: NonMemberInbound<usize> = NonMemberInbound::default();
        // 25 hosts at two identities in two /16s: 30 in one, 20 in another.
        for id in 0..MAX_NON_MEMBER_INBOUND {
            let group = if id < 30 { "10.1" } else { "10.2" };
            assert_eq!(slots.admit(id, group), InboundAdmission::Admitted);
        }
        assert_eq!(
            slots.admit(100, "192.0"),
            InboundAdmission::Evicted(29),
            "the youngest of the largest group"
        );
        assert_eq!(slots.len(), MAX_NON_MEMBER_INBOUND);
        assert_eq!(slots.admit(101, "10.1"), InboundAdmission::Refused);
        // Groups of 29 and 20: a newcomer of the second evicts from the
        // first while it holds two more.
        assert_eq!(slots.admit(102, "10.2"), InboundAdmission::Evicted(28));
        // A table of single connections in distinct groups refuses.
        let mut spread: NonMemberInbound<usize> = NonMemberInbound::default();
        for id in 0..MAX_NON_MEMBER_INBOUND {
            spread.admit(id, &format!("g{id}"));
        }
        assert_eq!(spread.admit(999, "new"), InboundAdmission::Refused);
        std::env::set_var("AINCORE_RESERVED_PEERS", " a, b ,,");
        assert_eq!(reserved_peers_from_env().len(), 2);
        std::env::remove_var("AINCORE_RESERVED_PEERS");
    }

    /// B56 witness: with every slot other IPs may use held by silent
    /// handshakes, a new IP is refused and a member's IP is still admitted.
    #[test]
    fn slots_are_kept_for_members_ips() {
        use libp2p::swarm::NetworkBehaviour;
        let members = MemberIps::default();
        let member: std::net::IpAddr = "10.9.9.9".parse().unwrap();
        members.write().unwrap().record_member(
            PeerId::random(),
            member,
            IpSource::Connected,
            std::time::Instant::now(),
            |_| true,
        );
        let mut gate = InboundGate::with_member_ips(members);
        let local: libp2p::Multiaddr = "/ip4/10.0.0.1/tcp/9101".parse().unwrap();
        let from =
            |ip: String| -> libp2p::Multiaddr { format!("/ip4/{ip}/tcp/40000").parse().unwrap() };
        let (mut ok, mut next) = (0, 0usize);
        // Two IPs in each of 32 network groups (B116 bounds a group).
        for i in 0..64u32 {
            let ip = format!("{}.0.2.{}", 100 + i / 2, i % 2);
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
        // B111: and it is not held to the per-IP admission rate: a member's
        // IP opening more than the burst at once is still admitted.
        let peer = PeerId::random();
        let mut admitted = 0;
        for i in 0..(ADMIT_BURST_PER_IP as usize + 8) {
            let id = libp2p::swarm::ConnectionId::new_unchecked(2_000_000 + i);
            if gate
                .handle_pending_inbound_connection(id, &local, &from(member.to_string()))
                .is_ok()
            {
                admitted += 1;
                let _ = gate.handle_established_inbound_connection(id, peer, &local, &local);
            }
        }
        assert_eq!(
            admitted,
            ADMIT_BURST_PER_IP as usize + 8,
            "a member's IP was rate-limited"
        );
        // B221: but held to a rate of its own (a member names the IP it
        // reports): past that burst, at one instant, it is refused.
        let refused = (0..ADMIT_KEPT_BURST as usize).any(|i| {
            let id = libp2p::swarm::ConnectionId::new_unchecked(3_000_000 + i);
            let ok = gate
                .handle_pending_inbound_connection(id, &local, &from(member.to_string()))
                .is_ok();
            if ok {
                let _ = gate.handle_established_inbound_connection(id, peer, &local, &local);
            }
            !ok
        });
        assert!(refused, "a kept IP opened connections without bound");
    }

    /// B116 witness: at a cold start no member has connected yet, and the
    /// bootnodes' IPs are kept from boot, so silent handshakes from other IPs
    /// cannot keep them out; a member's IP is kept one per member (its 32
    /// addresses no longer hold every slot), until it leaves the committee;
    /// and one network group cannot take the other IPs' share.
    #[test]
    fn the_kept_slots_hold_from_boot_and_one_ip_per_member() {
        use libp2p::swarm::NetworkBehaviour;
        let boot = boot_ips(&[
            "/ip4/10.7.7.7/tcp/9101".into(),
            "10.8.8.8:9101".into(),
            "seed.example.org:9101".into(),
        ]);
        assert_eq!(boot.len(), 2, "IP literals only: {boot:?}");
        let kept = MemberIps::new(RwLock::new(KeptIps::with_boot(boot)));
        let mut gate = InboundGate::with_member_ips(Arc::clone(&kept));
        let local: libp2p::Multiaddr = "/ip4/10.0.0.1/tcp/9101".parse().unwrap();
        let from =
            |ip: &str| -> libp2p::Multiaddr { format!("/ip4/{ip}/tcp/40000").parse().unwrap() };
        let mut next = 0usize;
        let mut try_from = |gate: &mut InboundGate, ip: &str| {
            next += 1;
            gate.handle_pending_inbound_connection(
                libp2p::swarm::ConnectionId::new_unchecked(next),
                &local,
                &from(ip),
            )
            .is_ok()
        };
        // One group takes at most PENDING_PER_GROUP of the others' share.
        let one_group = (0..12)
            .filter(|i| try_from(&mut gate, &format!("198.51.{i}.1")))
            .count();
        assert_eq!(one_group, PENDING_PER_GROUP);
        let mut others = one_group;
        for g in 0..64u32 {
            for host in 0..2u32 {
                for _ in 0..PENDING_PER_IP {
                    if try_from(&mut gate, &format!("{}.1.0.{host}", 20 + g)) {
                        others += 1;
                    }
                }
            }
        }
        assert_eq!(
            others,
            MAX_PENDING_INBOUND as usize - PENDING_KEPT_FOR_MEMBERS,
            "vacuous: the others' share is not full"
        );
        assert!(!try_from(&mut gate, "203.0.113.9"), "a new IP got in");
        assert!(try_from(&mut gate, "10.7.7.7"), "a bootnode was kept out");
        assert!(try_from(&mut gate, "10.8.8.8"), "a bootnode was kept out");
        // B132: each kept IP has its own slots: kept IPs holding sixteen
        // between them (all the old shared reservation) and the others'
        // share full, another kept IP still gets in.
        {
            let mut k = kept.write().unwrap();
            for i in 0..5u8 {
                k.record_member(
                    PeerId::random(),
                    std::net::IpAddr::from([10, 6, 0, i]),
                    IpSource::Connected,
                    std::time::Instant::now(),
                    |_| true,
                );
            }
        }
        for i in 0..4u8 {
            for _ in 0..PENDING_PER_IP {
                assert!(
                    try_from(&mut gate, &format!("10.6.0.{i}")),
                    "a kept IP's own slots"
                );
            }
        }
        assert!(
            try_from(&mut gate, "10.6.0.4"),
            "a kept IP shared sixteen slots with the others"
        );
        // B152: per member, its connection's IP and its reported one, each
        // replaced at most once a `KEPT_IP_HOLD`; none once it left the
        // committee. A member rotating its reported IPs gave each its own
        // slots, and two reported interfaces pushed out the connection's.
        let member = PeerId::random();
        let ip = |d: u8| std::net::IpAddr::from([10, 9, 0, d]);
        let t0 = std::time::Instant::now();
        let mut book = kept.write().unwrap();
        book.record_member(member, ip(0), IpSource::Connected, t0, |_| true);
        for i in 1..32u8 {
            book.record_member(member, ip(i), IpSource::Reported, t0, |_| true);
        }
        assert!(book.contains(&ip(0)), "the connection's IP was pushed out");
        assert!(book.contains(&ip(1)), "vacuous: no reported IP kept");
        assert!(
            !book.contains(&ip(31)),
            "a reported IP was replaced within the hold"
        );
        let later = t0 + KEPT_IP_HOLD;
        book.record_member(member, ip(31), IpSource::Reported, later, |_| true);
        assert!(book.contains(&ip(31)) && !book.contains(&ip(1)));
        assert!(book.contains(&ip(0)));
        book.record_member(
            PeerId::random(),
            std::net::IpAddr::from([10, 9, 1, 1]),
            IpSource::Connected,
            later,
            |p| *p != member,
        );
        assert!(
            !book.contains(&ip(31)) && !book.contains(&ip(0)),
            "a member that left kept its slot"
        );
        // B132: the boot list's host names are resolved into the kept set;
        // reserved peers may be given with addresses, kept like bootnodes.
        assert_eq!(
            boot_hosts(&[
                format!("/dns4/node1.example.org/tcp/9101/p2p/{}", PeerId::random()),
                "seed.example.org:9101".into(),
                "10.8.8.8:9101".into(),
            ]),
            vec![
                ("node1.example.org".to_string(), 9101),
                ("seed.example.org".to_string(), 9101)
            ]
        );
        book.set_resolved([std::net::IpAddr::from([10, 5, 5, 5])]);
        assert!(book.contains(&std::net::IpAddr::from([10, 5, 5, 5])));
        let peer = PeerId::random();
        let (peers, addresses) =
            reserved_peers(&format!(" {peer}, /ip4/10.4.4.4/tcp/9101/p2p/{peer} ,"));
        assert_eq!(peers.len(), 1);
        assert_eq!(
            boot_ips(&addresses),
            vec![std::net::IpAddr::from([10, 4, 4, 4])]
        );
    }

    /// B178 witness: a member is charged by its key but takes no kept
    /// snapshot slot or units; a reserved peer does; anyone else is its
    /// network group.
    #[test]
    fn only_a_reserved_peer_is_kept_for_snapshots() {
        let client = |member, reserved, group| snapshot_client("peer", member, reserved, group);
        assert_eq!(
            client(true, false, Some("10.1")),
            ("peer".to_string(), false)
        );
        assert_eq!(
            client(false, true, Some("10.2")),
            ("peer".to_string(), true)
        );
        assert_eq!(client(true, true, None), ("peer".to_string(), true));
        assert_eq!(
            client(false, false, Some("10.3")),
            ("10.3".to_string(), false)
        );
        assert_eq!(client(false, false, None), ("peer".to_string(), false));
    }

    /// B163 witness: a failed or empty lookup keeps a name's last answer;
    /// a new one replaces it.
    #[test]
    fn a_failed_lookup_keeps_the_last_answer() {
        let ip = |d: u8| std::net::IpAddr::from([10, 5, 5, d]);
        let mut names = ResolvedNames::default();
        names.record("seed.example.org", 9101, Some(vec![ip(1)]));
        names.record("seed.example.org", 9101, None);
        names.record("seed.example.org", 9101, Some(vec![]));
        assert_eq!(names.ips(), vec![ip(1)], "a failed lookup cleared it");
        names.record("seed.example.org", 9101, Some(vec![ip(2)]));
        assert_eq!(names.ips(), vec![ip(2)]);
    }

    /// B160 witness: a peer is on this host only when this node's own
    /// connection to it is a loopback one (it was what the peer reported).
    #[test]
    fn on_this_host_is_this_nodes_connection() {
        assert!(on_this_host(Some("127.0.0.1")));
        assert!(on_this_host(Some("::1")));
        assert!(!on_this_host(Some("172.17.0.2")));
        assert!(!on_this_host(Some("203.0.113.7")));
        assert!(!on_this_host(Some("localhost")));
        assert!(!on_this_host(None));
    }

    /// B146 witness: an address a peer reports is kept only as an IP
    /// literal another host can dial; a name it reports is never resolved.
    #[test]
    fn a_reported_name_is_not_kept() {
        let ok = |a: &str| learned_address_ok(&a.parse::<libp2p::Multiaddr>().unwrap());
        assert!(ok("/ip4/203.0.113.7/tcp/9101"));
        assert!(!ok("/dns4/localhost/tcp/9101"));
        assert!(!ok("/dnsaddr/example.org"));
        assert!(!ok("/ip4/127.0.0.1/tcp/9101"));
        let here =
            |a: &str| learned_address_ok_on_this_host(&a.parse::<libp2p::Multiaddr>().unwrap());
        assert!(here("/ip4/127.0.0.1/tcp/9101"));
        assert!(!here("/dns4/localhost/tcp/9101"));
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
        // B148: and its bytes, its largest messages at their cap.
        let largest = consensus::v4::MAX_WIRE_BYTES as f64;
        let bytes = (2.0 + consensus::v4::pull::CLIENT_REQS_PER_TICK as f64) * largest;
        assert!(MEMBER_BYTE_BURST >= 4.0 * bytes);
        assert!(MEMBER_BYTES_PER_SEC >= 4.0 * bytes / 3.0);
    }

    /// B157/B172 witness: a forwarding host's batches are charged their
    /// bytes, read unparsed, on a quota apart from block sync's: at one
    /// instant a burst's worth, whatever the batch holds (one that does not
    /// parse costs the same), at least a token a signature check, and the
    /// largest request fits a fresh quota (a batch of 64 cost one token).
    #[test]
    fn a_submit_is_charged_its_bytes() {
        let now = std::time::Instant::now();
        let tx = "t".repeat(crate::forward::MIN_WIRE_PER_CHECK - 3);
        let batch = format!(
            "{}{}",
            crate::forward::TX_SUBMIT,
            serde_json::to_string(&vec![tx; crate::forward::FORWARD_BATCH]).unwrap()
        );
        let junk = format!(
            "{}{}",
            crate::forward::TX_SUBMIT,
            "[".repeat(batch.len() - crate::forward::TX_SUBMIT.len())
        );
        assert!(
            batch.len() >= crate::forward::FORWARD_BATCH * crate::forward::MIN_WIRE_PER_CHECK,
            "a batch of 64 costs less than 64 checks' worth"
        );
        let fits = (TX_SUBMIT_BYTE_BURST / batch.len() as f64) as usize;
        assert!((1..64).contains(&fits), "vacuous: {fits}");
        for wire in [&batch, &junk] {
            let mut budget = SubmitBudget::default();
            let admitted = (0..64)
                .filter(|_| budget.admit("host:198.51.100.7", wire, false, now))
                .count();
            assert_eq!(admitted, fits, "a submit was not charged its bytes");
            assert!(
                SubmitBudget::default().admit("host:198.51.100.8", wire, false, now),
                "another host's quota is its own"
            );
        }
        let largest = "x".repeat(SYNC_REQUEST_CAP);
        assert!(
            SubmitBudget::default().admit("host:198.51.100.9", &largest, false, now),
            "the largest request does not fit a fresh quota"
        );
    }

    /// B477 witness: an operator's reserved peer (its RPC node, B114)
    /// forwards an observer's full mempool by bytes every re-forward period,
    /// B157's rate in the unit the pool is bounded by (B215); priced as a
    /// stranger, at a check's 324 bytes, it carried ~5 ML-DSA-65
    /// transactions a second to a member. A stranger keeps the check price.
    #[test]
    fn a_reserved_peer_forwards_a_full_pool_a_period() {
        let request = "x".repeat(SYNC_REQUEST_CAP);
        // The bytes one host gets in over a re-forward period once its
        // burst is spent, asking every second at the request cap.
        let carried = |reserved: bool| {
            let mut budget = SubmitBudget::default();
            let key = "host:198.51.100.10";
            let start = std::time::Instant::now();
            while budget.admit(key, &request, reserved, start) {}
            let mut bytes = 0usize;
            for second in 1..=crate::forward::FORWARD_RETRY_SECS {
                let now = start + std::time::Duration::from_secs(second);
                while budget.admit(key, &request, reserved, now) {
                    bytes += request.len();
                }
            }
            bytes
        };
        let reserved = carried(true);
        assert!(
            reserved + SYNC_REQUEST_CAP >= mempool::MAX_PENDING_BYTES,
            "a reserved peer carried {reserved} bytes a period"
        );
        let open = carried(false);
        assert!(
            open < mempool::MAX_PENDING_BYTES / 4,
            "a stranger's quota was raised: {open} bytes a period"
        );
    }

    /// B299 witness: a non-member's built answer is charged its bytes
    /// whether the held-answer bound keeps it or refuses it (a refused one
    /// was free, though the server had read, parsed and serialized it).
    #[test]
    fn a_refused_answer_is_charged_its_bytes() {
        let now = std::time::Instant::now();
        let mut budget: Budget<String> = Budget::new(0.0, 40.0);
        let key = "12D3KooWstranger".to_string();
        assert!(budget.spend(&key, now), "its request");
        let mut held: HeldAnswers<u32> = HeldAnswers::new(Arc::default());
        assert!(
            held.admit(1, "g", OPEN_HELD_PER_GROUP_BYTES),
            "the group's share, held"
        );
        let len = 16 * SYNC_ANSWER_TOKEN_BYTES;
        assert!(
            !charge_then_hold(&mut budget, &mut held, 2, &key, "g", len, now),
            "vacuous: the answer was not refused"
        );
        // 40 - 1 - 16 left: 23, not 24.
        assert!(
            !budget.spend_amount(&key, 24.0, now),
            "the refused answer cost nothing"
        );
        assert!(budget.spend_amount(&key, 23.0, now));
    }

    /// B312 witness: an answer whose requester went before it came is
    /// still charged its bytes, a stranger's and a member's alike (closing
    /// the connection made every answer cost one token); one whose
    /// requester stays is sent, charged as before.
    #[test]
    fn an_abandoned_answer_is_charged_its_bytes() {
        let now = std::time::Instant::now();
        let mut budget: Budget<String> = Budget::new(0.0, 40.0);
        let mut held: HeldAnswers<u32> = HeldAnswers::new(Arc::default());
        let mut serving: Serving<u32, &str> = Serving::default();
        let len = 16 * SYNC_ANSWER_TOKEN_BYTES;
        let answer = || Some("x".repeat(len));
        let open = |group: &str| {
            Some(OpenServe {
                busy: None,
                group: group.to_string(),
            })
        };
        for (id, key, open) in [(1, "host:10.0.0.1", open("g")), (2, "12D3KooWmember", None)] {
            let key = key.to_string();
            assert!(budget.spend(&key, now), "its request");
            serving.begin(id, "channel", key.clone(), open);
            serving.abandon(&id);
            assert!(matches!(
                serving.answered(id, answer(), &mut budget, &mut held, now),
                Answered::Nothing
            ));
            // 40 - 1 - 16 left: 23, not 24.
            assert!(
                !budget.spend_amount(&key, 24.0, now),
                "{key}: the abandoned answer cost nothing"
            );
            assert!(budget.spend_amount(&key, 23.0, now));
        }
        assert!(serving.is_empty());
        let key = "host:10.0.0.2".to_string();
        assert!(budget.spend(&key, now));
        serving.begin(3, "channel", key.clone(), open("h"));
        assert!(matches!(
            serving.answered(3, answer(), &mut budget, &mut held, now),
            Answered::Send("channel", _)
        ));
        assert!(!budget.spend_amount(&key, 24.0, now));
        assert!(budget.spend_amount(&key, 23.0, now));
        assert_eq!(held.bytes(), len, "the answer sent is held");
    }

    /// B148 witness: a member's pushes are charged their bytes, so at one
    /// instant it gets in at most a burst's worth of maximal bodies, though
    /// its message tokens would let in a thousand.
    #[test]
    fn a_members_pushes_are_charged_their_bytes() {
        let mut budget = MemberBudget::default();
        let member = "12D3KooWmember".to_string();
        let now = std::time::Instant::now();
        let largest = consensus::v4::MAX_WIRE_BYTES;
        let admitted = (0..MEMBER_MSG_BURST as usize)
            .filter(|_| budget.admit(&member, largest, now))
            .count();
        let fits = (MEMBER_BYTE_BURST / largest as f64) as usize;
        assert_eq!(
            admitted, fits,
            "maximal pushes were not charged their bytes"
        );
        assert!(
            budget.admit("12D3KooWother", largest, now),
            "another member's budget is its own"
        );
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

    fn swarm(key: identity::Keypair) -> Swarm<request_response::Behaviour<ConsensusCodec>> {
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
                                seen.push(Seen::Delivered(who.to_string(), request.to_string()));
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

    /// B187 witness: an IPv6 host counts by its /64 (loopback and mapped
    /// IPv4 as themselves); a reserved peer syncs on slots of its own.
    #[test]
    fn a_host_is_its_slash_64_and_reserved_peers_sync_apart() {
        use libp2p::swarm::NetworkBehaviour;
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(host_key(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(host_key(ip("::1")), ip("::1"));
        assert_eq!(host_key(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(host_key(ip("192.0.2.7")), ip("192.0.2.7"));
        // One /64's addresses share the per-host handshake bound.
        let mut gate = InboundGate::with_member_ips(MemberIps::default());
        let local: libp2p::Multiaddr = "/ip6/2001:db8::1/tcp/9101".parse().unwrap();
        let admitted = (0..2 * PENDING_PER_IP)
            .filter(|i| {
                let from: libp2p::Multiaddr = format!("/ip6/2001:db8:7:7::{:x}/tcp/40000", i + 1)
                    .parse()
                    .unwrap();
                let id = libp2p::swarm::ConnectionId::new_unchecked(*i);
                gate.handle_pending_inbound_connection(id, &local, &from)
                    .is_ok()
            })
            .count();
        assert_eq!(admitted, PENDING_PER_IP, "each address of a /64 was a host");
        assert_eq!(serve_pool(false, false, true), ServePool::Reserved);
        assert_eq!(serve_pool(false, true, true), ServePool::Member);
        assert_eq!(serve_pool(false, false, false), ServePool::Open);
        assert_eq!(serve_pool(true, false, true), ServePool::ReservedTxSubmit);
        assert_eq!(serve_pool(true, true, false), ServePool::TxSubmit);
    }

    /// B198 witness: successive QC_WANTs ask successive pairs, so every
    /// connected member is asked within `ceil(m / 2)` turns (it asked the
    /// same two every time).
    #[test]
    fn a_qc_want_asks_every_member_in_turn() {
        let peers: Vec<PeerId> = (1..=5u8)
            .map(|s| local_keypair(&[s; 32]).public().to_peer_id())
            .collect();
        let of = |members: Vec<PeerId>| qc_want_candidates(members, []);
        let mut asked = std::collections::HashSet::new();
        for turn in 0..3 {
            let pair = qc_want_peers(of(peers.clone()), turn);
            assert_eq!(pair.len(), 2);
            assert_ne!(pair[0], pair[1]);
            asked.extend(pair);
        }
        assert_eq!(asked.len(), 5, "a member was never asked");
        let mut reversed = peers.clone();
        reversed.reverse();
        assert_eq!(
            qc_want_peers(of(reversed), 1),
            qc_want_peers(of(peers.clone()), 1),
            "the turn depends on the book's order"
        );
        assert_eq!(
            qc_want_peers(of(peers[..1].to_vec()), 7),
            peers[..1].to_vec()
        );
        assert!(qc_want_peers(of(Vec::new()), 3).is_empty());
    }

    /// B207 witness: a member's kept IPv6 address has handshake slots of its
    /// own: a host in the same /64 holding the /64's bound does not keep the
    /// member out (the kept IP was recorded as the /64, shared with it).
    #[test]
    fn a_members_slots_are_its_own_in_a_shared_slash_64() {
        use libp2p::swarm::NetworkBehaviour;
        let members = MemberIps::default();
        let member: std::net::IpAddr = "2001:db8:5:5::10".parse().unwrap();
        members.write().unwrap().record_member(
            PeerId::random(),
            member,
            IpSource::Connected,
            std::time::Instant::now(),
            |_| true,
        );
        let mut gate = InboundGate::with_member_ips(members);
        let local: libp2p::Multiaddr = "/ip6/2001:db8::1/tcp/9101".parse().unwrap();
        let mut next = 0usize;
        let mut open = |gate: &mut InboundGate, ip: String| {
            next += 1;
            let from: libp2p::Multiaddr = format!("/ip6/{ip}/tcp/40000").parse().unwrap();
            let id = libp2p::swarm::ConnectionId::new_unchecked(next);
            gate.handle_pending_inbound_connection(id, &local, &from)
                .is_ok()
        };
        let neighbour = (0..2 * PENDING_PER_IP)
            .filter(|i| open(&mut gate, format!("2001:db8:5:5::{:x}", 0x100 + i)))
            .count();
        assert_eq!(neighbour, PENDING_PER_IP, "vacuous: the /64's bound");
        let admitted = (0..PENDING_PER_IP)
            .filter(|_| open(&mut gate, member.to_string()))
            .count();
        assert_eq!(
            admitted, PENDING_PER_IP,
            "a host in its /64 took the member's slots"
        );
    }

    /// B199 witness: a handshake counts in the bucket it was admitted to: a
    /// member whose kept IP leaves the kept set (it reported another) leaves
    /// that IP's unfinished handshakes in the members' slots, not in the
    /// shared ones (rotating its IP took four shared slots a member).
    #[test]
    fn a_handshake_stays_in_its_bucket() {
        use libp2p::swarm::NetworkBehaviour;
        let members = MemberIps::default();
        let peer = PeerId::random();
        let t0 = std::time::Instant::now();
        let a: std::net::IpAddr = "10.9.9.9".parse().unwrap();
        members
            .write()
            .unwrap()
            .record_member(peer, a, IpSource::Reported, t0, |_| true);
        let mut gate = InboundGate::with_member_ips(Arc::clone(&members));
        let local: libp2p::Multiaddr = "/ip4/10.0.0.1/tcp/9101".parse().unwrap();
        let from =
            |ip: String| -> libp2p::Multiaddr { format!("/ip4/{ip}/tcp/40000").parse().unwrap() };
        let mut next = 0usize;
        let mut open = |gate: &mut InboundGate, ip: String| {
            next += 1;
            let id = libp2p::swarm::ConnectionId::new_unchecked(next);
            gate.handle_pending_inbound_connection(id, &local, &from(ip))
                .is_ok()
        };
        let kept = (0..PENDING_PER_IP)
            .filter(|_| open(&mut gate, a.to_string()))
            .count();
        assert_eq!(kept, PENDING_PER_IP);
        members.write().unwrap().record_member(
            peer,
            "10.8.8.8".parse().unwrap(),
            IpSource::Reported,
            t0 + KEPT_IP_HOLD + std::time::Duration::from_secs(1),
            |_| true,
        );
        assert!(!members.read().unwrap().contains(&a), "vacuous: still kept");
        let mut others = 0;
        for i in 0..64u32 {
            let ip = format!("{}.0.2.{}", 100 + i / 2, i % 2);
            for _ in 0..PENDING_PER_IP {
                if open(&mut gate, ip.clone()) {
                    others += 1;
                }
            }
        }
        assert_eq!(
            others,
            MAX_PENDING_INBOUND as usize - PENDING_KEPT_FOR_MEMBERS,
            "a former kept IP's handshakes took the shared slots"
        );
    }

    /// B200 witness: an answer is read under its request's cap: a height's,
    /// a finality's or a QC's over `SMALL_ANSWER_CAP` is refused, a block
    /// request's of that size is read (every answer took the 10 MiB cap).
    #[test]
    fn an_answer_is_capped_by_its_request() {
        use request_response::Codec;
        let protocol = StreamProtocol::new(SYNC_PROTOCOL);
        let frame = |len: usize| {
            let mut out = (len as u32).to_be_bytes().to_vec();
            out.extend(std::iter::repeat_n(b'x', len));
            out
        };
        let read = |request: &str, len: usize| {
            futures::executor::block_on(async {
                let mut codec = FramedCodec::<String>::new(SYNC_REQUEST_CAP, SYNC_RESPONSE_CAP);
                let mut sink = libp2p::futures::io::Cursor::new(Vec::new());
                codec
                    .write_request(&protocol, &mut sink, request.to_string())
                    .await
                    .unwrap();
                let mut io = libp2p::futures::io::Cursor::new(frame(len));
                codec
                    .read_response(&protocol, &mut io)
                    .await
                    .map(|r| r.len())
            })
        };
        let big = SMALL_ANSWER_CAP + 1;
        for request in ["GET_HEIGHT", "GET_FINALITY", "QC_WANT:7"] {
            assert!(read(request, big).is_err(), "{request}");
        }
        assert_eq!(read("GET_HEIGHT", 40).unwrap(), 40);
        assert_eq!(read("SYNC_REQ:{}", big).unwrap(), big);
        assert!(read("TX_SUBMIT:[]", SUBMIT_ANSWER_CAP + 1).is_err());
    }

    /// B222 witness: an unchanged peer row saved within the hour is fresh
    /// (not written again on each reconnect); a changed or stale one is not.
    #[test]
    fn an_unchanged_peer_row_is_kept() {
        let dir = storage::test_dir::process_dir()
            .join(format!("aincore_b222_peer_rows_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = storage::StateDB::open(dir.to_str().unwrap()).unwrap();
        let addr = "/ip4/203.0.113.9/tcp/9100";
        db.save_peer_addr_at("12D3KooWpeer", addr, 1_000).unwrap();
        assert!(peer_row_is_fresh(&db, "12D3KooWpeer", addr, 1_000 + 60));
        assert!(!peer_row_is_fresh(
            &db,
            "12D3KooWpeer",
            "/ip4/203.0.113.10/tcp/9100",
            1_060
        ));
        assert!(!peer_row_is_fresh(
            &db,
            "12D3KooWpeer",
            addr,
            1_000 + PEER_ROW_FRESH_SECS
        ));
        assert!(!peer_row_is_fresh(&db, "12D3KooWother", addr, 1_060));
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// B186 witness: the key an address pins is read off it (a restore peer
    /// given with its key is answered from the open session to that key).
    #[test]
    fn an_address_names_the_key_it_pins() {
        let id = local_keypair(&[7; 32]).public().to_peer_id();
        let pinned: libp2p::Multiaddr = format!("/ip4/203.0.113.9/tcp/9100/p2p/{id}")
            .parse()
            .unwrap();
        assert_eq!(pinned_peer(&pinned), Some(id));
        let bare: libp2p::Multiaddr = "/ip4/203.0.113.9/tcp/9100".parse().unwrap();
        assert_eq!(pinned_peer(&bare), None);
    }

    /// B185 witness: a saved row naming a host is neither dialled nor then
    /// resolved as a boot name (only the operator's list names hosts), and
    /// one name keeps at most `MAX_IPS_PER_NAME` IPs.
    #[test]
    fn a_saved_name_is_not_a_boot_name() {
        let id = local_keypair(&[6; 32]).public().to_peer_id();
        let saved = vec![
            format!("/dns4/m.attacker.example/tcp/9100/p2p/{id}"),
            format!("/ip4/203.0.113.9/tcp/9100/p2p/{id}"),
        ];
        let list = boot_dial_list(&[], &saved);
        assert_eq!(list, vec![format!("/ip4/203.0.113.9/tcp/9100/p2p/{id}")]);
        assert!(boot_hosts(&list).is_empty(), "a saved name was resolved");
        let mut names = ResolvedNames::default();
        let answer: Vec<std::net::IpAddr> = (0..100u8)
            .map(|d| std::net::IpAddr::from([10, 7, 0, d]))
            .collect();
        names.record("seed.example.org", 9101, Some(answer));
        assert_eq!(names.ips().len(), MAX_IPS_PER_NAME);
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

    /// B334 witness: an IP's admission rate is charged before the unfinished
    /// handshakes are scanned, so a connect the slots refuse is charged too:
    /// past its burst, a freed slot does not let the IP in. The scans (three,
    /// the last allocating two strings an entry) ran first, on the swarm
    /// task, for every refused connect.
    #[test]
    fn the_admission_rate_is_charged_before_the_slots_are_scanned() {
        use libp2p::swarm::{ConnectionId, NetworkBehaviour};
        let mut gate = InboundGate::default();
        let local: Multiaddr = "/ip4/10.0.0.1/tcp/9101".parse().unwrap();
        let from: Multiaddr = "/ip4/9.9.9.9/tcp/40000".parse().unwrap();
        let ids: Vec<ConnectionId> = (0..64).map(ConnectionId::new_unchecked).collect();
        for id in &ids[..PENDING_PER_IP] {
            assert!(gate
                .handle_pending_inbound_connection(*id, &local, &from)
                .is_ok());
        }
        let burst = ADMIT_BURST_PER_IP as usize;
        for id in &ids[PENDING_PER_IP..burst] {
            assert!(gate
                .handle_pending_inbound_connection(*id, &local, &from)
                .is_err());
        }
        gate.pending.remove(&ids[0]);
        let refused = gate
            .handle_pending_inbound_connection(ids[burst], &local, &from)
            .unwrap_err();
        let why = refused
            .downcast_ref::<io::Error>()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            why.contains("too fast"),
            "the connects the slots refused were not charged: {why}"
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
