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
    pub dials: mpsc::Receiver<network::SyncDial>,
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
        let (dials_tx, dials) = mpsc::channel(16);
        let (serves, serves_rx) = mpsc::channel(64);
        (
            Self {
                book,
                table: Arc::clone(&table),
                asks,
                dials,
                serves,
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

/// G4 S5: the one gossip topic.
pub const GOSSIP_TOPIC: &str = "aincore-gossip";

/// G4 S5: what the network task tells gossipsub about a message it
/// received. With `validate_messages` a message is forwarded only once it
/// is accepted, so a message the node would drop is never relayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipVerdict {
    /// Delivered to the node and forwarded.
    Accept,
    /// Dropped, not forwarded, and counted against the peer that sent it
    /// (gossipsub P4): no honest node sends it.
    Reject,
    /// Dropped and not forwarded, without blame: the sender may be an
    /// honest relay whose committee book differs at an epoch boundary, or
    /// the message is merely over a rate.
    Ignore,
}

/// The gossip each prefix may carry and its size cap, checked before any
/// parse. No honest node gossips anything else (transactions travel in
/// vertices; `TX:` gossip had no publisher, B21).
const GOSSIP_CAPS: &[(&str, usize)] = &[
    (consensus::v4::WIRE_PREFIX, consensus::v4::MAX_WIRE_BYTES),
    ("QC_VOTE:", consensus::dag::QC_VOTE_MAX_BYTES),
    (consensus::dag::QC_WANT_PREFIX, 64),
    (consensus::dag::QC_CERT_PREFIX, CONSENSUS_REQUEST_CAP),
];

/// G4 S5 (NI-1): the verdict on a gossip message from `relay` (the peer
/// that sent it) signed by `publisher`. A member-only message from a
/// non-member is blamed on the relay only when the relay published it
/// itself; relayed, it may be an honest view difference.
pub fn judge_gossip(
    book: &PeerBook,
    publisher: Option<&PeerId>,
    relay: &PeerId,
    wire: &str,
) -> GossipVerdict {
    let Some(&(_, cap)) = GOSSIP_CAPS.iter().find(|(p, _)| wire.starts_with(p)) else {
        return GossipVerdict::Reject;
    };
    if wire.len() > cap {
        return GossipVerdict::Reject;
    }
    if admit_gossip(book, publisher, wire) {
        GossipVerdict::Accept
    } else if publisher.is_none_or(|p| p == relay) {
        GossipVerdict::Reject
    } else {
        GossipVerdict::Ignore
    }
}

/// G4 S5: gossipsub as the node runs it. `validate_messages`: nothing is
/// forwarded before `judge_gossip` accepts it. Signed publishers with
/// strict validation, a 1 MiB transmit cap, sha256 message ids and a 60 s
/// duplicate cache (M-05).
pub fn gossip_config() -> Result<libp2p::gossipsub::Config, String> {
    use libp2p::gossipsub::{ConfigBuilder, MessageId, ValidationMode};
    use sha2::{Digest, Sha256};
    ConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .validate_messages()
        .max_transmit_size(1 << 20)
        .mesh_n(6)
        .mesh_n_low(4)
        .mesh_n_high(12)
        .heartbeat_interval(std::time::Duration::from_secs(1))
        .duplicate_cache_time(std::time::Duration::from_secs(60))
        .message_id_fn(|msg| MessageId::from(Sha256::digest(&msg.data).to_vec()))
        .build()
        .map_err(|e| format!("gossipsub config: {e}"))
}

/// The gossipsub behaviour: `gossip_config`, peer scoring
/// (`gossip_score_params`, `gossip_score_thresholds`), subscribed to
/// `GOSSIP_TOPIC`.
pub fn gossip_behaviour(key: &identity::Keypair) -> Result<libp2p::gossipsub::Behaviour, String> {
    use libp2p::gossipsub::{Behaviour, IdentTopic, MessageAuthenticity};
    let mut gossip = Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossip_config()?)
        .map_err(|e| e.to_string())?;
    gossip.with_peer_score(gossip_score_params(), gossip_score_thresholds())?;
    gossip
        .subscribe(&IdentTopic::new(GOSSIP_TOPIC))
        .map_err(|e| e.to_string())?;
    Ok(gossip)
}

/// Lighthouse's peer-score thresholds
/// (`lighthouse_network/src/service/gossipsub_scoring_parameters.rs`).
pub fn gossip_score_thresholds() -> libp2p::gossipsub::PeerScoreThresholds {
    libp2p::gossipsub::PeerScoreThresholds {
        gossip_threshold: -4000.0,
        publish_threshold: -8000.0,
        graylist_threshold: -16000.0,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    }
}

/// Score decays are ticked every second (gossipsub's default interval;
/// Lighthouse ticks once a slot, at least a second).
const SCORE_DECAY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Lighthouse's epoch, the unit its decay times are given in (32 slots of
/// 12 s).
const LIGHTHOUSE_EPOCH_SECS: f64 = 384.0;
/// Lighthouse: a peer's mesh time earns at most 10, its first deliveries at
/// most 40, per unit of topic weight.
const MAX_IN_MESH_SCORE: f64 = 10.0;
const MAX_FIRST_DELIVERIES_SCORE: f64 = 40.0;

/// The per-tick factor that takes a counter to 1 % in `secs` (Lighthouse
/// `score_parameter_decay`).
fn decay_over(secs: f64) -> f64 {
    0.01f64.powf(SCORE_DECAY_INTERVAL.as_secs_f64() / secs)
}

/// G4 S5: gossipsub peer scoring, Lighthouse's rules on our one topic (its
/// weight is one). An invalid delivery (P4) cancels the most a peer can
/// earn (`-(10 + 40)`), and P4 is the square of the count, so a peer that
/// sends 9 invalid messages falls below the gossip threshold and one that
/// sends 18 below the graylist; the count decays to 1 % over 50 Lighthouse
/// epochs. Mesh delivery rates (P3) are not scored: consensus gossip has no
/// steady rate and Lighthouse leaves P3 off for such topics. More than 8
/// peers on one IP are penalised (P6), behaviour penalties (P7) past 6.
pub fn gossip_score_params() -> libp2p::gossipsub::PeerScoreParams {
    use libp2p::gossipsub::{IdentTopic, PeerScoreParams, TopicScoreParams};
    let max_positive = MAX_IN_MESH_SCORE + MAX_FIRST_DELIVERIES_SCORE;
    let topic_weight = 1.0;
    // Lighthouse: time in mesh reaches its cap after an hour.
    let quantum = SCORE_DECAY_INTERVAL;
    let time_in_mesh_cap = 3600.0 / quantum.as_secs_f64();
    // A choice: first deliveries count up to 40 and decay to 1 % in an
    // hour, so a peer earns the Lighthouse maximum by relaying 40 messages
    // first.
    let first_cap = MAX_FIRST_DELIVERIES_SCORE;
    let topic = TopicScoreParams {
        topic_weight,
        time_in_mesh_weight: MAX_IN_MESH_SCORE / time_in_mesh_cap,
        time_in_mesh_quantum: quantum,
        time_in_mesh_cap,
        first_message_deliveries_weight: MAX_FIRST_DELIVERIES_SCORE / first_cap,
        first_message_deliveries_decay: decay_over(3600.0),
        first_message_deliveries_cap: first_cap,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: -max_positive / topic_weight,
        invalid_message_deliveries_decay: decay_over(50.0 * LIGHTHOUSE_EPOCH_SECS),
        ..TopicScoreParams::default()
    };
    let thresholds = gossip_score_thresholds();
    let behaviour_penalty_threshold = 6.0;
    let behaviour_penalty_decay = decay_over(10.0 * LIGHTHOUSE_EPOCH_SECS);
    // Lighthouse: a peer earning 10 penalties an epoch converges to the
    // gossip threshold.
    let per_tick = 10.0 / LIGHTHOUSE_EPOCH_SECS * SCORE_DECAY_INTERVAL.as_secs_f64();
    let converged = per_tick / (1.0 - behaviour_penalty_decay) - behaviour_penalty_threshold;
    let topic_score_cap = max_positive * 0.5;
    let mut params = PeerScoreParams {
        topic_score_cap,
        app_specific_weight: 1.0,
        ip_colocation_factor_weight: -topic_score_cap,
        ip_colocation_factor_threshold: 8.0,
        behaviour_penalty_weight: thresholds.gossip_threshold / converged.powi(2),
        behaviour_penalty_threshold,
        behaviour_penalty_decay,
        decay_interval: SCORE_DECAY_INTERVAL,
        decay_to_zero: 0.01,
        retain_score: std::time::Duration::from_secs_f64(100.0 * LIGHTHOUSE_EPOCH_SECS),
        ..PeerScoreParams::default()
    };
    params
        .topics
        .insert(IdentTopic::new(GOSSIP_TOPIC).hash(), topic);
    params
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
        for wire in ["QC_WANT:7", "QC_CERT:{}"] {
            assert!(admit_gossip(&book, Some(&stranger), wire), "{wire}");
        }
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

    /// G4 S5: what a received gossip message gets. Accepted: a member's
    /// consensus message, and a boundary QC request or answer from anyone.
    /// Rejected (blamed on the sender): what no node gossips (transactions
    /// included, B21), anything over its type's cap, and a member-only
    /// message its non-member sender published itself. Ignored: the same
    /// message relayed by another peer, whose view may differ.
    #[test]
    fn every_gossip_message_gets_the_node_rules_verdict() {
        use GossipVerdict::*;
        let (a, sa) = member(1);
        let book = PeerBook::new(0, &[&[a]]);
        let member = local_keypair(&sa).public().to_peer_id();
        let stranger = local_keypair(&[9; 32]).public().to_peer_id();
        let relay = local_keypair(&[5; 32]).public().to_peer_id();
        for wire in ["DAG_V4:{}", "QC_VOTE:{}"] {
            assert_eq!(judge_gossip(&book, Some(&member), &relay, wire), Accept);
            assert_eq!(judge_gossip(&book, Some(&member), &member, wire), Accept);
            assert_eq!(
                judge_gossip(&book, Some(&stranger), &stranger, wire),
                Reject
            );
            assert_eq!(judge_gossip(&book, None, &stranger, wire), Reject);
            assert_eq!(judge_gossip(&book, Some(&stranger), &relay, wire), Ignore);
        }
        for wire in ["QC_WANT:7", "QC_CERT:{}"] {
            assert_eq!(
                judge_gossip(&book, Some(&stranger), &stranger, wire),
                Accept
            );
        }
        for wire in ["TX:{}", "{}", "DAG_VERTEX:{}", "HELLO", ""] {
            assert_eq!(
                judge_gossip(&book, Some(&member), &member, wire),
                Reject,
                "{wire}"
            );
        }
        let vote = format!("QC_VOTE:{}", "x".repeat(consensus::dag::QC_VOTE_MAX_BYTES));
        assert_eq!(judge_gossip(&book, Some(&member), &member, &vote), Reject);
        let want = format!("QC_WANT:{}", "9".repeat(64));
        assert_eq!(
            judge_gossip(&book, Some(&stranger), &stranger, &want),
            Reject
        );
    }

    /// G4 S5: the scoring is valid for gossipsub and does what its comment
    /// says: one invalid delivery cancels the most a peer can earn, 9 put
    /// a peer below the gossip threshold, 18 below the graylist.
    #[test]
    fn the_peer_score_follows_lighthouses_rules() {
        let params = gossip_score_params();
        params.validate().unwrap();
        let t = gossip_score_thresholds();
        let topic = &params.topics[&libp2p::gossipsub::IdentTopic::new(GOSSIP_TOPIC).hash()];
        let max_positive = topic.time_in_mesh_weight * topic.time_in_mesh_cap
            + topic.first_message_deliveries_weight * topic.first_message_deliveries_cap;
        assert!((max_positive - 50.0).abs() < 1e-9, "{max_positive}");
        assert_eq!(topic.invalid_message_deliveries_weight, -max_positive);
        let p4 = |k: f64| topic.invalid_message_deliveries_weight * k * k;
        assert!(p4(8.0) > t.gossip_threshold && p4(9.0) < t.gossip_threshold);
        assert!(p4(17.0) > t.graylist_threshold && p4(18.0) < t.graylist_threshold);
        // The behaviour-penalty weight Lighthouse derives (-15.9 at its 12 s
        // slot; the 1 s tick changes it by under 2 %).
        assert!(
            (-16.5..-15.5).contains(&params.behaviour_penalty_weight),
            "{}",
            params.behaviour_penalty_weight
        );
        // P4 halves in under 50 epochs: (decay ^ ticks) reaches 1 % then.
        let after = topic
            .invalid_message_deliveries_decay
            .powf(50.0 * LIGHTHOUSE_EPOCH_SECS);
        assert!((after - 0.01).abs() < 1e-6, "{after}");
    }

    fn gossip_swarm(key: &identity::Keypair) -> Swarm<libp2p::gossipsub::Behaviour> {
        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(key).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();
        Swarm::new(
            transport,
            gossip_behaviour(key).unwrap(),
            key.public().to_peer_id(),
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(30)),
        )
    }

    /// One swarm event, handled with the node's rule (`judge_gossip`, then
    /// the verdict reported to gossipsub). Returns a received message.
    fn on_gossip(
        swarm: &mut Swarm<libp2p::gossipsub::Behaviour>,
        book: &PeerBook,
        ev: SwarmEvent<libp2p::gossipsub::Event>,
    ) -> Option<String> {
        use libp2p::gossipsub::{Event, MessageAcceptance};
        let SwarmEvent::Behaviour(Event::Message {
            propagation_source,
            message_id,
            message,
        }) = ev
        else {
            return None;
        };
        let wire = String::from_utf8_lossy(&message.data).into_owned();
        let acceptance =
            match judge_gossip(book, message.source.as_ref(), &propagation_source, &wire) {
                GossipVerdict::Accept => MessageAcceptance::Accept,
                GossipVerdict::Reject => MessageAcceptance::Reject,
                GossipVerdict::Ignore => MessageAcceptance::Ignore,
            };
        let _ = swarm.behaviour_mut().report_message_validation_result(
            &message_id,
            &propagation_source,
            acceptance,
        );
        Some(wire)
    }

    /// G4 S5 witness: a stranger next to an honest relay cannot reach the
    /// relay's other peers with consensus gossip or junk, while a member's
    /// message crosses the same relay; and the stranger's invalid messages
    /// drive its score at the relay below the graylist. Without
    /// `validate_messages` the relay forwards before judging and the
    /// observer hears the stranger.
    #[tokio::test]
    async fn a_relay_forwards_what_the_node_accepts_and_scores_the_rest() {
        let (m_info, m_secret) = member(1);
        let book = PeerBook::new(0, &[&[m_info]]);
        let mut relay = gossip_swarm(&local_keypair(&[5; 32]));
        let mut member_node = gossip_swarm(&local_keypair(&m_secret));
        let mut stranger = gossip_swarm(&local_keypair(&[9; 32]));
        let mut observer = gossip_swarm(&local_keypair(&[6; 32]));
        let addr: Multiaddr = format!("/memory/{}", rand::random::<u64>() | 1)
            .parse()
            .unwrap();
        relay.listen_on(addr.clone()).unwrap();
        for s in [&mut member_node, &mut stranger, &mut observer] {
            s.dial(addr.clone()).unwrap();
        }
        let stranger_id = *stranger.local_peer_id();
        let topic = libp2p::gossipsub::IdentTopic::new(GOSSIP_TOPIC);
        let (mut heard, mut sent_member, mut sent_stranger) = (Vec::new(), false, 0usize);
        let start = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        while start.elapsed() < Duration::from_secs(20) {
            tokio::select! {
                ev = relay.select_next_some() => { on_gossip(&mut relay, &book, ev); }
                ev = member_node.select_next_some() => { on_gossip(&mut member_node, &book, ev); }
                ev = stranger.select_next_some() => { on_gossip(&mut stranger, &book, ev); }
                ev = observer.select_next_some() => {
                    if let Some(wire) = on_gossip(&mut observer, &book, ev) {
                        heard.push(wire);
                    }
                }
                _ = tick.tick() => {
                    // Publish once the mesh had three heartbeats to form.
                    if start.elapsed() < Duration::from_secs(3) {
                        continue;
                    }
                    if !sent_member {
                        sent_member = member_node
                            .behaviour_mut()
                            .publish(topic.clone(), b"DAG_V4:member".to_vec())
                            .is_ok();
                    }
                    if sent_stranger < 20 {
                        let junk = if sent_stranger % 2 == 0 { "DAG_V4" } else { "TX" };
                        let wire = format!("{junk}:stranger-{sent_stranger}");
                        if stranger.behaviour_mut().publish(topic.clone(), wire.into_bytes()).is_ok() {
                            sent_stranger += 1;
                        }
                    }
                    let score = relay.behaviour().peer_score(&stranger_id).unwrap_or(0.0);
                    if heard.iter().any(|w| w == "DAG_V4:member")
                        && sent_stranger == 20
                        && score < gossip_score_thresholds().graylist_threshold
                    {
                        break;
                    }
                }
            }
        }
        assert!(
            heard.iter().any(|w| w == "DAG_V4:member"),
            "positive control: the member's message crossed the relay: {heard:?}"
        );
        assert_eq!(sent_stranger, 20, "the stranger published");
        assert!(
            !heard.iter().any(|w| w.contains("stranger")),
            "the relay forwarded the stranger: {heard:?}"
        );
        let score = relay.behaviour().peer_score(&stranger_id).unwrap();
        assert!(
            score < gossip_score_thresholds().graylist_threshold,
            "the stranger's score at the relay: {score}"
        );
    }
}
