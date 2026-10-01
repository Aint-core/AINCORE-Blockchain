# G4 contract: network isolation

Status: draft, 2026-10-02. Gate (PRODUCTION_READINESS_GOAL.md): explicit session
authentication; bounded requests, queues, storage and CPU; validator connectivity under abusive
traffic. G1 depends on it (an authenticated session identity and reserved connection slots,
G1 LA-5 and RE-6). Every rule below cites the production system it is taken from; sources were
read at their branch heads on 2026-10-02 (aptos-core 9bc1a79b, sui f8892cab, anemo 68adc31d,
cometbft 65c54ed4, lighthouse 6db6ae93, libp2p/specs 78e75c6f, consensus-specs 889a389f,
agave 589b99b8).

## What exists today

| Surface | Today | Gap |
|---|---|---|
| libp2p (Noise + yamux, gossipsub, topic `aincore-gossip`) | Broadcast of vertices, attestations, certificates. Strict validation, 1 MiB transmit cap, message id = sha256(payload) | No peer scoring, no explicit validator peering, no link from PeerId to a committee member, no per-peer budgets |
| Legacy TCP (`common/network`) | Every message opens a new TCP connection with an ephemeral X25519 handshake and an ed25519-signed HELLO; 1 MiB frame cap, 100 msg/s per connection, 100 connections node-wide, 60 per IP | Per-message connections: on the NAS honest traffic alone hit the cap (~1,200 refusals per 10 min). Limits keyed on IP, not identity. No committee gate |
| Sync serving (`chain_sync::handle_message`: VERTEX_REQ, SYNC_REQ, GET_HEIGHT, GET_FINALITY, QC_*) | Over the legacy TCP channel | Request budgets are node-wide, not per authenticated peer |
| DA batches | Sent per batch over the legacy TCP channel | Broken: every batch is refused (`[DA] Identity mismatch`). The batch is signed by a separate random DA key, and receivers require address(DA key) = proposer address. 2,595 of 2,595 refused on the S6 cluster |
| Peer addresses | `storage.get_peer_ip` defaults to 127.0.0.1 | A restarted S6 validator dialled its peers' ports on 127.0.0.1 (refused, retried); addresses must come from the authenticated session or the operator's bootnodes |
| RPC (actix-web, `api_local`) | 127.0.0.1 unless `AINCORE_RPC_BIND`; 100 req/s per IP, burst 200 | Same process as consensus |

## Rules

**NI-1 One authenticated session per peer, bound to committee keys.** All consensus, sync and
DA traffic runs over persistent, encrypted, mutually authenticated sessions. The session
identity is the node's ed25519 key, so a session names a committee member (or no member). The
legacy per-message TCP channel is retired. Sources: Aptos Noise IK with
`HandshakeAuthMode::Mutual` against the on-chain `ValidatorSet`
(`network/framework/src/noise/handshake.rs`); Sui TLS 1.3 with `AllowPublicKeys` = committee
network keys (`crates/sui-tls/src/verifier.rs`); CometBFT SecretConnection (dialed ID must equal
the authenticated ID). Every system keeps one long-lived connection per peer; none connects per
message.

**NI-2 Reserved slots for the committee.** Members of C_E and C_{E+1} are always admitted and
never count against the caps for other peers. Non-members share a fixed cap (Aptos
`MAX_INBOUND_CONNECTIONS` = 50, counting only unknown peers; CometBFT 40 inbound, 10 outbound;
anemo `PeerAffinity::High` bypasses `max_concurrent_connections`). Before authentication only
an IP admission rate applies (anemo 10 per second per IP, burst 100; Agave 8 connections per
minute per IP).

**NI-3 Budgets per authenticated peer, not per IP.** Each peer has bounded queues and token
buckets keyed on its session identity:
- a FIFO per (peer, message type) with the newest dropped when full (Aptos consensus: 10 per
  key, `aptos_channel`; per-peer network FIFO 1,024);
- concurrent inbound requests per peer (Aptos `MAX_CONCURRENT_INBOUND_RPCS` 100; Ethereum
  `MAX_CONCURRENT_REQUESTS` 2 per protocol) with a timeout (Aptos 10 s);
- request quotas per peer and method (Lighthouse GCRA, e.g. 128 block-range requests per 10 s);
- a signature-verification budget per peer, spent before any expensive check: one verification
  costs ~80 µs, so a few tens of Mbps of signatures halt a HotStuff node (Giuliari et al.,
  AsiaCCS 2024).

**NI-4 Size caps before parsing.** Every message type has a byte cap checked on the frame
before decoding (Ethereum checks `MAX_PAYLOAD_SIZE` 10 MiB before decompression; Aptos 4 MiB
frames, 64 MiB messages; CometBFT 1 MB consensus messages). Ours: vertex ≤ `MAX_VERTEX_BYTES`
(768 KiB), attestations and votes a few KiB, sync responses bounded by count and bytes.

**NI-5 Byzantine fetch bounds.** Requests are clamped (Sui `max_blocks_per_fetch` 1,000,
`max_blocks_per_sync` 32; Ethereum `MAX_REQUEST_BLOCKS` 1,024). A pushed vertex must come from
its author's own session (Sui rejects `peer != author`). Nothing below the GC floor is kept,
and pending vertices are capped per author (`PENDING_MAX_PER_AUTHOR` 16 exists). Narwhal's
rules (first vertex per author per round, 2f+1 certificates to advance) keep the in-memory DAG
O(n) per round.

**NI-6 Gossip hygiene.** gossipsub v1.1 peer scoring (P1–P7, including P6 IP colocation and the
P7 behaviour penalty) with explicit peering among committee members, against the Sybil, eclipse
and flash attacks of Vyzovitis et al. 2020 (arXiv 2007.02754). Thresholds start from
Lighthouse's (greylist −16,000; gossip −4,000; publish −8,000; IP colocation factor threshold 8).

**NI-7 Public traffic stays out of the validator's path.** The RPC and transaction ingress have
their own budgets and never hold consensus locks (the non-blocking RPC already does the
latter). Stake-weighted QoS for transaction ingress (Agave: stream share by stake, unstaked
peers 200 TPS) is a later option, not a launch rule.

**NI-8 DA rides the same identity.** A DA batch is signed by the node key under its own domain
(or by a DA key that the node key certifies), so receivers check it against the committee.

## Stages

| Stage | Content | Witness |
|---|---|---|
| S1 | Committee-bound sessions: libp2p PeerId from the node key; map PeerId ↔ committee address per epoch; request-response protocols for VERTEX_REQ, SYNC_REQ and the QC messages over persistent sessions | A node accepts a request only from a session whose key it can name; a forged HELLO cannot claim a member's identity |
| S2 | Reserved committee slots, caps for non-members, IP admission rate | With non-member connections at the cap, every committee member still connects |
| S3 | Per-peer queues, request quotas and verification budgets | One member flooding each message type at line rate: the others keep finality, the victim's memory and CPU stay bounded |
| S4 | Size caps per type before decode | An oversized frame of each type is dropped before any parse |
| S5 | gossipsub scoring and explicit validator peering | A Sybil swarm of non-members cannot eclipse a member |
| S6 | Retire the legacy TCP channel; DA over sessions (NI-8, fixing the identity bug) | No code path opens a connection per message; DA batches are accepted across nodes |
| S7 | Flood harness and an adversarial review | The gate's "validator connectivity under abusive traffic", measured on the NAS and Pi |

Open: parameter values are set from these sources and the S7 measurements on real hardware,
not before.
