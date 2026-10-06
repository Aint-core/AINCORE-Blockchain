//! The node's view of its network task (G4). Every peer conversation runs
//! over libp2p sessions bound to node keys (`node::sessions`); this crate
//! holds only the types consensus and sync use to reach that task. The
//! legacy transport (a TCP connection plus handshake per message, S6) is
//! gone.

use std::sync::Arc;

/// G4 S1: what consensus hands the network task. Consensus traffic goes over
/// libp2p sessions bound to committee keys (`node::sessions`), never over a
/// connection opened per message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// To every member: gossip, plus a direct push on each member session
    /// (gossip drops a repeat of the same payload for a minute; the push
    /// carries the per-tick retry).
    Broadcast(String),
    /// To one member, by address: an attestation to its author, a pull
    /// answer to its requester.
    To { address: String, wire: String },
}

impl Outbound {
    /// The wire string, wherever it goes.
    pub fn wire(&self) -> &str {
        match self {
            Self::Broadcast(wire) | Self::To { wire, .. } => wire,
        }
    }
}

/// G4 S1: a session the network task holds: the peer's PeerId (as text) and
/// the committee member its key names, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPeer {
    pub peer: String,
    pub member: Option<String>,
}

/// The sessions the network task holds, shared read-only with sync.
pub type SessionTable = Arc<std::sync::RwLock<Vec<SessionPeer>>>;

/// G4 S1: a request on the sync protocol, answered by the session it names.
#[derive(Debug)]
pub struct SyncAsk {
    pub peer: String,
    pub wire: String,
    pub reply: tokio::sync::oneshot::Sender<Result<String, String>>,
}

/// G4 S1: a sync request a session sent, for the node to answer (`None`
/// refuses it: the requester sees a failure).
#[derive(Debug)]
pub struct SyncServe {
    pub peer: String,
    pub member: Option<String>,
    /// B114: a peer the operator reserved (`AINCORE_RESERVED_PEERS`).
    pub reserved: bool,
    pub wire: String,
    pub reply: tokio::sync::oneshot::Sender<Option<String>>,
}

/// G4 S6: a session the node asks the network task to open, to a peer given
/// by address (a restore peer); answered with the PeerId the session
/// authenticated.
#[derive(Debug)]
pub struct SyncDial {
    pub addr: String,
    pub reply: tokio::sync::oneshot::Sender<Result<String, String>>,
}

/// G4 S1: how sync reaches peers: over the sessions the network task holds,
/// never over a connection of its own.
#[derive(Debug, Clone)]
pub struct SessionClient {
    pub asks: tokio::sync::mpsc::Sender<SyncAsk>,
    pub dials: tokio::sync::mpsc::Sender<SyncDial>,
    pub table: SessionTable,
}

impl SessionClient {
    /// The sessions held now, committee members first.
    pub fn sessions(&self) -> Vec<SessionPeer> {
        let mut sessions = self.table.read().map(|t| t.clone()).unwrap_or_default();
        sessions.sort_by_key(|s| s.member.is_none());
        sessions
    }

    /// Open (or reuse) a session to the peer at multiaddr `addr`; its PeerId.
    pub async fn connect(
        &self,
        addr: &str,
        timeout: std::time::Duration,
    ) -> Result<String, String> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.dials
            .send(SyncDial {
                addr: addr.to_string(),
                reply,
            })
            .await
            .map_err(|_| "the network task is gone".to_string())?;
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("the network task dropped the dial".to_string()),
            Err(_) => Err(format!("no session to {addr} within {timeout:?}")),
        }
    }

    /// One request to `peer` and its answer, or why there is none.
    pub async fn ask(
        &self,
        peer: &str,
        wire: &str,
        timeout: std::time::Duration,
    ) -> Result<String, String> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.asks
            .send(SyncAsk {
                peer: peer.to_string(),
                wire: wire.to_string(),
                reply,
            })
            .await
            .map_err(|_| "the network task is gone".to_string())?;
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("the network task dropped the request".to_string()),
            Err(_) => Err(format!("no answer from {peer} within {timeout:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn client() -> (
        SessionClient,
        tokio::sync::mpsc::Receiver<SyncAsk>,
        tokio::sync::mpsc::Receiver<SyncDial>,
    ) {
        let (asks, asks_rx) = tokio::sync::mpsc::channel(4);
        let (dials, dials_rx) = tokio::sync::mpsc::channel(4);
        let client = SessionClient {
            asks,
            dials,
            table: SessionTable::default(),
        };
        (client, asks_rx, dials_rx)
    }

    #[test]
    fn sessions_list_committee_members_first() {
        let (client, _, _) = client();
        let session = |peer: &str, member: Option<&str>| SessionPeer {
            peer: peer.into(),
            member: member.map(Into::into),
        };
        *client.table.write().unwrap() = vec![
            session("a", None),
            session("b", Some("m1")),
            session("c", None),
            session("d", Some("m2")),
        ];
        let peers: Vec<_> = client.sessions().into_iter().map(|s| s.peer).collect();
        assert_eq!(peers, ["b", "d", "a", "c"]);
    }

    #[tokio::test]
    async fn an_ask_is_answered_by_the_session_it_names() {
        let (client, mut asks, _) = client();
        tokio::spawn(async move {
            let ask = asks.recv().await.unwrap();
            let _ = ask.reply.send(Ok(format!("{}:{}", ask.peer, ask.wire)));
        });
        let answer = client.ask("p", "GET_HEIGHT", Duration::from_secs(5)).await;
        assert_eq!(answer.as_deref(), Ok("p:GET_HEIGHT"));
    }

    #[tokio::test]
    async fn an_unanswered_ask_times_out() {
        // The request waits in the task's queue, never taken.
        let (client, _queued, _) = client();
        let answer = client
            .ask("p", "GET_HEIGHT", Duration::from_millis(50))
            .await;
        assert!(answer.unwrap_err().contains("no answer"), "timed out");
    }

    #[tokio::test]
    async fn a_dropped_request_or_a_gone_task_fails_at_once() {
        let (client, mut asks, dials) = client();
        tokio::spawn(async move { drop(asks.recv().await) });
        let dropped = client.ask("p", "x", Duration::from_secs(5)).await;
        assert!(dropped.unwrap_err().contains("dropped"));
        drop(dials);
        let gone = client
            .connect("/ip4/127.0.0.1/tcp/1", Duration::from_secs(5))
            .await;
        assert!(gone.unwrap_err().contains("gone"));
    }
}
