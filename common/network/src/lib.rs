use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Reserved for future rate limiting implementation
const MAX_CONNECTIONS: usize = 100;
// Default per-IP concurrent inbound connection cap (SEC-#28). Env-tunable via
// AINCORE_MAX_CONN_PER_IP — raise it for CGNAT/reverse-proxy deployments where
// many honest peers legitimately share one source IP.
const MAX_CONN_PER_IP_MIN: usize = 60;

/// Max time allowed for the pre-message-loop handshake (each direction) and for
/// an outbound connect + handshake. Prevents half-open / unresponsive peers from
/// pinning a file descriptor indefinitely (root cause of FD exhaustion).
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const FRAME_LENGTH_TIMEOUT_SECS: u64 = 120;
const FRAME_BODY_TIMEOUT_SECS: u64 = 120;

fn is_docker_bridge_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 172 && (16..=31).contains(&octets[1])
        }
        std::net::IpAddr::V6(_) => false,
    }
}

struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
    per_ip: Arc<Mutex<HashMap<std::net::IpAddr, usize>>>,
    ip: std::net::IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut m) = self.per_ip.lock() {
            if let Some(c) = m.get_mut(&self.ip) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    m.remove(&self.ip);
                }
            }
        }
    }
}

use crypto::transport::TransportEngine;
use storage::StateDB;

pub type PeerList = Arc<Mutex<HashMap<String, u16>>>;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn start_server<F>(
    port: u16,
    node_id: String,
    peers: PeerList,
    db: Arc<StateDB>,
    my_signing_key: Arc<ed25519_dalek::SigningKey>,
    handler: F,
) where
    F: Fn(String) -> Option<String> + Send + Sync + 'static,
{
    use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Failed to bind to port {}: {}", port, e);
            return;
        }
    };
    println!("🌐 Encrypted P2P Server Listening on port {}", port);

    let handler = Arc::new(handler);
    let active_connections = Arc::new(AtomicUsize::new(0));
    // SEC-#28: per-IP concurrent inbound connection cap (anti-Sybil/eclipse).
    // Env-tunable for CGNAT/reverse-proxy where honest peers share a source IP.
    let per_ip_connections: Arc<Mutex<HashMap<std::net::IpAddr, usize>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let max_conn_per_ip = std::env::var("AINCORE_MAX_CONN_PER_IP")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(MAX_CONN_PER_IP_MIN);

    loop {
        let (mut socket, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("⚠️ Accept error: {}", e);
                continue;
            }
        };

        if active_connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            eprintln!(
                "⚠️ Max TCP Connections reached ({}). Rejecting {}",
                MAX_CONNECTIONS, addr
            );
            continue;
        }

        // SEC-#28: per-IP cap. Docker-bridge shared IPs (172.16-31.x) are exempt —
        // many containers legitimately egress one bridge gateway. One source IP
        // cannot otherwise open MAX_CONNECTIONS sessions and starve real peers.
        let peer_ip = addr.ip();
        if !is_docker_bridge_ip(peer_ip) {
            match per_ip_connections.lock() {
                Ok(mut ipm) => {
                    let c = ipm.entry(peer_ip).or_insert(0);
                    if *c >= max_conn_per_ip {
                        eprintln!(
                            "⚠️ Per-IP connection cap ({}) reached for {}; rejecting",
                            max_conn_per_ip, peer_ip
                        );
                        continue;
                    }
                    *c += 1;
                }
                Err(_) => continue,
            }
        }

        let active_counter = active_connections.clone();
        active_counter.fetch_add(1, Ordering::Relaxed);

        let node_id_clone = node_id.clone();
        let peers_clone = peers.clone();
        let db_clone = db.clone();
        let handler_clone = handler.clone();
        let signing_key_clone = Arc::clone(&my_signing_key);
        let per_ip_for_guard = per_ip_connections.clone();

        tokio::spawn(async move {
            let _guard = ConnectionGuard {
                counter: active_counter,
                per_ip: per_ip_for_guard,
                ip: peer_ip,
            };
            let (my_secret, my_public) = TransportEngine::generate_ephemeral();

            // 1. HANDSHAKE INITIATION (Receiver Side)
            // Bounded by a timeout: a peer that completes the TCP handshake (consuming
            // an FD + a ConnectionGuard slot) but never sends its 32-byte ephemeral key
            // would otherwise park this task forever, leaking the FD and the connection
            // slot. Repeated half-open connections were the source of FD exhaustion
            // ("Too many open files", os error 24) on long-lived nodes.
            let mut buf = [0u8; 32];
            match tokio::time::timeout(
                std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                socket.read_exact(&mut buf),
            )
            .await
            {
                Ok(Ok(_)) => {}
                _ => return, // timeout or read error → drop guard, close FD
            }
            let client_public = buf;

            // 2. Compute Signature over Ephemeral Keys
            let mut msg_to_sign = Vec::new();
            msg_to_sign.extend_from_slice(my_public.as_bytes());
            msg_to_sign.extend_from_slice(&client_public);
            let my_signature = signing_key_clone.sign(&msg_to_sign);

            let my_identity_bytes = signing_key_clone.verifying_key().to_bytes();

            // 3. Send Server Hello (Ephemeral Pub, Server Pub Identity, Signature)
            let mut server_hello = Vec::new();
            server_hello.extend_from_slice(my_public.as_bytes());
            server_hello.extend_from_slice(&my_identity_bytes);
            server_hello.extend_from_slice(&my_signature.to_bytes());

            match tokio::time::timeout(
                std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                socket.write_all(&server_hello),
            )
            .await
            {
                Ok(Ok(_)) => {}
                _ => return,
            }

            // 4. Compute Shared Secret
            let shared_key = TransportEngine::diffie_hellman(my_secret, &client_public);

            // Loop for Encrypted Messages
            let mut len_buf = [0u8; 4];
            loop {
                let read_len_res = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    socket.read_exact(&mut len_buf),
                )
                .await;
                match read_len_res {
                    Ok(Ok(_)) => {} // successfully read 4 bytes
                    _ => break,     // Timeout or EOF/connection closed
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;

                if msg_len > 10 * 1024 * 1024 {
                    eprintln!("⚠️ Message too large from {}", addr);
                    break;
                }

                let mut encrypted_msg = vec![0u8; msg_len];
                let read_msg_res = tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    socket.read_exact(&mut encrypted_msg),
                )
                .await;
                match read_msg_res {
                    Ok(Ok(_)) => {}
                    _ => break, // Timeout or EOF
                }

                if msg_len < 12 {
                    break;
                }
                let nonce = &encrypted_msg[0..12];
                let ciphertext = &encrypted_msg[12..];

                let mut nonce_arr = [0u8; 12];
                nonce_arr.copy_from_slice(nonce);

                match TransportEngine::decrypt(&shared_key, &nonce_arr, ciphertext) {
                    Ok(plaintext) => {
                        let msg = String::from_utf8_lossy(&plaintext).to_string();
                        if msg.starts_with("HELLO:") {
                            let parts: Vec<&str> = msg.split(':').collect();
                            if parts.len() >= 5 {
                                let peer_id = parts[1].to_string();
                                let peer_port = parts[2].trim().parse::<u16>().unwrap_or(0);
                                let peer_pubkey_hex = parts[3].to_string();
                                let peer_sig_hex = parts[4].to_string();

                                // Verify Client Signature
                                if let (Ok(pubkey_bytes), Ok(sig_bytes)) =
                                    (hex::decode(&peer_pubkey_hex), hex::decode(&peer_sig_hex))
                                {
                                    if pubkey_bytes.len() == 32 && sig_bytes.len() == 64 {
                                        if let (Ok(pk_arr), Ok(sig_arr)) = (
                                            pubkey_bytes.as_slice().try_into(),
                                            sig_bytes.as_slice().try_into(),
                                        ) {
                                            if let Ok(verifying_key) =
                                                VerifyingKey::from_bytes(pk_arr)
                                            {
                                                let signature = Signature::from_bytes(sig_arr);
                                                let mut verify_msg = Vec::new();
                                                verify_msg.extend_from_slice(&client_public);
                                                verify_msg.extend_from_slice(my_public.as_bytes());

                                                if verifying_key
                                                    .verify(&verify_msg, &signature)
                                                    .is_ok()
                                                {
                                                    // Signature Valid! Register Peer.
                                                    let expected_node_id =
                                                        match crypto::derive_address(&pubkey_bytes)
                                                        {
                                                            Ok(addr) => addr,
                                                            Err(e) => {
                                                                eprintln!(
                                                                    "🚨 Invalid peer public key address derivation from {}: {}",
                                                                    addr, e
                                                                );
                                                                break;
                                                            }
                                                        };
                                                    if expected_node_id == peer_id
                                                        && !peer_id.starts_with("__")
                                                        && peer_port != 0
                                                    {
                                                        let remote_ip = addr.ip();
                                                        let remote_ip_is_docker_bridge =
                                                            is_docker_bridge_ip(remote_ip);
                                                        let remote_ip = remote_ip.to_string();

                                                        if let Ok(mut peers) = peers_clone.lock() {
                                                            peers
                                                                .insert(peer_id.clone(), peer_port);
                                                        } else {
                                                            eprintln!(
                                                                "⚠️ Peers lock poisoned, cannot register peer {}",
                                                                peer_id
                                                            );
                                                        }

                                                        if remote_ip_is_docker_bridge {
                                                            // Docker publishes container ports through the bridge
                                                            // gateway (commonly 172.23.0.1), so a legitimate inbound
                                                            // peer can appear with that source address from inside the
                                                            // container. Keep the authenticated peer in memory for this
                                                            // session, but never persist the bridge gateway as a dial-back
                                                            // address; doing so poisons reconnect with unreachable
                                                            // 172.x:port entries.
                                                            println!(
                                                                "🤝 Authenticated Peer session: {} via Docker bridge (port {})",
                                                                peer_id, peer_port
                                                            );
                                                        } else {
                                                            let _ = db_clone
                                                                .save_peer(&peer_id, peer_port);
                                                            let _ = db_clone
                                                                .save_peer_ip(&peer_id, &remote_ip);
                                                            println!(
                                                                "🤝 Authenticated Peer registered: {} ({}:{})",
                                                                peer_id, remote_ip, peer_port
                                                            );
                                                        }
                                                    }
                                                } else {
                                                    eprintln!(
                                                        "🚨 Invalid Client Signature from {}",
                                                        addr
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                let reply = format!("WELCOME:{}:{}", node_id_clone, port);
                                let _ = send_encrypted(&mut socket, &shared_key, &reply).await;
                            }
                        } else {
                            // Delegate every non-handshake message to the node-provided
                            // handler, which owns the SINGLE serving implementation
                            // (chain_sync::handle_message for GET_HEIGHT / GET_FINALITY /
                            // SYNC_REQ, plus TX / DAG_VERTEX / DA_COMMIT side effects). Any
                            // response it returns is sent back over THIS encrypted socket.
                            // GET_HEIGHT/GET_FINALITY/SYNC_REQ were previously reimplemented
                            // inline here, silently shadowing chain_sync's handlers and
                            // letting serving-side fixes (QC, prune-horizon) land on dead code.
                            if let Some(response) = handler_clone(msg) {
                                let _ = send_encrypted(&mut socket, &shared_key, &response).await;
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("❌ Decryption Failed from {}", addr);
                        break;
                    }
                }
            }
        });
    }
}

async fn send_encrypted(
    socket: &mut tokio::net::TcpStream,
    key: &[u8; 32],
    msg: &str,
) -> std::io::Result<()> {
    // SECURITY: Uses atomic-counter-based nonce generation (encrypt_safe)
    // to guarantee nonce uniqueness per message under the same session key.
    let (nonce, ciphertext) =
        TransportEngine::encrypt_safe(key, msg.as_bytes()).map_err(std::io::Error::other)?;

    // Packet: [Length (4B)][Nonce (12B)][Ciphertext]
    let total_len = 12 + ciphertext.len();
    let len_bytes = (total_len as u32).to_be_bytes();

    let mut packet = Vec::new();
    packet.extend_from_slice(&len_bytes);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);

    socket.write_all(&packet).await
}

pub async fn secure_connect(
    peer_ip: &str,
    peer_port: u16,
    my_node_id: &str,
    my_port: u16,
    expected_peer_id: Option<&str>,
    my_signing_key: &ed25519_dalek::SigningKey,
) -> Result<(tokio::net::TcpStream, [u8; 32], String), Box<dyn std::error::Error + Send + Sync>> {
    use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

    let peer_addr = format!("{}:{}", peer_ip, peer_port);
    // Bounded connect: a dead/unroutable peer (e.g. a stale 127.0.0.1:NNNN entry)
    // must not park this task. Refused connects already return immediately; this
    // guards the SYN-dropped / silent-host case.
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&peer_addr),
    )
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> { "TCP connect timeout".into() })??;

    // 1. Client Hello (Send Ephemeral Public Key)
    let (my_secret, my_public) = TransportEngine::generate_ephemeral();
    tokio::time::timeout(
        std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        stream.write_all(my_public.as_bytes()),
    )
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
        "Handshake write timeout".into()
    })??;

    // 2. Server Hello (Read Ephemeral Pub, Server Pub Identity, Signature)
    // Timeout so a peer that accepts the TCP connection but never replies cannot
    // pin this FD forever (this is the sync-path leak, since the sync caller does
    // not wrap secure_connect in its own timeout).
    let mut server_hello = [0u8; 32 + 32 + 64];
    tokio::time::timeout(
        std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        stream.read_exact(&mut server_hello),
    )
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> { "Server hello timeout".into() })??;

    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&server_hello[0..32]);
    let mut server_identity_bytes = [0u8; 32];
    server_identity_bytes.copy_from_slice(&server_hello[32..64]);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&server_hello[64..128]);

    // 2a. Verify Server Identity Signature
    let server_verifying_key = VerifyingKey::from_bytes(&server_identity_bytes)?;
    let server_signature = Signature::from_bytes(&sig_bytes);

    let mut msg_to_verify = Vec::new();
    msg_to_verify.extend_from_slice(&server_pub);
    msg_to_verify.extend_from_slice(my_public.as_bytes());
    if server_verifying_key
        .verify(&msg_to_verify, &server_signature)
        .is_err()
    {
        return Err("Server Authentication Failed: Invalid Signature".into());
    }

    // 3. Compute Shared Secret
    let shared = TransportEngine::diffie_hellman(my_secret, &server_pub);

    // 4. Client Authentication (Sign and Send Encrypted Identity)
    let mut msg_to_sign = Vec::new();
    msg_to_sign.extend_from_slice(my_public.as_bytes());
    msg_to_sign.extend_from_slice(&server_pub);
    let my_signature = my_signing_key.sign(&msg_to_sign);

    let my_identity_hex = hex::encode(my_signing_key.verifying_key().to_bytes());
    let sig_hex = hex::encode(my_signature.to_bytes());

    // HELLO:<node_id>:<port>:<pubkey_hex>:<sig_hex>
    let hello_msg = format!(
        "HELLO:{}:{}:{}:{}",
        my_node_id, my_port, my_identity_hex, sig_hex
    );
    send_encrypted(&mut stream, &shared, &hello_msg).await?;

    // 5. Read Encrypted Welcome (bounded)
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        stream.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
        "Welcome length timeout".into()
    })??;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    // Guard against a malicious/garbage length pinning a huge allocation.
    if msg_len > 10 * 1024 * 1024 {
        return Err("Welcome message too large".into());
    }
    // SECURITY (FIX-5): a valid encrypted frame is at least a 12-byte nonce.
    // A shorter frame (truncated or hostile peer reply) would otherwise panic
    // on the enc_msg[0..12] slice below and kill the caller's task (permanently
    // disabling periodic sync). Mirror the server accept loop (msg_len < 12).
    if msg_len < 12 {
        return Err("Welcome message too short".into());
    }

    let mut enc_msg = vec![0u8; msg_len];
    tokio::time::timeout(
        std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        stream.read_exact(&mut enc_msg),
    )
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> { "Welcome body timeout".into() })??;

    let nonce = &enc_msg[0..12];
    let cipher = &enc_msg[12..];
    let mut n_arr = [0u8; 12];
    n_arr.copy_from_slice(nonce);

    let plain = TransportEngine::decrypt(&shared, &n_arr, cipher)
        .map_err(|_| "Handshake Decryption Failed")?;

    let resp = String::from_utf8_lossy(&plain).to_string();
    if !resp.starts_with("WELCOME:") {
        return Err("Invalid Handshake Response".into());
    }

    let parts: Vec<&str> = resp.split(':').collect();
    let peer_node_id = if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        "unknown".to_string()
    };

    let server_addr_expected = crypto::derive_address(&server_identity_bytes)
        .map_err(|e| format!("Server identity address derivation failed: {}", e))?;
    if peer_node_id != server_addr_expected {
        eprintln!(
            "🚨 MitM DETECTED! Expected Node Id {}, Got {}",
            server_addr_expected, peer_node_id
        );
        return Err(
            "Identity Mismatch: Node ID does not match the authenticated Public Key!".into(),
        );
    }

    // QUANTUM AUDIT VERIFICATION
    if let Some(expected) = expected_peer_id {
        if peer_node_id != expected {
            eprintln!(
                "🚨 MitM DETECTED! Expected Node {}, Got {}",
                expected, peer_node_id
            );
            return Err(format!(
                "Identity Mismatch! Expected {}, Got {}",
                expected, peer_node_id
            )
            .into());
        }
    }

    Ok((stream, shared, peer_node_id))
}

// Keep synchronous handshake wrapper for backward compatibility if needed,
// using a temporary runtime.
pub fn handshake(
    node_id: &str,
    peer_ip: &str,
    peer_port: u16,
    my_port: u16,
    peers: Arc<Mutex<HashMap<String, u16>>>,
    storage: Arc<StateDB>,
    my_signing_key: Arc<ed25519_dalek::SigningKey>,
) {
    let node_id = node_id.to_string();
    let peer_ip = peer_ip.to_string();

    GOSSIP_RUNTIME.spawn(async move {
        match secure_connect(
            &peer_ip,
            peer_port,
            &node_id,
            my_port,
            None,
            &my_signing_key,
        )
        .await
        {
            Ok((_stream, _shared, peer_node_id)) => {
                println!(
                    "🔒 Encryption Handshake Verified with {}:{} (Node: {})",
                    peer_ip, peer_port, peer_node_id
                );
                if let Ok(mut p) = peers.lock() {
                    p.insert(peer_node_id.clone(), peer_port);
                }
                let _ = storage.save_peer_ip(&peer_node_id, &peer_ip);
            }
            Err(e) => {
                eprintln!(
                    "❌ Secure Handshake Failed with {}:{}: {}",
                    peer_ip, peer_port, e
                );
            }
        }
    });
}

// Expose send/read encrypted helpers for consumers
pub async fn send_encrypted_msg(
    socket: &mut tokio::net::TcpStream,
    key: &[u8; 32],
    msg: &str,
) -> std::io::Result<()> {
    send_encrypted(socket, key, msg).await
}

pub async fn read_encrypted_msg(
    socket: &mut tokio::net::TcpStream,
    key: &[u8; 32],
) -> std::io::Result<String> {
    let mut len_buf = [0u8; 4];
    // Add Timeout for Length Read
    match tokio::time::timeout(
        std::time::Duration::from_secs(FRAME_LENGTH_TIMEOUT_SECS),
        socket.read_exact(&mut len_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Read Length Timeout",
            ));
        }
    }
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if !(12..=10 * 1024 * 1024).contains(&msg_len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid encrypted message length",
        ));
    }

    let mut enc_msg = vec![0u8; msg_len];
    match tokio::time::timeout(
        std::time::Duration::from_secs(FRAME_BODY_TIMEOUT_SECS),
        socket.read_exact(&mut enc_msg),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Read Body Timeout",
            ));
        }
    }

    let nonce = &enc_msg[0..12];
    let cipher = &enc_msg[12..];
    let mut n_arr = [0u8; 12];
    n_arr.copy_from_slice(nonce);

    let plain = TransportEngine::decrypt(key, &n_arr, cipher)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(String::from_utf8_lossy(&plain).to_string())
}

/// Legacy/Simple wrapper for sending encrypted message (Gossip)
/// Uses an ephemeral identity ("gossip", 0) for handshake.
// Use a global runtime for background gossip tasks to avoid thread explosion
use once_cell::sync::Lazy;
static GOSSIP_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2) // Low thread count for background tasks
        .enable_all()
        .build()
        .expect("Failed to create Gossip Runtime")
});

pub fn send_message(addr: &str, msg: &str) -> std::io::Result<()> {
    let addr = addr.to_string();
    let msg = msg.to_string();

    // Spawn on the global runtime instead of creating a new one per message
    GOSSIP_RUNTIME.spawn(async move {
        if let Some((ip, p_str)) = addr.split_once(':') {
            if let Ok(port) = p_str.parse::<u16>() {
                // Generate ephemeral signing key for broadcast
                use rand::rngs::OsRng;
                let mut csprng = OsRng;
                let ephemeral_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

                // C-3 FIX: Use ephemeral key identity instead of __broadcast__ magic string
                let ephemeral_node_id =
                    match crypto::derive_address(&ephemeral_signing_key.verifying_key().to_bytes())
                    {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("❌ Failed to derive ephemeral gossip address: {}", e);
                            return;
                        }
                    };

                // Attempt secure connect with timeout
                if let Ok(Ok((mut stream, shared, _peer_id))) = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    secure_connect(
                        ip,
                        port,
                        &ephemeral_node_id,
                        0,
                        None,
                        &ephemeral_signing_key,
                    ),
                )
                .await
                {
                    let _ = send_encrypted_msg(&mut stream, &shared, &msg).await;
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a peer that accepts the TCP connection but never completes the
    /// handshake must NOT pin secure_connect forever. Before the timeout fix this
    /// hung indefinitely, leaking the FD — the root cause of "Too many open files".
    #[tokio::test]
    async fn secure_connect_times_out_on_stalled_peer() {
        // Listener that accepts then goes silent (never sends server hello).
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept and hold the socket open without writing anything.
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                drop(sock);
            }
        });

        let mut csprng = rand::rngs::OsRng;
        let key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let started = std::time::Instant::now();
        let result = secure_connect("127.0.0.1", addr.port(), "__test__", 0, None, &key).await;

        // Must error out (not succeed) and return well before the stalled peer's
        // 120s hold — i.e. bounded by HANDSHAKE_TIMEOUT_SECS (+ small slack).
        assert!(
            result.is_err(),
            "stalled peer must not produce a live channel"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 5),
            "secure_connect did not respect handshake timeout (elapsed {:?})",
            started.elapsed()
        );
    }

    /// A connect to a port with no listener must fail fast (bounded by connect
    /// timeout), never hang.
    #[tokio::test]
    async fn secure_connect_fails_fast_on_dead_port() {
        let mut csprng = rand::rngs::OsRng;
        let key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let started = std::time::Instant::now();
        // Port 1 on loopback: nothing listens; connect refuses or times out.
        let result = secure_connect("127.0.0.1", 1, "__test__", 0, None, &key).await;
        assert!(result.is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS + 3),
            "connect to dead port did not respect timeout (elapsed {:?})",
            started.elapsed()
        );
    }
}
