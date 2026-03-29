use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::IpAddr;
use std::time::Instant;

// Reserved for future rate limiting implementation
const MAX_CONNECTIONS: usize = 100;
#[allow(dead_code)]
const MAX_CONN_PER_IP_MIN: usize = 60; 

struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

use storage::StateDB;
use crypto::transport::TransportEngine;

pub type PeerList = Arc<Mutex<HashMap<String, u16>>>;

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn start_server<F>(
    port: u16, 
    node_id: String, 
    peers: PeerList, 
    db: Arc<StateDB>, 
    my_signing_key: Arc<ed25519_dalek::SigningKey>,
    handler: F
)
where
    F: Fn(String) + Send + Sync + 'static, 
{
    use ed25519_dalek::{Signer, Verifier, Signature, VerifyingKey};

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

    loop {
        let (mut socket, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("⚠️ Accept error: {}", e);
                continue;
            }
        };

        if active_connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
             eprintln!("⚠️ Max TCP Connections reached ({}). Rejecting {}", MAX_CONNECTIONS, addr);
             continue;
        }

        let active_counter = active_connections.clone();
        active_counter.fetch_add(1, Ordering::Relaxed);
        
        let node_id_clone = node_id.clone();
        let peers_clone = peers.clone();
        let db_clone = db.clone();
        let handler_clone = handler.clone();
        let signing_key_clone = Arc::clone(&my_signing_key);

        tokio::spawn(async move {
            let _guard = ConnectionGuard { counter: active_counter };
            let (my_secret, my_public) = TransportEngine::generate_ephemeral();
            
            // 1. HANDSHAKE INITIATION (Receiver Side)
            let mut buf = [0u8; 32];
            if socket.read_exact(&mut buf).await.is_err() {
                return; 
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
            
            if socket.write_all(&server_hello).await.is_err() {
                return;
            }
            
            // 4. Compute Shared Secret
            let shared_key = TransportEngine::diffie_hellman(my_secret, &client_public);
            
            // Loop for Encrypted Messages
            let mut len_buf = [0u8; 4]; 
            loop {
                if tokio::time::timeout(std::time::Duration::from_secs(60), socket.read_exact(&mut len_buf)).await.is_err() { break; }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                
                if msg_len > 10 * 1024 * 1024 { 
                     eprintln!("⚠️ Message too large from {}", addr);
                     break;
                }
                
                let mut encrypted_msg = vec![0u8; msg_len];
                if tokio::time::timeout(std::time::Duration::from_secs(120), socket.read_exact(&mut encrypted_msg)).await.is_err() { 
                     break; 
                }
                
                if msg_len < 12 { break; }
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
                                 if let (Ok(pubkey_bytes), Ok(sig_bytes)) = (hex::decode(&peer_pubkey_hex), hex::decode(&peer_sig_hex)) {
                                     if pubkey_bytes.len() == 32 && sig_bytes.len() == 64 {
                                         if let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
                                             let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
                                             let mut verify_msg = Vec::new();
                                             verify_msg.extend_from_slice(&client_public);
                                             verify_msg.extend_from_slice(my_public.as_bytes());
                                             
                                             if verifying_key.verify(&verify_msg, &signature).is_ok() {
                                                 // Signature Valid! Register Peer.
                                                 let expected_node_id = hex::encode(&pubkey_bytes)[0..32].to_string();
                                                 if expected_node_id == peer_id && !peer_id.starts_with("__") && peer_port != 0 {
                                                     let remote_ip = addr.ip().to_string();
                                                     peers_clone.lock().unwrap().insert(peer_id.clone(), peer_port);
                                                     let _ = db_clone.save_peer(&peer_id, peer_port);
                                                     let _ = db_clone.save_peer_ip(&peer_id, &remote_ip);
                                                     println!("🤝 Authenticated Peer registered: {} ({}:{})", peer_id, remote_ip, peer_port);
                                                 }
                                             } else {
                                                 eprintln!("🚨 Invalid Client Signature from {}", addr);
                                                 break;
                                             }
                                         }
                                     }
                                 }
                                 
                                 let reply = format!("WELCOME:{}:{}", node_id_clone, port);
                                 let _ = send_encrypted(&mut socket, &shared_key, &reply).await;
                             }
                        } else if msg == "GET_HEIGHT" {
                            // Respond with chain height over the encrypted channel
                            let height = db_clone.get_chain_height();
                            let resp = format!("HEIGHT:{}", height);
                            let _ = send_encrypted(&mut socket, &shared_key, &resp).await;
                        } else if let Some(req_json) = msg.strip_prefix("SYNC_REQ:") {
                            // Handle sync request inline (avoid circular dep with chain_sync)
                            if let Ok(req) = serde_json::from_str::<serde_json::Value>(req_json) {
                                let from_height = req["from_height"].as_u64().unwrap_or(0);
                                let local_height = db_clone.get_chain_height();
                                let end = std::cmp::min(local_height, from_height + 500);
                                let mut blocks_json = Vec::new();
                                for h in (from_height + 1)..=end {
                                    let key = format!("block_{}", h);
                                    if let Ok(Some(data)) = db_clone.get(&key) {
                                        if let Ok(block) = serde_json::from_str::<serde_json::Value>(&data) {
                                            blocks_json.push(block);
                                        }
                                    }
                                }
                                let resp = serde_json::json!({"blocks": blocks_json});
                                let msg = format!("SYNC_RESP:{}", resp);
                                let _ = send_encrypted(&mut socket, &shared_key, &msg).await;
                            }
                        } else {
                            handler_clone(msg);
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

async fn send_encrypted(socket: &mut tokio::net::TcpStream, key: &[u8; 32], msg: &str) -> std::io::Result<()> {
    // Nonce: Random or Counter. For simplicity here: Random 12 bytes
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    
    let ciphertext = TransportEngine::encrypt(key, &nonce, msg.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
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
    use ed25519_dalek::{Signer, Verifier, Signature, VerifyingKey};

    let peer_addr = format!("{}:{}", peer_ip, peer_port);
    let mut stream = tokio::net::TcpStream::connect(&peer_addr).await?;

    // 1. Client Hello (Send Ephemeral Public Key)
    let (my_secret, my_public) = TransportEngine::generate_ephemeral();
    stream.write_all(my_public.as_bytes()).await?;

    // 2. Server Hello (Read Ephemeral Pub, Server Pub Identity, Signature)
    let mut server_hello = [0u8; 32 + 32 + 64];
    stream.read_exact(&mut server_hello).await?;
    
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
    if server_verifying_key.verify(&msg_to_verify, &server_signature).is_err() {
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
    let hello_msg = format!("HELLO:{}:{}:{}:{}", my_node_id, my_port, my_identity_hex, sig_hex);
    send_encrypted(&mut stream, &shared, &hello_msg).await?;

    // 5. Read Encrypted Welcome
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    
    let mut enc_msg = vec![0u8; msg_len];
    stream.read_exact(&mut enc_msg).await?;

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
    let peer_node_id = if parts.len() >= 2 { parts[1].to_string() } else { "unknown".to_string() };

    let server_addr_expected = hex::encode(server_identity_bytes)[0..32].to_string();
    if peer_node_id != server_addr_expected {
         eprintln!("🚨 MitM DETECTED! Expected Node Id {}, Got {}", server_addr_expected, peer_node_id);
         return Err("Identity Mismatch: Node ID does not match the authenticated Public Key!".into());
    }

    // QUANTUM AUDIT VERIFICATION
    if let Some(expected) = expected_peer_id {
        if peer_node_id != expected {
             eprintln!("🚨 MitM DETECTED! Expected Node {}, Got {}", expected, peer_node_id);
             return Err(format!("Identity Mismatch! Expected {}, Got {}", expected, peer_node_id).into());
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
         match secure_connect(&peer_ip, peer_port, &node_id, my_port, None, &my_signing_key).await {
             Ok((_stream, _shared, peer_node_id)) => {
                 println!("🔒 Encryption Handshake Verified with {}:{} (Node: {})", peer_ip, peer_port, peer_node_id);
                 if let Ok(mut p) = peers.lock() {
                     p.insert(peer_node_id.clone(), peer_port);
                 }
                 let _ = storage.save_peer_ip(&peer_node_id, &peer_ip);
             }
             Err(e) => {
                 eprintln!("❌ Secure Handshake Failed with {}:{}: {}", peer_ip, peer_port, e);
             }
         }
     });
}

// Expose send/read encrypted helpers for consumers
pub async fn send_encrypted_msg(socket: &mut tokio::net::TcpStream, key: &[u8; 32], msg: &str) -> std::io::Result<()> {
    send_encrypted(socket, key, msg).await
}

pub async fn read_encrypted_msg(socket: &mut tokio::net::TcpStream, key: &[u8; 32]) -> std::io::Result<String> {
    let mut len_buf = [0u8; 4];
    // Add Timeout for Length Read
    if tokio::time::timeout(std::time::Duration::from_secs(10), socket.read_exact(&mut len_buf)).await.is_err() {
         return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Read Length Timeout"));
    }
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    
    if msg_len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Message too large"));
    }

    let mut enc_msg = vec![0u8; msg_len];
    if tokio::time::timeout(std::time::Duration::from_secs(30), socket.read_exact(&mut enc_msg)).await.is_err() {
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Read Body Timeout"));
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
                 
                 // Attempt secure connect with timeout
                 if let Ok(res) = tokio::time::timeout(
                     std::time::Duration::from_secs(3), 
                     secure_connect(ip, port, "__broadcast__", 0, None, &ephemeral_signing_key)
                 ).await {
                     if let Ok((mut stream, shared, _peer_id)) = res {
                         let _ = send_encrypted_msg(&mut stream, &shared, &msg).await;
                     }
                 }
             }
         }
    });
    
    Ok(())
}