use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::IpAddr;
use std::time::{Instant, Duration};

const MAX_CONNECTIONS: usize = 100;
const MAX_CONN_PER_IP_MIN: usize = 60; // 60 connections per minute per IP

struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

use storage::StateDB;

pub type PeerList = Arc<Mutex<HashMap<String, u16>>>;

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn start_server<F>(port: u16, node_id: String, peers: PeerList, db: Arc<StateDB>, handler: F)
where
    F: Fn(String) + Send + Sync + 'static, // Handler needs to be Send + Sync for Arc
{
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Failed to bind to port {}: {}", port, e);
            return;
        }
    };
    println!("🌐 Async TCP Server Listening on port {}", port);

    let handler = Arc::new(handler); // Share handler across tasks
    let active_connections = Arc::new(AtomicUsize::new(0));
    let ip_limiter: Arc<Mutex<HashMap<IpAddr, (usize, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        // Accept new connection
        let (mut socket, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("⚠️ Accept error: {}", e);
                continue;
            }
        };

        // 🛡️ Global Connection Limit
        let current_conns = active_connections.load(Ordering::Relaxed);
        if current_conns >= MAX_CONNECTIONS {
            eprintln!("⚠️ Connection limit reached ({}/{}) - Rejecting {}", current_conns, MAX_CONNECTIONS, addr);
            continue;
        }

        // 🛡️ Per-IP Rate Limiting
        let is_rate_limited = {
             let mut limiter = ip_limiter.lock().expect("IP Limiter Mutex Poisoned");
             let (count, start_time) = limiter.entry(addr.ip()).or_insert((0, Instant::now()));
             
             if start_time.elapsed() > Duration::from_secs(60) {
                 *count = 0;
                 *start_time = Instant::now();
             }
             
             *count += 1;
             *count > MAX_CONN_PER_IP_MIN
        }; // Drop lock

        if is_rate_limited {
             eprintln!("⚠️ Rate limit exceeded for {} (Max {}/min) - Rejecting", addr.ip(), MAX_CONN_PER_IP_MIN);
             continue;
        }
        
        // Increment before spawn
        active_connections.fetch_add(1, Ordering::Relaxed);

        let node_id_clone = node_id.clone();
        let peers_clone = peers.clone();
        let db_clone = db.clone();
        let handler_clone = handler.clone();
        let active_counter = active_connections.clone();

        // Spawn a task for every connection (Non-blocking!)
        tokio::spawn(async move {
            let _guard = ConnectionGuard { counter: active_counter };
            
            // eprintln!("🌐 New connection from {:?} (Active: {})\n", addr, _guard.counter.load(Ordering::Relaxed));
            
            // 🛡️ DDoS Protection: Enforce Timeout of 5 seconds for handshake/data
            let timeout_duration = std::time::Duration::from_secs(5);
            let mut buffer = [0u8; 65536]; // 64KB Request Limit

            let read_future = socket.read(&mut buffer);
            match tokio::time::timeout(timeout_duration, read_future).await {
                Ok(read_result) => {
                    match read_result {
                        Ok(size) if size > 0 => {
                            // Valid read
                            // eprintln!("🌐 Read {} bytes from {}", size, addr);
                            let msg = String::from_utf8_lossy(&buffer[..size]).to_string();

                            if msg.starts_with("HELLO:") || msg.starts_with("HANDSHAKE:") {
                                let parts: Vec<&str> = msg.split(':').collect();
                                if parts.len() >= 3 {
                                    let peer_id = parts[1].to_string();
                                    let peer_port = parts[2].trim().parse::<u16>().unwrap_or(0);
        
                                    if peer_port > 0 {
                                        {
                                             if let Ok(mut p) = peers_clone.lock() {
                                                 p.insert(peer_id.clone(), peer_port);
                                             }
                                        }
                                        if let Err(e) = db_clone.save_peer(&peer_id, peer_port) {
                                             eprintln!("❌ Failed to save peer: {}", e);
                                        }

                                        let reply = format!("WELCOME:{}:{}", node_id_clone, port);
                                        let _ = socket.write_all(reply.as_bytes()).await;
                                        // println!("🤝 Handshake OK with peer {} ({})", peer_id, addr);
                                    }
                                }
                            } else {
                                handler_clone(msg);
                            }
                        },
                        Ok(_) => {
                            // 0 bytes = Disconnected
                        },
                        Err(e) => {
                             eprintln!("❌ Read error from {}: {}", addr, e);
                        }
                    }
                },
                Err(_) => {
                    eprintln!("⏳ Connection Timed Out (Slowloris Protection) from {}", addr);
                    // Connection drops here automatically
                }
            }
        });
    }
}

pub fn send_message(peer_addr: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = std::net::TcpStream::connect(peer_addr)?;
    stream.write_all(message.as_bytes())?;
    Ok(())
}

pub fn handshake(
    node_id: &str,  // ID node kita sendiri
    peer_ip: &str,  // IP address peer target (FIXED: was hardcoded to 127.0.0.1)
    peer_port: u16, // Port peer target
    my_port: u16,   // Port kita sendiri
    peers: Arc<Mutex<HashMap<String, u16>>>,
    storage: Arc<StateDB>,
) {
    // 1. Connect ke peer (FIXED: now uses peer_ip parameter)
    let peer_addr = format!("{}:{}", peer_ip, peer_port);
    
    match std::net::TcpStream::connect(&peer_addr) {
        Ok(mut stream) => {
            // 2. Send handshake message dengan node_id dan port kita
            let handshake_msg = format!("HANDSHAKE:{}:{}", node_id, my_port);
            
            if let Err(e) = stream.write_all(handshake_msg.as_bytes()) {
                eprintln!("❌ Failed to send handshake to {}: {}", peer_addr, e);
                return;
            }
            
            // 3. Receive handshake response dari peer
            let mut buffer = [0; 1024];
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                    
                    // 4. Parse response: Expected format "WELCOME:<peer_node_id>:<peer_port>"
                    if response.starts_with("WELCOME:") {
                        let parts: Vec<&str> = response.split(':').collect();
                        if parts.len() >= 3 {
                            let peer_node_id = parts[1].trim().to_string();
                            let confirmed_peer_port = parts[2].trim().parse::<u16>().unwrap_or(peer_port);
                            
                            // Simpan peer dengan node_id yang benar dari response
                            {
                                if let Ok(mut p) = peers.lock() {
                                    p.insert(peer_node_id.clone(), confirmed_peer_port);
                                }
                            }
                            
                            // Simpan ke storage
                            if let Err(e) = storage.save_peer(&peer_node_id, confirmed_peer_port) {
                                 eprintln!("❌ Failed to save peer to DB: {}", e);
                            }
                            
                            println!("🔗 Connected to peer {} (port {})", peer_node_id, confirmed_peer_port);
                        }
                    } else {
                        eprintln!("⚠️ Unexpected handshake response from {}: {}", peer_addr, response);
                    }
                }
                Ok(_) => {
                    eprintln!("⚠️ Empty response from {}", peer_addr);
                }
                Err(e) => {
                    eprintln!("❌ Failed to read handshake response from {}: {}", peer_addr, e);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to {}: {}", peer_addr, e);
        }
    }
}