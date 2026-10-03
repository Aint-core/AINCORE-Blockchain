//! G4 S6 witness: the legacy transport (a TCP connection plus a handshake
//! per message) is gone from every crate. Peers are reached only over the
//! libp2p sessions of `node::sessions`; a raw socket anywhere in the sources
//! would be a second channel past the session layer's identity checks and
//! budgets.

use std::path::{Path, PathBuf};

/// What a raw peer channel needs, and the names the legacy one had.
const FORBIDDEN: [&str; 5] = [
    "TcpStream",
    "TcpListener",
    "secure_connect",
    "GOSSIP_RUNTIME",
    "start_server",
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            rust_sources(&path, out);
        } else if name.ends_with(".rs") && Path::new(file!()).file_name() != path.file_name() {
            out.push(path);
        }
    }
}

fn offences(text: &str) -> Vec<&'static str> {
    FORBIDDEN
        .into_iter()
        .filter(|name| text.contains(name))
        .collect()
}

#[test]
fn no_crate_opens_a_raw_peer_socket() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("core/node/src/p2p.rs")),
        "positive control: the walk reached the node's network task ({} files)",
        files.len()
    );
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for name in offences(&text) {
            found.push(format!("{}: {name}", file.display()));
        }
    }
    assert!(
        found.is_empty(),
        "legacy transport in the sources: {found:#?}"
    );
}

#[test]
fn the_scan_sees_a_raw_socket() {
    let line = format!("use tokio::net::{}{};", "Tcp", "Stream");
    assert_eq!(offences(&line), ["TcpStream"]);
    assert!(offences("use libp2p::tcp;").is_empty());
}
