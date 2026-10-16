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

/// The flood harness is an attacker, not a node: it dials from chosen
/// loopback sources so one host floods as many (`--sources`).
const ALLOWED: [&str; 1] = ["core/node/src/bin/flood.rs"];

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

/// What a build without tests compiles of `text`: up to its first top-level
/// test module. A test's mock RPC server (the CLI's, the indexer's, the
/// bridge's, bench-tps's) is no peer channel.
fn outside_tests(text: &str) -> &str {
    [
        "\n#[cfg(test)]\nmod ",
        "\n#[cfg(test)]\npub mod ",
        "\n#[cfg(test)]\npub(crate) mod ",
    ]
    .iter()
    .filter_map(|marker| text.find(marker))
    .min()
    .map_or(text, |at| &text[..at])
}

fn offences(text: &str) -> Vec<&'static str> {
    let text = outside_tests(text);
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
        if ALLOWED.iter().any(|allowed| file.ends_with(allowed)) {
            continue;
        }
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
    // A test module's mock server is not one; code before it still is.
    let listener = format!("std::net::{}{}", "Tcp", "Listener");
    let in_tests = format!("fn main() {{}}\n#[cfg(test)]\nmod tests {{ {listener} }}");
    assert!(offences(&in_tests).is_empty());
    let before = format!("{line}\n#[cfg(test)]\nmod tests {{}}");
    assert_eq!(offences(&before), ["TcpStream"]);
}
