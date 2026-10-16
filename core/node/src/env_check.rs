//! B349: the environment a node reads, checked at boot. A value the node
//! could not read fell back to a default without a word: a mistyped
//! `AINCORE_STORAGE_MODE` ran an archive node as a pruning one (its history
//! deleted for good), a bad `AINCORE_RPC_TRUSTED_PROXIES` entry was
//! dropped, an `AINCORE_RESERVED_PEERS` address without `/p2p/` was ignored,
//! and an interval below its floor was replaced. Each rule here is the one
//! the reading site applies, made strict.

/// Every problem with the environment `get` gives (`get(name)`: the
/// variable's value, if set), or `Ok` when there is none.
pub fn check_with(get: impl Fn(&str) -> Option<String>) -> Result<(), String> {
    let mut problems = Vec::new();
    if let Some(mode) = get("AINCORE_STORAGE_MODE") {
        if !["archive", "full", "observer"].contains(&mode.to_ascii_lowercase().as_str()) {
            problems.push(format!(
                "AINCORE_STORAGE_MODE={mode:?} is not archive, full or observer"
            ));
        }
    }
    // B369: a node keeps at least twice the blocks that may wait on their
    // QCs (`MAX_UNFINALIZED_BLOCKS`); a retention of 10 pruned a block whose
    // QC was still pending, and the node never proposed again.
    for (name, floor) in [
        (
            "AINCORE_BLOCK_RETENTION",
            2 * consensus::v4::MAX_UNFINALIZED_BLOCKS,
        ),
        ("AINCORE_BLOCK_PRUNE_BATCH", 1),
        ("AINCORE_CONSENSUS_TICK_MS", 100),
        ("AINCORE_SYNC_INTERVAL_MS", 500),
    ] {
        if let Some(raw) = get(name) {
            if !raw.parse::<u64>().is_ok_and(|v| v >= floor) {
                problems.push(format!(
                    "{name}={raw:?} is not a whole number of at least {floor}"
                ));
            }
        }
    }
    // B370: the pull size is used only within 1..=10,000 (500 otherwise).
    if let Some(raw) = get("AINCORE_MEMPOOL_PULL") {
        if !raw
            .parse::<usize>()
            .is_ok_and(|v| (1..=10_000).contains(&v))
        {
            problems.push(format!(
                "AINCORE_MEMPOOL_PULL={raw:?} is not a whole number from 1 to 10000"
            ));
        }
    }
    // B370: a switch takes only the values its reading site understands
    // (`AINCORE_GUARD_ORIGIN_INIT=true` read as off: validators holding a
    // third of the stake abstained at launch without a word;
    // `AINCORE_P2P_LISTEN=off` listened publicly).
    for (name, values) in [
        ("AINCORE_P2P_LISTEN", &["0", "1", "false", "true"][..]),
        ("AINCORE_GUARD_ORIGIN_INIT", &["0", "1"][..]),
        ("AINCORE_SERVE_SNAPSHOTS", &["0", "1"][..]),
        ("AINCORE_P2P_TRACE", &["0", "1"][..]),
        ("AINCORE_LOG_RPC", &["0", "1"][..]),
        (
            "AINCORE_PERMISSIVE_CORS",
            &["0", "1", "false", "true", "no", "yes"][..],
        ),
    ] {
        if let Some(raw) = get(name) {
            if !values.contains(&raw.to_ascii_lowercase().as_str()) {
                problems.push(format!(
                    "{name}={raw:?} is not one of {}",
                    values.join(", ")
                ));
            }
        }
    }
    if let Some(raw) = get("AINCORE_RPC_PROXY_PORT") {
        if !raw.trim().parse::<u16>().is_ok_and(|p| p > 0) {
            problems.push(format!("AINCORE_RPC_PROXY_PORT={raw:?} is not a port"));
        }
    }
    if let Some(raw) = get("AINCORE_RPC_TRUSTED_PROXIES") {
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            if entry.parse::<std::net::IpAddr>().is_err() {
                problems.push(format!(
                    "AINCORE_RPC_TRUSTED_PROXIES entry {entry:?} is not an IP address"
                ));
            }
        }
    }
    if let Some(raw) = get("AINCORE_RESERVED_PEERS") {
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let named = entry.parse::<libp2p::PeerId>().is_ok()
                || entry.parse::<libp2p::Multiaddr>().is_ok_and(|addr| {
                    matches!(
                        addr.iter().last(),
                        Some(libp2p::multiaddr::Protocol::P2p(_))
                    )
                });
            if !named {
                problems.push(format!(
                    "AINCORE_RESERVED_PEERS entry {entry:?} is neither a PeerId nor an \
                     address ending in /p2p/<PeerId>"
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// `check_with` the process environment.
pub fn check() -> Result<(), String> {
    check_with(|name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    /// B349 witness: a value the node cannot read stops it at boot, as its
    /// flags do (it fell back to a default without a word; an archive node
    /// mistyped as `achive` pruned its history for good).
    #[test]
    fn a_value_the_node_cannot_read_stops_it() {
        let check = |vars: &[(&str, &str)]| {
            super::check_with(|name| {
                vars.iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| v.to_string())
            })
        };
        let peer = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        let reserved = format!("{peer},/ip4/10.0.0.2/tcp/9101/p2p/{peer}");
        assert_eq!(check(&[]), Ok(()));
        assert_eq!(
            check(&[
                ("AINCORE_STORAGE_MODE", "Archive"),
                ("AINCORE_BLOCK_RETENTION", "100"),
                ("AINCORE_MEMPOOL_PULL", "10000"),
                ("AINCORE_P2P_LISTEN", "FALSE"),
                ("AINCORE_GUARD_ORIGIN_INIT", "1"),
                ("AINCORE_SERVE_SNAPSHOTS", "0"),
                ("AINCORE_PERMISSIVE_CORS", "Yes"),
                ("AINCORE_CONSENSUS_TICK_MS", "100"),
                ("AINCORE_SYNC_INTERVAL_MS", "500"),
                ("AINCORE_RPC_PROXY_PORT", "8102"),
                ("AINCORE_RPC_TRUSTED_PROXIES", "127.0.0.1, ::1"),
                ("AINCORE_RESERVED_PEERS", reserved.as_str()),
            ]),
            Ok(())
        );
        for bad in [
            ("AINCORE_STORAGE_MODE", "achive"),
            ("AINCORE_BLOCK_RETENTION", "1k"),
            ("AINCORE_BLOCK_RETENTION", "99"),
            ("AINCORE_MEMPOOL_PULL", "0"),
            ("AINCORE_MEMPOOL_PULL", "10001"),
            ("AINCORE_P2P_LISTEN", "off"),
            ("AINCORE_GUARD_ORIGIN_INIT", "true"),
            ("AINCORE_SERVE_SNAPSHOTS", "true"),
            ("AINCORE_P2P_TRACE", "yes"),
            ("AINCORE_LOG_RPC", "on"),
            ("AINCORE_PERMISSIVE_CORS", "on"),
            ("AINCORE_BLOCK_PRUNE_BATCH", "0"),
            ("AINCORE_CONSENSUS_TICK_MS", "50"),
            ("AINCORE_SYNC_INTERVAL_MS", "100"),
            ("AINCORE_RPC_PROXY_PORT", "70000"),
            ("AINCORE_RPC_TRUSTED_PROXIES", "127.0.0.1,proxy.local"),
            ("AINCORE_RESERVED_PEERS", "/ip4/10.0.0.2/tcp/9101"),
        ] {
            assert!(check(&[bad]).is_err(), "{bad:?} was taken");
        }
    }
}
