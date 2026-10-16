use chrono::Local;
use colored::*;
use reqwest::blocking::Client;
use serde_json::Value;
use std::thread;
use std::time::Duration;

fn main() {
    // L2 FIX: Configurable node list via AINCORE_NODES env var
    // Example: AINCORE_NODES=9001,9002,9003 (B305: the default is a node
    // left to its default port).
    // B382: an entry that did not parse was dropped, so the RPC list shifted
    // and a halted node showed another node's status. Now any bad entry, or
    // an RPC list of another length, stops the monitor (exit 2).
    let nodes_env = std::env::var("AINCORE_NODES").ok();
    let rpc_env = std::env::var("AINCORE_RPC_PORTS").ok();
    let targets = match parse_targets(nodes_env.as_deref(), rpc_env.as_deref()) {
        Ok(targets) => targets,
        Err(problems) => {
            for problem in &problems {
                eprintln!("❌ {problem}");
            }
            eprintln!("   Example: AINCORE_NODES=9001,9002 AINCORE_RPC_PORTS=8001,8002");
            std::process::exit(2);
        }
    };
    let rpc_source = if given(rpc_env.as_deref()).is_some() {
        "AINCORE_RPC_PORTS"
    } else {
        "node port less 1000"
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| Client::new());

    println!(
        "{}",
        "🚀 AINCORE Cluster Monitor (RPC Mode)".bold().purple()
    );
    println!(
        "{}",
        "─────────────────────────────────────────────".dimmed()
    );
    // B382: the mapping it will poll, so a wrong pairing is seen at start.
    println!("Node -> RPC ({rpc_source}):");
    for (port, rpc_port) in &targets {
        println!("   Node {port} -> http://localhost:{rpc_port}/rpc");
    }

    loop {
        // Clear screen
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);

        println!(
            "{}",
            "🚀 AINCORE Cluster Monitor (RPC Mode)".bold().purple()
        );
        println!(
            "{}",
            "─────────────────────────────────────────────".dimmed()
        );

        let mut max_height = 0;
        let mut node_data = Vec::new();

        for &(port, rpc_port) in &targets {
            let url = format!("http://localhost:{}/rpc", rpc_port);

            let mut status = "Offline".to_string();
            let mut height = 0;
            let mut peers = 0;

            // B269: the node's status call. `get_status` (and the fallback,
            // `get_block_height`) are served by no node; the answer's
            // `"result": null` was read as Active at height 0, so a halted
            // node never showed.
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "aincore_getStatus",
                "params": [],
                "id": 1
            });

            if let Ok(resp) = client.post(&url).json(&body).send() {
                status = "No status".to_string();
                if let Some((h, p)) = resp.json::<Value>().ok().as_ref().and_then(node_status) {
                    status = "Active".to_string();
                    height = h;
                    peers = p;
                    max_height = max_height.max(height);
                }
            }

            node_data.push((port, rpc_port, status, height, peers));
        }

        // Display Data
        for (port, rpc_port, status, height, peers) in &node_data {
            let (status_icon, color_status) = match status.as_str() {
                "Active" => ("🟢", "green"),
                _ => ("🔴", "red"),
            };

            let color_fn = match color_status {
                "green" => |s: ColoredString| s.green().bold(),
                "red" => |s: ColoredString| s.red().bold(),
                _ => |s: ColoredString| s.white().bold(),
            };

            let height_color_fn = if *height == max_height && max_height > 0 {
                |s: ColoredString| s.green()
            } else if *height > 0 {
                |s: ColoredString| s.yellow()
            } else {
                |s: ColoredString| s.red()
            };

            println!(
                "{} {} (RPC: {}) | {} | Peers: {} | Height: {}",
                color_fn(status_icon.into()),
                format!("Node {}", port).bold(),
                rpc_port,
                status,
                peers,
                height_color_fn(height.to_string().bold()),
            );

            // Progress Bar
            if max_height > 0 {
                let progress_ratio = *height as f64 / max_height as f64;
                let bar_length = 20;
                let filled_length = (progress_ratio * bar_length as f64).round() as usize;
                let empty_length = bar_length - filled_length;

                let filled_part = "▓".repeat(filled_length).green();
                let empty_part = "░".repeat(empty_length).red();
                print!("   ");
                print!("{}", filled_part);
                print!("{}", empty_part);
                println!("  ({}/{})", height, max_height);
            } else {
                println!("   {} {}", "N/A".dimmed(), "(0/0)".dimmed());
            }
            println!(
                "{}",
                "─────────────────────────────────────────────".dimmed()
            );
        }

        println!(
            "Last update: {}",
            Local::now().format("%H:%M:%S").to_string().yellow()
        );

        thread::sleep(Duration::from_secs(2));
    }
}

/// B278: a node's RPC port when only its P2P port is named: the node's own
/// rule. It was less 999, one above every node's RPC, so every node showed
/// no status; then (B296) less 1000 for the default port too, whose RPC is
/// 8002 when the node is left to its default.
fn rpc_port_of(node_port: u16) -> u16 {
    config::api_port_for(node_port)
}

/// B382: an unset variable and an empty one both mean "not given".
fn given(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

/// B382: the comma-separated ports in `value`; every entry that is not a
/// port (1-65535) adds a problem naming the variable and the entry.
fn parse_ports(name: &str, value: &str, problems: &mut Vec<String>) -> Vec<u16> {
    let mut ports = Vec::new();
    for (i, entry) in value.split(',').enumerate() {
        match entry.trim().parse::<u16>() {
            Ok(port) if port > 0 => ports.push(port),
            _ => problems.push(format!(
                "{name} entry {} ({:?}) is not a port (1-65535)",
                i + 1,
                entry.trim()
            )),
        }
    }
    ports
}

/// B382: each node's P2P port paired with the RPC port it is polled on,
/// from AINCORE_NODES (default: `config::DEFAULT_PORT`) and
/// AINCORE_RPC_PORTS (default: each node port less 1000). Every problem is
/// returned: an entry that is not a port, or an RPC list whose length is
/// not the node list's. Before, bad entries were dropped and the lists
/// were paired by position, so one bad RPC entry shifted every later node
/// onto its neighbour's RPC.
fn parse_targets(
    nodes: Option<&str>,
    rpc_ports: Option<&str>,
) -> Result<Vec<(u16, u16)>, Vec<String>> {
    let default_nodes = config::DEFAULT_PORT.to_string();
    let nodes_value = given(nodes).unwrap_or(default_nodes.as_str());
    let mut problems = Vec::new();
    let node_ports = parse_ports("AINCORE_NODES", nodes_value, &mut problems);
    let rpc = given(rpc_ports).map(|value| {
        let rpc_entries = value.split(',').count();
        let node_entries = nodes_value.split(',').count();
        if rpc_entries != node_entries {
            problems.push(format!(
                "AINCORE_RPC_PORTS has {rpc_entries} entries but AINCORE_NODES has \
                 {node_entries}: give one RPC port per node, in the same order"
            ));
        }
        parse_ports("AINCORE_RPC_PORTS", value, &mut problems)
    });
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(match rpc {
        Some(rpc) => node_ports.into_iter().zip(rpc).collect(),
        None => node_ports
            .into_iter()
            .map(|port| (port, rpc_port_of(port)))
            .collect(),
    })
}

/// B269: the height and session count an `aincore_getStatus` answer
/// carries; `None` for any other answer (an error, a null result).
fn node_status(answer: &Value) -> Option<(u64, u64)> {
    let result = answer.get("result")?;
    let height = match &result["latest_height"] {
        Value::String(h) => h.parse().ok()?,
        other => other.as_u64()?,
    };
    Some((height, result["peers_count"].as_u64().unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::{node_status, parse_targets, rpc_port_of};
    use serde_json::json;

    /// B278 witness: the RPC port guessed from a node port is the node's
    /// (9002 serves RPC on 8002; the guess was 8003).
    #[test]
    fn the_rpc_port_is_the_node_port_less_1000() {
        assert_eq!(rpc_port_of(9002), 8002);
        assert_eq!(rpc_port_of(9000), 8000);
        assert_eq!(rpc_port_of(9001), 8001, "B305: one port, one RPC");
        assert_eq!(rpc_port_of(config::DEFAULT_PORT), 8002, "the default's");
    }

    /// B269 witness: a node's status is its `aincore_getStatus` answer; an
    /// error or a null result is no status (the null answer to `get_status`,
    /// which no node serves, was read as Active at height 0).
    #[test]
    fn a_status_is_the_nodes_answer_or_none() {
        assert_eq!(
            node_status(&json!({"result": {"latest_height": "42", "peers_count": 3}})),
            Some((42, 3))
        );
        assert_eq!(node_status(&json!({"result": null})), None);
        assert_eq!(
            node_status(&json!({"error": {"code": -32601, "message": "Method not found"}})),
            None
        );
    }

    /// B382 witness: an RPC entry that does not parse stops the monitor.
    /// Before, `8O02` was dropped, so node 9002 was polled on 8003 (node
    /// 9003's RPC) and showed its status, and a halted 9002 looked alive.
    #[test]
    fn a_bad_rpc_entry_is_refused_not_shifted() {
        let problems = parse_targets(Some("9001,9002,9003"), Some("8001,8O02,8003"))
            .expect_err("a bad RPC entry must be refused");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("AINCORE_RPC_PORTS entry 2"),
            "{problems:?}"
        );
    }

    /// B382 witness: a bad node entry, an empty entry, port 0 and an RPC
    /// list of another length are all refused, and every problem is
    /// reported at once.
    #[test]
    fn every_problem_is_reported() {
        let problems = parse_targets(Some("x,9002"), Some("y")).unwrap_err();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("AINCORE_NODES entry 1")));
        assert!(problems
            .iter()
            .any(|p| p.contains("has 1 entries but AINCORE_NODES has 2")));
        assert!(problems
            .iter()
            .any(|p| p.contains("AINCORE_RPC_PORTS entry 1")));
        assert!(
            parse_targets(Some("9001,,9002"), None).is_err(),
            "an empty entry"
        );
        assert!(parse_targets(Some("0"), None).is_err(), "port 0");
        assert!(parse_targets(Some("70000"), None).is_err(), "above u16");
        assert!(
            parse_targets(Some("9001,9002"), Some("8001")).is_err(),
            "an RPC list shorter than the node list"
        );
    }

    /// B382: well-formed lists pair by position; without an RPC list each
    /// node is polled on its own port less 1000; empty means not given.
    #[test]
    fn good_lists_pair_node_to_rpc() {
        assert_eq!(
            parse_targets(Some(" 9001, 9002 "), Some("8101 ,8102")),
            Ok(vec![(9001, 8101), (9002, 8102)])
        );
        assert_eq!(
            parse_targets(Some("9001,9002"), None),
            Ok(vec![(9001, 8001), (9002, 8002)])
        );
        assert_eq!(
            parse_targets(None, None),
            Ok(vec![(
                config::DEFAULT_PORT,
                rpc_port_of(config::DEFAULT_PORT)
            )])
        );
        assert_eq!(
            parse_targets(Some(" "), Some("")),
            parse_targets(None, None)
        );
    }
}
