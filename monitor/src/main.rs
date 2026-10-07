use chrono::Local;
use colored::*;
use reqwest::blocking::Client;
use serde_json::Value;
use std::thread;
use std::time::Duration;

fn main() {
    // L2 FIX: Configurable node list via AINCORE_NODES env var
    // Example: AINCORE_NODES=9000,9001,9002,9003
    let nodes: Vec<u16> = std::env::var("AINCORE_NODES")
        .unwrap_or_else(|_| "9000".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let rpc_ports_override: Option<Vec<u16>> = std::env::var("AINCORE_RPC_PORTS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect::<Vec<u16>>()
        })
        .filter(|ports| !ports.is_empty());

    if nodes.is_empty() {
        eprintln!("❌ No valid node ports specified. Set AINCORE_NODES=9000,9001,...");
        return;
    }

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

        for &port in &nodes {
            let rpc_port = rpc_ports_override
                .as_ref()
                .and_then(|ports| ports.get(node_data.len()).copied())
                .unwrap_or_else(|| rpc_port_of(port));
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
/// rule (`NodeConfig`: the API port is the node port less 1000). It was
/// less 999, one above every node's RPC, so every node showed no status.
fn rpc_port_of(node_port: u16) -> u16 {
    node_port.saturating_sub(1000)
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
    use super::{node_status, rpc_port_of};
    use serde_json::json;

    /// B278 witness: the RPC port guessed from a node port is the node's
    /// (9002 serves RPC on 8002; the guess was 8003).
    #[test]
    fn the_rpc_port_is_the_node_port_less_1000() {
        assert_eq!(rpc_port_of(9002), 8002);
        assert_eq!(rpc_port_of(9000), 8000);
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
}
