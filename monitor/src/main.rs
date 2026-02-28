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
    
    if nodes.is_empty() {
        eprintln!("❌ No valid node ports specified. Set AINCORE_NODES=9000,9001,...");
        return;
    }
    
    let client = Client::new();

    println!("{}", "🚀 AINCORE Cluster Monitor (RPC Mode)".bold().purple());
    println!("{}", "─────────────────────────────────────────────".dimmed());

    loop {
        // Clear screen
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);

        println!("{}", "🚀 AINCORE Cluster Monitor (RPC Mode)".bold().purple());
        println!("{}", "─────────────────────────────────────────────".dimmed());

        let mut max_height = 0;
        let mut node_data = Vec::new();

        for &port in &nodes {
            // RPC URL (assuming standard port mapping: 9001 -> 8001, 9002 -> 8002, etc.)
            // Or if ports are direct RPC ports. Let's assume standard AINCORE RPC ports are 8000 + (port - 9000)
            // Actually, based on previous context, RPC is on 8002.
            // Let's try to guess RPC port from Node port.
            // Node 9001 -> RPC 8001
            // Node 9002 -> RPC 8002
            let rpc_port = port - 1000; 
            let url = format!("http://localhost:{}/rpc", rpc_port);

            let mut status = "Offline".to_string();
            let mut height = 0;
            let mut peers = 0;
            let mut version = "Unknown".to_string();

            // JSON-RPC Request for Status
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "get_status",
                "params": [],
                "id": 1
            });

            match client.post(&url).json(&body).send() {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<Value>() {
                        if let Some(result) = json.get("result") {
                            status = "Active".to_string();
                            height = result["block_height"].as_u64().unwrap_or(0);
                            peers = result["peer_count"].as_u64().unwrap_or(0);
                            version = result["version"].as_str().unwrap_or("0.1.0").to_string();
                            
                            if height > max_height {
                                max_height = height;
                            }
                        }
                    }
                }
                Err(_) => {
                    // Try get_block_height if get_status fails (fallback)
                    let body_h = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "get_block_height",
                        "params": [],
                        "id": 1
                    });
                    if let Ok(resp) = client.post(&url).json(&body_h).send() {
                         if let Ok(json) = resp.json::<Value>() {
                            if let Some(res) = json.get("result") {
                                status = "Active".to_string();
                                height = res.as_u64().unwrap_or(0);
                                if height > max_height { max_height = height; }
                            }
                         }
                    }
                }
            }

            node_data.push((port, rpc_port, status, height, peers, version));
        }

        // Display Data
        for (port, rpc_port, status, height, peers, version) in &node_data {
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
                "{} {} (RPC: {}) | Peers: {} | Height: {} | v{}",
                color_fn(status_icon.into()),
                format!("Node {}", port).bold(),
                rpc_port,
                peers,
                height_color_fn(height.to_string().bold()),
                version.dimmed()
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
            println!("{}", "─────────────────────────────────────────────".dimmed());
        }

        println!(
            "Last update: {}",
            Local::now().format("%H:%M:%S").to_string().yellow()
        );

        thread::sleep(Duration::from_secs(2));
    }
}