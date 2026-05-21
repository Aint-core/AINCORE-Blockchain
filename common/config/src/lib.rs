use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub port: u16,
    pub api_port: u16,
    pub datadir: String,
    pub initial_peers: Vec<u16>,
    pub bootnodes: Vec<String>,
    pub enable_mdns: bool,
    pub enable_nat: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            port: 9001,
            api_port: 8002,
            datadir: "data".to_string(),
            initial_peers: Vec::new(),
            bootnodes: Vec::new(),
            enable_mdns: false,
            enable_nat: false,
        }
    }
}

impl NodeConfig {
    pub fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut config = Self::default();

        // Flags to track if user explicitly set ports
        let mut port_set = false;
        let mut api_port_set = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--port" => {
                    if i + 1 < args.len() {
                        config.port = args[i + 1].parse().unwrap_or(9001);
                        port_set = true;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "--datadir" => {
                    if i + 1 < args.len() {
                        config.datadir = args[i + 1].clone();
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "--peers" => {
                    if i + 1 < args.len() {
                        config.initial_peers = args[i + 1]
                            .split(',')
                            .filter_map(|s| s.trim().parse::<u16>().ok())
                            .collect();
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "--bootnodes" => {
                    if i + 1 < args.len() {
                        config.bootnodes = args[i + 1]
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "--enable-mdns" => {
                    config.enable_mdns = true;
                    i += 1;
                }
                "--enable-nat" => {
                    config.enable_nat = true;
                    i += 1;
                }
                "--rpc-port" => {
                    if i + 1 < args.len() {
                        config.api_port = args[i + 1].parse().unwrap_or(8002);
                        api_port_set = true;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                _ => i += 1,
            }
        }

        // Auto-configure API port if not set but Node port is set
        // Convention: API = Node - 1000 (e.g., 9000 -> 8000)
        // Original logic: api_port = port - 1000;
        if port_set && !api_port_set {
            if config.port > 1000 {
                config.api_port = config.port - 1000;
            } else {
                // Fallback if port is too low
                config.api_port = 8002;
            }
        }

        config
    }
}
