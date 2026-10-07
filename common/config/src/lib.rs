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

/// The P2P port a node runs on when none is named (B305: its RPC, the
/// port less 1000, is `DEFAULT_API_PORT`, as for every other port).
pub const DEFAULT_PORT: u16 = 9002;
/// The RPC port of a node on `DEFAULT_PORT`.
pub const DEFAULT_API_PORT: u16 = DEFAULT_PORT - 1000;

/// B296/B305: a node's RPC port when only its P2P port is named, the one
/// rule the node and every tool read: the port less 1000 (below 1001:
/// `DEFAULT_API_PORT`). B296 found a node named on the default port (9001)
/// ran its RPC on 8001 and one left to it on 8002; it mapped the default
/// to 8002 as a special case, so 9001 and 9002 both took 8002 (B305: the
/// second node of a one-host bring-up ran with no RPC). The default port is
/// now the one whose port less 1000 is 8002.
pub fn api_port_for(port: u16) -> u16 {
    if port <= 1000 {
        DEFAULT_API_PORT
    } else {
        port - 1000
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            api_port: DEFAULT_API_PORT,
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
                        config.port = args[i + 1].parse().unwrap_or(DEFAULT_PORT);
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

        // Auto-configure API port if not set but Node port is set (B296:
        // `api_port_for`, the rule every tool reads).
        if port_set && !api_port_set {
            config.api_port = api_port_for(config.port);
        }

        config
    }
}

#[cfg(test)]
mod tests {
    /// B296/B305 witness: one rule maps a node's P2P port to its RPC port,
    /// the default port included, and no two ports to one (B296's special
    /// case mapped 9001 and 9002 both to 8002).
    #[test]
    fn the_rpc_port_follows_one_rule() {
        assert_eq!(
            super::api_port_for(super::DEFAULT_PORT),
            super::DEFAULT_API_PORT
        );
        assert_eq!(super::api_port_for(9001), 8001);
        assert_eq!(super::api_port_for(9002), 8002);
        assert_eq!(super::api_port_for(9003), 8003);
        assert_eq!(super::api_port_for(1000), super::DEFAULT_API_PORT);
        assert_eq!(
            super::NodeConfig::default().api_port,
            super::DEFAULT_API_PORT
        );
    }
}
