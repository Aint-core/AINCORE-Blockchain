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

/// B331: the flags a node takes. Anything else is refused: an unknown flag
/// was skipped and a value that did not parse fell back to a default, so a
/// mistyped flag (`--api-port`, as the operator guide gave it) or port ran
/// the node on defaults without a word.
pub const USAGE: &str = "usage: node [--port P2P_PORT] [--rpc-port RPC_PORT] [--datadir DIR] \
                         [--bootnodes ADDR,...] [--enable-nat] [--enable-mdns]";

impl NodeConfig {
    /// The node's flags; on one it does not take, or a value it cannot read,
    /// the usage on stderr and exit 2. `--help`: the usage, and exit 0
    /// before anything starts (it started a node on defaults).
    pub fn parse() -> Self {
        let args: Vec<String> = env::args().skip(1).collect();
        match Self::parse_from(&args) {
            Ok(Some(config)) => config,
            Ok(None) => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("{e}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }

    /// `parse` over `args` (the program's name left out): `Ok(None)` for
    /// `--help`.
    pub fn parse_from(args: &[String]) -> Result<Option<Self>, String> {
        let mut config = Self::default();
        let (mut port_set, mut api_port_set) = (false, false);
        let mut i = 0;
        while i < args.len() {
            let flag = args[i].as_str();
            let value = || {
                args.get(i + 1)
                    .map(String::as_str)
                    .ok_or_else(|| format!("{flag} needs a value"))
            };
            match flag {
                "--help" | "-h" => return Ok(None),
                "--enable-mdns" => config.enable_mdns = true,
                "--enable-nat" => config.enable_nat = true,
                "--port" => {
                    // B349: libp2p listens at the port + 100.
                    config.port = parse_port(flag, value()?)?;
                    if config.port > MAX_P2P_PORT {
                        return Err(format!(
                            "--port {} is past {MAX_P2P_PORT} (libp2p listens at the port + 100)",
                            config.port
                        ));
                    }
                    port_set = true;
                }
                "--rpc-port" => {
                    config.api_port = parse_port(flag, value()?)?;
                    api_port_set = true;
                }
                "--datadir" => config.datadir = value()?.to_string(),
                "--peers" => {
                    config.initial_peers = value()?
                        .split(',')
                        .map(|p| parse_port(flag, p))
                        .collect::<Result<_, _>>()?;
                }
                "--bootnodes" => {
                    config.bootnodes = value()?.split(',').map(|s| s.trim().to_string()).collect();
                }
                _ => return Err(format!("unknown flag {flag:?}")),
            }
            i += if matches!(flag, "--enable-mdns" | "--enable-nat") {
                1
            } else {
                2
            };
        }
        // B296: the RPC port follows the P2P port by `api_port_for`, the rule
        // every tool reads, unless it is named.
        if port_set && !api_port_set {
            config.api_port = api_port_for(config.port);
        }
        Ok(Some(config))
    }
}

/// B349: the highest `--port` (libp2p listens at the port + 100: past this,
/// a release build listened at a port that wrapped to 0, a random one).
pub const MAX_P2P_PORT: u16 = u16::MAX - 100;

/// A port `flag` names: a number from 1 to 65535.
fn parse_port(flag: &str, raw: &str) -> Result<u16, String> {
    raw.trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| format!("{flag} {raw:?} is not a port"))
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

    /// B331 witness: a flag the node does not take, or a port it cannot
    /// read, is refused (an unknown flag was skipped and a bad port fell
    /// back to a default, so `--api-port 8001` ran the RPC on 8000 without a
    /// word); `--help` is answered, never a node started.
    #[test]
    fn a_flag_the_node_does_not_take_is_refused() {
        let parse = |args: &[&str]| {
            super::NodeConfig::parse_from(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>())
        };
        let config = parse(&["--port", "9001", "--datadir", "d", "--enable-nat"])
            .unwrap()
            .unwrap();
        assert_eq!((config.port, config.api_port), (9001, 8001));
        assert_eq!(config.datadir, "d");
        assert!(config.enable_nat);
        assert_eq!(
            parse(&["--port", "9001", "--rpc-port", "7000"])
                .unwrap()
                .unwrap()
                .api_port,
            7000
        );
        for bad in [
            &["--api-port", "8001"][..],
            &["--port", "90o1"],
            &["--port", "0"],
            &["--port"],
            &["--rpc-port", "70000"],
            &["9001"],
            &["--port", "65436"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} was taken");
        }
        assert!(parse(&["--help"]).unwrap().is_none());
    }
}
