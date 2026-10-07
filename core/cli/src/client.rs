use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub struct RpcClient {
    url: String,
    client: Client,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i32,
    message: String,
}

/// The node's answer when its heavy-call slots are all taken.
const BUSY_CODE: i32 = -32005;

/// B296: how many times a call the node answered busy (or rate limited) is
/// sent in all.
const BUSY_ATTEMPTS: u32 = 6;

/// B296: a busy or rate-limited answer: worth asking again.
#[derive(Debug)]
struct Busy(String);

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the node is busy: {}", self.0)
    }
}

impl std::error::Error for Busy {}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(),
        }
    }

    /// B296: a busy answer (`BUSY_CODE`) or a rate limit (HTTP 429) is
    /// asked again, up to `BUSY_ATTEMPTS` sends, after a jittered wait that
    /// doubles. Every transfer asks for a gas estimate first, which runs on
    /// two slots network-wide, so under load the CLI failed outright (B260
    /// taught the SDK this, not the CLI).
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut wait = std::time::Duration::from_millis(250);
        let mut attempt = 1;
        loop {
            match self.call_once(method, params.clone()) {
                Err(e) if attempt < BUSY_ATTEMPTS && e.downcast_ref::<Busy>().is_some() => {
                    let jitter = rand::random::<u64>() % (wait.as_millis() as u64 + 1);
                    std::thread::sleep(wait + std::time::Duration::from_millis(jitter));
                    wait = (wait * 2).min(std::time::Duration::from_secs(4));
                    attempt += 1;
                }
                outcome => return outcome,
            }
        }
    }

    fn call_once(&self, method: &str, params: Value) -> Result<Value> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 1,
        };

        let res = self.client.post(&self.url).json(&request).send()?;

        if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(Busy("HTTP 429".into()).into());
        }
        if !res.status().is_success() {
            return Err(anyhow!("HTTP Error: {}", res.status()));
        }

        let body: JsonRpcResponse = res.json()?;

        if let Some(err) = body.error {
            if err.code == BUSY_CODE {
                return Err(Busy(err.message).into());
            }
            return Err(anyhow!("RPC Error {}: {}", err.code, err.message));
        }

        Ok(body.result.unwrap_or(Value::Null))
    }

    /// B243: the chain the node runs, the `network` of its
    /// `/get_network_info` (the REST root is the RPC URL without a trailing
    /// `/rpc`).
    pub fn network(&self) -> Result<String> {
        let root = self.url.strip_suffix('/').unwrap_or(&self.url);
        let root = root.strip_suffix("/rpc").unwrap_or(root);
        let info: Value = self
            .client
            .get(format!("{root}/get_network_info"))
            .send()?
            .error_for_status()?
            .json()?;
        info.get("network")
            .and_then(Value::as_str)
            .filter(|network| !network.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("get_network_info named no chain"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    /// One HTTP request off `stream`, headers and body.
    fn read_request(stream: &mut std::net::TcpStream) {
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                return;
            }
            seen.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&seen);
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if seen.len() >= end + 4 + length {
                    return;
                }
            }
        }
    }

    /// B296 witness: a call the node answers busy is sent again, and its
    /// answer returned (the CLI failed on the first busy answer, so a
    /// transfer, which asks for a gas estimate first, failed under load).
    #[test]
    fn a_busy_answer_is_asked_again() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/rpc", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for (i, stream) in listener.incoming().take(3).enumerate() {
                let mut stream = stream.unwrap();
                read_request(&mut stream);
                let body = if i < 2 {
                    r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"busy; retry"},"id":1}"#
                } else {
                    r#"{"jsonrpc":"2.0","result":42,"id":1}"#
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        let client = super::RpcClient::new(&url);
        let answer = client
            .call("aincore_estimateGas", serde_json::json!([]))
            .unwrap();
        assert_eq!(answer, 42);
        server.join().unwrap();
    }
}
