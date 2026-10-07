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

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(),
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 1,
        };

        let res = self.client.post(&self.url).json(&request).send()?;

        if !res.status().is_success() {
            return Err(anyhow!("HTTP Error: {}", res.status()));
        }

        let body: JsonRpcResponse = res.json()?;

        if let Some(err) = body.error {
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
