use anyhow::{anyhow, Result};

pub struct AincoreClient {
    rpc_url: String,
    private_key: String,
}

impl AincoreClient {
    pub fn new(rpc_url: String, private_key: String) -> Self {
        Self {
            rpc_url,
            private_key,
        }
    }

    pub async fn mint_wbtc(&self, user: &str, amount_sats: u64) -> Result<String> {
        let _ = (&self.rpc_url, &self.private_key, user, amount_sats);
        Err(anyhow!(
            "legacy bridge RPC submit_transaction_with_key is disabled in secure mode; migrate bridge to signed aincore_sendTransaction"
        ))
    }
}
