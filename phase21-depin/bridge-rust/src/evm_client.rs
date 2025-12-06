use ethers::prelude::*;
use ethers::providers::{Provider, Http};
use std::sync::Arc;
use std::error::Error;
use log::info;

#[derive(Debug, Clone)]
pub struct EvmClient {
    provider: Provider<Http>,
    wallet: LocalWallet,
    contract_address: Address,
}

// Minimal ABI for Minting
abigen!(
    WrappedAIN,
    r#"[
        function mint(address to, uint256 amount) external
    ]"#
);

impl EvmClient {
    pub fn new(rpc_url: &str, private_key: &str, contract_addr: &str) -> Result<Self, Box<dyn Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet: LocalWallet = private_key.parse()?;
        let contract_address: Address = contract_addr.parse()?;

        Ok(Self {
            provider,
            wallet: wallet.with_chain_id(11155111u64), // Sepolia
            contract_address,
        })
    }

    pub async fn mint_tokens(&self, to: &str, amount: u64) -> Result<String, Box<dyn Error>> {
        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());
        let contract = WrappedAIN::new(self.contract_address, Arc::new(client));

        let to_addr: Address = to.parse()?;
        let amount_u256 = U256::from(amount);

        info!("🦄 Minting {} W-AIN to {} on EVM...", amount, to);
        
        // In a real implementation, we would wait for confirmations.
        // For prototype, we just send.
        let call = contract.mint(to_addr, amount_u256);
        let pending_tx = call.send().await?;
        let receipt = pending_tx.await?;

        match receipt {
            Some(r) => {
                let hash = format!("{:?}", r.transaction_hash);
                info!("✅ Mint Success! Tx Hash: {}", hash);
                Ok(hash)
            },
            None => Err("Transaction dropped".into())
        }
    }
}
