use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::LocalWallet;
use log::info;
use std::error::Error;
use std::sync::Arc;

// CRITICAL-4 FIX: Multi-signature configuration
const MULTISIG_THRESHOLD: usize = 3; // 3-of-5 required

#[derive(Clone)]
pub struct EvmClient {
    provider: Arc<Provider<Http>>,
    contract_address: Address,
    signers: Vec<LocalWallet>, // Multiple signers for multi-sig
    threshold: usize,
}

abigen!(
    WrappedAIN,
    r#"[
        function mint(address to, uint256 amount, uint256 nonce, bytes[] signatures) external
    ]"#
);

impl EvmClient {
    /// CRITICAL-4 FIX: Initialize with multiple signers for multi-sig
    pub fn new(
        rpc_url: String,
        contract_address: String,
        signers: Vec<LocalWallet>,
    ) -> Result<Self, Box<dyn Error>> {
        // Validate we have enough signers
        if signers.len() < MULTISIG_THRESHOLD {
            return Err(format!(
                "Insufficient signers: {} provided, {} required",
                signers.len(),
                MULTISIG_THRESHOLD
            )
            .into());
        }

        let provider = Provider::<Http>::try_from(rpc_url)?;
        let contract_addr = contract_address.parse::<Address>()?;

        info!(
            "🔐 Multi-sig bridge initialized with {} signers (threshold: {})",
            signers.len(),
            MULTISIG_THRESHOLD
        );

        Ok(Self {
            provider: Arc::new(provider),
            contract_address: contract_addr,
            signers,
            threshold: MULTISIG_THRESHOLD,
        })
    }

    pub async fn mint_tokens(
        &self,
        to_str: &str,
        amount_u128: u128,
        nonce: u64,
    ) -> Result<TxHash, Box<dyn Error>> {
        // Parse address
        let to_addr: Address = to_str.parse()?;
        let amount = U256::from(amount_u128);
        let nonce_u256 = U256::from(nonce);

        info!(
            "🔐 Executing mint with {}/{} multi-sig threshold",
            self.threshold,
            self.signers.len()
        );

        // Use the first signer for the transaction origin
        if self.signers.is_empty() {
            return Err("No signers available".into());
        }

        let message = ethers::abi::encode(&[
            ethers::abi::Token::Address(to_addr),
            ethers::abi::Token::Uint(amount),
            ethers::abi::Token::Uint(nonce_u256),
        ]);
        let message_hash = ethers::utils::keccak256(&message);

        let mut sig_bytes = Vec::new();
        for signer in self.signers.iter().take(self.threshold) {
            let sig = signer.sign_message(message_hash).await?;
            sig_bytes.push(Bytes::from(sig.to_vec()));
        }

        let client = SignerMiddleware::new(self.provider.clone(), self.signers[0].clone());
        let contract = WrappedAIN::new(self.contract_address, Arc::new(client));

        // Send transaction
        let call = contract.mint(to_addr, amount, nonce_u256, sig_bytes);
        let pending_tx = call.send().await?;
        match pending_tx.await? {
            Some(receipt) => Ok(receipt.transaction_hash),
            None => Err("Transaction dropped".into()),
        }
    }
}
