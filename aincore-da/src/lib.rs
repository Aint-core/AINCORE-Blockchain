use celestia_rpc::{Client, BlobClient, HeaderClient};
use celestia_types::{Blob, nmt::Namespace};
use celestia_types::TxConfig;
use anyhow::Result;

pub struct DAPublisher {
    client: Client,
    namespace: Namespace,
}

impl DAPublisher {
    /// Connect to a Celestia Node (e.g., "http://localhost:26658")
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let client = Client::new(rpc_url, None).await?;
        // Namespace: "NEC" (0x4e, 0x45, 0x43) padded to 29 bytes
        let namespace = Namespace::new_v0(&[0x4e, 0x45, 0x43])?;
        Ok(Self { client, namespace })
    }


    /// Publish a batch of data (block) to Celestia
    /// Returns the height at which it was included
    pub async fn publish_batch(&self, batch_data: Vec<u8>) -> Result<u64> {
        let blob = Blob::new(self.namespace, batch_data)?;
        
        // Submit to Celestia
        // Note: In production, we should handle gas fees (TIA)
        let height = self.client.blob_submit(&[blob], TxConfig::default()).await?;
        Ok(height)
    }
}

pub struct DAVerifier {
    client: Client,
}

impl DAVerifier {
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let client = Client::new(rpc_url, None).await?;
        Ok(Self { client })
    }

    /// Verify that data is available for a given height and commitment
    pub async fn verify_availability(&self, height: u64, commitment: [u8; 32]) -> Result<bool> {
        // 1. Get the header
        let header = self.client.header_get_by_height(height).await?;
        
        // 2. Verify Data Root matches
        let data_root = header.dah.hash();
        if data_root.as_bytes() != commitment {
            return Ok(false);
        }

        // 3. Perform Data Availability Sampling (DAS)
        // The light client automatically does this when fetching the header/shares.
        // If we can fetch the shares for our namespace, it's available.
        let namespace = Namespace::new_v0(&[0x4e, 0x45, 0x43])?;
        let blobs = self.client.blob_get_all(height, &[namespace]).await?;
        
        // blob_get_all returns Option<Vec<Blob>> in some versions, or Vec<Blob> in others.
        // Based on error, it returns Option.
        Ok(blobs.map(|b| !b.is_empty()).unwrap_or(false))
    }
}