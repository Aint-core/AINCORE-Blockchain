pub mod watcher;
pub mod signer;
pub mod dispatcher;

use watcher::BitcoinWatcher;
use signer::FederationSigner;
use dispatcher::Dispatcher;
use std::time::Duration;
use tokio::time::sleep;

pub async fn start_relayer() {
    println!("🌉 BTC-AIN Bridge Relayer Started");
    
    let mut watcher = BitcoinWatcher::new("http://127.0.0.1:18443", "user", "pass");
    // Real Federation Private Key (Corresponding to Address c9c3...)
    let signer = FederationSigner::new("dc555f21bad22f9c4f203049681745db6a78572683c8d577de950c67a0ddd60b");
    let dispatcher = Dispatcher::new("http://127.0.0.1:8001/rpc");

    loop {
        if let Some(deposits) = watcher.check_new_blocks().await {
            for (amount, recipient) in deposits {
                println!("🔔 Processing Deposit: {} Sats for {}", amount, recipient);
                
                // Dispatch to AINCORE (Signer is passed to method)
                dispatcher.submit_mint(&signer, amount, &recipient).await;
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}
