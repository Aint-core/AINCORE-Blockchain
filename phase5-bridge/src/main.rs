use bridge_relayer::start_relayer;

#[tokio::main]
async fn main() {
    env_logger::init();
    start_relayer().await;
}
