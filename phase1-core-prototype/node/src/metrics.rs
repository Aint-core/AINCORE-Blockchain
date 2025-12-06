use lazy_static::lazy_static;
use prometheus::{opts, register_counter, register_int_gauge, Counter, IntGauge};

lazy_static! {
    pub static ref BLOCK_HEIGHT: IntGauge = register_int_gauge!(opts!(
        "aincore_block_height",
        "Current block height of the blockchain"
    ))
    .unwrap();

    pub static ref TRANSACTION_COUNT: Counter = register_counter!(opts!(
        "aincore_transaction_count",
        "Total number of transactions processed"
    ))
    .unwrap();

    pub static ref PEER_COUNT: IntGauge = register_int_gauge!(opts!(
        "aincore_peer_count",
        "Number of connected peers"
    ))
    .unwrap();
}

pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
