// account/src/lib.rs
// Tempat kita akan mendefinisikan struktur Account dan logikanya.
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub sequence_number: u64,
}

pub trait AccountAbstraction {
    fn validate_transaction(&self, transaction: &str) -> bool;
    fn execute_transaction(&mut self, transaction: &str);
}

impl AccountAbstraction for Account {
    fn validate_transaction(&self, _transaction: &str) -> bool {
        // Validasi sederhana
        true
    }

    fn execute_transaction(&mut self, _transaction: &str) {
        // Eksekusi sederhana
        println!("Executing transaction...");
    }
}