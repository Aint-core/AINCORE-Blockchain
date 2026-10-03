/// B23: consensus alarms raised by the code that finds them, never read from text.
pub mod alarm;
pub mod dag;
pub mod ingress_v4;
pub mod ordering;
pub mod qc;
pub mod qc_producer;
pub mod staging;
pub mod state_proof_client;
pub mod v4;
pub mod vcert;
pub mod work;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) mod test_txs;
pub use dag::DagConsensus;

// The retired `SimpleConsensus` engine and its own `Block`, `BlockHeader`,
// `Vote` and `Proposal` types were deleted (G3 FX-18). Nothing constructed
// them, and their block hash was a second ambiguous concatenation
// (`parent_hash ‖ height ‖ round ‖ proposer`). Blocks are
// `blockchain::Block`, hashed by `blockchain::calculate_header_hash`.
