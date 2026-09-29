pub mod dag;
pub mod ordering;
pub mod qc;
pub mod qc_producer;
pub mod state_proof_client;
pub mod vcert;

#[cfg(test)]
mod tests;
pub use dag::DagConsensus;

// The retired `SimpleConsensus` engine and its own `Block`, `BlockHeader`,
// `Vote` and `Proposal` types were deleted (G3 FX-18). Nothing constructed
// them, and their block hash was a second ambiguous concatenation
// (`parent_hash ‖ height ‖ round ‖ proposer`). Blocks are
// `blockchain::Block`, hashed by `blockchain::calculate_header_hash`.
