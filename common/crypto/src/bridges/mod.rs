// Cross-Chain Bridges - Interoperability
//
// Logic for verifying cross-chain messages and state proofs.

use crate::poseidon::PoseidonHash;

pub struct CrossChainMessage {
    pub source_chain_id: u64,
    pub dest_chain_id: u64,
    pub nonce: u64,
    pub payload: Vec<u8>,
}

pub struct BridgeValidator {
    pub validator_set_hash: u64,
    hasher: PoseidonHash,
}

impl BridgeValidator {
    pub fn new(initial_set_hash: u64) -> Self {
        Self {
            validator_set_hash: initial_set_hash,
            hasher: PoseidonHash::new(),
        }
    }

    pub fn process_message(
        &mut self,
        msg: &CrossChainMessage,
        proof: &[u64],
    ) -> Result<bool, String> {
        // 1. Hash the message
        let mut msg_hash = self.hasher.hash_two(msg.source_chain_id, msg.dest_chain_id);
        msg_hash = self.hasher.hash_two(msg_hash, msg.nonce);
        for b in &msg.payload {
            msg_hash = self.hasher.hash_two(msg_hash, *b as u64);
        }

        // 2. Verify Proof (Simplified: Proof sum + Validator Hash should match something)
        // In real logic: Merkle inclusion proof or Multi-sig verification
        let proof_sum: u64 = proof.iter().sum();

        if proof_sum.wrapping_add(self.validator_set_hash) == 0 {
            // Failure condition check
            return Err("Invalid proof".to_string());
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_logic() {
        let mut bridge = BridgeValidator::new(100);
        let msg = CrossChainMessage {
            source_chain_id: 1,
            dest_chain_id: 2,
            nonce: 1,
            payload: vec![1, 2, 3],
        };

        // Use dummy proof
        let proof = vec![1, 1, 1];
        let result = bridge.process_message(&msg, &proof);

        assert!(result.is_ok());
    }
}
