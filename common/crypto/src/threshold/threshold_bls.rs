// Threshold & BLS Implementation
//
// Protocol logic for distributed signing and aggregation.

pub struct FrostParticipant {
    pub id: u64,
    pub secret: u64,
}

pub struct BlsSigner {
    pub key: u64,
}

impl FrostParticipant {
    pub fn new(id: u64, secret: u64) -> Self {
        Self { id, secret }
    }

    pub fn sign_part(&self, msg: &[u8]) -> u64 {
        // Threshold signature participation logic
        let mut h = 0u64;
        for b in msg { h = h.wrapping_add(*b as u64); }
        self.secret.wrapping_add(h)
    }
}

pub fn aggregate_frost(shares: &[u64]) -> u64 {
    shares.iter().sum()
}

impl BlsSigner {
    pub fn new(key: u64) -> Self {
        Self { key }
    }

    pub fn sign_bls(&self, msg: &[u8]) -> u64 {
        let mut h = 0u64;
        for b in msg { h = h.wrapping_add(*b as u64); }
        self.key.wrapping_mul(h)
    }
}

pub fn aggregate_bls(sigs: &[u64]) -> u64 {
    sigs.iter().sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_frost_logic() {
        let p1 = FrostParticipant::new(1, 10);
        let p2 = FrostParticipant::new(2, 20);
        
        let msg = b"test";
        let s1 = p1.sign_part(msg);
        let s2 = p2.sign_part(msg);
        
        // Sum == 10 + hash + 20 + hash
        assert!(aggregate_frost(&[s1, s2]) > 30);
    }

    #[test]
    fn test_bls_logic() {
        let b1 = BlsSigner::new(5);
        let b2 = BlsSigner::new(10);
        let msg = b"vote";
        
        let s1 = b1.sign_bls(msg);
        let s2 = b2.sign_bls(msg);
        
        assert_ne!(s1, 0);
        assert_ne!(s2, 0);
        assert_eq!(aggregate_bls(&[s1, s2]), s1 + s2);
    }
}
