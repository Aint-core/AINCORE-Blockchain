/// Audit #33 — BTC custody verification (pure, deterministic).
///
/// The previous deposit pipeline trusted the indexer's `addr` string on each
/// output. That is two layers of trust away from the chain:
///   1. it trusts the indexer to label the output's address correctly, and
///   2. it never checks that the configured custody address is actually the
///      one whose *script* we control.
///
/// This module closes both gaps by deriving the canonical custody
/// `scriptPubKey` (and address) from a configured redeem/witness *script* that
/// the operator controls, then:
///   - on boot: asserting the derived address equals the configured custody
///     address (refuse boot on mismatch), and
///   - per deposit: asserting the output's raw `scriptPubKey` bytes equal the
///     derived custody `scriptPubKey` (not a string compare on an indexer
///     label).
///
/// All derivation here is pure hashing/encoding — no wall-clock, no RNG, no
/// per-node environment — so two operators with the same config derive the
/// identical script and address.
use anyhow::{anyhow, bail, Result};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Bitcoin network the custody address lives on. Determines the bech32 HRP
/// (p2wsh) and the base58 version byte (p2sh).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" | "main" | "bitcoin" => Ok(Network::Mainnet),
            "testnet" | "test" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            other => bail!("unknown BTC network '{}' (expected mainnet|testnet|regtest)", other),
        }
    }

    /// bech32 human-readable part for native segwit (BIP-173).
    fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
            Network::Regtest => "bcrt",
        }
    }

    /// base58check version byte for P2SH addresses.
    fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            // testnet and regtest share the P2SH version byte 0xc4.
            Network::Testnet | Network::Regtest => 0xc4,
        }
    }
}

/// Custody output type. The custody address is derived from a *script* the
/// operator controls (e.g. a multisig redeem/witness script).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyType {
    /// Pay-to-Witness-Script-Hash (native segwit v0).
    P2wsh,
    /// Pay-to-Script-Hash (legacy wrapped).
    P2sh,
}

impl CustodyType {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "p2wsh" => Ok(CustodyType::P2wsh),
            "p2sh" => Ok(CustodyType::P2sh),
            other => bail!("unknown BTC custody type '{}' (expected p2wsh|p2sh)", other),
        }
    }
}

/// SHA256(data).
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// HASH160 = RIPEMD160(SHA256(data)).
fn hash160(data: &[u8]) -> [u8; 20] {
    let mut h = Ripemd160::new();
    h.update(sha256(data));
    h.finalize().into()
}

/// The custody descriptor: a script the operator controls plus how it is
/// committed on-chain. `expected_script_pubkey` is computed once and reused
/// for every per-deposit comparison.
#[derive(Clone, Debug)]
pub struct Custody {
    pub custody_type: CustodyType,
    pub network: Network,
    /// Raw redeem (p2sh) / witness (p2wsh) script bytes the operator controls.
    pub script: Vec<u8>,
    /// Canonical scriptPubKey that any deposit output MUST match exactly.
    expected_script_pubkey: Vec<u8>,
}

impl Custody {
    /// Build a custody descriptor from a hex-encoded redeem/witness script.
    pub fn from_hex_script(script_hex: &str, custody_type: CustodyType, network: Network) -> Result<Self> {
        let script = hex::decode(script_hex.trim())
            .map_err(|e| anyhow!("BTC_CUSTODY_SCRIPT is not valid hex: {}", e))?;
        if script.is_empty() {
            bail!("BTC_CUSTODY_SCRIPT decodes to an empty script");
        }
        let expected_script_pubkey = match custody_type {
            CustodyType::P2wsh => p2wsh_script_pubkey(&script),
            CustodyType::P2sh => p2sh_script_pubkey(&script),
        };
        Ok(Self {
            custody_type,
            network,
            script,
            expected_script_pubkey,
        })
    }

    /// The canonical scriptPubKey as lowercase hex (for indexer comparison).
    pub fn expected_script_pubkey_hex(&self) -> String {
        hex::encode(&self.expected_script_pubkey)
    }

    /// The custody address derived from the script + network.
    pub fn derived_address(&self) -> Result<String> {
        match self.custody_type {
            CustodyType::P2wsh => p2wsh_address(&self.script, self.network),
            CustodyType::P2sh => Ok(p2sh_address(&self.script, self.network)),
        }
    }

    /// Per-deposit check: does this output's raw scriptPubKey hex actually pay
    /// the custody script? This is a *bytes* comparison against the derived
    /// scriptPubKey — NOT a compare on the indexer's `addr` label.
    pub fn output_pays_custody(&self, output_script_pubkey_hex: &str) -> bool {
        match hex::decode(output_script_pubkey_hex.trim()) {
            Ok(bytes) => bytes == self.expected_script_pubkey,
            Err(_) => false,
        }
    }
}

/// P2WSH scriptPubKey: `OP_0 <0x20> SHA256(witnessScript)` (BIP-141).
pub fn p2wsh_script_pubkey(witness_script: &[u8]) -> Vec<u8> {
    let h = sha256(witness_script);
    let mut spk = Vec::with_capacity(34);
    spk.push(0x00); // OP_0 (witness version 0)
    spk.push(0x20); // push 32 bytes
    spk.extend_from_slice(&h);
    spk
}

/// P2SH scriptPubKey: `OP_HASH160 <0x14> HASH160(redeemScript) OP_EQUAL` (BIP-16).
pub fn p2sh_script_pubkey(redeem_script: &[u8]) -> Vec<u8> {
    let h = hash160(redeem_script);
    let mut spk = Vec::with_capacity(23);
    spk.push(0xa9); // OP_HASH160
    spk.push(0x14); // push 20 bytes
    spk.extend_from_slice(&h);
    spk.push(0x87); // OP_EQUAL
    spk
}

/// Bech32 (BIP-173) native segwit v0 P2WSH address.
pub fn p2wsh_address(witness_script: &[u8], network: Network) -> Result<String> {
    use bech32::{ToBase32, Variant};
    let program = sha256(witness_script);
    // Witness version 0 is encoded as the first 5-bit value, then the
    // program is squashed to base32 (BIP-173 §segwit).
    let mut data = vec![bech32::u5::try_from_u8(0).expect("0 is a valid u5")];
    data.extend(program.to_base32());
    bech32::encode(network.bech32_hrp(), data, Variant::Bech32)
        .map_err(|e| anyhow!("bech32 encode failed: {}", e))
}

/// Base58Check P2SH address.
pub fn p2sh_address(redeem_script: &[u8], network: Network) -> String {
    let h = hash160(redeem_script);
    let mut payload = Vec::with_capacity(21);
    payload.push(network.p2sh_version());
    payload.extend_from_slice(&h);
    bs58::encode(payload).with_check().into_string()
}

/// Pure confirmation finality check, extracted so it is unit-testable.
///
/// A deposit at `tx_height` is finalized once the chain tip (`current_height`)
/// is at least `min_confirmations - 1` blocks ahead (the including block counts
/// as the first confirmation).
pub fn is_finalized(tx_height: u64, current_height: u64, min_confirmations: u64) -> bool {
    confirmations(tx_height, current_height) >= min_confirmations
}

/// Number of confirmations for a tx mined at `tx_height` given chain tip
/// `current_height`. The including block is 1 confirmation. Saturating so a
/// stale/forked tip that reports below the tx height yields 0, never panics.
pub fn confirmations(tx_height: u64, current_height: u64) -> u64 {
    if current_height < tx_height {
        return 0;
    }
    current_height - tx_height + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny but valid-looking witness/redeem script: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
    fn sample_script() -> Vec<u8> {
        let mut s = vec![0x51]; // OP_1
        s.push(0x21); // push 33 bytes
        s.extend_from_slice(&[0x02; 33]); // fake compressed pubkey
        s.push(0x51); // OP_1
        s.push(0xae); // OP_CHECKMULTISIG
        s
    }

    #[test]
    fn p2wsh_script_pubkey_shape() {
        let spk = p2wsh_script_pubkey(&sample_script());
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x00);
        assert_eq!(spk[1], 0x20);
    }

    #[test]
    fn p2sh_script_pubkey_shape() {
        let spk = p2sh_script_pubkey(&sample_script());
        assert_eq!(spk.len(), 23);
        assert_eq!(spk[0], 0xa9);
        assert_eq!(spk[1], 0x14);
        assert_eq!(spk[22], 0x87);
    }

    #[test]
    fn known_p2wsh_vector() {
        // BIP-173 test vector: witness program 32 zero bytes is not used; instead
        // verify against a deterministic recompute. We assert determinism + HRP.
        let addr_main = p2wsh_address(&sample_script(), Network::Mainnet).unwrap();
        let addr_test = p2wsh_address(&sample_script(), Network::Testnet).unwrap();
        assert!(addr_main.starts_with("bc1"), "got {}", addr_main);
        assert!(addr_test.starts_with("tb1"), "got {}", addr_test);
        // Deterministic: same input → same output.
        assert_eq!(addr_main, p2wsh_address(&sample_script(), Network::Mainnet).unwrap());
    }

    #[test]
    fn p2sh_address_versions() {
        let main = p2sh_address(&sample_script(), Network::Mainnet);
        let test = p2sh_address(&sample_script(), Network::Regtest);
        // Mainnet P2SH (version 0x05) addresses start with '3'.
        assert!(main.starts_with('3'), "got {}", main);
        // Testnet/regtest P2SH (version 0xc4) addresses start with '2'.
        assert!(test.starts_with('2'), "got {}", test);
        assert_eq!(main, p2sh_address(&sample_script(), Network::Mainnet));
    }

    #[test]
    fn custody_output_pays_custody_p2wsh() {
        let script_hex = hex::encode(sample_script());
        let custody = Custody::from_hex_script(&script_hex, CustodyType::P2wsh, Network::Mainnet).unwrap();
        let good = custody.expected_script_pubkey_hex();
        assert!(custody.output_pays_custody(&good));
        // Any other script must NOT match.
        let other = p2wsh_script_pubkey(b"different script");
        assert!(!custody.output_pays_custody(&hex::encode(other)));
        // Garbage hex rejected, not panicked.
        assert!(!custody.output_pays_custody("zzzz"));
    }

    #[test]
    fn custody_mismatch_rejected() {
        // Custody derived from one script must reject an output that pays a
        // DIFFERENT script even if an indexer were to label it as ours.
        let custody = Custody::from_hex_script(
            &hex::encode(sample_script()),
            CustodyType::P2wsh,
            Network::Mainnet,
        )
        .unwrap();
        let attacker_spk = p2wsh_script_pubkey(b"attacker controlled script");
        assert!(
            !custody.output_pays_custody(&hex::encode(attacker_spk)),
            "output paying a non-custody script must be rejected"
        );
    }

    #[test]
    fn boot_address_assertion_matches_self() {
        // The derived address must equal what derived_address() returns; this
        // is exactly the boot-time equality the main loop asserts against the
        // configured BTC_MULTISIG_ADDRESS.
        let custody = Custody::from_hex_script(
            &hex::encode(sample_script()),
            CustodyType::P2sh,
            Network::Mainnet,
        )
        .unwrap();
        let derived = custody.derived_address().unwrap();
        assert_eq!(derived, p2sh_address(&sample_script(), Network::Mainnet));
        assert_ne!(derived, "3SomeOtherAddressThatWontMatch");
    }

    #[test]
    fn empty_script_rejected() {
        assert!(Custody::from_hex_script("", CustodyType::P2wsh, Network::Mainnet).is_err());
    }

    #[test]
    fn confirmations_threshold() {
        // tx in block 100, tip at 100 = 1 confirmation.
        assert_eq!(confirmations(100, 100), 1);
        assert_eq!(confirmations(100, 105), 6);
        // Forked/stale tip below tx height = 0, no panic.
        assert_eq!(confirmations(100, 99), 0);
    }

    #[test]
    fn is_finalized_below_threshold_rejected() {
        // 6 confirmations required.
        // tip 104 → tx@100 has 5 confirmations → NOT finalized.
        assert!(!is_finalized(100, 104, 6));
        // tip 105 → 6 confirmations → finalized.
        assert!(is_finalized(100, 105, 6));
        // tip 106 → 7 confirmations → finalized.
        assert!(is_finalized(100, 106, 6));
        // tip below tx height → 0 confirmations → NOT finalized.
        assert!(!is_finalized(100, 50, 6));
    }

    #[test]
    fn network_and_type_parse() {
        assert_eq!(Network::parse("mainnet").unwrap(), Network::Mainnet);
        assert_eq!(Network::parse("TESTNET").unwrap(), Network::Testnet);
        assert!(Network::parse("nope").is_err());
        assert_eq!(CustodyType::parse("p2wsh").unwrap(), CustodyType::P2wsh);
        assert_eq!(CustodyType::parse("P2SH").unwrap(), CustodyType::P2sh);
        assert!(CustodyType::parse("p2pkh").is_err());
    }
}
