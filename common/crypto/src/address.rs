//! Human-readable AINCORE address format: `A1n…`.
//!
//! On chain an address is 32 bytes, `SHA-256(public_key)`, and every storage
//! key, Move value and signed preimage keeps using its lowercase 64-hex form.
//! `A1n` is the form shown to people: Base58 over
//! `A1N_VERSION ‖ address ‖ checksum`, where the checksum is the first 4 bytes
//! of `SHA-256(SHA-256(A1N_VERSION ‖ address))` (Base58Check, as in Bitcoin).
//!
//! The 3-byte version was chosen so that EVERY 32-byte address encodes to
//! exactly 53 characters starting with `A1n`: the smallest and largest possible
//! payloads both do, and Base58 of fixed-length input is monotonic
//! (`every_address_encodes_to_53_chars_starting_a1n`). The same format is used
//! on every network: one key controls the same address everywhere.
//!
//! Never convert to `A1n` inside consensus code. Parse it at the edge (RPC,
//! CLI, SDK) into bytes or 64-hex with [`parse_address`].

use crate::ADDRESS_BYTES;
use sha2::{Digest, Sha256};
use std::fmt;

/// Version bytes prepended before encoding. Fixes the `A1n` prefix.
pub const A1N_VERSION: [u8; 3] = [0x0d, 0xce, 0x00];

/// Prefix every encoded address starts with.
pub const A1N_PREFIX: &str = "A1n";

/// Length of every encoded address in characters.
pub const A1N_LEN: usize = 53;

const CHECKSUM_LEN: usize = 4;
const RAW_LEN: usize = A1N_VERSION.len() + ADDRESS_BYTES + CHECKSUM_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    /// Neither 53-char `A1n`, 64-hex, nor `0x` + 64-hex.
    BadLength(usize),
    /// Contains a character outside the Base58 alphabet (e.g. `0`, `O`, `I`, `l`).
    NotBase58,
    /// Decodes, but was not produced with [`A1N_VERSION`].
    WrongVersion,
    /// Decodes with the right version, but the checksum does not match: a typo.
    BadChecksum,
    NotHex,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressError::Empty => write!(f, "address is empty"),
            AddressError::BadLength(n) => write!(
                f,
                "address has {} characters; expected {} ({}…), {} hex, or 0x + {} hex",
                n,
                A1N_LEN,
                A1N_PREFIX,
                ADDRESS_BYTES * 2,
                ADDRESS_BYTES * 2
            ),
            AddressError::NotBase58 => write!(f, "address contains a character that is not Base58"),
            AddressError::WrongVersion => write!(f, "not an AINCORE address (wrong version bytes)"),
            AddressError::BadChecksum => {
                write!(f, "address checksum does not match; check it for a typo")
            }
            AddressError::NotHex => write!(f, "hex address contains a non-hex character"),
        }
    }
}

impl std::error::Error for AddressError {}

fn checksum(versioned: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(Sha256::digest(versioned));
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Encode 32 address bytes as `A1n…`.
pub fn to_a1n(address: &[u8; ADDRESS_BYTES]) -> String {
    let mut raw = Vec::with_capacity(RAW_LEN);
    raw.extend_from_slice(&A1N_VERSION);
    raw.extend_from_slice(address);
    let check = checksum(&raw);
    raw.extend_from_slice(&check);
    bs58::encode(raw).into_string()
}

/// Decode an `A1n…` address to its 32 bytes, verifying version and checksum.
pub fn from_a1n(encoded: &str) -> Result<[u8; ADDRESS_BYTES], AddressError> {
    if encoded.is_empty() {
        return Err(AddressError::Empty);
    }
    if encoded.len() != A1N_LEN {
        return Err(AddressError::BadLength(encoded.len()));
    }
    let raw = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| AddressError::NotBase58)?;
    if raw.len() != RAW_LEN {
        return Err(AddressError::BadLength(encoded.len()));
    }
    let (versioned, check) = raw.split_at(RAW_LEN - CHECKSUM_LEN);
    if versioned[..A1N_VERSION.len()] != A1N_VERSION {
        return Err(AddressError::WrongVersion);
    }
    if checksum(versioned) != check {
        return Err(AddressError::BadChecksum);
    }
    let mut address = [0u8; ADDRESS_BYTES];
    address.copy_from_slice(&versioned[A1N_VERSION.len()..]);
    Ok(address)
}

/// Encode a 64-hex address (optionally `0x`-prefixed, any case) as `A1n…`.
pub fn hex_to_a1n(hex_address: &str) -> Result<String, AddressError> {
    Ok(to_a1n(&parse_hex(hex_address)?))
}

/// Parse any accepted address form into 32 bytes:
/// `A1n…` (checksummed), 64 hex, or `0x` + 64 hex. Hex is case-insensitive.
/// Surrounding whitespace is ignored; short hex such as `0x1` is refused.
pub fn parse_address(input: &str) -> Result<[u8; ADDRESS_BYTES], AddressError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(AddressError::Empty);
    }
    if input.starts_with(A1N_PREFIX) {
        return from_a1n(input);
    }
    parse_hex(input)
}

/// Parse any accepted form and return the canonical lowercase 64-hex string,
/// which is what storage keys, Move and signed preimages use.
pub fn canonical_address_hex(input: &str) -> Result<String, AddressError> {
    parse_address(input).map(hex::encode)
}

fn parse_hex(input: &str) -> Result<[u8; ADDRESS_BYTES], AddressError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(AddressError::Empty);
    }
    let digits = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if digits.len() != ADDRESS_BYTES * 2 {
        return Err(AddressError::BadLength(input.len()));
    }
    let bytes = hex::decode(digits).map_err(|_| AddressError::NotHex)?;
    let mut address = [0u8; ADDRESS_BYTES];
    address.copy_from_slice(&bytes);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    const VALIDATOR_HEX: &str = "dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42";
    const VALIDATOR_A1N: &str = "A1nB31ipYCNJJR7Gcsat1oE8J6kFPdEbJP5pAkq7u2ZLjdokxA3nH";

    fn random_address() -> [u8; ADDRESS_BYTES] {
        let mut a = [0u8; ADDRESS_BYTES];
        rand::thread_rng().fill_bytes(&mut a);
        a
    }

    #[test]
    fn known_vector_encodes_and_decodes() {
        assert_eq!(hex_to_a1n(VALIDATOR_HEX).unwrap(), VALIDATOR_A1N);
        assert_eq!(hex::encode(from_a1n(VALIDATOR_A1N).unwrap()), VALIDATOR_HEX);
    }

    #[test]
    fn every_address_encodes_to_53_chars_starting_a1n() {
        // Base58 of fixed-length input is monotonic, so the extremes bound all
        // payloads. They are checked without a checksum so the bound covers
        // every checksum value too.
        for fill in [0x00u8, 0xff] {
            let mut raw = A1N_VERSION.to_vec();
            raw.extend_from_slice(&[fill; ADDRESS_BYTES + CHECKSUM_LEN]);
            let s = bs58::encode(raw).into_string();
            assert_eq!(s.len(), A1N_LEN, "extreme {:#x}", fill);
            assert!(s.starts_with(A1N_PREFIX), "extreme {:#x}: {}", fill, s);
        }
        for _ in 0..2_000 {
            let s = to_a1n(&random_address());
            assert_eq!(s.len(), A1N_LEN);
            assert!(s.starts_with(A1N_PREFIX), "{}", s);
        }
    }

    #[test]
    fn round_trips_through_every_accepted_form() {
        for _ in 0..500 {
            let a = random_address();
            let hex_lower = hex::encode(a);
            assert_eq!(from_a1n(&to_a1n(&a)).unwrap(), a);
            assert_eq!(parse_address(&to_a1n(&a)).unwrap(), a);
            assert_eq!(parse_address(&hex_lower).unwrap(), a);
            assert_eq!(parse_address(&format!("0x{}", hex_lower)).unwrap(), a);
            assert_eq!(parse_address(&hex_lower.to_uppercase()).unwrap(), a);
            assert_eq!(canonical_address_hex(&to_a1n(&a)).unwrap(), hex_lower);
        }
    }

    #[test]
    fn every_single_character_typo_is_refused() {
        const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let original: Vec<char> = VALIDATOR_A1N.chars().collect();
        let mut tried = 0;
        for pos in 0..original.len() {
            for replacement in ALPHABET.chars() {
                if replacement == original[pos] {
                    continue;
                }
                let mut typo = original.clone();
                typo[pos] = replacement;
                let typo: String = typo.into_iter().collect();
                assert!(
                    from_a1n(&typo).is_err(),
                    "typo at position {} ({}→{}) was accepted",
                    pos,
                    original[pos],
                    replacement
                );
                tried += 1;
            }
        }
        assert_eq!(
            tried,
            A1N_LEN * 57,
            "positive control: every substitution was tried"
        );
    }

    #[test]
    fn a_checksum_mismatch_is_reported_as_such() {
        let mut raw = bs58::decode(VALIDATOR_A1N).into_vec().unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = bs58::encode(raw).into_string();
        assert_eq!(tampered.len(), A1N_LEN);
        assert_eq!(from_a1n(&tampered), Err(AddressError::BadChecksum));
    }

    #[test]
    fn another_version_is_refused_even_with_a_valid_checksum() {
        let a = hex::decode(VALIDATOR_HEX).unwrap();
        let mut raw = vec![0x0d, 0xce, 0x01];
        raw.extend_from_slice(&a);
        let check = checksum(&raw);
        raw.extend_from_slice(&check);
        let foreign = bs58::encode(raw).into_string();
        assert_eq!(foreign.len(), A1N_LEN);
        assert_eq!(from_a1n(&foreign), Err(AddressError::WrongVersion));
    }

    #[test]
    fn malformed_inputs_are_refused() {
        assert_eq!(parse_address(""), Err(AddressError::Empty));
        assert_eq!(parse_address("   "), Err(AddressError::Empty));
        // Base58 excludes 0, O, I and l.
        let with_zero = format!("{}0", &VALIDATOR_A1N[..A1N_LEN - 1]);
        assert_eq!(from_a1n(&with_zero), Err(AddressError::NotBase58));
        // Too short / too long.
        assert!(matches!(
            parse_address(&VALIDATOR_A1N[..A1N_LEN - 1]),
            Err(AddressError::BadLength(_))
        ));
        assert!(matches!(
            parse_address(&format!("{}1", VALIDATOR_A1N)),
            Err(AddressError::BadLength(_))
        ));
        // Short hex (Move-style `0x1`) is not an account address here.
        assert!(matches!(
            parse_address("0x1"),
            Err(AddressError::BadLength(_))
        ));
        assert!(matches!(
            parse_address(&VALIDATOR_HEX[..63]),
            Err(AddressError::BadLength(_))
        ));
        let not_hex = format!("{}g", &VALIDATOR_HEX[..63]);
        assert_eq!(parse_address(&not_hex), Err(AddressError::NotHex));
    }

    #[test]
    fn whitespace_around_a_pasted_address_is_ignored() {
        let a = parse_address(&format!("  {}\n", VALIDATOR_A1N)).unwrap();
        assert_eq!(hex::encode(a), VALIDATOR_HEX);
    }
}
