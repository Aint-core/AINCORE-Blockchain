//! Multi-validator genesis.json generator (#15 bring-up tooling).
//!
//! A multi-validator genesis CANNOT self-derive BLS keys: each validator's BLS
//! finality key is derived from ITS OWN node.key seed, which only the genesis
//! ceremony operator can collect. If genesis.json omitted the per-validator BLS
//! keys, every booting node would self-derive a DIFFERENT key for the same peer
//! address, write a divergent `sys:validator_set:v1`, and no QC would ever
//! verify against another node (see `node::genesis::resolve_genesis_bls_identity`,
//! SEC-#5). This tool closes that gap: given each validator's 32-byte node-key
//! seed + stake, it emits a genesis.json with the EXACT fields the loader
//! expects, including the embedded `bls_public_key` + `bls_pop`.
//!
//! Derivation chain (must stay byte-identical to a running node):
//!   seed (node.key, 32 bytes)
//!     -> ed25519 SigningKey::from_bytes(seed) -> verifying_key  (public_key)
//!     -> crypto::derive_address(public_key)                     (address)
//!     -> consensus::qc::derive_validator_bls_seed(seed)         (bls seed)
//!         -> BLSEngine::consensus().pubkey_raw(bls_seed)        (bls_public_key)
//!         -> BLSEngine::consensus().prove_possession_raw(...)   (bls_pop)
//!
//! The node treats `node.key` (`signing_key.to_bytes()`) as the genesis node
//! identity, and `SigningKey::to_bytes()` returns exactly the 32-byte seed it was
//! constructed from — so the seed passed here IS the node identity, and the
//! fields generated here match what each node derives from its own node.key.

use clap::Args;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single validator spec on the CLI: `--validator <seed_hex>:<stake_ain>`.
/// `seed_hex` is the 32-byte (64 hex char) node.key seed; `stake_ain` is the
/// whole-AIN stake (converted to 10^18 quanta in the emitted file).
#[derive(Clone, Debug)]
pub struct ValidatorSpec {
    pub seed: [u8; 32],
    pub stake_ain: u128,
}

#[derive(Args, Debug)]
pub struct GenMultiArgs {
    /// One per validator: `<node_key_seed_hex>:<stake_whole_ain>`.
    /// `node_key_seed_hex` = 32-byte hex (64 chars) = the validator's node.key.
    /// Repeat the flag for each validator (order does not matter — the set hash
    /// is address-sorted and order-independent).
    #[arg(long = "validator", value_name = "SEED_HEX:STAKE_AIN", required = true)]
    pub validators: Vec<String>,

    /// Output path for the generated genesis.json.
    #[arg(short, long, default_value = "genesis.json")]
    pub out: PathBuf,

    /// Chain ID embedded in genesis.json.
    #[arg(long, default_value = "AINCORE-MAINNET-1")]
    pub chain_id: String,

    /// Treasury reserve in whole AIN (converted to 10^18 quanta).
    #[arg(long, default_value_t = 50_000)]
    pub treasury_reserve_ain: u128,

    /// Epoch duration (seconds). Must be > 0.
    #[arg(long, default_value_t = 10)]
    pub epoch_duration: u64,

    /// Overwrite the output file if it already exists.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

/// 10^18 quanta per whole AIN. Mirrors `node::genesis` COIN_SCALE.
const COIN_SCALE: u128 = 1_000_000_000_000_000_000;

/// Per-validator genesis entry. Field names + types match
/// `node::genesis::GenesisValidatorConfig` EXACTLY (the loader's
/// `#[derive(Deserialize)]` shape): `address`, `public_key`, `stake` (String),
/// `bls_public_key`, `bls_pop` (hex strings).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GenesisValidatorConfig {
    pub address: String,
    pub public_key: String,
    pub stake: String,
    pub bls_public_key: String,
    pub bls_pop: String,
}

/// Top-level genesis file. Field names + types match
/// `node::genesis::GenesisFile`: `chain_id`, `validators`, `treasury_reserve`
/// (String), `epoch_duration` (u64).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GenesisFile {
    pub chain_id: String,
    pub validators: Vec<GenesisValidatorConfig>,
    pub treasury_reserve: String,
    pub epoch_duration: u64,
}

/// Derive every genesis field for one validator from its 32-byte node.key seed.
/// Returns `(address, ed25519_pubkey_hex, bls_public_key_hex, bls_pop_hex)`.
///
/// This is the single source of truth the tool uses; it deliberately routes
/// through the same public APIs a node uses so the values can never drift.
pub fn derive_validator_fields(
    seed: &[u8; 32],
) -> Result<(String, String, String, String), Box<dyn std::error::Error>> {
    // 1. ed25519 identity from the seed (same as node.key -> SigningKey).
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_hex = hex::encode(public_key_bytes);

    // 2. address = crypto::derive_address(ed25519 pubkey) (#35: full 32-byte).
    let address = crypto::derive_address(&public_key_bytes)
        .map_err(|e| format!("derive_address failed: {}", e))?;

    // 3. BLS finality identity from the SAME seed, via the canonical consensus
    //    derivation (re-exported from consensus::qc). The node uses
    //    signing_key.to_bytes() (== seed) as the node identity, so this matches.
    let bls_seed = consensus::qc::derive_validator_bls_seed(seed);
    let bls = crypto::bls::BLSEngine::consensus();
    let bls_public_key_hex = hex::encode(bls.pubkey_raw(&bls_seed));
    let bls_pop_hex = hex::encode(bls.prove_possession_raw(&bls_seed));

    Ok((address, public_key_hex, bls_public_key_hex, bls_pop_hex))
}

/// Parse a `--validator SEED_HEX:STAKE_AIN` argument.
pub fn parse_validator_spec(raw: &str) -> Result<ValidatorSpec, Box<dyn std::error::Error>> {
    let (seed_hex, stake_str) = raw.rsplit_once(':').ok_or_else(|| {
        format!(
            "invalid --validator '{}': expected <node_key_seed_hex>:<stake_whole_ain>",
            raw
        )
    })?;
    let seed_bytes = hex::decode(seed_hex.trim())
        .map_err(|e| format!("invalid seed hex in '{}': {}", raw, e))?;
    if seed_bytes.len() != 32 {
        return Err(format!(
            "node-key seed must be exactly 32 bytes (64 hex chars), got {} bytes in '{}'",
            seed_bytes.len(),
            raw
        )
        .into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let stake_ain: u128 = stake_str
        .trim()
        .parse::<u128>()
        .map_err(|e| format!("invalid stake '{}' in '{}': {}", stake_str, raw, e))?;
    if stake_ain == 0 {
        return Err(format!("validator stake must be > 0 (in '{}')", raw).into());
    }

    Ok(ValidatorSpec { seed, stake_ain })
}

/// Build the in-memory `GenesisFile` from parsed validator specs + parameters.
pub fn build_genesis_file(
    specs: &[ValidatorSpec],
    chain_id: &str,
    treasury_reserve_ain: u128,
    epoch_duration: u64,
) -> Result<GenesisFile, Box<dyn std::error::Error>> {
    if specs.is_empty() {
        return Err("at least one --validator is required".into());
    }
    if chain_id.trim().is_empty() {
        return Err("chain_id must not be empty".into());
    }
    if epoch_duration == 0 {
        return Err("epoch_duration must be > 0".into());
    }

    let mut validators = Vec::with_capacity(specs.len());
    let mut seen_addr = std::collections::BTreeSet::new();
    for spec in specs {
        let (address, public_key, bls_public_key, bls_pop) = derive_validator_fields(&spec.seed)?;
        if !seen_addr.insert(address.clone()) {
            return Err(format!(
                "duplicate validator address {} — the same node-key seed was supplied twice",
                address
            )
            .into());
        }
        let stake_quanta = spec
            .stake_ain
            .checked_mul(COIN_SCALE)
            .ok_or_else(|| format!("stake {} AIN overflows u128 quanta", spec.stake_ain))?;
        validators.push(GenesisValidatorConfig {
            address,
            public_key,
            stake: stake_quanta.to_string(),
            bls_public_key,
            bls_pop,
        });
    }

    let treasury_reserve = treasury_reserve_ain
        .checked_mul(COIN_SCALE)
        .ok_or_else(|| {
            format!(
                "treasury_reserve {} AIN overflows u128 quanta",
                treasury_reserve_ain
            )
        })?;

    Ok(GenesisFile {
        chain_id: chain_id.to_string(),
        validators,
        treasury_reserve: treasury_reserve.to_string(),
        epoch_duration,
    })
}

pub fn run(args: GenMultiArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("🛠️  AINCORE Multi-Validator Genesis Generator");

    let mut specs = Vec::with_capacity(args.validators.len());
    for raw in &args.validators {
        specs.push(parse_validator_spec(raw)?);
    }

    let genesis = build_genesis_file(
        &specs,
        &args.chain_id,
        args.treasury_reserve_ain,
        args.epoch_duration,
    )?;

    if args.out.exists() && !args.force {
        return Err(format!(
            "refusing to overwrite existing {} (pass --force to overwrite)",
            args.out.display()
        )
        .into());
    }

    let json = serde_json::to_string_pretty(&genesis)?;
    std::fs::write(&args.out, &json)?;

    println!("⛓️  Chain ID: {}", genesis.chain_id);
    println!("🛡️  Validators: {}", genesis.validators.len());
    for v in &genesis.validators {
        println!(
            "   • {} (stake={} quanta, bls_pk={}…)",
            v.address,
            v.stake,
            &v.bls_public_key[..16.min(v.bls_public_key.len())]
        );
    }
    println!("🏦 Treasury reserve: {} quanta", genesis.treasury_reserve);
    println!("⏳ Epoch duration: {}s", genesis.epoch_duration);
    println!("✅ Wrote {}", args.out.display());
    println!(
        "ℹ️  Each validator must run with its node.key set to the SAME 32-byte seed \
         used here, and all nodes must use this identical genesis.json."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use storage::StateDB;

    /// Deterministic distinct seeds for tests.
    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn stdlib_path() -> String {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vm_move/stdlib/bytecode")
            .to_string_lossy()
            .to_string()
    }

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path =
            std::env::temp_dir().join(format!("aincore_genmulti_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(path.to_str().expect("utf8 temp path")).expect("test DB opens"))
    }

    #[test]
    fn parse_validator_spec_roundtrip() {
        let s = format!("{}:{}", hex::encode(seed(3)), 5_000u128);
        let spec = parse_validator_spec(&s).expect("valid spec parses");
        assert_eq!(spec.seed, seed(3));
        assert_eq!(spec.stake_ain, 5_000);
    }

    #[test]
    fn parse_validator_spec_rejects_bad_seed_len() {
        let err = parse_validator_spec("abcd:1000").expect_err("short seed must fail");
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_validator_spec_rejects_zero_stake() {
        let s = format!("{}:0", hex::encode(seed(4)));
        let err = parse_validator_spec(&s).expect_err("zero stake must fail");
        assert!(err.to_string().contains("stake must be > 0"));
    }

    /// The fields the tool derives MUST equal what a node derives from the same
    /// node.key seed. Address = derive_address(ed25519 pubkey); BLS pk/pop come
    /// from the canonical consensus seed derivation. This locks the tool to the
    /// runtime so the emitted genesis is actually loadable + verifiable.
    #[test]
    fn derived_fields_match_node_runtime_derivation() {
        let s = seed(11);
        let (addr, pk_hex, bls_pk_hex, bls_pop_hex) = derive_validator_fields(&s).expect("derive");

        // ed25519 + address, exactly as the node computes them.
        let sk = SigningKey::from_bytes(&s);
        let vk = sk.verifying_key();
        assert_eq!(pk_hex, hex::encode(vk.to_bytes()));
        assert_eq!(addr, crypto::derive_address(&vk.to_bytes()).unwrap());

        // BLS: the seed the node uses is signing_key.to_bytes() (== s).
        let bls_seed = consensus::qc::derive_validator_bls_seed(&sk.to_bytes());
        let bls = crypto::bls::BLSEngine::consensus();
        assert_eq!(bls_pk_hex, hex::encode(bls.pubkey_raw(&bls_seed)));

        // PoP must verify against the derived public key.
        let pk_bytes = hex::decode(&bls_pk_hex).unwrap();
        let pop_bytes = hex::decode(&bls_pop_hex).unwrap();
        assert!(
            bls.verify_possession(&pk_bytes, &pop_bytes).unwrap(),
            "generated bls_pop must verify against generated bls_public_key"
        );
        // Length invariants the loader enforces (pk=48 MinPk, pop=96).
        assert_eq!(pk_bytes.len(), 48);
        assert_eq!(pop_bytes.len(), 96);
    }

    #[test]
    fn build_genesis_file_rejects_duplicate_seed() {
        let specs = vec![
            ValidatorSpec {
                seed: seed(9),
                stake_ain: 1000,
            },
            ValidatorSpec {
                seed: seed(9),
                stake_ain: 2000,
            },
        ];
        let err = build_genesis_file(&specs, "AINCORE-MAINNET-1", 50_000, 10)
            .expect_err("duplicate must fail");
        assert!(err.to_string().contains("duplicate validator address"));
    }

    /// Two validators independently deriving their genesis fields from the same
    /// emitted set must compute IDENTICAL validator_set_hashes (this is what a QC
    /// binds to). If the BLS keys were embedded wrong, the hashes would differ
    /// and QCs would never verify across nodes.
    #[test]
    fn two_validators_agree_on_validator_set_hash() {
        let specs = vec![
            ValidatorSpec {
                seed: seed(21),
                stake_ain: 1_000_000,
            },
            ValidatorSpec {
                seed: seed(22),
                stake_ain: 2_000_000,
            },
        ];
        let genesis = build_genesis_file(&specs, "AINCORE-MAINNET-1", 50_000, 10).unwrap();

        // Reconstruct consensus::qc::ValidatorInfo from the emitted file (this is
        // the same shape genesis.rs writes to sys:validator_set:v1, with stake
        // scaled to whole AIN).
        let to_info = |v: &GenesisValidatorConfig| consensus::qc::ValidatorInfo {
            address: v.address.clone(),
            stake: (v.stake.parse::<u128>().unwrap() / COIN_SCALE) as u64,
            ed25519_public_key: v.public_key.clone(),
            bls_public_key: v.bls_public_key.clone(),
            bls_pop: v.bls_pop.clone(),
        };
        let set: Vec<_> = genesis.validators.iter().map(to_info).collect();

        // validator_set_hash is address-sorted + order-independent: whichever node
        // computes it from the same genesis gets the same hash.
        let hash_a = consensus::qc::validator_set_hash(&set);
        let mut reversed = set.clone();
        reversed.reverse();
        let hash_b = consensus::qc::validator_set_hash(&reversed);
        assert_eq!(hash_a, hash_b, "set hash must be order-independent");
        assert_eq!(hash_a.len(), 64, "set hash must be a 32-byte sha256 hex");
    }

    /// End-to-end: generate a 2-validator genesis, write it to disk, point the
    /// genesis loader at it (AINCORE_GENESIS_PATH), and prove init succeeds with
    /// the embedded BLS keys (no self-derivation, multi-validator path). Then
    /// confirm sys:validator_set:v1 round-trips to the SAME validator_set_hash
    /// the file implies — i.e. the BLS keys were embedded correctly.
    #[test]
    fn generated_multi_validator_genesis_loads_and_set_hash_matches() {
        // Guard the genesis env var against the node crate's own tests, which set
        // AINCORE_GENESIS_PATH / AINCORE_EXPECTED_GENESIS_HASH. We run in a
        // separate process per test binary, but be defensive about leftover env.
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");

        let specs = vec![
            ValidatorSpec {
                seed: seed(31),
                stake_ain: 1_500_000,
            },
            ValidatorSpec {
                seed: seed(32),
                stake_ain: 2_500_000,
            },
        ];
        let genesis = build_genesis_file(&specs, "AINCORE-MAINNET-1", 50_000, 7).unwrap();

        let dir = std::env::temp_dir().join(format!("aincore_genmulti_e2e_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_path = dir.join("genesis.json");
        std::fs::write(
            &genesis_path,
            serde_json::to_string_pretty(&genesis).unwrap(),
        )
        .unwrap();
        std::env::set_var("AINCORE_GENESIS_PATH", &genesis_path);

        // The loader's single-node-fallback args (genesis_addr/pubkey/node_identity)
        // are irrelevant here because genesis.json supplies an explicit
        // multi-validator set with embedded BLS keys.
        let db = temp_db("e2e_load");
        let first = &genesis.validators[0];
        node::genesis::initialize_genesis(
            &db,
            &stdlib_path(),
            &first.address,
            &first.public_key,
            &seed(99), // arbitrary node identity; NOT used for BLS in multi mode
        )
        .expect("multi-validator genesis with embedded BLS keys must load");

        std::env::remove_var("AINCORE_GENESIS_PATH");

        // sys:validator_set:v1 must have been written with all validators.
        let stored = db
            .get("sys:validator_set:v1")
            .unwrap()
            .expect("validator set v1 written");
        let loaded: Vec<consensus::qc::ValidatorInfo> = serde_json::from_str(&stored).unwrap();
        assert_eq!(loaded.len(), 2);

        // Recompute the set hash from the emitted genesis (whole-AIN scaled) and
        // confirm it equals the hash of what genesis init persisted. This is the
        // crux: both "views" agree -> any QC signed under one verifies under the
        // other.
        let expected: Vec<_> = genesis
            .validators
            .iter()
            .map(|v| consensus::qc::ValidatorInfo {
                address: v.address.clone(),
                stake: (v.stake.parse::<u128>().unwrap() / COIN_SCALE) as u64,
                ed25519_public_key: v.public_key.clone(),
                bls_public_key: v.bls_public_key.clone(),
                bls_pop: v.bls_pop.clone(),
            })
            .collect();
        assert_eq!(
            consensus::qc::validator_set_hash(&loaded),
            consensus::qc::validator_set_hash(&expected),
            "persisted validator set hash must match the generated genesis"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
