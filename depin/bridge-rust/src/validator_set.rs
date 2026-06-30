//! SEC-#18 Tier-B: the bridge's TRUSTED validator set, loaded independently of
//! the RPC node it queries.
//!
//! Tier-A made the bridge require the queried node's *own* `verified` flag on a
//! quorum certificate. That still trusts the node: a malicious / compromised RPC
//! could simply return `verified: true` over a forged QC. Tier-B removes that
//! trust by verifying the QC's aggregate BLS signature **client-side**, on the
//! bridge, against a validator set the operator ships with the bridge — NEVER one
//! the RPC supplies.
//!
//! Source of the set: a local JSON file pointed to by `AINCORE_VALIDATOR_SET_PATH`.
//! Two shapes are accepted.
//!
//! Shape 1 — a flat array, exactly the format a node persists at
//! `sys:validator_set:v1` / `sys:validator_set:epoch:{E}`
//! (`Vec<consensus::qc::ValidatorInfo>`):
//!
//! ```json
//! [ { "address": "...", "stake": 1000, "ed25519_public_key": "..",
//!     "bls_public_key": "..", "bls_pop": ".." } ]
//! ```
//!
//! This single set is used to verify QCs for **every** epoch. Use this when the
//! bridge operator pins one genesis validator set.
//!
//! Shape 2 — a per-epoch object, for chains whose validator set rotates by epoch:
//!
//! ```json
//! { "epochs": { "0": [], "1": [] }, "default": [] }
//! ```
//!
//! `resolve_for_epoch(E)` returns `epochs["E"]` if present, else `default` if
//! present, else `None` (fail-closed — no set, no acceptance).
//!
//! There is intentionally NO network fetch here: trusting the RPC for the set
//! would defeat the entire control.

use consensus::qc::ValidatorInfo;
use serde::Deserialize;
use std::collections::HashMap;

/// Env var naming the trusted validator-set file the operator ships.
pub const VALIDATOR_SET_PATH_ENV: &str = "AINCORE_VALIDATOR_SET_PATH";

/// In-memory trusted validator set(s) used for client-side QC verification.
#[derive(Debug, Clone)]
pub enum TrustedValidatorSet {
    /// One pinned set used for QCs of any epoch.
    Single(Vec<ValidatorInfo>),
    /// Per-epoch sets with an optional default fallback.
    PerEpoch {
        epochs: HashMap<u64, Vec<ValidatorInfo>>,
        default: Option<Vec<ValidatorInfo>>,
    },
}

/// Internal deserialization shape for the per-epoch object form.
#[derive(Debug, Deserialize)]
struct PerEpochFile {
    #[serde(default)]
    epochs: HashMap<String, Vec<ValidatorInfo>>,
    #[serde(default)]
    default: Option<Vec<ValidatorInfo>>,
}

impl TrustedValidatorSet {
    /// Parse from raw JSON text. Tries the flat-array shape first, then the
    /// per-epoch object shape. Returns an error string on any parse failure or
    /// if the parsed set is effectively empty (fail-closed: an empty trusted set
    /// can never meet quorum, so we surface it as a config error instead of
    /// silently rejecting every block).
    pub fn from_json_str(s: &str) -> Result<Self, String> {
        // Shape 1: flat array of ValidatorInfo.
        if let Ok(flat) = serde_json::from_str::<Vec<ValidatorInfo>>(s) {
            if flat.is_empty() {
                return Err("trusted validator set file is an empty array".to_string());
            }
            return Ok(TrustedValidatorSet::Single(flat));
        }

        // Shape 2: per-epoch object.
        let parsed: PerEpochFile = serde_json::from_str(s).map_err(|e| {
            format!("validator set file is neither a ValidatorInfo array nor a per-epoch object: {e}")
        })?;

        let mut epochs: HashMap<u64, Vec<ValidatorInfo>> = HashMap::new();
        for (k, v) in parsed.epochs {
            let epoch: u64 = k
                .parse()
                .map_err(|_| format!("invalid epoch key '{k}' in validator set file"))?;
            epochs.insert(epoch, v);
        }

        if epochs.is_empty() && parsed.default.as_ref().map(|d| d.is_empty()).unwrap_or(true) {
            return Err("per-epoch validator set file has no epochs and no usable default".to_string());
        }

        Ok(TrustedValidatorSet::PerEpoch {
            epochs,
            default: parsed.default,
        })
    }

    /// Load from the file named by `AINCORE_VALIDATOR_SET_PATH`. Missing env or
    /// unreadable file -> `Err` (fail-closed: without a trusted set the bridge
    /// cannot verify any QC and must refuse to act).
    pub fn from_env() -> Result<Self, String> {
        let path = std::env::var(VALIDATOR_SET_PATH_ENV).map_err(|_| {
            format!(
                "{VALIDATOR_SET_PATH_ENV} is not set; bridge cannot verify QCs without a trusted validator set"
            )
        })?;
        Self::from_path(&path)
    }

    /// Load from an explicit path.
    pub fn from_path(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read validator set file '{path}': {e}"))?;
        Self::from_json_str(&raw)
    }

    /// Resolve the trusted set to verify a QC for `epoch` against.
    ///
    /// - `Single` -> always returns the one pinned set.
    /// - `PerEpoch` -> the exact epoch's set, else the configured `default`,
    ///   else `None` (fail-closed — no trusted set for this epoch).
    pub fn resolve_for_epoch(&self, epoch: u64) -> Option<&[ValidatorInfo]> {
        match self {
            TrustedValidatorSet::Single(set) => Some(set.as_slice()),
            TrustedValidatorSet::PerEpoch { epochs, default } => epochs
                .get(&epoch)
                .map(|v| v.as_slice())
                .or_else(|| default.as_ref().map(|v| v.as_slice())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vinfo(addr: &str, stake: u64) -> ValidatorInfo {
        ValidatorInfo {
            address: addr.to_string(),
            stake,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: "11".repeat(48),
            bls_pop: "22".repeat(96),
        }
    }

    #[test]
    fn parses_flat_array_form() {
        let json = serde_json::to_string(&vec![vinfo("aa", 10), vinfo("bb", 20)]).unwrap();
        let set = TrustedValidatorSet::from_json_str(&json).unwrap();
        // Single set used for any epoch.
        assert_eq!(set.resolve_for_epoch(0).unwrap().len(), 2);
        assert_eq!(set.resolve_for_epoch(999).unwrap().len(), 2);
    }

    #[test]
    fn empty_flat_array_is_fail_closed_error() {
        let json = "[]";
        assert!(TrustedValidatorSet::from_json_str(json).is_err());
    }

    #[test]
    fn parses_per_epoch_form_with_default() {
        let json = serde_json::json!({
            "epochs": {
                "3": [vinfo("aa", 10)],
            },
            "default": [vinfo("bb", 20), vinfo("cc", 30)],
        })
        .to_string();
        let set = TrustedValidatorSet::from_json_str(&json).unwrap();
        // Exact epoch resolves to its set.
        assert_eq!(set.resolve_for_epoch(3).unwrap().len(), 1);
        // Unknown epoch falls back to default.
        assert_eq!(set.resolve_for_epoch(7).unwrap().len(), 2);
    }

    #[test]
    fn per_epoch_without_default_fails_closed_for_unknown_epoch() {
        let json = serde_json::json!({
            "epochs": { "1": [vinfo("aa", 10)] }
        })
        .to_string();
        let set = TrustedValidatorSet::from_json_str(&json).unwrap();
        assert_eq!(set.resolve_for_epoch(1).unwrap().len(), 1);
        // No default -> unknown epoch has no trusted set.
        assert!(set.resolve_for_epoch(2).is_none());
    }

    #[test]
    fn garbage_json_is_error() {
        assert!(TrustedValidatorSet::from_json_str("not json").is_err());
        assert!(TrustedValidatorSet::from_json_str("{\"epochs\":{}}").is_err());
    }

    #[test]
    fn missing_env_is_fail_closed() {
        // Ensure unset (other tests in this process don't set it).
        unsafe {
            std::env::remove_var(VALIDATOR_SET_PATH_ENV);
        }
        assert!(TrustedValidatorSet::from_env().is_err());
    }
}
