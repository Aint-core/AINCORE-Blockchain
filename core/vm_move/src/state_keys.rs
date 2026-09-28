//! The ONE canonical encoder of Move state keys (G3 KV-2, FX-9).
//!
//! The format is frozen: proof clients derive `KeyHash = SHA-256(key)` from it
//! themselves, so any change breaks every proof already issued.
//!
//! - `resource_{addr}_{tag}`: `addr` is `AccountAddress` Display (64 lowercase
//!   hex, no `0x`, with the `address32` feature); `tag` is move-core
//!   `StructTag` Display (`0x1::coin::CoinStore<0x1::staking::AincoreCoin>`).
//! - `module_{addr}_{name}`.
//!
//! Hand-written keys elsewhere in Rust are pinned to these functions by the
//! golden tests below and in `core/executor`.

use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::StructTag;

pub fn resource_key(address: &AccountAddress, tag: &StructTag) -> String {
    format!("resource_{}_{}", address, tag)
}

pub fn module_key(address: &AccountAddress, name: &str) -> String {
    format!("module_{}_{}", address, name)
}

/// Parse a Move type string (`0x1::staking::ValidatorSet`) and encode its
/// key at `address`. For pinning hand-written keys in tests.
pub fn resource_key_str(address: &AccountAddress, tag: &str) -> String {
    let tag: StructTag = tag.parse().expect("a valid Move struct tag");
    resource_key(address, &tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden: the frozen format for the keys every client needs.
    #[test]
    fn the_key_format_is_frozen() {
        let one = AccountAddress::ONE;
        assert_eq!(
            resource_key_str(&one, "0x1::staking::ValidatorSet"),
            "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet"
        );
        assert_eq!(
            resource_key_str(&one, "0x1::coin::CoinStore<0x1::staking::AincoreCoin>"),
            "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::coin::CoinStore<0x1::staking::AincoreCoin>"
        );
        assert_eq!(
            resource_key_str(
                &one,
                "0x1::dex::LiquidityPool<0x1::staking::AincoreCoin, 0x1::wbtc::WBTC>"
            ),
            "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::dex::LiquidityPool<0x1::staking::AincoreCoin, 0x1::wbtc::WBTC>"
        );
        assert_eq!(
            module_key(&one, "staking"),
            "module_0000000000000000000000000000000000000000000000000000000000000001_staking"
        );
    }
}
