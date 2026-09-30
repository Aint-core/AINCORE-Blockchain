/// Exact integer arithmetic for balances (G5 S3): products of two u128
/// balance-sized quantities (up to about 2e52 at 18 decimals) exceed u128, so
/// they are formed in u256 and divided back. Rounding is explicit at every
/// call site: down when paying a user, up when a user must give up value
/// (EIP-4626's rule, docs/research/delegation_pools.md).
module 0x1::math {
    use std::error;

    const EDIVIDE_BY_ZERO: u64 = 1;
    const EOVERFLOW: u64 = 2;

    const U128_MAX: u256 = 340282366920938463463374607431768211455;

    /// floor(a * b / c).
    public fun mul_div_floor(a: u128, b: u128, c: u128): u128 {
        assert!(c > 0, error::invalid_argument(EDIVIDE_BY_ZERO));
        narrow(((a as u256) * (b as u256)) / (c as u256))
    }

    /// ceil(a * b / c).
    public fun mul_div_ceil(a: u128, b: u128, c: u128): u128 {
        assert!(c > 0, error::invalid_argument(EDIVIDE_BY_ZERO));
        let n = (a as u256) * (b as u256);
        let d = (c as u256);
        narrow((n + d - 1) / d)
    }

    /// floor((a * b + c) / d) and its remainder: a counter that carries the
    /// remainder into its next step loses nothing over any number of steps.
    public fun mul_add_div(a: u128, b: u128, c: u128, d: u128): (u128, u128) {
        assert!(d > 0, error::invalid_argument(EDIVIDE_BY_ZERO));
        // a * b + c < 2^256: (2^128 - 1)^2 + 2^128 - 1 = 2^256 - 2^128.
        let n = (a as u256) * (b as u256) + (c as u256);
        let d = (d as u256);
        (narrow(n / d), narrow(n % d))
    }

    fun narrow(x: u256): u128 {
        assert!(x <= U128_MAX, error::out_of_range(EOVERFLOW));
        (x as u128)
    }
}
