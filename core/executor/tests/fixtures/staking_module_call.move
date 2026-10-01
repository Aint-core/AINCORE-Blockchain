module 0x0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08::stakewrap {
    use 0x1::staking;

    /// G5 review: a module call into the staking entries skips every check
    /// the executor runs on a direct call (the BLS proof of possession, the
    /// tombstone) and leaves the committee's set out of step with Move: a
    /// validator could leave, take its stake back after unbonding, and keep
    /// its seat. Compiled against the stdlib in which these entries were
    /// `public entry`; with them `entry` only, publishing this must fail.
    public entry fun leave(account: &signer) {
        staking::leave_validator_set(account);
    }

    public entry fun join(
        account: &signer,
        amount: u128,
        public_key: vector<u8>,
        bls_public_key: vector<u8>,
        bls_pop: vector<u8>,
    ) {
        staking::join_validator_set(account, amount, public_key, bls_public_key, bls_pop);
    }

    public entry fun add(account: &signer, amount: u128) {
        staking::add_stake(account, amount);
    }
}
