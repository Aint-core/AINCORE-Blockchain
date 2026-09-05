module 0x0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08::coinforge {
    use 0x1::coin;
    use 0x1::staking;

    /// PRE-MAINNET AUDIT B1 (CRITICAL): no signer is forged here at all, so the
    /// signer-reachability guards never fire. The `Coin<AincoreCoin>` parameter
    /// is a plain value parameter, and move-vm's deserialize_args constructs it
    /// straight from the caller's BCS bytes -- a coin the protocol never issued.
    /// Depositing it mints unlimited AIN. Any account may publish this.
    public entry fun forge_coin(to: address, c: coin::Coin<staking::AincoreCoin>) {
        coin::deposit<staking::AincoreCoin>(to, c);
    }
}
