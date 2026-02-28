module 0x1::scripts {
    use 0x1::token_factory;
    use std::signer;

    /// Entry function to create a token with image support
    public entry fun create_token(
        creator: &signer,
        name: vector<u8>,
        symbol: vector<u8>,
        decimals: u8,
        max_supply: u128,
        initial_supply: u128,
        icon_url: vector<u8>,
        project_url: vector<u8>
    ) {
        token_factory::create_token(
            creator,
            name,
            symbol,
            decimals,
            max_supply,
            initial_supply,
            icon_url,
            project_url
        );
    }
}
