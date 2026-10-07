/// Token Factory Module
/// Allows developers to create custom tokens on AINCORE
/// All fees are paid in native AIN
module 0x1::token_factory {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::staking::{Self, AincoreCoin};

    /// Error codes
    const ETOKEN_EXISTS: u64 = 1;
    const ETOKEN_NOT_FOUND: u64 = 2;
    const ENOT_AUTHORIZED: u64 = 3;
    const EINSUFFICIENT_BALANCE: u64 = 4;
    const EMAX_SUPPLY_EXCEEDED: u64 = 5;
    const EINVALID_DECIMALS: u64 = 6;
    const EWALLET_NOT_INITIALIZED: u64 = 7;
    const EINVALID_AMOUNT: u64 = 8;
    const ESELF_TRANSFER: u64 = 9;
    /// B99: a field longer than its bound, or the creator's registry full.
    const EFIELD_TOO_LONG: u64 = 10;
    const ETOO_MANY_TOKENS: u64 = 11;
    /// B135: the wallet has not registered the token, or holds its maximum.
    const ENOT_REGISTERED: u64 = 12;
    const EWALLET_FULL: u64 = 13;

    /// B99: field lengths (bytes), so a registry stays small to load.
    const MAX_NAME_BYTES: u64 = 64;
    const MAX_SYMBOL_BYTES: u64 = 16;
    const MAX_URL_BYTES: u64 = 256;
    /// B135: tokens one creator may hold (a choice: its registry, loaded by
    /// each of its creates, mints, burns and disables, stays under ~26 KB).
    /// Each creator has its own registry: one global one, capped, could be
    /// filled by anyone for 51,200 AIN and closed to everyone for good.
    const MAX_TOKENS_PER_CREATOR: u64 = 64;
    /// B135: tokens one wallet may register (its owner's choice).
    const MAX_WALLET_TOKENS: u64 = 256;

    /// Token creation fee (100 AIN, burned to create economic scarcity)
    const TOKEN_CREATION_FEE: u128 = 100_000_000_000_000_000_000; // 100 * 10^18

    /// Token metadata
    struct TokenInfo has store, copy, drop {
        token_id: vector<u8>,
        name: vector<u8>,
        symbol: vector<u8>,
        decimals: u8,
        max_supply: u128,
        current_supply: u128,
        creator: address,
        is_mintable: bool,
        icon_url: vector<u8>,    // URL to token logo (e.g., IPFS or HTTPS)
        project_url: vector<u8>, // URL to project website
    }

    /// B135: one creator's tokens, at the creator's address.
    struct CreatorTokens has key {
        tokens: vector<TokenInfo>,
    }

    /// User's balance for a specific token
    struct TokenBalance has key, store, drop {
        token_id: vector<u8>,
        balance: u128,
    }

    /// User's token balances (multiple tokens). B135: only the tokens its
    /// owner registered (anyone could push balances of any number of tokens
    /// into a wallet, and every later operation of its owner scanned them).
    struct TokenWallet has key {
        balances: vector<TokenBalance>,
    }

    /// Create a new token
    /// Fee: 100 AIN (burned)
    public entry fun create_token(
        creator: &signer,
        name: vector<u8>,
        symbol: vector<u8>,
        decimals: u8,
        max_supply: u128,
        initial_supply: u128,
        icon_url: vector<u8>,    // New argument
        project_url: vector<u8>  // New argument
) acquires CreatorTokens, TokenWallet {
        let creator_addr = signer::address_of(creator);
        
        // Validate decimals (max 18)
        assert!(decimals <= 18, error::invalid_argument(EINVALID_DECIMALS));
        
        // Validate initial supply <= max supply
        assert!(initial_supply <= max_supply, error::invalid_argument(EMAX_SUPPLY_EXCEEDED));
        
        // Validate max_supply > 0
        assert!(max_supply > 0, error::invalid_argument(EINVALID_AMOUNT));
        assert!(
            vector::length(&name) <= MAX_NAME_BYTES
                && vector::length(&symbol) <= MAX_SYMBOL_BYTES
                && vector::length(&icon_url) <= MAX_URL_BYTES
                && vector::length(&project_url) <= MAX_URL_BYTES,
            error::invalid_argument(EFIELD_TOO_LONG)
        );
        
        // B99/B135: a full registry refuses before the fee is taken.
        if (!exists<CreatorTokens>(creator_addr)) {
            move_to(creator, CreatorTokens { tokens: vector::empty() });
        };
        assert!(
            vector::length(&borrow_global<CreatorTokens>(creator_addr).tokens)
                < MAX_TOKENS_PER_CREATOR,
            error::resource_exhausted(ETOO_MANY_TOKENS)
        );

        // Charge creation fee (100 AIN)
        let fee = coin::withdraw<AincoreCoin>(creator, TOKEN_CREATION_FEE);
        staking::burn_ain(fee); // Burn the fee and update canonical supply
        
        // M1 FIX: Token ID = symbol + creator address bytes
        // This prevents front-running attacks where an attacker deploys a token
        // with the same symbol to block the legitimate creator.
        // Each creator gets a unique namespace for their tokens.
        let creator_bytes = std::bcs::to_bytes(&creator_addr);
        let token_id = copy symbol;
        vector::append(&mut token_id, creator_bytes);
        
        // Check token doesn't exist
        let registry = borrow_global_mut<CreatorTokens>(creator_addr);
        let len = vector::length(&registry.tokens);
        let i = 0;
        while (i < len) {
            let t = vector::borrow(&registry.tokens, i);
            assert!(t.token_id != token_id, error::already_exists(ETOKEN_EXISTS));
            i = i + 1;
        };
        
        // Create token info
        let token_info = TokenInfo {
            token_id: copy token_id,
            name,
            symbol,
            decimals,
            max_supply,
            current_supply: initial_supply,
            creator: creator_addr,
            is_mintable: true,
            icon_url,
            project_url,
        };
        
        vector::push_back(&mut registry.tokens, token_info);
        
        // Mint initial supply to creator (its wallet registers the token).
        if (initial_supply > 0) {
            register_internal(creator_addr, copy token_id);
            mint_internal(creator_addr, token_id, initial_supply);
        }
    }

    /// B135: register `token_id` in the account's wallet (made if missing),
    /// so the wallet can receive it.
    public entry fun register(account: &signer, token_id: vector<u8>) acquires TokenWallet {
        let addr = signer::address_of(account);
        if (!exists<TokenWallet>(addr)) {
            move_to(account, TokenWallet { balances: vector::empty() });
        };
        register_internal(addr, token_id);
    }

    fun register_internal(owner: address, token_id: vector<u8>) acquires TokenWallet {
        assert!(exists<TokenWallet>(owner), error::invalid_state(EWALLET_NOT_INITIALIZED));
        let wallet = borrow_global_mut<TokenWallet>(owner);
        let len = vector::length(&wallet.balances);
        let i = 0;
        while (i < len) {
            if (vector::borrow(&wallet.balances, i).token_id == token_id) {
                return
            };
            i = i + 1;
        };
        assert!(len < MAX_WALLET_TOKENS, error::resource_exhausted(EWALLET_FULL));
        vector::push_back(&mut wallet.balances, TokenBalance { token_id, balance: 0 });
    }

    /// Mint tokens (only token creator can mint)
    public entry fun mint(
        admin: &signer,
        token_id: vector<u8>,
        to: address,
        amount: u128
    ) acquires CreatorTokens, TokenWallet {
        // Validate amount > 0
        assert!(amount > 0, error::invalid_argument(EINVALID_AMOUNT));
        let admin_addr = signer::address_of(admin);
        
        // B135: the token is in its creator's registry, the signer's.
        assert!(exists<CreatorTokens>(admin_addr), error::not_found(ETOKEN_NOT_FOUND));
        let registry = borrow_global_mut<CreatorTokens>(admin_addr);
        let len = vector::length(&registry.tokens);
        let i = 0;
        let found = false;
        
        while (i < len) {
            let t = vector::borrow_mut(&mut registry.tokens, i);
            if (t.token_id == token_id) {
                // Check authorization
                assert!(t.creator == admin_addr, error::permission_denied(ENOT_AUTHORIZED));
                assert!(t.is_mintable, error::permission_denied(ENOT_AUTHORIZED));
                
                // Check max supply
                assert!(t.current_supply + amount <= t.max_supply, error::invalid_state(EMAX_SUPPLY_EXCEEDED));
                
                t.current_supply = t.current_supply + amount;
                found = true;
                break
            };
            i = i + 1;
        };
        
        assert!(found, error::not_found(ETOKEN_NOT_FOUND));
        
        mint_internal(to, token_id, amount);
    }

    /// Internal mint helper: credit a wallet that registered the token.
    fun mint_internal(to: address, token_id: vector<u8>, amount: u128) acquires TokenWallet {
        // CRITICAL: Fail if wallet not initialized to prevent token loss
        assert!(exists<TokenWallet>(to), error::invalid_state(EWALLET_NOT_INITIALIZED));
        
        let wallet = borrow_global_mut<TokenWallet>(to);
        let len = vector::length(&wallet.balances);
        let i = 0;
        let found = false;
        
        while (i < len) {
            let bal = vector::borrow_mut(&mut wallet.balances, i);
            if (bal.token_id == token_id) {
                bal.balance = bal.balance + amount;
                found = true;
                break
            };
            i = i + 1;
        };
        
        // B135: only a token the wallet's owner registered.
        assert!(found, error::invalid_state(ENOT_REGISTERED));
    }

    /// Burn tokens. B135: `creator` names the token's registry (the address
    /// `token_id` ends with).
    public entry fun burn(
        owner: &signer,
        creator: address,
        token_id: vector<u8>,
        amount: u128
    ) acquires CreatorTokens, TokenWallet {
        let owner_addr = signer::address_of(owner);
        
        // Deduct from user's balance
        let wallet = borrow_global_mut<TokenWallet>(owner_addr);
        let len = vector::length(&wallet.balances);
        let i = 0;
        let found = false;
        
        while (i < len) {
            let bal = vector::borrow_mut(&mut wallet.balances, i);
            if (bal.token_id == token_id) {
                assert!(bal.balance >= amount, error::invalid_argument(EINSUFFICIENT_BALANCE));
                bal.balance = bal.balance - amount;
                found = true;
                break
            };
            i = i + 1;
        };
        
        assert!(found, error::not_found(ETOKEN_NOT_FOUND));
        
        // Update total supply, in the token's own registry.
        assert!(exists<CreatorTokens>(creator), error::not_found(ETOKEN_NOT_FOUND));
        let registry = borrow_global_mut<CreatorTokens>(creator);
        let reg_len = vector::length(&registry.tokens);
        let j = 0;
        let listed = false;
        while (j < reg_len) {
            let t = vector::borrow_mut(&mut registry.tokens, j);
            if (t.token_id == token_id) {
                t.current_supply = t.current_supply - amount;
                listed = true;
                break
            };
            j = j + 1;
        };
        assert!(listed, error::not_found(ETOKEN_NOT_FOUND));
    }

    /// Transfer tokens between accounts
    public entry fun transfer(
        from: &signer,
        token_id: vector<u8>,
        to: address,
        amount: u128
    ) acquires TokenWallet {
        let from_addr = signer::address_of(from);
        
        // Validate: no self-transfer
        assert!(from_addr != to, error::invalid_argument(ESELF_TRANSFER));
        
        // Validate amount > 0
        assert!(amount > 0, error::invalid_argument(EINVALID_AMOUNT));
        
        // Deduct from sender
        let from_wallet = borrow_global_mut<TokenWallet>(from_addr);
        let len = vector::length(&from_wallet.balances);
        let i = 0;
        let found = false;
        
        while (i < len) {
            let bal = vector::borrow_mut(&mut from_wallet.balances, i);
            if (bal.token_id == token_id) {
                assert!(bal.balance >= amount, error::invalid_argument(EINSUFFICIENT_BALANCE));
                bal.balance = bal.balance - amount;
                found = true;
                break
            };
            i = i + 1;
        };
        
        assert!(found, error::not_found(EINSUFFICIENT_BALANCE));
        
        // Add to recipient
        mint_internal(to, token_id, amount);
    }

    /// Initialize user's token wallet
    public entry fun init_wallet(account: &signer) {
        let addr = signer::address_of(account);
        if (!exists<TokenWallet>(addr)) {
            move_to(account, TokenWallet {
                balances: vector::empty(),
            });
        }
    }

    /// Get token info (B135: from its creator's registry).
    public fun get_token_info(creator: address, token_id: vector<u8>): TokenInfo acquires CreatorTokens {
        assert!(exists<CreatorTokens>(creator), error::not_found(ETOKEN_NOT_FOUND));
        let registry = borrow_global<CreatorTokens>(creator);
        let len = vector::length(&registry.tokens);
        let i = 0;
        
        while (i < len) {
            let t = vector::borrow(&registry.tokens, i);
            if (t.token_id == token_id) {
                return *t
            };
            i = i + 1;
        };
        
        abort error::not_found(ETOKEN_NOT_FOUND)
    }

    /// Get user's balance for a token
    public fun get_balance(owner: address, token_id: vector<u8>): u128 acquires TokenWallet {
        if (!exists<TokenWallet>(owner)) {
            return 0
        };
        
        let wallet = borrow_global<TokenWallet>(owner);
        let len = vector::length(&wallet.balances);
        let i = 0;
        
        while (i < len) {
            let bal = vector::borrow(&wallet.balances, i);
            if (bal.token_id == token_id) {
                return bal.balance
            };
            i = i + 1;
        };
        
        0
    }

    /// Disable minting for a token (irreversible)
    public entry fun disable_minting(admin: &signer, token_id: vector<u8>) acquires CreatorTokens {
        let admin_addr = signer::address_of(admin);
        
        assert!(exists<CreatorTokens>(admin_addr), error::not_found(ETOKEN_NOT_FOUND));
        let registry = borrow_global_mut<CreatorTokens>(admin_addr);
        let len = vector::length(&registry.tokens);
        let i = 0;
        
        while (i < len) {
            let t = vector::borrow_mut(&mut registry.tokens, i);
            if (t.token_id == token_id) {
                assert!(t.creator == admin_addr, error::permission_denied(ENOT_AUTHORIZED));
                t.is_mintable = false;
                return
            };
            i = i + 1;
        };
        
        abort error::not_found(ETOKEN_NOT_FOUND)
    }
}
