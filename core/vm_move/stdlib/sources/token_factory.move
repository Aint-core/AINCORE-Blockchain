/// Token Factory Module
/// Allows developers to create custom tokens on AINCORE
/// All fees are paid in native AIN
module 0x1::token_factory {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::staking::{AincoreCoin};

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

    /// Token creation fee (100 AIN, burned to create economic scarcity)
    const TOKEN_CREATION_FEE: u128 = 100_000_000_000_000_000_000; // 100 * 10^18

    /// Token metadata
    struct TokenInfo has key, store, copy, drop {
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

    /// Global registry of all tokens
    struct TokenRegistry has key {
        tokens: vector<TokenInfo>,
    }

    /// User's balance for a specific token
    struct TokenBalance has key, store, drop {
        token_id: vector<u8>,
        balance: u128,
    }

    /// User's token balances (multiple tokens)
    struct TokenWallet has key {
        balances: vector<TokenBalance>,
    }

    /// Initialize the registry (called once at genesis)
    public fun initialize(admin: &signer) {
        move_to(admin, TokenRegistry {
            tokens: vector::empty(),
        });
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
    ) acquires TokenRegistry, TokenWallet {
        let creator_addr = signer::address_of(creator);
        
        // Validate decimals (max 18)
        assert!(decimals <= 18, error::invalid_argument(EINVALID_DECIMALS));
        
        // Validate initial supply <= max supply
        assert!(initial_supply <= max_supply, error::invalid_argument(EMAX_SUPPLY_EXCEEDED));
        
        // Validate max_supply > 0
        assert!(max_supply > 0, error::invalid_argument(EINVALID_AMOUNT));
        
        // Charge creation fee (100 AIN)
        let fee = coin::withdraw<AincoreCoin>(creator, TOKEN_CREATION_FEE);
        coin::burn(fee); // Burn the fee (deflationary)
        
        // Generate token_id from symbol + creator address
        let token_id = symbol; // Simplified: use symbol as token_id
        
        // Check token doesn't exist
        let registry = borrow_global_mut<TokenRegistry>(@0x1);
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
        
        // Mint initial supply to creator
        if (initial_supply > 0) {
            mint_internal(creator_addr, token_id, initial_supply);
        }
    }

    /// Mint tokens (only token creator can mint)
    public entry fun mint(
        admin: &signer,
        token_id: vector<u8>,
        to: address,
        amount: u128
    ) acquires TokenRegistry, TokenWallet {
        // Validate amount > 0
        assert!(amount > 0, error::invalid_argument(EINVALID_AMOUNT));
        let admin_addr = signer::address_of(admin);
        
        let registry = borrow_global_mut<TokenRegistry>(@0x1);
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

    /// Internal mint helper
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
        
        if (!found) {
            vector::push_back(&mut wallet.balances, TokenBalance {
                token_id,
                balance: amount,
            });
        }
    }

    /// Burn tokens
    public entry fun burn(
        owner: &signer,
        token_id: vector<u8>,
        amount: u128
    ) acquires TokenRegistry, TokenWallet {
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
        
        // Update total supply
        let registry = borrow_global_mut<TokenRegistry>(@0x1);
        let reg_len = vector::length(&registry.tokens);
        let j = 0;
        while (j < reg_len) {
            let t = vector::borrow_mut(&mut registry.tokens, j);
            if (t.token_id == token_id) {
                t.current_supply = t.current_supply - amount;
                break
            };
            j = j + 1;
        };
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

    /// Get token info
    public fun get_token_info(token_id: vector<u8>): TokenInfo acquires TokenRegistry {
        let registry = borrow_global<TokenRegistry>(@0x1);
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
    public entry fun disable_minting(admin: &signer, token_id: vector<u8>) acquires TokenRegistry {
        let admin_addr = signer::address_of(admin);
        
        let registry = borrow_global_mut<TokenRegistry>(@0x1);
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
