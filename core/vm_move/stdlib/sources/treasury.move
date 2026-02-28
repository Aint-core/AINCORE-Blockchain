/// Treasury Module
/// Manages the sales of AIN from the genesis reserve (e.g., via Bill Acceptor).
/// Implements a simple pricing mechanism (or bonding curve).

module 0x1::treasury {
    use std::signer;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::staking::{AincoreCoin};

    /// Error Codes
    const ENOT_AUTHORIZED: u64 = 1;
    const EINSUFFICIENT_FUNDS: u64 = 2;
    const EINVALID_PAYMENT: u64 = 3;

    /// The address of the Apex 7600 Machine Controller (who calls the sell function)
    /// In production, this should be a resource account or multisig.
    const MACHINE_ADDRESS: address = @0x1; 

    /// Treasury Resource
    struct Treasury has key {
        reserve: Coin<AincoreCoin>,
        total_sold: u128,
        price_usd_cents: u64, // Price per AIN in USD cents (Fixed for Phase 1)
                              // e.g. 100 = $1.00
    }

    /// Initialize Treasury with initial reserve
    public fun initialize(account: &signer, initial_funds: Coin<AincoreCoin>) {
        move_to(account, Treasury {
            reserve: initial_funds,
            total_sold: 0,
            price_usd_cents: 100, // Start at $1.00
        });
    }

    /// Sell AIN to a user (Called by Bill Acceptor Driver)
    /// 
    /// Flow:
    /// 1. Machine receives Cash ($10).
    /// 2. Machine Driver verifies cash.
    /// 3. Machine Driver calls this function with `amount_usd_cents = 1000`.
    /// 4. This function calculates AIN amount and sends to `recipient`.
    /// 
    /// Note: This function is 'trusted' because the machine already collected the fiat off-chain.
    /// The 'payment' here is the proof from the machine address.
    public entry fun sell_ain(
        machine: &signer,
        recipient: address,
        amount_usd_cents: u64
    ) acquires Treasury {
        let machine_addr = signer::address_of(machine);
        assert!(machine_addr == MACHINE_ADDRESS, error::permission_denied(ENOT_AUTHORIZED));

        let treasury = borrow_global_mut<Treasury>(@0x1);
        
        // Calculate AIN amount: (USD_CENTS / PRICE) * 10^18
        // Example: $10 (1000 cents) / $1 (100 cents) = 10 AIN
        // 10 * 10^18
        
        // Safety check for price
        if (treasury.price_usd_cents == 0) {
            treasury.price_usd_cents = 100; // Fallback safety
        };

        let amount_u128 = (amount_usd_cents as u128);
        let price_u128 = (treasury.price_usd_cents as u128);
        let ain_amount = (amount_u128 * 1000000000000000000) / price_u128;
        
        // Check reserve
        assert!(coin::value(&treasury.reserve) >= ain_amount, error::invalid_state(EINSUFFICIENT_FUNDS));
        
        // Transfer
        let sold_coins = coin::split(&mut treasury.reserve, ain_amount);
        coin::deposit<AincoreCoin>(recipient, sold_coins);
        
        treasury.total_sold = treasury.total_sold + ain_amount;
    }

    /// Update Price (Admin only - or Oracle later)
    public entry fun set_price(admin: &signer, new_price_cents: u64) acquires Treasury {
        assert!(signer::address_of(admin) == @0x1, error::permission_denied(ENOT_AUTHORIZED));
        let treasury = borrow_global_mut<Treasury>(@0x1);
        treasury.price_usd_cents = new_price_cents;
    }

    /// Get current price
    public fun get_price(): u64 acquires Treasury {
        borrow_global<Treasury>(@0x1).price_usd_cents
    }
}
