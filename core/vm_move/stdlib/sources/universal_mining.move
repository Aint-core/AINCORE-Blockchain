module 0x1::universal_mining {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin;
    use 0x1::staking::AincoreCoin;

    /// Error codes
    const ENOT_AUTHORIZED: u64 = 1;
    const EDEVICE_ALREADY_REGISTERED: u64 = 2;
    const EDEVICE_NOT_REGISTERED: u64 = 3;
    // 4 = ALREADY_VOTED, raised inline by submit_vote.
    const EINVALID_DEVICE_PUBKEY: u64 = 5;
    const EOWNER_DEVICE_LIMIT: u64 = 6;
    const EREGISTRY_FULL: u64 = 7;

    /// The address of the authorized Oracle who can submit proofs
    const ORACLE_ADDRESS: address = @0x1; // For prototype, system account is oracle

    /// BOUNDS (G3 S6 open item: global resources had no size bound).
    ///
    /// register_device used to append to ONE vector at @0x1, for anyone, with
    /// no limit on the key length or the count, and it scanned the whole
    /// vector on every call. Measured before this change: gas = 125 + 180*N
    /// for N registered devices, and the key bytes were free (a 16 MiB key
    /// cost the same 125 gas as a 32-byte one). At N ~ 55,500 (about 4.2 MB)
    /// the load alone exceeded MAX_GAS_LIMIT, so every registration,
    /// verification and reward aborted for good.
    ///
    /// Now nothing a caller can grow is shared: a registration lands in the
    /// caller's own DeviceClaims, capped per owner. Only feeders write the
    /// global DeviceRegistry, and it is capped too. A global cap on
    /// permissionless registrations was not an option: one attacker could
    /// fill it and lock every honest owner out.
    ///
    /// A device key is an Ed25519 public key: the only scheme the feeders
    /// verify off-chain (see add_verified_device) and the one the IoT SDK
    /// generates.
    const DEVICE_PUBKEY_BYTES: u64 = 32;
    /// Devices one address may register. Bounds the caller's DeviceClaims
    /// resource and the scan in each of its registrations.
    const MAX_DEVICES_PER_OWNER: u64 = 32;
    /// Verified bindings the global DeviceRegistry may hold. At 73 bytes an
    /// entry the full registry stays under 1 MiB (one state-sync part), and a
    /// feeder call that loads and scans all of it costs about 1.64M gas
    /// (measured), under a fifth of MAX_GAS_LIMIT. Growing past this needs
    /// keyed storage (Move tables), which this VM does not have.
    const MAX_VERIFIED_DEVICES: u64 = 10000;

    /// A device an owner registered. Unverified: it earns nothing until a
    /// feeder verifies the binding (add_verified_device).
    struct DeviceClaim has store, drop {
        device_pubkey: vector<u8>,
        device_type: u8,
        // 0=Unknown
        // 1=Wearable (Watch/Band)
        // 2=Stationary (Air Monitor)
        // 3=Mobile (Phone App)
        // 4=Desktop (Laptop/PC)
        // 5=Browser (Web Extension)
    }

    /// The devices one owner registered, stored at the owner's address.
    struct DeviceClaims has key {
        devices: vector<DeviceClaim>,
    }

    /// A feeder-verified (owner_addr, device_pubkey) binding.
    /// SECURITY (H3): only these receive rewards.
    struct VerifiedDevice has store, drop {
        device_pubkey: vector<u8>,
        owner_addr: address,
        // AUDIT-#10: per-device per-epoch reward rate limit. The last staking
        // epoch this device was PAID in; distribute_reward pays at most once per
        // device per epoch (feeders could otherwise re-finalize the same device
        // arbitrarily often -- each finalize is a fresh proof -- minting without
        // bound). 0 = never paid; devices earn from epoch 1 onward.
        last_reward_epoch: u64,
    }

    /// Device Type Constants
    const DEVICE_WEARABLE: u8 = 1;
    const DEVICE_STATIONARY: u8 = 2;
    const DEVICE_MOBILE: u8 = 3;
    const DEVICE_DESKTOP: u8 = 4;
    const DEVICE_BROWSER: u8 = 5;

    /// Global registry of VERIFIED devices, at most one entry per pubkey.
    /// Only feeders add to it, up to MAX_VERIFIED_DEVICES.
    struct DeviceRegistry has key {
        devices: vector<VerifiedDevice>,
    }

    /// Initialize the module (called at genesis)
    public fun initialize(account: &signer) {
        move_to(account, DeviceRegistry {
            devices: vector::empty(),
        });
    }

    /// Register a new device.
    ///
    /// SECURITY (H3): `owner_addr` is ALWAYS the authenticated transaction signer
    /// (the VM rebinds the leading `&signer` slot to the real sender via FIX #1
    /// bind_signer_args). There is NO ed25519 native available to Move here, so we
    /// cannot prove on-chain that the registrant controls device_pubkey's private
    /// key. To stop the front-running lock-out + reward-theft we therefore:
    ///   1. Scope the duplicate guard to (owner_addr, device_pubkey) so a
    ///      front-runner registering someone else's pubkey can no longer lock the
    ///      real owner out of registering it under their own address.
    ///   2. Trust the FEEDER SET to bind a physical device to an owner: only a
    ///      feeder-verified binding earns rewards (see add_verified_device +
    ///      distribute_reward).
    ///
    /// The registration is stored under the caller's own address, so it can
    /// neither grow a shared resource nor collide with anyone else's (see
    /// BOUNDS above).
    public entry fun register_device(
        account: &signer,
        device_pubkey: vector<u8>,
        device_type: u8
    ) acquires DeviceClaims {
        assert!(
            vector::length(&device_pubkey) == DEVICE_PUBKEY_BYTES,
            error::invalid_argument(EINVALID_DEVICE_PUBKEY)
        );
        let owner_addr = signer::address_of(account);
        if (!exists<DeviceClaims>(owner_addr)) {
            move_to(account, DeviceClaims { devices: vector::empty() });
        };
        let claims = borrow_global_mut<DeviceClaims>(owner_addr);

        // Duplicate guard scoped to (owner_addr, device_pubkey): an attacker
        // registering a victim's pubkey under the attacker address can NOT prevent
        // the victim from registering the same pubkey under the victim address.
        assert!(
            !claims_device(&claims.devices, &device_pubkey),
            error::already_exists(EDEVICE_ALREADY_REGISTERED)
        );
        assert!(
            vector::length(&claims.devices) < MAX_DEVICES_PER_OWNER,
            error::resource_exhausted(EOWNER_DEVICE_LIMIT)
        );

        vector::push_back(&mut claims.devices, DeviceClaim {
            device_pubkey,
            device_type,
        });
    }

    /// True when `devices` holds `device_pubkey`.
    fun claims_device(devices: &vector<DeviceClaim>, device_pubkey: &vector<u8>): bool {
        let len = vector::length(devices);
        let i = 0;
        while (i < len) {
            if (&vector::borrow(devices, i).device_pubkey == device_pubkey) {
                return true
            };
            i = i + 1;
        };
        false
    }

    /// The index of `device_pubkey` in the verified registry, if it is there.
    fun find_verified(devices: &vector<VerifiedDevice>, device_pubkey: &vector<u8>): (bool, u64) {
        let len = vector::length(devices);
        let i = 0;
        while (i < len) {
            if (&vector::borrow(devices, i).device_pubkey == device_pubkey) {
                return (true, i)
            };
            i = i + 1;
        };
        (false, 0)
    }

    /// FEEDER-GATED key-ownership binding.
    ///
    /// Because Move has no ed25519 native here, the feeder set (the same trust
    /// anchor that finalizes rewards in submit_vote) is the authority that
    /// confirms which registered owner truly controls a device. A feeder verifies
    /// the device's key-ownership proof OFF-CHAIN (device signs a challenge over
    /// its claimed owner address with its ed25519 key; the feeder verifies it with
    /// the real ed25519 verifier in Rust) and then marks exactly one
    /// (owner_addr, device_pubkey) registration verified. Only verified devices
    /// receive rewards.
    ///
    /// The owner must have registered the device. That is also what bounds a
    /// registry entry: every key in it passed register_device's length check.
    public entry fun add_verified_device(
        feeder: &signer,
        owner_addr: address,
        device_pubkey: vector<u8>
    ) acquires OracleConfig, DeviceClaims, DeviceRegistry {
        let feeder_addr = signer::address_of(feeder);
        let config = borrow_global<OracleConfig>(@0x1);
        assert!(
            vector::contains(&config.feeders, &feeder_addr),
            error::permission_denied(ENOT_AUTHORIZED)
        );
        assert!(
            exists<DeviceClaims>(owner_addr)
                && claims_device(&borrow_global<DeviceClaims>(owner_addr).devices, &device_pubkey),
            error::not_found(EDEVICE_NOT_REGISTERED)
        );

        let registry = borrow_global_mut<DeviceRegistry>(@0x1);
        let (found, idx) = find_verified(&registry.devices, &device_pubkey);
        if (found) {
            // Single verified owner per pubkey: a pubkey already verified for a
            // different owner cannot be re-bound here. Verifying the same owner
            // again changes nothing, so last_reward_epoch is kept.
            assert!(
                vector::borrow(&registry.devices, idx).owner_addr == owner_addr,
                error::permission_denied(ENOT_AUTHORIZED)
            );
            return
        };
        assert!(
            vector::length(&registry.devices) < MAX_VERIFIED_DEVICES,
            error::resource_exhausted(EREGISTRY_FULL)
        );
        vector::push_back(&mut registry.devices, VerifiedDevice {
            device_pubkey,
            owner_addr,
            last_reward_epoch: 0,
        });
    }

    /// Decentralization: Voting Logic
    struct Vote has store, drop {
        feeder: address,
        bqi_score: u64,
    }

    struct PendingProof has store {
        device_pubkey: vector<u8>,
        votes: vector<Vote>,
        status: u8, // 0: Pending, 1: Finalized
    }

    struct OracleConfig has key {
        feeders: vector<address>,
        threshold: u64, // e.g. 3 out of 5
        active_proofs: vector<PendingProof>,
    }

    /// Initialize Oracle Config (Decentralized)
    public fun init_oracle(account: &signer) {
        let feeders = vector::empty();
        // Add initial feeders (Validators)
        vector::push_back(&mut feeders, @0x1); 
        // In real world, we add more addresses here
        
        move_to(account, OracleConfig {
            feeders,
            threshold: 1, // Start with 1 for simplicity in Beta
            active_proofs: vector::empty(),
        });
    }

    /// Register a trusted feeder (Validator) - Governance Only
    public entry fun add_feeder(admin: &signer, new_feeder: address) acquires OracleConfig {
        assert!(signer::address_of(admin) == ORACLE_ADDRESS, error::permission_denied(ENOT_AUTHORIZED));
        let config = borrow_global_mut<OracleConfig>(@0x1);
        vector::push_back(&mut config.feeders, new_feeder);
        // AUDIT-#10: BFT-style threshold -- same formula as the chain's consensus
        // quorum ((N*2)/3 + 1) -- instead of the old N-of-N (threshold+1 per
        // feeder). N-of-N had ZERO fault tolerance: one offline feeder would halt
        // DePIN finalization forever. NOTE: with N=1 this is still 1 (a single
        // feeder can self-finalize) -- do NOT re-enable DEPIN_BPS in staking.move
        // until the feeder set is >= 4.
        let n = vector::length(&config.feeders);
        config.threshold = (n * 2) / 3 + 1;
    }

    /// Validator submits a vote for a device's breath quality
    public entry fun submit_vote(
        feeder: &signer,
        device_pubkey: vector<u8>,
        bqi_score: u64
    ) acquires OracleConfig, DeviceRegistry {
        let feeder_addr = signer::address_of(feeder);
        let config = borrow_global_mut<OracleConfig>(@0x1);
        
        // Verify feeder list
        let is_authorized = vector::contains(&config.feeders, &feeder_addr);
        assert!(is_authorized, error::permission_denied(ENOT_AUTHORIZED));

        // Find or Create Pending Proof (Simplified)
        // Note: Real implementation would use Table or Map. Vector scan for prototype.
        let len = vector::length(&config.active_proofs);
        let i = 0;
        let proof_idx = 999999;
        
        while (i < len) {
            let p = vector::borrow(&config.active_proofs, i);
            if (p.device_pubkey == device_pubkey && p.status == 0) {
                proof_idx = i;
                break
            };
            i = i + 1;
        };

        if (proof_idx == 999999) {
            // New Proof
            let votes = vector::empty();
            vector::push_back(&mut votes, Vote { feeder: feeder_addr, bqi_score });
            vector::push_back(&mut config.active_proofs, PendingProof {
                device_pubkey,
                votes,
                status: 0
            });
            proof_idx = vector::length(&config.active_proofs) - 1;
        } else {
            // Add vote to existing
            let p = vector::borrow_mut(&mut config.active_proofs, proof_idx);
            // Check double vote
            let v_len = vector::length(&p.votes);
            let j = 0;
            while (j < v_len) {
                let v = vector::borrow(&p.votes, j);
                assert!(v.feeder != feeder_addr, error::invalid_argument(4)); // 4 = ALREADY_VOTED
                j = j + 1;
            };
            vector::push_back(&mut p.votes, Vote { feeder: feeder_addr, bqi_score });
        };

        // Check Quorum
        let p = vector::borrow_mut(&mut config.active_proofs, proof_idx);
        if (vector::length(&p.votes) >= config.threshold) {
             // Consensus Reached!
             // Calculate Median Score (Simplified: Take Average)
             let total_score = 0;
             let k = 0;
             let count = vector::length(&p.votes);
             while (k < count) {
                 let v = vector::borrow(&p.votes, k);
                 total_score = total_score + v.bqi_score;
                 k = k + 1;
             };
             let final_score = total_score / count;

             // AUDIT-#10: PRUNE the finalized proof instead of leaving a
             // status=1 tombstone forever. Tombstones made active_proofs grow
             // without bound, and every vote linear-scans that vector -- gas per
             // vote grows until submit_vote OOG-halts DePIN (same class as the
             // AUDIT-#2 epoch OOG). swap_remove is O(1); PendingProof has no
             // drop ability, so destructure it. (`status` is now always 0 for
             // entries still in the vector; the field is kept for layout
             // stability.)
             let PendingProof { device_pubkey: _, votes: _, status: _ } =
                 vector::swap_remove(&mut config.active_proofs, proof_idx);

             // EXECUTE REWARD (per-device per-epoch rate limit inside).
             distribute_reward(device_pubkey, final_score);
        }
    }

    /// Internal function to distribute reward (Extracted from old submit_mining_proof)
    fun distribute_reward(device_pubkey: vector<u8>, bqi_score: u64) acquires DeviceRegistry {
        // AUDIT-#10: current staking epoch drives the per-device rate limit.
        let epoch = 0x1::staking::get_current_epoch();

        // Find device owner. SECURITY (H3): only a feeder-VERIFIED binding may be
        // paid, and the registry holds nothing else. An unverified (e.g.
        // front-run) registration lives only in its registrant's DeviceClaims, so
        // a pubkey squatted by an attacker who never passed feeder key-ownership
        // verification receives nothing.
        let registry = borrow_global_mut<DeviceRegistry>(@0x1);
        let (found, idx) = find_verified(&registry.devices, &device_pubkey);
        let owner = @0x0;

        // AUDIT-#10: pay a verified device AT MOST ONCE per epoch. Feeders can
        // re-finalize the same device arbitrarily often (each proof is fresh), so
        // without this a colluding feeder set could mint the DePIN reward every
        // block. `last_reward_epoch` = 0 means never paid; epoch starts at 1 once
        // the chain advances, so the first epoch's reward is allowed.
        if (found) {
            let dev = vector::borrow_mut(&mut registry.devices, idx);
            if (epoch <= dev.last_reward_epoch) {
                return
            };
            dev.last_reward_epoch = epoch;
            owner = dev.owner_addr;
        };

        if (found) {
            // V3.0: Device Rewards align with Tail Emission scale (0.36 AIN base)
            // AUDIT-#9 FIX: compute in u128. Previously `base_reward` was an
            // untyped literal inferred as u64 (multiplied by u64 bqi_score), so
            // 3.6e17 * bqi >= 52 overflowed u64 and ABORTED -- the whole upper
            // half [52,100] of the quality curve (incl. bqi=100) could never be
            // paid. u128 arithmetic removes the abort.
            let base_reward: u128 = 360000000000000000; // 0.36 AIN
            let reward_amount = (base_reward * (bqi_score as u128)) / 100;
            
            if (reward_amount > 0) {
                 // FIXED: Use Staking Module to mint (enforces Supply Cap)
                 let coins = 0x1::staking::mint_depin_reward((reward_amount as u128));
                 
                 // If cap reached, value is 0
                 if (coin::value(&coins) > 0) {
                     coin::deposit<AincoreCoin>(owner, coins);
                 } else {
                     coin::burn(coins); // Destroy empty coin
                 }
            }
        }
    }

    // Deprecated Single-Sig Entry (Kept for backward compatibility, but calls new logic if threshold=1)
    public entry fun submit_mining_proof(
        oracle: &signer,
        device_pubkey: vector<u8>,
        bqi_score: u64 
    ) acquires DeviceRegistry, OracleConfig {
        submit_vote(oracle, device_pubkey, bqi_score);
    }
}
