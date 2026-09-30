/// Delegation pools, the committee payout and the slash (G5 DL-1..DL-3, CM-1,
/// SL-1; docs/G5_ECONOMICS_CONTRACT.md, derivations and sources in
/// docs/research/delegation_pools.md).
///
/// A pool keeps aggregates only. Each delegator's positions and unbonding
/// tickets live at its own address, at most MAX_POSITIONS and MAX_TICKETS.
/// No operation reads another delegator's state or iterates a pool's
/// delegators, so every operation costs the same whatever a pool's size, and
/// no delegator population can make a payout or a slash run out of gas.
///
/// Principal is accounted in points: a position of p points is worth
/// p x C / P, and that price moves only when the pool is slashed. Rewards
/// are liquid, through a per-point counter rho (scaled by REWARD_SCALE) with
/// its remainder carried, so the pool is paid to the unit. Every conversion
/// rounds in the pool's favour (EIP-4626), and a payout from an escrow is
/// clamped to it, so flooring dust never makes anyone's operation abort.
///
/// The payout and the slash live here, not in `staking`, because each
/// touches both the validator's stake and its pool, and Move forbids
/// `staking` from calling `delegation`.
module 0x1::delegation {
    use std::signer;
    use std::vector;
    use std::error;
    use 0x1::coin::{Self, Coin};
    use 0x1::staking::{Self, AincoreCoin, Emission};
    use 0x1::chain;
    use 0x1::math;

    const EPOOL_NOT_FOUND: u64 = 1;
    const EAMOUNT_TOO_SMALL: u64 = 2;
    const ENO_POSITION: u64 = 3;
    const ENOTHING_MATURED: u64 = 4;
    const EINVALID_COMMISSION: u64 = 5;
    const EPOOL_EXISTS: u64 = 6;
    /// FIX #2: caller is not the system address (@0x1)
    const EUNAUTHORIZED: u64 = 7;
    /// FIX H1: slash basis points out of range (> 10000)
    const EINVALID_SLASH_BPS: u64 = 8;
    /// SL-1: a slashed pool takes no new delegation.
    const EPOOL_CLOSED: u64 = 9;
    /// DL-3: the account holds MAX_TICKETS unbonding tickets; withdraw first.
    const ETOO_MANY_TICKETS: u64 = 10;
    /// CM-1: an increase above MAX_COMMISSION_INCREASE
    const ECOMMISSION_INCREASE_TOO_LARGE: u64 = 11;
    /// DL-1: delegation goes to active validators only.
    const ENOT_VALIDATOR: u64 = 12;
    /// DL-3: the account holds MAX_POSITIONS positions.
    const ETOO_MANY_POSITIONS: u64 = 13;
    /// EM-2: committee members and weights of different lengths.
    const EINVALID_COMMITTEE: u64 = 14;
    /// CM-1: a matured increase no payout has charged yet; retry after the
    /// next payout (at most one reward period).
    const ECOMMISSION_UNSETTLED: u64 = 15;

    const MAX_BPS: u64 = 10000;
    /// The smallest delegation, undelegation and remaining position: 1 AIN.
    const MIN_DELEGATION: u128 = 1000000000000000000;
    /// Maximum commission: 30%
    const MAX_COMMISSION: u64 = 3000;
    /// G5 CM-1 (Delta c): the most one notice may raise the commission, in
    /// basis points. A delegator locked in by the unbonding period tolerates
    /// about (1 - c) x U / T before leaving pays (5.5 points for a one-year
    /// delegator); Aptos caps a change at 10 points.
    const MAX_COMMISSION_INCREASE: u64 = 500;
    /// DL-3: pools one account may delegate to at once.
    const MAX_POSITIONS: u64 = 8;
    /// DL-3: unbonding tickets one account may hold (Cosmos allows 7 per
    /// delegator and validator, Polkadot 32 per member). Per account, so no
    /// one can block another's undelegation.
    const MAX_TICKETS: u64 = 16;
    /// SL-1: slash events a pool keeps for its unpaid tickets. An event is
    /// dropped once every ticket it may cut is paid; past the bound the two
    /// oldest merge into one that cuts at least as much (never less).
    const MAX_SLASH_EVENTS: u64 = 8;
    /// DL-2: the reward counter's scale (Polkadot's RewardCounter, FixedU128).
    const REWARD_SCALE: u128 = 1000000000000000000;
    /// DL-2: a pool with fewer points takes no reward, which bounds each step
    /// of the counter by the reward itself (step <= reward x S / P + 1).
    const MIN_REWARD_POINTS: u128 = 1000000000000000000;
    /// EM-2: the largest committee weight, in whole AIN: all of MAX_SUPPLY.
    const MAX_WEIGHT: u128 = 150000000;
    /// EM-2 saturation clip (Cardano-k / Polkadot style): a member's payout
    /// weight is capped at total / SATURATION_DIVISOR. Flattens concentration
    /// for honest distributions; not sybil-proof (documented limitation).
    const SATURATION_DIVISOR: u128 = 50;

    /// SL-1: a slash recorded for the pool's unpaid tickets. It cuts a ticket
    /// created in `infraction_epoch` or later and before the slash
    /// (`ticket.slash_seq <= seq`) by `bps`, when the ticket is paid.
    /// `pending_tickets` counts the tickets that may still meet it.
    struct SlashEvent has store, copy, drop {
        seq: u64,
        infraction_epoch: u64,
        bps: u64,
        pending_tickets: u64,
    }

    /// A validator's pool, at its address. Fixed size.
    ///   principal == active_coins + unbonding_coins
    ///   rewards covers every position's claim, within flooring dust
    struct Pool has key {
        /// C: the bonded delegated principal.
        active_coins: u128,
        /// P: the points of all positions.
        active_points: u128,
        /// rho: rewards per point since the pool began, scaled by REWARD_SCALE.
        reward_counter: u128,
        /// kappa < P: the scaled remainder of the last reward step.
        reward_carry: u128,
        /// B: the nominal amount of the pool's unpaid tickets.
        unbonding_coins: u128,
        principal: Coin<AincoreCoin>,
        rewards: Coin<AincoreCoin>,
        /// Basis points. CM-1: the one pending increase (equal to
        /// commission_rate when none is pending) and the consensus time it
        /// takes effect.
        commission_rate: u64,
        pending_commission: u64,
        commission_effective_time: u64,
        /// SL-1: set by a slash, for good: no new delegation, no reward, no
        /// committee weight. Delegators leave through undelegation.
        closed: bool,
        /// Slashes applied, ever; a ticket records it at creation.
        slash_count: u64,
        ticket_count: u64,
        position_count: u64,
        slash_events: vector<SlashEvent>,
    }

    /// Points in one pool and the counter they were last paid at.
    struct Position has store {
        validator: address,
        points: u128,
        reward_snapshot: u128,
    }

    /// Unbonding principal (SL-2): unlocks at `unlock_time` in consensus
    /// time, and stays slashable (SL-1) until paid.
    struct Ticket has store {
        validator: address,
        amount: u128,
        created_epoch: u64,
        slash_seq: u64,
        unlock_time: u64,
    }

    /// A delegator's state, at its address.
    struct Book has key {
        positions: vector<Position>,
        tickets: vector<Ticket>,
    }

    /// A validator opens its pool.
    public entry fun enable_delegation(validator: &signer, commission_rate: u64) {
        let addr = signer::address_of(validator);
        assert!(commission_rate <= MAX_COMMISSION, error::invalid_argument(EINVALID_COMMISSION));
        assert!(!exists<Pool>(addr), error::already_exists(EPOOL_EXISTS));
        move_to(validator, Pool {
            active_coins: 0,
            active_points: 0,
            reward_counter: 0,
            reward_carry: 0,
            unbonding_coins: 0,
            principal: coin::mint<AincoreCoin>(0),
            rewards: coin::mint<AincoreCoin>(0),
            commission_rate,
            pending_commission: commission_rate,
            commission_effective_time: 0,
            closed: false,
            slash_count: 0,
            ticket_count: 0,
            position_count: 0,
            slash_events: vector::empty(),
        });
    }

    /// DL-2, DL-3: delegate `amount` to an active validator's open pool, for
    /// floor(amount x P / C) points. The position earns from the next payout
    /// and weighs the committee from the next epoch (DL-1).
    public entry fun delegate(
        delegator: &signer,
        validator_addr: address,
        amount: u128
    ) acquires Pool, Book {
        assert!(amount >= MIN_DELEGATION, error::invalid_argument(EAMOUNT_TOO_SMALL));
        assert!(exists<Pool>(validator_addr), error::not_found(EPOOL_NOT_FOUND));
        assert!(staking::is_validator(validator_addr), error::invalid_state(ENOT_VALIDATOR));
        let addr = signer::address_of(delegator);
        if (!exists<Book>(addr)) {
            move_to(delegator, Book { positions: vector::empty(), tickets: vector::empty() });
        };
        let pool = borrow_global_mut<Pool>(validator_addr);
        assert!(!pool.closed, error::invalid_state(EPOOL_CLOSED));
        let book = borrow_global_mut<Book>(addr);

        let (found, i) = position_index(&book.positions, validator_addr);
        if (found) {
            settle(pool, vector::borrow_mut(&mut book.positions, i), addr);
        } else {
            assert!(
                vector::length(&book.positions) < MAX_POSITIONS,
                error::resource_exhausted(ETOO_MANY_POSITIONS)
            );
            vector::push_back(&mut book.positions, Position {
                validator: validator_addr,
                points: 0,
                reward_snapshot: pool.reward_counter,
            });
            pool.position_count = pool.position_count + 1;
            i = vector::length(&book.positions) - 1;
        };

        // An open pool's price C / P never falls (only a slash lowers it,
        // and a slash closes the pool), so P <= C and an empty pool has C = 0.
        let points = if (pool.active_points == 0) {
            amount
        } else {
            math::mul_div_floor(amount, pool.active_points, pool.active_coins)
        };
        coin::merge(&mut pool.principal, coin::withdraw<AincoreCoin>(delegator, amount));
        pool.active_coins = pool.active_coins + amount;
        pool.active_points = pool.active_points + points;
        let position = vector::borrow_mut(&mut book.positions, i);
        position.points = position.points + points;
    }

    /// DL-3: undelegate `amount`. Burns ceil(amount x P / C) points and
    /// tickets floor(points x C / P) coins, unlocking at SL-2's time. A
    /// remainder below MIN_DELEGATION, or an amount at or above the
    /// position's value, exits in full.
    public entry fun undelegate(
        delegator: &signer,
        validator_addr: address,
        amount: u128
    ) acquires Pool, Book {
        let addr = signer::address_of(delegator);
        assert!(exists<Pool>(validator_addr), error::not_found(EPOOL_NOT_FOUND));
        assert!(exists<Book>(addr), error::not_found(ENO_POSITION));
        let pool = borrow_global_mut<Pool>(validator_addr);
        let book = borrow_global_mut<Book>(addr);
        let (found, i) = position_index(&book.positions, validator_addr);
        assert!(found, error::not_found(ENO_POSITION));
        settle(pool, vector::borrow_mut(&mut book.positions, i), addr);

        let held = vector::borrow(&book.positions, i).points;
        let (burn, coins_out) = if (pool.active_coins == 0) {
            // A pool slashed to nothing: the position is worth nothing.
            (held, 0)
        } else {
            let value = math::mul_div_floor(held, pool.active_coins, pool.active_points);
            let burn = if (amount >= value) {
                held
            } else {
                assert!(amount >= MIN_DELEGATION, error::invalid_argument(EAMOUNT_TOO_SMALL));
                let q = math::mul_div_ceil(amount, pool.active_points, pool.active_coins);
                let rest = math::mul_div_floor(held - q, pool.active_coins, pool.active_points);
                if (rest < MIN_DELEGATION) { held } else { q }
            };
            (burn, math::mul_div_floor(burn, pool.active_coins, pool.active_points))
        };
        if (coins_out > 0) {
            assert!(
                vector::length(&book.tickets) < MAX_TICKETS,
                error::resource_exhausted(ETOO_MANY_TICKETS)
            );
        };

        pool.active_points = pool.active_points - burn;
        pool.active_coins = pool.active_coins - coins_out;
        let position = vector::borrow_mut(&mut book.positions, i);
        position.points = position.points - burn;
        if (position.points == 0) {
            let Position { validator: _, points: _, reward_snapshot: _ } =
                vector::swap_remove(&mut book.positions, i);
            pool.position_count = pool.position_count - 1;
        };
        if (coins_out > 0) {
            pool.unbonding_coins = pool.unbonding_coins + coins_out;
            pool.ticket_count = pool.ticket_count + 1;
            vector::push_back(&mut book.tickets, Ticket {
                validator: validator_addr,
                amount: coins_out,
                created_epoch: current_epoch(),
                slash_seq: pool.slash_count,
                unlock_time: chain::unbonding_unlock_time(),
            });
        };
    }

    /// DL-3: pay the caller's matured tickets of this pool, each cut by the
    /// pool's slash events that reach it (SL-1).
    public entry fun withdraw_unbonded(
        delegator: &signer,
        validator_addr: address
    ) acquires Pool, Book {
        let addr = signer::address_of(delegator);
        assert!(exists<Book>(addr), error::not_found(ENOTHING_MATURED));
        let book = borrow_global_mut<Book>(addr);
        let now = chain::time();
        let paid = 0;
        let i = 0;
        while (i < vector::length(&book.tickets)) {
            let ticket = vector::borrow(&book.tickets, i);
            if (ticket.validator == validator_addr && ticket.unlock_time <= now) {
                let ticket = vector::remove(&mut book.tickets, i);
                pay_ticket(borrow_global_mut<Pool>(validator_addr), ticket, addr);
                paid = paid + 1;
            } else {
                i = i + 1;
            };
        };
        assert!(paid > 0, error::invalid_state(ENOTHING_MATURED));
    }

    /// DL-2: claim this pool's rewards without undelegating.
    public entry fun claim_rewards(
        delegator: &signer,
        validator_addr: address
    ) acquires Pool, Book {
        let addr = signer::address_of(delegator);
        assert!(exists<Pool>(validator_addr), error::not_found(EPOOL_NOT_FOUND));
        assert!(exists<Book>(addr), error::not_found(ENO_POSITION));
        let book = borrow_global_mut<Book>(addr);
        let (found, i) = position_index(&book.positions, validator_addr);
        assert!(found, error::not_found(ENO_POSITION));
        settle(
            borrow_global_mut<Pool>(validator_addr),
            vector::borrow_mut(&mut book.positions, i),
            addr
        );
    }

    /// G5 CM-1: announce a commission change. A decrease (or no change) takes
    /// effect at once and cancels any pending increase. An increase may raise
    /// the rate in force by at most MAX_COMMISSION_INCREASE, and takes effect
    /// `chain::commission_notice_secs` later, fixed now. A new announcement
    /// replaces a pending one.
    public entry fun update_commission(
        validator: &signer,
        new_commission: u64
    ) acquires Pool {
        let addr = signer::address_of(validator);
        assert!(new_commission <= MAX_COMMISSION, error::invalid_argument(EINVALID_COMMISSION));
        assert!(exists<Pool>(addr), error::not_found(EPOOL_NOT_FOUND));
        let pool = borrow_global_mut<Pool>(addr);
        let now = chain::time();
        let in_force = commission_at(pool, now);
        if (in_force != pool.commission_rate) {
            // A matured increase becomes the base rate once no payout can
            // still charge a period that began before it took effect (the
            // next payout's period begins at the last one). Until then, at
            // most one reward period, a change may not exceed the base rate,
            // so no increase is ever retroactive.
            if (staking::last_reward_time() >= pool.commission_effective_time) {
                pool.commission_rate = in_force;
            } else {
                assert!(
                    new_commission <= pool.commission_rate,
                    error::invalid_state(ECOMMISSION_UNSETTLED)
                );
            };
        };
        if (new_commission <= in_force) {
            pool.commission_rate = new_commission;
            pool.pending_commission = new_commission;
            pool.commission_effective_time = 0;
        } else {
            assert!(
                new_commission - in_force <= MAX_COMMISSION_INCREASE,
                error::invalid_argument(ECOMMISSION_INCREASE_TOO_LARGE)
            );
            pool.pending_commission = new_commission;
            pool.commission_effective_time = now + chain::commission_notice_secs();
        }
    }

    /// G5 EM-1, EM-2, DL-2: pay the emission for the consensus time since the
    /// last payout to `members`, the committee of this block's epoch (never
    /// the live set, jailed members already removed by the executor), with
    /// each member's frozen split: `self_weights` and `delegated_weights` in
    /// whole AIN, from the committee record. System-only: the executor binds
    /// the genuine @0x1 signer and never lets a user forge it (FIX #1).
    ///
    /// A member's share r of the pot (by saturation-clipped weight) splits
    /// into floor(r x s / (s + d)) for its own stake and floor(r x d / (s + d))
    /// for its pool; the commission, at the rate in force when the period
    /// began, is taken from the pool's part. Nothing beyond the drawn
    /// emission can be paid, and what is not paid (flooring dust, a member
    /// without a coin store, a pool that cannot take rewards) stays in the
    /// reserve (`staking::Emission`).
    public entry fun pay_rewards(
        account: &signer,
        members: vector<address>,
        self_weights: vector<u64>,
        delegated_weights: vector<u64>,
    ) acquires Pool {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(EUNAUTHORIZED));
        let len = vector::length(&members);
        assert!(
            vector::length(&self_weights) == len && vector::length(&delegated_weights) == len,
            error::invalid_argument(EINVALID_COMMITTEE)
        );
        let (emission, period_start) = staking::draw_emission(account);
        let pot = staking::emission_value(&emission);
        if (len == 0 || pot == 0) {
            staking::close_emission(emission);
            return
        };

        // The pot is FIXED; members divide it by clipped weight. Adding
        // members thins the slices; it cannot enlarge the pot.
        let total = 0u128;
        let k = 0;
        while (k < len) {
            total = total + member_weight(&self_weights, &delegated_weights, k);
            k = k + 1;
        };
        if (total == 0) {
            staking::close_emission(emission);
            return
        };
        // Saturation point: weight above z0 earns nothing more.
        let z0 = total / SATURATION_DIVISOR;
        if (z0 == 0) {
            z0 = total;
        };
        let clipped_total = 0u128;
        let k = 0;
        while (k < len) {
            let w = member_weight(&self_weights, &delegated_weights, k);
            clipped_total = clipped_total + (if (w > z0) { z0 } else { w });
            k = k + 1;
        };

        let i = 0;
        while (i < len) {
            let w = member_weight(&self_weights, &delegated_weights, i);
            let clipped = if (w > z0) { z0 } else { w };
            let share = math::mul_div_floor(pot, clipped, clipped_total);
            pay_member(
                &mut emission,
                *vector::borrow(&members, i),
                share,
                (*vector::borrow(&self_weights, i) as u128),
                (*vector::borrow(&delegated_weights, i) as u128),
                period_start,
            );
            i = i + 1;
        };
        staking::close_emission(emission);
    }

    /// G5 SL-1: slash a validator's own stake and its pool by `bps`, for an
    /// infraction in `infraction_epoch`, in one call so neither half can land
    /// alone. The pool's active principal is cut at once, rounded up; its
    /// unpaid tickets are cut when paid, through the recorded event. The pool
    /// closes for good. The work is constant whatever the pool's size.
    /// System-only (FIX #1 binds the genuine @0x1 signer).
    public entry fun slash(
        account: &signer,
        validator_addr: address,
        bps: u64,
        infraction_epoch: u64
    ) acquires Pool {
        assert!(signer::address_of(account) == @0x1, error::permission_denied(EUNAUTHORIZED));
        assert!(bps <= MAX_BPS, error::invalid_argument(EINVALID_SLASH_BPS));
        staking::slash_validator_bps(account, validator_addr, bps);
        if (bps == 0 || !exists<Pool>(validator_addr)) {
            return
        };
        let pool = borrow_global_mut<Pool>(validator_addr);
        pool.closed = true;
        let cut = math::mul_div_ceil(pool.active_coins, (bps as u128), (MAX_BPS as u128));
        if (cut > 0) {
            pool.active_coins = pool.active_coins - cut;
            staking::burn_ain(coin::extract(&mut pool.principal, cut));
        };
        // Only tickets that exist now can be reached by this slash.
        if (pool.ticket_count > 0) {
            if (vector::length(&pool.slash_events) == MAX_SLASH_EVENTS) {
                // Merge the two oldest into one that cuts, for every ticket
                // either would reach, at least as much as both: the earlier
                // epoch, the later sequence, and the compounded fraction with
                // its kept part rounded down. Never an under-slash.
                let first = vector::remove(&mut pool.slash_events, 0);
                let second = vector::borrow_mut(&mut pool.slash_events, 0);
                if (first.infraction_epoch < second.infraction_epoch) {
                    second.infraction_epoch = first.infraction_epoch;
                };
                let kept = ((MAX_BPS - first.bps) as u128) * ((MAX_BPS - second.bps) as u128)
                    / (MAX_BPS as u128);
                second.bps = MAX_BPS - (kept as u64);
            };
            vector::push_back(&mut pool.slash_events, SlashEvent {
                seq: pool.slash_count,
                infraction_epoch,
                bps,
                pending_tickets: pool.ticket_count,
            });
        };
        pool.slash_count = pool.slash_count + 1;
    }

    /// DL-2: pay a position floor(points x (rho - snapshot) / S), clamped to
    /// the reward escrow (flooring dust never aborts a claim), and restart it
    /// at the current counter.
    fun settle(pool: &mut Pool, position: &mut Position, owner: address) {
        let owed = math::mul_div_floor(
            position.points,
            pool.reward_counter - position.reward_snapshot,
            REWARD_SCALE
        );
        position.reward_snapshot = pool.reward_counter;
        let held = coin::value(&pool.rewards);
        if (owed > held) {
            owed = held;
        };
        if (owed > 0) {
            coin::deposit<AincoreCoin>(owner, coin::extract(&mut pool.rewards, owed));
        };
    }

    /// DL-3, SL-1: pay one ticket from the principal escrow, less every
    /// recorded slash that reaches it: made in its creation epoch or later,
    /// and after it was created. The slashed part is burned.
    fun pay_ticket(pool: &mut Pool, ticket: Ticket, owner: address) {
        let Ticket { validator: _, amount, created_epoch, slash_seq, unlock_time: _ } = ticket;
        let paid = amount;
        let i = 0;
        let n = vector::length(&pool.slash_events);
        while (i < n) {
            let event = vector::borrow_mut(&mut pool.slash_events, i);
            if (slash_seq <= event.seq) {
                event.pending_tickets = event.pending_tickets - 1;
                if (created_epoch >= event.infraction_epoch) {
                    paid = math::mul_div_floor(
                        paid,
                        ((MAX_BPS - event.bps) as u128),
                        (MAX_BPS as u128)
                    );
                };
            };
            i = i + 1;
        };
        // Drop the events no unpaid ticket can meet any more.
        let i = 0;
        while (i < vector::length(&pool.slash_events)) {
            if (vector::borrow(&pool.slash_events, i).pending_tickets == 0) {
                vector::remove(&mut pool.slash_events, i);
            } else {
                i = i + 1;
            };
        };
        pool.unbonding_coins = pool.unbonding_coins - amount;
        pool.ticket_count = pool.ticket_count - 1;
        let coins = coin::extract(&mut pool.principal, amount);
        if (paid < amount) {
            staking::burn_ain(coin::extract(&mut coins, amount - paid));
        };
        coin::deposit<AincoreCoin>(owner, coins);
    }

    /// EM-2, DL-2: pay one committee member its `share` of the emission. Its
    /// own part and the commission go to its coin store; the rest goes to
    /// its pool's reward counter, with the remainder carried.
    fun pay_member(
        emission: &mut Emission,
        member: address,
        share: u128,
        self_weight: u128,
        delegated_weight: u128,
        period_start: u64,
    ) acquires Pool {
        if (share == 0) {
            return
        };
        let weight = self_weight + delegated_weight;
        let to_validator = math::mul_div_floor(share, self_weight, weight);
        let delegated = math::mul_div_floor(share, delegated_weight, weight);
        if (delegated > 0 && exists<Pool>(member)) {
            let pool = borrow_global_mut<Pool>(member);
            if (!pool.closed && pool.active_points >= MIN_REWARD_POINTS) {
                let commission = delegated * (commission_at(pool, period_start) as u128)
                    / (MAX_BPS as u128);
                to_validator = to_validator + commission;
                let reward = delegated - commission;
                let (step, carry) = math::mul_add_div(
                    reward,
                    REWARD_SCALE,
                    pool.reward_carry,
                    pool.active_points
                );
                pool.reward_counter = pool.reward_counter + step;
                pool.reward_carry = carry;
                coin::merge(&mut pool.rewards, staking::take_emission(emission, reward));
            };
        };
        // Liquid, never compounded automatically; restaking is opt-in.
        if (to_validator > 0 && coin::has_store<AincoreCoin>(member)) {
            coin::deposit<AincoreCoin>(member, staking::take_emission(emission, to_validator));
        };
    }

    /// A member's committee weight (its own and its pool's stake), bounded
    /// so the pot arithmetic cannot overflow whatever the executor passes.
    fun member_weight(self_weights: &vector<u64>, delegated_weights: &vector<u64>, i: u64): u128 {
        let w = (*vector::borrow(self_weights, i) as u128)
            + (*vector::borrow(delegated_weights, i) as u128);
        if (w > MAX_WEIGHT) { MAX_WEIGHT } else { w }
    }

    /// CM-1: the commission in force at consensus time `time`.
    fun commission_at(pool: &Pool, time: u64): u64 {
        if (pool.pending_commission != pool.commission_rate
            && time >= pool.commission_effective_time) {
            pool.pending_commission
        } else {
            pool.commission_rate
        }
    }

    /// The committee epoch of the executing block, E(h) = (h - 1) / I (G1).
    /// Read from the clock, not `staking.current_epoch`, which advances in a
    /// transaction that can abort (FX-14).
    fun current_epoch(): u64 {
        let height = chain::height();
        if (height == 0) { 0 } else { (height - 1) / chain::epoch_blocks() }
    }

    fun position_index(positions: &vector<Position>, validator: address): (bool, u64) {
        let len = vector::length(positions);
        let i = 0;
        while (i < len) {
            if (vector::borrow(positions, i).validator == validator) {
                return (true, i)
            };
            i = i + 1;
        };
        (false, 0)
    }

    /// View: a delegator's position in a pool, (value, unclaimed rewards).
    #[view]
    public fun get_delegation(delegator: address, validator_addr: address): (u128, u128)
        acquires Pool, Book
    {
        if (!exists<Pool>(validator_addr) || !exists<Book>(delegator)) {
            return (0, 0)
        };
        let pool = borrow_global<Pool>(validator_addr);
        let book = borrow_global<Book>(delegator);
        let (found, i) = position_index(&book.positions, validator_addr);
        if (!found) {
            return (0, 0)
        };
        let position = vector::borrow(&book.positions, i);
        let value = if (pool.active_points == 0) {
            0
        } else {
            math::mul_div_floor(position.points, pool.active_coins, pool.active_points)
        };
        let owed = math::mul_div_floor(
            position.points,
            pool.reward_counter - position.reward_snapshot,
            REWARD_SCALE
        );
        let held = coin::value(&pool.rewards);
        (value, if (owed > held) { held } else { owed })
    }

    /// View: a pool's (bonded principal, commission in force, positions).
    #[view]
    public fun get_pool_info(validator_addr: address): (u128, u64, u64) acquires Pool {
        if (!exists<Pool>(validator_addr)) {
            return (0, 0, 0)
        };
        let pool = borrow_global<Pool>(validator_addr);
        (pool.active_coins, commission_at(pool, chain::time()), pool.position_count)
    }
}
