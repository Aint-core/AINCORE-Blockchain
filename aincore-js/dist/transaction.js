"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = exports.BYTE_GAS = void 0;
exports.tokenIdOf = tokenIdOf;
const crypto_1 = require("crypto");
const address_1 = require("./address");
const bcs_1 = require("./bcs");
/**
 * A token_factory token's id: its symbol's bytes followed by its creator's
 * 32 address bytes, as hex (the form the token methods take). The id holds
 * raw address bytes, so it is not text: passing it as a UTF-8 string, as
 * these methods once did, sent different bytes.
 */
function tokenIdOf(symbol, creator) {
    return (0, bcs_1.bytesToHex)(new TextEncoder().encode(symbol)) + (0, address_1.toHexAddress)(creator);
}
// ============================================================
// Helper: Build a standard 0x1 entry function call
// ============================================================
function systemCall(moduleName, functionName, tyArgs, args) {
    const call = {
        module: { address: bcs_1.SYSTEM_ADDRESS, name: moduleName },
        function: functionName,
        tyArgs,
        args,
    };
    const payload = { kind: 'EntryFunction', call };
    const bytes = (0, bcs_1.serializeTransactionPayload)(payload);
    return (0, bcs_1.bytesToHex)(bytes);
}
// ============================================================
// Transaction Class
// ============================================================
/** B14: gas per byte of the signed transaction JSON, as the node charges it. */
exports.BYTE_GAS = 400;
class Transaction {
    constructor() {
        this.sender = '';
        this.inputObjects = [];
        this.payload = '';
        this.gasLimit = 0;
        this.executionGas = 10000;
        // At least the node's base fee (B15): `Number(await connection.getGasPrice())`.
        this.gasPrice = 1;
        this.sequenceNumber = 0;
        this.publicKey = '';
        this.signature = '';
        this.chainId = '';
    }
    // ============ CORE METHODS ============
    /**
     * Create a transfer transaction (AIN native coin)
     * Calls: 0x1::coin::transfer<0x1::staking::AincoreCoin>
     */
    static createTransfer(sender, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('coin', 'transfer', [bcs_1.AINCORE_COIN_TYPE], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(to),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Create a Move smart contract publication
     * Uses: TransactionPayload::PublishModule
     */
    static createPublish(sender, bytecodeHex, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        const bytes = (0, bcs_1.hexToBytes)(bytecodeHex);
        const payload = { kind: 'PublishModule', modules: [bytes] };
        tx.payload = (0, bcs_1.bytesToHex)((0, bcs_1.serializeTransactionPayload)(payload));
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Create a generic Move entry function call
     * This is the universal builder — all specialized methods use this internally
     */
    static createMoveCall(sender, moduleName, functionName, tyArgs, args, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall(moduleName, functionName, tyArgs, args);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ DePIN METHODS ============
    /**
     * Create a DePIN proof submission transaction
     * Calls: 0x1::universal_mining::submit_mining_proof(oracle, device_pubkey, bqi_score)
     */
    static createDePINProof(sender, deviceId, bqi, sequenceNumber = 0) {
        if (bqi < 0 || bqi > 100) {
            throw new Error('BQI must be between 0 and 100');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        const deviceBytes = (0, bcs_1.hexToBytes)(deviceId);
        tx.payload = systemCall('universal_mining', 'submit_mining_proof', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)(deviceBytes),
            (0, bcs_1.bcsU64)(BigInt(bqi)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ STAKING METHODS ============
    /**
     * Register as a validator
     * Calls: 0x1::staking::join_validator_set(account, stake_amount, public_key)
     */
    /// 0x1::staking::join_validator_set takes FIVE args: account, stake,
    /// public_key, bls_public_key, bls_pop. The old helper sent only three and
    /// the node rejected every call with NUMBER_OF_ARGUMENTS_MISMATCH. The BLS
    /// proof-of-possession cannot be produced by this SDK (no BLS12-381 signing),
    /// so blsPublicKey (48 bytes) and blsPop (96 bytes) must be obtained
    /// out-of-band from the node keygen and passed in; there is no safe default.
    static createRegisterValidator(sender, stakeAmount, blsPublicKey, blsPop, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        const pkBytes = (0, bcs_1.hexToBytes)(sender.publicKey);
        tx.payload = systemCall('staking', 'join_validator_set', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsU128)(stakeAmount),
            (0, bcs_1.bcsVectorU8)(pkBytes),
            (0, bcs_1.bcsVectorU8)(blsPublicKey),
            (0, bcs_1.bcsVectorU8)(blsPop),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ DELEGATION METHODS ============
    /**
     * Delegate tokens to a validator
     * Calls: 0x1::delegation::delegate(delegator, validator_addr, amount)
     */
    static createDelegate(sender, validatorAddress, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'delegate', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(validatorAddress),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Undelegate tokens from a validator (starts 21-day unbonding)
     * Calls: 0x1::delegation::undelegate(delegator, validator_addr, amount)
     */
    static createUndelegate(sender, validatorAddress, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'undelegate', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(validatorAddress),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Claim delegation rewards from a validator
     * Calls: 0x1::delegation::claim_rewards(delegator, validator_addr)
     */
    static createClaimRewards(sender, validatorAddress, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'claim_rewards', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(validatorAddress),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Withdraw unbonded tokens (after 21-day unbonding period)
     * Calls: 0x1::delegation::withdraw_unbonded(delegator, validator_addr)
     */
    static createWithdrawUnbonded(sender, validatorAddress, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'withdraw_unbonded', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(validatorAddress),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Enable delegation for a validator (validator only)
     * Calls: 0x1::delegation::enable_delegation(validator, commission_rate)
     */
    static createEnableDelegation(sender, commissionRate, sequenceNumber = 0) {
        if (commissionRate < 0 || commissionRate > 3000) {
            throw new Error('Commission rate must be between 0 and 3000 basis points (0-30%)');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'enable_delegation', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsU64)(BigInt(commissionRate)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ TOKEN FACTORY METHODS ============
    /**
     * Create a new token
     * Calls: 0x1::token_factory::create_token(creator, name, symbol, decimals, max_supply, initial_supply, icon_url, project_url)
     */
    static createToken(sender, name, symbol, decimals, maxSupply, initialSupply, iconUrl, projectUrl, sequenceNumber = 0) {
        if (decimals < 0 || decimals > 18) {
            throw new Error('Decimals must be between 0 and 18');
        }
        if (initialSupply > maxSupply) {
            throw new Error('Initial supply cannot exceed max supply');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'create_token', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsString)(name),
            (0, bcs_1.bcsString)(symbol),
            (0, bcs_1.bcsU8)(decimals),
            (0, bcs_1.bcsU128)(maxSupply),
            (0, bcs_1.bcsU128)(initialSupply),
            (0, bcs_1.bcsString)(iconUrl),
            (0, bcs_1.bcsString)(projectUrl),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Mint tokens (only token creator can mint). `tokenId` is hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::mint(admin, token_id, to, amount)
     */
    static mintToken(sender, tokenId, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'mint', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)((0, bcs_1.hexToBytes)(tokenId)),
            (0, bcs_1.bcsAddress)(to),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Burn tokens. `creator` names the token's registry (B135); `tokenId` is
     * hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::burn(holder, creator, token_id, amount)
     */
    static burnToken(sender, creator, tokenId, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'burn', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)((0, address_1.toHexAddress)(creator)),
            (0, bcs_1.bcsVectorU8)((0, bcs_1.hexToBytes)(tokenId)),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Transfer tokens to another address (which must have registered the
     * token, `registerToken`). `tokenId` is hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::transfer(from, token_id, to, amount)
     */
    static transferToken(sender, tokenId, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'transfer', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)((0, bcs_1.hexToBytes)(tokenId)),
            (0, bcs_1.bcsAddress)(to),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Register a token in the sender's wallet (made if missing), so it can
     * receive it (B135: a wallet takes only tokens its owner registered).
     * `tokenId` is hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::register(account, token_id)
     */
    static registerToken(sender, tokenId, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'register', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)((0, bcs_1.hexToBytes)(tokenId)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Initialize token wallet (required before receiving custom tokens)
     * Calls: 0x1::token_factory::init_wallet(account)
     */
    static initTokenWallet(sender, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'init_wallet', [], [
            (0, bcs_1.bcsAddress)(sender.address),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ NATIVE DEX METHODS ============
    /**
     * Create a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::create_pool<X, Y>(creator)
     */
    static createDexPool(sender, tokenX, tokenY, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'create_pool', [tokenX, tokenY], [
            (0, bcs_1.bcsAddress)(sender.address),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Add liquidity to an existing AINCORE CPMM pool.
     * Calls: 0x1::dex::add_liquidity<X, Y>(provider, pool_addr, amount_x, amount_y, min_lp)
     */
    static addDexLiquidity(sender, poolAddress, tokenX, tokenY, amountX, amountY, minLp, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'add_liquidity', [tokenX, tokenY], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(poolAddress),
            (0, bcs_1.bcsU128)(amountX),
            (0, bcs_1.bcsU128)(amountY),
            (0, bcs_1.bcsU128)(minLp),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Remove liquidity from an existing AINCORE CPMM pool.
     * Calls: 0x1::dex::remove_liquidity<X, Y>(provider, pool_addr, lp_amount, min_x, min_y)
     */
    static removeDexLiquidity(sender, poolAddress, tokenX, tokenY, lpAmount, minX, minY, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'remove_liquidity', [tokenX, tokenY], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(poolAddress),
            (0, bcs_1.bcsU128)(lpAmount),
            (0, bcs_1.bcsU128)(minX),
            (0, bcs_1.bcsU128)(minY),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Swap token X to token Y through a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::swap_x_to_y<X, Y>(trader, pool_addr, amount_x_in, min_y_out)
     */
    static createDexSwapXToY(sender, poolAddress, tokenX, tokenY, amountXIn, minYOut, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'swap_x_to_y', [tokenX, tokenY], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(poolAddress),
            (0, bcs_1.bcsU128)(amountXIn),
            (0, bcs_1.bcsU128)(minYOut),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Swap token Y to token X through a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::swap_y_to_x<X, Y>(trader, pool_addr, amount_y_in, min_x_out)
     */
    static createDexSwapYToX(sender, poolAddress, tokenX, tokenY, amountYIn, minXOut, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'swap_y_to_x', [tokenX, tokenY], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsAddress)(poolAddress),
            (0, bcs_1.bcsU128)(amountYIn),
            (0, bcs_1.bcsU128)(minXOut),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ GOVERNANCE METHODS ============
    /**
     * Create a governance proposal
     * Calls: 0x1::governance::create_proposal(proposer, description, action_type, action_value)
     */
    static createProposal(sender, description, actionType, actionValue, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'create_proposal', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsString)(description),
            (0, bcs_1.bcsU8)(actionType),
            (0, bcs_1.bcsU64)(BigInt(actionValue)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Vote on a governance proposal with `amount` quanta of AIN, locked
     * until its voting ends (B71); `claimVoteTokens` takes it back after.
     * Calls: 0x1::governance::vote(voter, proposal_id, approve, amount)
     */
    static vote(sender, proposalId, approve, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'vote', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsU64)(BigInt(proposalId)),
            (0, bcs_1.bcsBool)(approve),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Resolve a passed governance proposal once its voting has ended (a
     * signal: it records the outcome).
     * Calls: 0x1::governance::execute_proposal(executor, proposal_id)
     */
    static executeProposal(sender, proposalId, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'execute_proposal', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsU64)(BigInt(proposalId)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Take back the AIN of every vote whose proposal's voting has ended,
     * whatever the outcome (B71).
     * Calls: 0x1::governance::claim_vote_tokens(voter)
     */
    static claimVoteTokens(sender, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'claim_vote_tokens', [], [
            (0, bcs_1.bcsAddress)(sender.address),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ TRANSACTION LIFECYCLE ============
    /**
     * Set Chain ID (e.g. for Testnet)
     */
    setChainId(chainId) {
        this.chainId = chainId;
    }
    /**
     * Sign the transaction
     */
    sign(signer) {
        if (signer.address !== this.sender) {
            throw new Error('Signer does not match sender');
        }
        if (!this.chainId) {
            throw new Error('CRITICAL: Chain ID must be explicitly set to prevent replay attacks');
        }
        // Must match the node byte for byte. Both the mempool gate
        // (core/mempool/src/lib.rs) and the executor's re-verify
        // (core/executor/src/lib.rs) rebuild:
        //   chain_id:sender:payload:sequence_number:gas_limit:gas_price:input_objects
        // where input_objects is Rust's Vec<String>::join(","), so an empty list
        // yields the empty string and the message ends with a bare trailing colon.
        //
        // This used to sign only the first four fields. Everything built on it
        // produced signatures the node rejects, because gas_limit, gas_price and
        // input_objects are bound into the signature (F4) -- leaving them out is
        // both a malleability hole and, in practice, a total submit failure.
        // B14: the limit covers the signed JSON's own bytes. Measure it with
        // placeholders of the final sizes (the key, an Ed25519 signature and,
        // when a paymaster is set first, its signature), gas_limit 0, and 20
        // bytes of slack for the limit's own digits.
        this.publicKey = signer.publicKey;
        this.gasLimit = 0;
        this.signature = '0'.repeat(128);
        const pending = this.paymaster !== undefined && this.paymasterSignature === undefined;
        if (pending)
            this.paymasterSignature = '0'.repeat(128);
        const unsized = Buffer.byteLength(this.toString());
        if (pending)
            this.paymasterSignature = undefined;
        this.gasLimit = this.executionGas + exports.BYTE_GAS * (unsized + 20);
        this.signature = signer.sign(Buffer.from(this.signingMessage()));
    }
    /**
     * B65: the transaction as `aincore_estimateGas` takes it before signing:
     * the sender's key, zero signatures of the final length, gas_limit 0.
     */
    estimateDraft(publicKey) {
        const draft = JSON.parse(this.toString());
        draft.public_key = publicKey;
        draft.signature = '0'.repeat(128);
        draft.gas_limit = 0;
        if (this.paymaster !== undefined && this.paymasterSignature === undefined) {
            draft.paymaster_signature = '0'.repeat(128);
        }
        return draft;
    }
    /**
     * The seven fields the sender signs (F4), as the node rebuilds them, and
     * for a sponsored transaction an eighth, the paymaster's public key
     * (B73: a relay could otherwise strip the paymaster and make the sender
     * pay). Name the paymaster with `setPaymasterKey` before `sign`.
     */
    signingMessage() {
        const fields = [
            this.chainId,
            this.sender,
            this.payload,
            this.sequenceNumber,
            this.gasLimit,
            this.gasPrice,
            this.inputObjects.join(','),
        ];
        // B106: the same condition as `toString`, so an empty paymaster is
        // neither signed nor sent.
        if (this.paymaster)
            fields.push(this.paymaster);
        return fields.join(':');
    }
    /**
     * Set Paymaster details: the paymaster's PUBLIC KEY (hex) and its
     * signature. The node pays gas from the address derived from that key
     * (B13).
     */
    setPaymaster(paymasterPublicKey, signature) {
        this.paymaster = paymasterPublicKey;
        this.paymasterSignature = signature;
    }
    /**
     * Sign the transaction as a Paymaster. The signed bytes are
     * SHA-256("PAYMASTER_AUTH_V2:" + the sender's signing message), so the
     * paymaster binds every field the sender does, the gas price included
     * (`executor::admission::paymaster_message`, B28).
     */
    /**
     * Name the paymaster before the sender signs, so `sign` counts its
     * signature's bytes in the gas limit; `signAsPaymaster` signs after.
     */
    setPaymasterKey(paymasterPublicKey) {
        this.paymaster = paymasterPublicKey;
        this.paymasterSignature = undefined;
    }
    signAsPaymaster(paymasterKeypair) {
        if (!this.chainId) {
            throw new Error('CRITICAL: Chain ID must be explicitly set to prevent replay attacks');
        }
        const message = `PAYMASTER_AUTH_V2:${this.signingMessage()}`;
        const digest = (0, crypto_1.createHash)('sha256').update(message).digest();
        const signature = paymasterKeypair.sign(digest);
        this.setPaymaster(paymasterKeypair.publicKey, signature);
    }
    /**
     * Convert to JSON string for API
     */
    toString() {
        const json = {
            chain_id: this.chainId,
            sender: this.sender,
            input_objects: this.inputObjects,
            payload: this.payload,
            gas_limit: this.gasLimit,
            gas_price: this.gasPrice,
            sequence_number: this.sequenceNumber,
            public_key: this.publicKey,
            signature: this.signature,
        };
        if (this.paymaster) {
            json.paymaster = this.paymaster;
            json.paymaster_signature = this.paymasterSignature;
        }
        return JSON.stringify(json);
    }
}
exports.Transaction = Transaction;
