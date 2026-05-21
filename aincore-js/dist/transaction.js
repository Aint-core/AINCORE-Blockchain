"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = void 0;
const bcs_1 = require("./bcs");
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
class Transaction {
    constructor() {
        this.sender = '';
        this.inputObjects = [];
        this.payload = '';
        this.gasLimit = 10000;
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
    static createRegisterValidator(sender, stakeAmount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        const pkBytes = (0, bcs_1.hexToBytes)(sender.publicKey);
        tx.payload = systemCall('staking', 'join_validator_set', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsU128)(stakeAmount),
            (0, bcs_1.bcsVectorU8)(pkBytes),
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
     * Mint tokens (only token creator can mint)
     * Calls: 0x1::token_factory::mint(admin, token_id, to, amount)
     */
    static mintToken(sender, tokenId, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'mint', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)(new TextEncoder().encode(tokenId)),
            (0, bcs_1.bcsAddress)(to),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Burn tokens
     * Calls: 0x1::token_factory::burn(holder, token_id, amount)
     */
    static burnToken(sender, tokenId, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'burn', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)(new TextEncoder().encode(tokenId)),
            (0, bcs_1.bcsU128)(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Transfer tokens to another address
     * Calls: 0x1::token_factory::transfer(from, token_id, to, amount)
     */
    static transferToken(sender, tokenId, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'transfer', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsVectorU8)(new TextEncoder().encode(tokenId)),
            (0, bcs_1.bcsAddress)(to),
            (0, bcs_1.bcsU128)(amount),
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
     * Vote on a governance proposal
     * Calls: 0x1::governance::vote(voter, proposal_id, approve)
     */
    static vote(sender, proposalId, approve, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'vote', [], [
            (0, bcs_1.bcsAddress)(sender.address),
            (0, bcs_1.bcsU64)(BigInt(proposalId)),
            (0, bcs_1.bcsBool)(approve),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Execute a passed governance proposal (after timelock)
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
        // Include sender, chain ID, and sequence number in signature payload
        const message = `${this.chainId}:${this.sender}:${this.payload}:${this.sequenceNumber}`;
        this.signature = signer.sign(Buffer.from(message));
        this.publicKey = signer.publicKey;
    }
    /**
     * Set Paymaster details
     */
    setPaymaster(paymasterAddress, signature) {
        this.paymaster = paymasterAddress;
        this.paymasterSignature = signature;
    }
    /**
     * Sign the transaction as a Paymaster (Hardened payload)
     * Payload: PAYMASTER_AUTH:{chain_id}:{sender}:{payload}:{gas_limit}:{sequence_number}
     */
    signAsPaymaster(paymasterKeypair) {
        if (!this.chainId) {
            throw new Error('CRITICAL: Chain ID must be explicitly set to prevent replay attacks');
        }
        const message = `PAYMASTER_AUTH:${this.chainId}:${this.sender}:${this.payload}:${this.gasLimit}:${this.sequenceNumber}`;
        const signature = paymasterKeypair.sign(Buffer.from(message));
        this.setPaymaster(paymasterKeypair.address, signature);
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
