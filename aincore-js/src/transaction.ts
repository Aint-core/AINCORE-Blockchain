import { Keypair } from './keypair';
import {
    serializeTransactionPayload,
    TransactionPayload,
    EntryFunctionCall,
    TypeTag,
    SYSTEM_ADDRESS,
    AINCORE_COIN_TYPE,
    bcsAddress,
    bcsU64,
    bcsU128,
    bcsU8,
    bcsBool,
    bcsString,
    bcsVectorU8,
    hexToBytes,
    bytesToHex,
} from './bcs';

// ============================================================
// Helper: Build a standard 0x1 entry function call
// ============================================================

function systemCall(
    moduleName: string,
    functionName: string,
    tyArgs: TypeTag[],
    args: Uint8Array[]
): string {
    const call: EntryFunctionCall = {
        module: { address: SYSTEM_ADDRESS, name: moduleName },
        function: functionName,
        tyArgs,
        args,
    };
    const payload: TransactionPayload = { kind: 'EntryFunction', call };
    const bytes = serializeTransactionPayload(payload);
    return bytesToHex(bytes);
}

// ============================================================
// Transaction Class
// ============================================================

export class Transaction {
    sender: string;
    inputObjects: string[];
    payload: string;
    gasLimit: number;
    gasPrice: number;
    sequenceNumber: number;
    publicKey: string;
    signature: string;
    chainId: string;
    paymaster?: string;
    paymasterSignature?: string;

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
    static createTransfer(sender: Keypair, to: string, amount: bigint, sequenceNumber: number = 0): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('coin', 'transfer', [AINCORE_COIN_TYPE], [
            bcsAddress(sender.address),
            bcsAddress(to),
            bcsU128(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Create a Move smart contract publication
     * Uses: TransactionPayload::PublishModule
     */
    static createPublish(sender: Keypair, bytecodeHex: string, sequenceNumber: number = 0): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        const bytes = hexToBytes(bytecodeHex);
        const payload: TransactionPayload = { kind: 'PublishModule', modules: [bytes] };
        tx.payload = bytesToHex(serializeTransactionPayload(payload));
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Create a generic Move entry function call
     * This is the universal builder — all specialized methods use this internally
     */
    static createMoveCall(
        sender: Keypair,
        moduleName: string,
        functionName: string,
        tyArgs: TypeTag[],
        args: Uint8Array[],
        sequenceNumber: number = 0
    ): Transaction {
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
    static createDePINProof(sender: Keypair, deviceId: string, bqi: number, sequenceNumber: number = 0): Transaction {
        if (bqi < 0 || bqi > 100) {
            throw new Error('BQI must be between 0 and 100');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        const deviceBytes = hexToBytes(deviceId);
        tx.payload = systemCall('universal_mining', 'submit_mining_proof', [], [
            bcsAddress(sender.address),
            bcsVectorU8(deviceBytes),
            bcsU64(BigInt(bqi)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    // ============ STAKING METHODS ============

    /**
     * Register as a validator
     * Calls: 0x1::staking::join_validator_set(account, stake_amount, public_key)
     */
    static createRegisterValidator(sender: Keypair, stakeAmount: bigint, sequenceNumber: number = 0): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        const pkBytes = hexToBytes(sender.publicKey);
        tx.payload = systemCall('staking', 'join_validator_set', [], [
            bcsAddress(sender.address),
            bcsU128(stakeAmount),
            bcsVectorU8(pkBytes),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    // ============ DELEGATION METHODS ============

    /**
     * Delegate tokens to a validator
     * Calls: 0x1::delegation::delegate(delegator, validator_addr, amount)
     */
    static createDelegate(
        sender: Keypair,
        validatorAddress: string,
        amount: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'delegate', [], [
            bcsAddress(sender.address),
            bcsAddress(validatorAddress),
            bcsU128(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Undelegate tokens from a validator (starts 21-day unbonding)
     * Calls: 0x1::delegation::undelegate(delegator, validator_addr, amount)
     */
    static createUndelegate(
        sender: Keypair,
        validatorAddress: string,
        amount: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'undelegate', [], [
            bcsAddress(sender.address),
            bcsAddress(validatorAddress),
            bcsU128(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Claim delegation rewards from a validator
     * Calls: 0x1::delegation::claim_rewards(delegator, validator_addr)
     */
    static createClaimRewards(
        sender: Keypair,
        validatorAddress: string,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'claim_rewards', [], [
            bcsAddress(sender.address),
            bcsAddress(validatorAddress),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Withdraw unbonded tokens (after 21-day unbonding period)
     * Calls: 0x1::delegation::withdraw_unbonded(delegator, validator_addr)
     */
    static createWithdrawUnbonded(
        sender: Keypair,
        validatorAddress: string,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'withdraw_unbonded', [], [
            bcsAddress(sender.address),
            bcsAddress(validatorAddress),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Enable delegation for a validator (validator only)
     * Calls: 0x1::delegation::enable_delegation(validator, commission_rate)
     */
    static createEnableDelegation(
        sender: Keypair,
        commissionRate: number,
        sequenceNumber: number = 0
    ): Transaction {
        if (commissionRate < 0 || commissionRate > 3000) {
            throw new Error('Commission rate must be between 0 and 3000 basis points (0-30%)');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('delegation', 'enable_delegation', [], [
            bcsAddress(sender.address),
            bcsU64(BigInt(commissionRate)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    // ============ TOKEN FACTORY METHODS ============

    /**
     * Create a new token
     * Calls: 0x1::token_factory::create_token(creator, name, symbol, decimals, max_supply, initial_supply, icon_url, project_url)
     */
    static createToken(
        sender: Keypair,
        name: string,
        symbol: string,
        decimals: number,
        maxSupply: bigint,
        initialSupply: bigint,
        iconUrl: string,
        projectUrl: string,
        sequenceNumber: number = 0
    ): Transaction {
        if (decimals < 0 || decimals > 18) {
            throw new Error('Decimals must be between 0 and 18');
        }
        if (initialSupply > maxSupply) {
            throw new Error('Initial supply cannot exceed max supply');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'create_token', [], [
            bcsAddress(sender.address),
            bcsString(name),
            bcsString(symbol),
            bcsU8(decimals),
            bcsU128(maxSupply),
            bcsU128(initialSupply),
            bcsString(iconUrl),
            bcsString(projectUrl),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Mint tokens (only token creator can mint)
     * Calls: 0x1::token_factory::mint(admin, token_id, to, amount)
     */
    static mintToken(
        sender: Keypair,
        tokenId: string,
        to: string,
        amount: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'mint', [], [
            bcsAddress(sender.address),
            bcsVectorU8(new TextEncoder().encode(tokenId)),
            bcsAddress(to),
            bcsU128(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Burn tokens
     * Calls: 0x1::token_factory::burn(holder, token_id, amount)
     */
    static burnToken(
        sender: Keypair,
        tokenId: string,
        amount: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'burn', [], [
            bcsAddress(sender.address),
            bcsVectorU8(new TextEncoder().encode(tokenId)),
            bcsU128(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Transfer tokens to another address
     * Calls: 0x1::token_factory::transfer(from, token_id, to, amount)
     */
    static transferToken(
        sender: Keypair,
        tokenId: string,
        to: string,
        amount: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'transfer', [], [
            bcsAddress(sender.address),
            bcsVectorU8(new TextEncoder().encode(tokenId)),
            bcsAddress(to),
            bcsU128(amount),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Initialize token wallet (required before receiving custom tokens)
     * Calls: 0x1::token_factory::init_wallet(account)
     */
    static initTokenWallet(
        sender: Keypair,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('token_factory', 'init_wallet', [], [
            bcsAddress(sender.address),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    // ============ NATIVE DEX METHODS ============

    /**
     * Create a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::create_pool<X, Y>(creator)
     */
    static createDexPool(
        sender: Keypair,
        tokenX: TypeTag,
        tokenY: TypeTag,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'create_pool', [tokenX, tokenY], [
            bcsAddress(sender.address),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Add liquidity to an existing AINCORE CPMM pool.
     * Calls: 0x1::dex::add_liquidity<X, Y>(provider, pool_addr, amount_x, amount_y, min_lp)
     */
    static addDexLiquidity(
        sender: Keypair,
        poolAddress: string,
        tokenX: TypeTag,
        tokenY: TypeTag,
        amountX: bigint,
        amountY: bigint,
        minLp: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'add_liquidity', [tokenX, tokenY], [
            bcsAddress(sender.address),
            bcsAddress(poolAddress),
            bcsU128(amountX),
            bcsU128(amountY),
            bcsU128(minLp),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Remove liquidity from an existing AINCORE CPMM pool.
     * Calls: 0x1::dex::remove_liquidity<X, Y>(provider, pool_addr, lp_amount, min_x, min_y)
     */
    static removeDexLiquidity(
        sender: Keypair,
        poolAddress: string,
        tokenX: TypeTag,
        tokenY: TypeTag,
        lpAmount: bigint,
        minX: bigint,
        minY: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'remove_liquidity', [tokenX, tokenY], [
            bcsAddress(sender.address),
            bcsAddress(poolAddress),
            bcsU128(lpAmount),
            bcsU128(minX),
            bcsU128(minY),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Swap token X to token Y through a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::swap_x_to_y<X, Y>(trader, pool_addr, amount_x_in, min_y_out)
     */
    static createDexSwapXToY(
        sender: Keypair,
        poolAddress: string,
        tokenX: TypeTag,
        tokenY: TypeTag,
        amountXIn: bigint,
        minYOut: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'swap_x_to_y', [tokenX, tokenY], [
            bcsAddress(sender.address),
            bcsAddress(poolAddress),
            bcsU128(amountXIn),
            bcsU128(minYOut),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Swap token Y to token X through a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::swap_y_to_x<X, Y>(trader, pool_addr, amount_y_in, min_x_out)
     */
    static createDexSwapYToX(
        sender: Keypair,
        poolAddress: string,
        tokenX: TypeTag,
        tokenY: TypeTag,
        amountYIn: bigint,
        minXOut: bigint,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('dex', 'swap_y_to_x', [tokenX, tokenY], [
            bcsAddress(sender.address),
            bcsAddress(poolAddress),
            bcsU128(amountYIn),
            bcsU128(minXOut),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    // ============ GOVERNANCE METHODS ============

    /**
     * Create a governance proposal
     * Calls: 0x1::governance::create_proposal(proposer, description, action_type, action_value)
     */
    static createProposal(
        sender: Keypair,
        description: string,
        actionType: number,
        actionValue: number,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'create_proposal', [], [
            bcsAddress(sender.address),
            bcsString(description),
            bcsU8(actionType),
            bcsU64(BigInt(actionValue)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Vote on a governance proposal
     * Calls: 0x1::governance::vote(voter, proposal_id, approve)
     */
    static vote(
        sender: Keypair,
        proposalId: number,
        approve: boolean,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'vote', [], [
            bcsAddress(sender.address),
            bcsU64(BigInt(proposalId)),
            bcsBool(approve),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Execute a passed governance proposal (after timelock)
     * Calls: 0x1::governance::execute_proposal(executor, proposal_id)
     */
    static executeProposal(
        sender: Keypair,
        proposalId: number,
        sequenceNumber: number = 0
    ): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = systemCall('governance', 'execute_proposal', [], [
            bcsAddress(sender.address),
            bcsU64(BigInt(proposalId)),
        ]);
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    // ============ TRANSACTION LIFECYCLE ============

    /**
     * Set Chain ID (e.g. for Testnet)
     */
    setChainId(chainId: string) {
        this.chainId = chainId;
    }

    /**
     * Sign the transaction
     */
    sign(signer: Keypair) {
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
        const message = [
            this.chainId,
            this.sender,
            this.payload,
            this.sequenceNumber,
            this.gasLimit,
            this.gasPrice,
            this.inputObjects.join(','),
        ].join(':');
        this.signature = signer.sign(Buffer.from(message));
        this.publicKey = signer.publicKey;
    }

    /**
     * Set Paymaster details
     */
    setPaymaster(paymasterAddress: string, signature: string) {
        this.paymaster = paymasterAddress;
        this.paymasterSignature = signature;
    }

    /**
     * Sign the transaction as a Paymaster (Hardened payload)
     * Payload: PAYMASTER_AUTH:{chain_id}:{sender}:{payload}:{gas_limit}:{sequence_number}
     */
    signAsPaymaster(paymasterKeypair: Keypair) {
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
    toString(): string {
        const json: any = {
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
