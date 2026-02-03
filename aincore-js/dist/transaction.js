"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = void 0;
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
        this.chainId = 'AINCORE-MAINNET-1';
    }
    /**
     * Create a transfer transaction
     */
    static createTransfer(sender, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `transfer:${to}:${amount}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Create a Move smart contract call
     * @param sender - Sender keypair
     * @param bytecodeHex - Move bytecode as hex string (starting with 0x)
     * @param sequenceNumber - Transaction sequence number
     */
    static createMoveCall(sender, bytecodeHex, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = bytecodeHex.startsWith('0x') ? bytecodeHex : `0x${bytecodeHex}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Create a DePIN proof submission transaction
     * @param sender - Device keypair (device address must match sender)
     * @param deviceId - Device ID (should match sender address)
     * @param bqi - Bandwidth Quality Index (0-100)
     * @param sequenceNumber - Transaction sequence number
     */
    static createDePINProof(sender, deviceId, bqi, sequenceNumber = 0) {
        if (bqi < 0 || bqi > 100) {
            throw new Error('BQI must be between 0 and 100');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `submit_proof:${deviceId}:${bqi}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Create a validator registration transaction
     * @param sender - Validator keypair (must have staking balance)
     * @param sequenceNumber - Transaction sequence number
     */
    static createRegisterValidator(sender, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = 'register_validator';
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ DELEGATION METHODS ============
    /**
     * Delegate tokens to a validator
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator to delegate to
     * @param amount - Amount to delegate (in smallest unit, 1 AIN = 1e18)
     * @param sequenceNumber - Transaction sequence number
     */
    static createDelegate(sender, validatorAddress, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `delegate:${validatorAddress}:${amount.toString()}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Undelegate tokens from a validator (starts 21-day unbonding)
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator to undelegate from
     * @param amount - Amount to undelegate
     * @param sequenceNumber - Transaction sequence number
     */
    static createUndelegate(sender, validatorAddress, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `undelegate:${validatorAddress}:${amount.toString()}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Claim delegation rewards from a validator
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator
     * @param sequenceNumber - Transaction sequence number
     */
    static createClaimRewards(sender, validatorAddress, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `claim_rewards:${validatorAddress}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Withdraw unbonded tokens (after 21-day unbonding period)
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator
     * @param sequenceNumber - Transaction sequence number
     */
    static createWithdrawUnbonded(sender, validatorAddress, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `withdraw_unbonded:${validatorAddress}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Enable delegation for a validator (validator only)
     * @param sender - Validator keypair
     * @param commissionRate - Commission rate in basis points (100 = 1%, max 3000 = 30%)
     * @param sequenceNumber - Transaction sequence number
     */
    static createEnableDelegation(sender, commissionRate, sequenceNumber = 0) {
        if (commissionRate < 0 || commissionRate > 3000) {
            throw new Error('Commission rate must be between 0 and 3000 basis points (0-30%)');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `enable_delegation:${commissionRate}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ TOKEN FACTORY METHODS ============
    /**
     * Create a new token
     * @param sender - Creator keypair (must have 100 AIN for creation fee)
     * @param name - Token name (e.g., "My Token")
     * @param symbol - Token symbol (e.g., "MTK")
     * @param decimals - Number of decimals (max 18)
     * @param maxSupply - Maximum supply (in smallest unit)
     * @param initialSupply - Initial supply to mint to creator
     * @param sequenceNumber - Transaction sequence number
     */
    static createToken(sender, name, symbol, decimals, maxSupply, initialSupply, sequenceNumber = 0) {
        if (decimals < 0 || decimals > 18) {
            throw new Error('Decimals must be between 0 and 18');
        }
        if (initialSupply > maxSupply) {
            throw new Error('Initial supply cannot exceed max supply');
        }
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `create_token:${name}:${symbol}:${decimals}:${maxSupply.toString()}:${initialSupply.toString()}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Mint tokens (only token creator can mint)
     * @param sender - Token creator's keypair
     * @param tokenId - Token ID (symbol)
     * @param to - Recipient address
     * @param amount - Amount to mint
     * @param sequenceNumber - Transaction sequence number
     */
    static mintToken(sender, tokenId, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `mint_token:${tokenId}:${to}:${amount.toString()}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Burn tokens
     * @param sender - Token holder's keypair
     * @param tokenId - Token ID (symbol)
     * @param amount - Amount to burn
     * @param sequenceNumber - Transaction sequence number
     */
    static burnToken(sender, tokenId, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `burn_token:${tokenId}:${amount.toString()}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Transfer tokens to another address
     * @param sender - Token holder's keypair
     * @param tokenId - Token ID (symbol)
     * @param to - Recipient address
     * @param amount - Amount to transfer
     * @param sequenceNumber - Transaction sequence number
     */
    static transferToken(sender, tokenId, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `transfer_token:${tokenId}:${to}:${amount.toString()}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Initialize token wallet (required before receiving custom tokens)
     * @param sender - User's keypair
     * @param sequenceNumber - Transaction sequence number
     */
    static initTokenWallet(sender, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = 'init_token_wallet';
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    // ============ GOVERNANCE METHODS ============
    /**
     * Create a governance proposal
     * @param sender - Proposer's keypair
     * @param proposalId - Unique proposal ID
     * @param title - Proposal title
     * @param description - Proposal description
     * @param durationSeconds - Voting duration in seconds
     * @param sequenceNumber - Transaction sequence number
     */
    static createProposal(sender, proposalId, title, description, durationSeconds, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        // For governance, we need to use RPC directly (via aincore_createProposal)
        // This is a helper that creates a proposal via transaction
        tx.payload = `create_proposal:${proposalId}:${title}:${description}:${durationSeconds}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Vote on a governance proposal
     * @param sender - Voter's keypair
     * @param proposalId - Proposal ID to vote on
     * @param approve - true for yes, false for no
     * @param sequenceNumber - Transaction sequence number
     */
    static vote(sender, proposalId, approve, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `vote:${proposalId}:${approve ? 'yes' : 'no'}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Execute a passed governance proposal (after timelock)
     * @param sender - Executor's keypair
     * @param proposalId - Proposal ID to execute
     * @param sequenceNumber - Transaction sequence number
     */
    static executeProposal(sender, proposalId, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `execute_proposal:${proposalId}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
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
        // Include sequence number AND Chain ID in signature payload (REPLAY PROTECTION)
        const message = `${this.chainId}:${this.payload}:${this.sequenceNumber}`;
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
