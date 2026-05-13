import { Keypair } from './keypair';
export declare class Transaction {
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
    constructor();
    /**
     * Create a transfer transaction
     */
    static createTransfer(sender: Keypair, to: string, amount: number, sequenceNumber?: number): Transaction;
    /**
     * Create a Move smart contract call
     * @param sender - Sender keypair
     * @param bytecodeHex - Move bytecode as hex string (starting with 0x)
     * @param sequenceNumber - Transaction sequence number
     */
    static createMoveCall(sender: Keypair, bytecodeHex: string, sequenceNumber?: number): Transaction;
    /**
     * Create a DePIN proof submission transaction
     * @param sender - Device keypair (device address must match sender)
     * @param deviceId - Device ID (should match sender address)
     * @param bqi - Bandwidth Quality Index (0-100)
     * @param sequenceNumber - Transaction sequence number
     */
    static createDePINProof(sender: Keypair, deviceId: string, bqi: number, sequenceNumber?: number): Transaction;
    /**
     * Create a validator registration transaction
     * @param sender - Validator keypair (must have staking balance)
     * @param sequenceNumber - Transaction sequence number
     */
    static createRegisterValidator(sender: Keypair, sequenceNumber?: number): Transaction;
    /**
     * Delegate tokens to a validator
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator to delegate to
     * @param amount - Amount to delegate (in smallest unit, 1 AIN = 1e18)
     * @param sequenceNumber - Transaction sequence number
     */
    static createDelegate(sender: Keypair, validatorAddress: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Undelegate tokens from a validator (starts 21-day unbonding)
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator to undelegate from
     * @param amount - Amount to undelegate
     * @param sequenceNumber - Transaction sequence number
     */
    static createUndelegate(sender: Keypair, validatorAddress: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Claim delegation rewards from a validator
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator
     * @param sequenceNumber - Transaction sequence number
     */
    static createClaimRewards(sender: Keypair, validatorAddress: string, sequenceNumber?: number): Transaction;
    /**
     * Withdraw unbonded tokens (after 21-day unbonding period)
     * @param sender - Delegator keypair
     * @param validatorAddress - Address of the validator
     * @param sequenceNumber - Transaction sequence number
     */
    static createWithdrawUnbonded(sender: Keypair, validatorAddress: string, sequenceNumber?: number): Transaction;
    /**
     * Enable delegation for a validator (validator only)
     * @param sender - Validator keypair
     * @param commissionRate - Commission rate in basis points (100 = 1%, max 3000 = 30%)
     * @param sequenceNumber - Transaction sequence number
     */
    static createEnableDelegation(sender: Keypair, commissionRate: number, sequenceNumber?: number): Transaction;
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
    static createToken(sender: Keypair, name: string, symbol: string, decimals: number, maxSupply: bigint, initialSupply: bigint, iconUrl: string, projectUrl: string, sequenceNumber?: number): Transaction;
    /**
     * Mint tokens (only token creator can mint)
     * @param sender - Token creator's keypair
     * @param tokenId - Token ID (symbol)
     * @param to - Recipient address
     * @param amount - Amount to mint
     * @param sequenceNumber - Transaction sequence number
     */
    static mintToken(sender: Keypair, tokenId: string, to: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Burn tokens
     * @param sender - Token holder's keypair
     * @param tokenId - Token ID (symbol)
     * @param amount - Amount to burn
     * @param sequenceNumber - Transaction sequence number
     */
    static burnToken(sender: Keypair, tokenId: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Transfer tokens to another address
     * @param sender - Token holder's keypair
     * @param tokenId - Token ID (symbol)
     * @param to - Recipient address
     * @param amount - Amount to transfer
     * @param sequenceNumber - Transaction sequence number
     */
    static transferToken(sender: Keypair, tokenId: string, to: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Initialize token wallet (required before receiving custom tokens)
     * @param sender - User's keypair
     * @param sequenceNumber - Transaction sequence number
     */
    static initTokenWallet(sender: Keypair, sequenceNumber?: number): Transaction;
    /**
     * Create a governance proposal
     * @param sender - Proposer's keypair
     * @param proposalId - Unique proposal ID
     * @param title - Proposal title
     * @param description - Proposal description
     * @param durationSeconds - Voting duration in seconds
     * @param sequenceNumber - Transaction sequence number
     */
    static createProposal(sender: Keypair, proposalId: string, title: string, description: string, durationSeconds: number, sequenceNumber?: number): Transaction;
    /**
     * Vote on a governance proposal
     * @param sender - Voter's keypair
     * @param proposalId - Proposal ID to vote on
     * @param approve - true for yes, false for no
     * @param sequenceNumber - Transaction sequence number
     */
    static vote(sender: Keypair, proposalId: string, approve: boolean, sequenceNumber?: number): Transaction;
    /**
     * Execute a passed governance proposal (after timelock)
     * @param sender - Executor's keypair
     * @param proposalId - Proposal ID to execute
     * @param sequenceNumber - Transaction sequence number
     */
    static executeProposal(sender: Keypair, proposalId: string, sequenceNumber?: number): Transaction;
    /**
     * Set Chain ID (e.g. for Testnet)
     */
    setChainId(chainId: string): void;
    /**
     * Sign the transaction
     */
    sign(signer: Keypair): void;
    /**
     * Set Paymaster details
     */
    setPaymaster(paymasterAddress: string, signature: string): void;
    /**
     * Sign the transaction as a Paymaster (Hardened payload)
     * Payload: PAYMASTER_AUTH:{chain_id}:{sender}:{payload}:{gas_limit}:{sequence_number}
     */
    signAsPaymaster(paymasterKeypair: Keypair): void;
    /**
     * Convert to JSON string for API
     */
    toString(): string;
}
