import { Keypair } from './keypair';
import { TypeTag } from './bcs';
/**
 * A token_factory token's id: its symbol's bytes followed by its creator's
 * 32 address bytes, as hex (the form the token methods take). The id holds
 * raw address bytes, so it is not text: passing it as a UTF-8 string, as
 * these methods once did, sent different bytes.
 */
export declare function tokenIdOf(symbol: string, creator: string): string;
/** B14: gas per byte of the signed transaction JSON, as the node charges it. */
export declare const BYTE_GAS = 400;
export declare class Transaction {
    sender: string;
    inputObjects: string[];
    payload: string;
    /** Set by `sign`: `executionGas` plus BYTE_GAS per byte of the signed JSON. */
    gasLimit: number;
    /**
     * Execution gas: Move execution and the state the writes add (B65);
     * `sign` adds the byte gas on top. Set it from
     * `connection.estimateExecutionGas(tx, publicKey)` before signing: a
     * transfer to an address with no coins, or a publish, needs far more
     * than the default.
     */
    executionGas: number;
    gasPrice: number;
    sequenceNumber: number;
    publicKey: string;
    signature: string;
    chainId: string;
    paymaster?: string;
    paymasterSignature?: string;
    constructor();
    /**
     * Create a transfer transaction (AIN native coin)
     * Calls: 0x1::coin::transfer<0x1::staking::AincoreCoin>
     */
    static createTransfer(sender: Keypair, to: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Create a Move smart contract publication
     * Uses: TransactionPayload::PublishModule
     */
    static createPublish(sender: Keypair, bytecodeHex: string, sequenceNumber?: number): Transaction;
    /**
     * Create a generic Move entry function call
     * This is the universal builder — all specialized methods use this internally
     */
    static createMoveCall(sender: Keypair, moduleName: string, functionName: string, tyArgs: TypeTag[], args: Uint8Array[], sequenceNumber?: number): Transaction;
    /**
     * Create a DePIN proof submission transaction
     * Calls: 0x1::universal_mining::submit_mining_proof(oracle, device_pubkey, bqi_score)
     */
    static createDePINProof(sender: Keypair, deviceId: string, bqi: number, sequenceNumber?: number): Transaction;
    /**
     * Register as a validator
     * Calls: 0x1::staking::join_validator_set(account, stake_amount, public_key)
     */
    static createRegisterValidator(sender: Keypair, stakeAmount: bigint, blsPublicKey: Uint8Array, blsPop: Uint8Array, sequenceNumber?: number): Transaction;
    /**
     * Delegate tokens to a validator
     * Calls: 0x1::delegation::delegate(delegator, validator_addr, amount)
     */
    static createDelegate(sender: Keypair, validatorAddress: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Undelegate tokens from a validator (starts 21-day unbonding)
     * Calls: 0x1::delegation::undelegate(delegator, validator_addr, amount)
     */
    static createUndelegate(sender: Keypair, validatorAddress: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Claim delegation rewards from a validator
     * Calls: 0x1::delegation::claim_rewards(delegator, validator_addr)
     */
    static createClaimRewards(sender: Keypair, validatorAddress: string, sequenceNumber?: number): Transaction;
    /**
     * Withdraw unbonded tokens (after 21-day unbonding period)
     * Calls: 0x1::delegation::withdraw_unbonded(delegator, validator_addr)
     */
    static createWithdrawUnbonded(sender: Keypair, validatorAddress: string, sequenceNumber?: number): Transaction;
    /**
     * Enable delegation for a validator (validator only)
     * Calls: 0x1::delegation::enable_delegation(validator, commission_rate)
     */
    static createEnableDelegation(sender: Keypair, commissionRate: number, sequenceNumber?: number): Transaction;
    /**
     * Create a new token
     * Calls: 0x1::token_factory::create_token(creator, name, symbol, decimals, max_supply, initial_supply, icon_url, project_url)
     */
    static createToken(sender: Keypair, name: string, symbol: string, decimals: number, maxSupply: bigint, initialSupply: bigint, iconUrl: string, projectUrl: string, sequenceNumber?: number): Transaction;
    /**
     * Mint tokens (only token creator can mint). `tokenId` is hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::mint(admin, token_id, to, amount)
     */
    static mintToken(sender: Keypair, tokenId: string, to: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Burn tokens. `creator` names the token's registry (B135); `tokenId` is
     * hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::burn(holder, creator, token_id, amount)
     */
    static burnToken(sender: Keypair, creator: string, tokenId: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Transfer tokens to another address (which must have registered the
     * token, `registerToken`). `tokenId` is hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::transfer(from, token_id, to, amount)
     */
    static transferToken(sender: Keypair, tokenId: string, to: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Register a token in the sender's wallet (made if missing), so it can
     * receive it (B135: a wallet takes only tokens its owner registered).
     * `tokenId` is hex (`tokenIdOf`).
     * Calls: 0x1::token_factory::register(account, token_id)
     */
    static registerToken(sender: Keypair, tokenId: string, sequenceNumber?: number): Transaction;
    /**
     * Initialize token wallet (required before receiving custom tokens)
     * Calls: 0x1::token_factory::init_wallet(account)
     */
    static initTokenWallet(sender: Keypair, sequenceNumber?: number): Transaction;
    /**
     * Create a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::create_pool<X, Y>(creator)
     */
    static createDexPool(sender: Keypair, tokenX: TypeTag, tokenY: TypeTag, sequenceNumber?: number): Transaction;
    /**
     * Add liquidity to an existing AINCORE CPMM pool.
     * Calls: 0x1::dex::add_liquidity<X, Y>(provider, pool_addr, amount_x, amount_y, min_lp)
     */
    static addDexLiquidity(sender: Keypair, poolAddress: string, tokenX: TypeTag, tokenY: TypeTag, amountX: bigint, amountY: bigint, minLp: bigint, sequenceNumber?: number): Transaction;
    /**
     * Remove liquidity from an existing AINCORE CPMM pool.
     * Calls: 0x1::dex::remove_liquidity<X, Y>(provider, pool_addr, lp_amount, min_x, min_y)
     */
    static removeDexLiquidity(sender: Keypair, poolAddress: string, tokenX: TypeTag, tokenY: TypeTag, lpAmount: bigint, minX: bigint, minY: bigint, sequenceNumber?: number): Transaction;
    /**
     * Swap token X to token Y through a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::swap_x_to_y<X, Y>(trader, pool_addr, amount_x_in, min_y_out)
     */
    static createDexSwapXToY(sender: Keypair, poolAddress: string, tokenX: TypeTag, tokenY: TypeTag, amountXIn: bigint, minYOut: bigint, sequenceNumber?: number): Transaction;
    /**
     * Swap token Y to token X through a canonical AINCORE CPMM pool.
     * Calls: 0x1::dex::swap_y_to_x<X, Y>(trader, pool_addr, amount_y_in, min_x_out)
     */
    static createDexSwapYToX(sender: Keypair, poolAddress: string, tokenX: TypeTag, tokenY: TypeTag, amountYIn: bigint, minXOut: bigint, sequenceNumber?: number): Transaction;
    /**
     * Create a governance proposal
     * Calls: 0x1::governance::create_proposal(proposer, description, action_type, action_value)
     */
    static createProposal(sender: Keypair, description: string, actionType: number, actionValue: number, sequenceNumber?: number): Transaction;
    /**
     * Vote on a governance proposal with `amount` quanta of AIN, locked
     * until its voting ends (B71); `claimVoteTokens` takes it back after.
     * Calls: 0x1::governance::vote(voter, proposal_id, approve, amount)
     */
    static vote(sender: Keypair, proposalId: number, approve: boolean, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Resolve a passed governance proposal once its voting has ended (a
     * signal: it records the outcome).
     * Calls: 0x1::governance::execute_proposal(executor, proposal_id)
     */
    static executeProposal(sender: Keypair, proposalId: number, sequenceNumber?: number): Transaction;
    /**
     * Take back the AIN of every vote whose proposal's voting has ended,
     * whatever the outcome (B71).
     * Calls: 0x1::governance::claim_vote_tokens(voter)
     */
    static claimVoteTokens(sender: Keypair, sequenceNumber?: number): Transaction;
    /**
     * Set Chain ID (e.g. for Testnet)
     */
    setChainId(chainId: string): void;
    /**
     * Sign the transaction
     */
    sign(signer: Keypair): void;
    /**
     * B65: the transaction as `aincore_estimateGas` takes it before signing:
     * the sender's key, zero signatures of the final length, gas_limit 0.
     */
    estimateDraft(publicKey: string): Record<string, unknown>;
    /**
     * The seven fields the sender signs (F4), as the node rebuilds them, and
     * for a sponsored transaction an eighth, the paymaster's public key
     * (B73: a relay could otherwise strip the paymaster and make the sender
     * pay). Name the paymaster with `setPaymasterKey` before `sign`.
     */
    private signingMessage;
    /**
     * Set Paymaster details: the paymaster's PUBLIC KEY (hex) and its
     * signature. The node pays gas from the address derived from that key
     * (B13).
     */
    setPaymaster(paymasterPublicKey: string, signature: string): void;
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
    setPaymasterKey(paymasterPublicKey: string): void;
    signAsPaymaster(paymasterKeypair: Keypair): void;
    /**
     * Convert to JSON string for API
     */
    toString(): string;
}
