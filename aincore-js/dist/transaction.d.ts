import { Keypair } from './keypair';
import { TypeTag } from './bcs';
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
    static createRegisterValidator(sender: Keypair, stakeAmount: bigint, sequenceNumber?: number): Transaction;
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
     * Mint tokens (only token creator can mint)
     * Calls: 0x1::token_factory::mint(admin, token_id, to, amount)
     */
    static mintToken(sender: Keypair, tokenId: string, to: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Burn tokens
     * Calls: 0x1::token_factory::burn(holder, token_id, amount)
     */
    static burnToken(sender: Keypair, tokenId: string, amount: bigint, sequenceNumber?: number): Transaction;
    /**
     * Transfer tokens to another address
     * Calls: 0x1::token_factory::transfer(from, token_id, to, amount)
     */
    static transferToken(sender: Keypair, tokenId: string, to: string, amount: bigint, sequenceNumber?: number): Transaction;
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
     * Vote on a governance proposal
     * Calls: 0x1::governance::vote(voter, proposal_id, approve)
     */
    static vote(sender: Keypair, proposalId: number, approve: boolean, sequenceNumber?: number): Transaction;
    /**
     * Execute a passed governance proposal (after timelock)
     * Calls: 0x1::governance::execute_proposal(executor, proposal_id)
     */
    static executeProposal(sender: Keypair, proposalId: number, sequenceNumber?: number): Transaction;
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
