import { Transaction } from './transaction';
export interface DexPool {
    pool_key: string;
    pool_addr: string;
    token_x: string;
    token_y: string;
    fee_bp: number;
    creator: string;
    active: boolean;
    reserve_x: string;
    reserve_y: string;
    lp_supply: string;
}
export interface DexQuote {
    status: string;
    pool_key?: string;
    pool_addr?: string;
    direction?: string;
    amount_in?: string;
    amount_out?: string | null;
    fee_bp?: number;
    reserve_in?: string;
    reserve_out?: string;
}
export interface DexSpotPrice {
    status: string;
    token_in: string;
    token_out: string;
    unit_amount_in: string;
    amount_out: string | null;
    approx_price: number | null;
    quote: DexQuote;
}
export interface DexTrade {
    tx_hash: string;
    pool_addr: string;
    function: string;
    token_x: string;
    token_y: string;
    token_in: string;
    token_out: string;
    amount_in: string;
    amount_out: string;
    block_height: number;
    timestamp: number;
}
export interface DexOhlcCandle {
    time: number;
    open: number;
    high: number;
    low: number;
    close: number;
    volume: number;
}
export interface DexPairSummary {
    base_token: string;
    quote_token: string;
    last_price: number;
    price_change_24h_pct: number;
    volume_base_24h: number;
    volume_quote_24h: number;
    trades_24h: number;
    high_24h: number;
    low_24h: number;
    first_trade_at: number;
    last_trade_at: number;
}
export interface DexMarketSummary {
    token_x: string;
    token_y: string;
    pool_addr: string;
    last_price: number;
    price_change_24h_pct: number;
    volume_x_24h: number;
    volume_y_24h: number;
    trades_24h: number;
    last_trade_at: number;
}
export interface DexLpBalance {
    address: string;
    status: string;
    pool_key?: string;
    pool_addr?: string;
    token_x?: string;
    token_y?: string;
    balance: string;
    lp_supply: string;
    share_bps: number;
    balance_source?: string;
}
export interface TransactionReceipt {
    tx_hash: string;
    status: string;
    confirmations: number;
    block_height?: number;
    block_hash?: string;
    execution_receipt?: {
        status?: string;
        gas_charged?: string;
        error?: string;
        metadata?: Record<string, unknown>;
    } | null;
}
/** A token as the node reports it (`aincore_getToken`, `aincore_getTokens`). */
export interface TokenInfo {
    tokenId: string;
    name: string;
    symbol: string;
    decimals: number;
    maxSupply: string;
    currentSupply: string;
    creator: string;
    isMintable: boolean;
}
export declare class Connection {
    private rpcUrl;
    private client;
    private indexerUrl?;
    constructor(endpoint: string, indexerEndpoint?: string);
    /**
     * B260: busy answers (-32005: the node's heavy-call slots are taken, or
     * this client's last heavy call still runs: one at a time a client) are
     * asked again this many times, after a wait doubling from
     * `busyBackoffMs`. They failed at once, so a dapp's parallel receipts
     * failed against the node's admission rules.
     */
    busyRetries: number;
    busyBackoffMs: number;
    /**
     * B267: how long one request may take before it fails (axios had no
     * timeout, so a stalled node held a call, and `waitForConfirmation`'s
     * own timeout, for good).
     */
    timeoutMs: number;
    /** B267: the heavy call this Connection sent last (`HEAVY_METHODS`). */
    private heavyTail;
    /**
     * B267: the wait before busy retry `attempt`: half of
     * `busyBackoffMs * 2^attempt`, plus up to as much again at random, so
     * clients refused together do not all ask again at the same instant.
     */
    backoffMs(attempt: number): number;
    /**
     * B329: a GET asked again on a rate limit (HTTP 429) or a busy answer
     * (HTTP 503), as `send` asks a busy JSON-RPC call again; any other
     * failure throws. The REST reads threw at the first 429, so a wallet took
     * a busy node for one that runs no chain or holds no validators.
     */
    private getWithRetry;
    /**
     * Generic JSON-RPC call. B267: heavy calls one at a time.
     */
    request(method: string, params?: any[]): Promise<any>;
    private send;
    /**
     * Get account data (balance, sequence number). B479: `balance` is the
     * Move CoinStore balance in quanta, exactly, as a bigint (`move_balance`
     * is the same as a decimal string); it was a `number`, rounded past 2^53
     * quanta. A balance that is not a decimal integer throws.
     */
    getAccount(address: string): Promise<{
        balance: bigint;
        sequence_number: number;
        move_balance: string;
        balance_source: string;
    }>;
    /**
     * The native AIN balance from the Move CoinStore, in quanta (10^18 to
     * the coin), exactly. B479: a bigint, the type transfer amounts take, so
     * `balance - fee` is exact. It was a `number`, which rounded every
     * balance past 2^53 quanta (about 0.009 AIN), and a "send max" built
     * from it could sign more than the account holds (included, aborted and
     * charged). For JSON, which carries no bigint, use `getMoveBalance`.
     */
    getBalance(address: string): Promise<bigint>;
    /**
     * Get exact native AIN balance from Move CoinStore as a decimal string.
     */
    getMoveBalance(address: string): Promise<string>;
    /**
     * Get account nonce/sequence number directly from the node wallet RPC.
     */
    getAccountNonce(address: string): Promise<number>;
    /**
     * Get an exact Move CoinStore balance for native AIN or synthetic test WBTC.
     */
    getCoinBalance(address: string, token: 'AIN' | 'WBTC' | string): Promise<{
        address: string;
        token: string;
        balance: string;
        decimals: number;
        balance_source: string;
        market_mode?: string;
    }>;
    /**
     * G3 PF-1: the value of a consensus-state key (or its absence) with a
     * Merkle proof, plus that height's header and quorum certificate. Check
     * it with `verifyStateProof` against a root you trust, taken from a
     * verified quorum certificate, never from `state_root` in the answer.
     */
    getStateProof(key: string, height?: number): Promise<{
        key: string;
        value: string | null;
        height: number;
        state_root: string;
        proof: import('./stateProof').WireProof;
        header: any;
        quorum_certificate: any;
    }>;
    /**
     * @deprecated Removed from the node (G3 FX-8). The faucet wrote balances
     * straight into one node's database, outside consensus. Fund an account
     * with a signed transfer from a funded account instead. Kept so callers
     * fail with the reason rather than a missing method.
     */
    requestFaucet(_address: string, _amount?: string | number, _publicKey?: string): Promise<never>;
    /**
     * @deprecated Removed from the node (G3 FX-8), like `requestFaucet`. WBTC
     * is minted by the bridge authority through a signed `wbtc::mint`.
     */
    requestTestMintWbtc(_address: string, _amount: string | number, _publicKey?: string): Promise<never>;
    /**
     * Get latest blocks
     */
    getBlocks(limit?: number): Promise<any[]>;
    /**
     * Get a forward block range in ascending order.
     */
    getBlocksRange(startHeight: number, limit?: number): Promise<any[]>;
    /**
     * Get transaction details
     */
    getTransaction(hash: string): Promise<any>;
    /**
     * Get transaction receipt/status from the node.
     */
    getTransactionReceipt(hash: string): Promise<TransactionReceipt>;
    /**
     * B65: the execution gas `tx` needs, the state its writes add included:
     * the node runs it against the current state. Set `tx.executionGas` to
     * the answer, then `sign`.
     */
    estimateExecutionGas(tx: Transaction, publicKey: string): Promise<number>;
    /**
     * Send a signed transaction
     */
    sendTransaction(signedTxJson: string): Promise<string>;
    /**
     * Alias for browser/native wallet integrations that already produce tx JSON.
     */
    submitSignedTransaction(signedTxJson: string | Record<string, unknown>): Promise<string>;
    /**
     * Get transaction history from Indexer
     */
    getHistory(address: string): Promise<any[]>;
    /**
     * The node's base fee (B15), quanta per gas, as a decimal string (it can
     * pass 2^53). A transaction's gasPrice must be at least this.
     */
    getGasPrice(): Promise<string>;
    /**
     * Get any object by ID
     */
    getObject(objectId: string): Promise<any>;
    /**
     * Get node status (round, peers, height)
     */
    getNodeStatus(): Promise<{
        node_id: string;
        current_round: number;
        /** Every libp2p session the node holds, observers included. */
        peers_count: number;
        /** The sessions whose key names a committee member (G4 S6). */
        committee_sessions?: number;
        latest_height: string;
    }>;
    /**
     * Get DAG vertices (for explorer/debugging)
     */
    getDag(): Promise<any[]>;
    /**
     * Get connected peers list
     */
    /** The node's sessions: PeerId and whether a committee key names it (B90: no addresses). */
    getPeers(): Promise<Array<{
        peer_id: string;
        member: boolean;
    }>>;
    /**
     * Get a single block by height
     */
    getBlock(height: number): Promise<any>;
    /**
     * Get all canonical DEX pools from the on-chain Move registry.
     */
    getDexPools(): Promise<DexPool[]>;
    /**
     * Get a single DEX pool by canonical pool key or token pair.
     */
    getDexPool(poolKeyOrTokenX: string, tokenY?: string): Promise<DexPool | null>;
    /**
     * Quote a CPMM swap using the canonical on-chain pool state.
     */
    getDexQuote(tokenIn: string, tokenOut: string, amountIn: string | number): Promise<DexQuote>;
    /**
     * Read a provider's native Move LPToken balance for a DEX pool.
     *
     * When `poolAddrOrTokenX` is omitted, the node defaults to the Phase DEX
     * AIN/WBTC market. Passing a pool address reads that pool directly; passing
     * `poolAddrOrTokenX` + `tokenY` resolves a canonical token pair.
     */
    getDexLpBalance(address: string, poolAddrOrTokenX?: string, tokenY?: string): Promise<DexLpBalance>;
    /**
     * Compute spot price from current reserves for a canonical pool.
     * Returns how many `tokenOut` units back one whole `tokenIn` unit.
     */
    getDexSpotPrice(tokenIn: string, tokenOut: string, unitAmountIn?: string | number): Promise<DexSpotPrice>;
    /**
     * Read recent native DEX trades from the indexer.
     */
    getDexTrades(tokenIn: string, tokenOut: string, limit?: number): Promise<DexTrade[]>;
    /**
     * Read native OHLC candles aggregated from DEX swap history.
     */
    getDexOhlc(tokenIn: string, tokenOut: string, resolution?: number, limit?: number): Promise<DexOhlcCandle[]>;
    /**
     * Read a market summary for one canonical pair from the indexer.
     */
    getDexPairSummary(tokenIn: string, tokenOut: string): Promise<DexPairSummary | null>;
    /**
     * Read market summaries across all indexed canonical pools.
     */
    getDexMarkets(limit?: number): Promise<DexMarketSummary[]>;
    /**
     * Wait until a block executed the transaction.
     *
     * B123: this reads the receipt. `aincore_getTransaction` answers a pending
     * transaction in the same shape as a committed one, and a transaction a
     * block included can still have aborted (charged, nothing moved): both
     * used to come back `confirmed`. `confirmed` is true only when a block
     * executed it successfully; `status` says what is known ("success",
     * "aborted", "pending", "not_found", ...).
     * @param txHash - Transaction hash to wait for
     * @param timeout - Timeout in milliseconds (default 30000)
     * @param pollInterval - Polling interval in milliseconds (default 1000)
     */
    waitForConfirmation(txHash: string, timeout?: number, pollInterval?: number): Promise<{
        confirmed: boolean;
        status: string;
        receipt?: TransactionReceipt;
        transaction?: any;
    }>;
    /**
     * Get the latest block height
     */
    getLatestBlockHeight(): Promise<number>;
    /**
     * Get list of validators with their stake
     */
    /**
     * The node's active validators, as `/get_validators` answers them
     * (B236): it throws when the node cannot be reached or answers no list.
     * It used to answer [] on any failure, and typed a `voting_power` the
     * node never sends.
     */
    getValidators(): Promise<Array<{
        address: string;
        stake: number;
        status: string;
    }>>;
    /**
     * B236: the node's REST root: the RPC endpoint without a trailing
     * `/rpc`. Cutting the first "/rpc" anywhere in it turned
     * `https://rpc.example/rpc` into `https:/.example/rpc`.
     */
    restBase(): string;
    /**
     * The node's network information, as the node answers it (B223): the
     * chain it runs (`chain_id`, the node's `network`), its latest block,
     * its peers and committee sessions, the recent TPS. It throws when the
     * node cannot be reached: it used to answer a guessed object instead,
     * with `chain_id` 'AINCORE-MAINNET-1' whatever the node runs, so a
     * client that took its chain id from here signed for mainnet.
     */
    getNetworkInfo(): Promise<{
        chain_id: string;
        /** `null` when the node's consensus was busy answering. */
        node_id: string | null;
        block_height: number;
        /** `null` when the node's consensus was busy answering. */
        current_round: number | null;
        peer_count: number;
        committee_sessions: number;
        tps: number;
        protocol_version: number;
    }>;
    /**
     * Check if node is healthy
     */
    checkHealth(): Promise<boolean>;
    /**
     * Create a governance proposal
     * @deprecated The node refuses `aincore_createProposal`: submit a signed
     * transaction calling `0x1::governance::create_proposal` (sendTransaction).
     * @param id - Unique proposal ID
     * @param title - Proposal title
     * @param description - Proposal description
     * @param proposer - Proposer address
     * @param durationSeconds - Voting duration in seconds
     */
    createProposal(id: string, title: string, description: string, proposer: string, durationSeconds: number): Promise<{
        status: string;
        proposal_id: string;
    }>;
    /**
     * Vote on a governance proposal
     * @deprecated The node refuses `aincore_vote`: submit a signed transaction
     * calling `0x1::governance::vote` (sendTransaction).
     * @param proposalId - Proposal ID
     * @param voter - Voter address
     * @param approve - true = approve, false = reject
     */
    vote(proposalId: string, voter: string, approve: boolean): Promise<{
        status: string;
    }>;
    /**
     * A proposal as `0x1::governance` holds it on chain (B194): `id`,
     * `proposer`, `description`, `votes_for` / `votes_against` (decimal
     * strings), `executed`, `action_type`, `voting_ends` (consensus time,
     * seconds). `null` when there is no such proposal.
     * @param proposalId - Proposal id (a number, or its decimal string)
     */
    getProposal(proposalId: number | string): Promise<any>;
    /**
     * The votes of a proposal as the chain holds them (B194): `id`,
     * `votes_for`, `votes_against`, `executed`, `voting_ends`. Read-only.
     * @param proposalId - Proposal id (a number, or its decimal string)
     */
    tally(proposalId: number | string): Promise<any>;
    /**
     * Get mempool status (pending transactions)
     */
    getMempoolStatus(): Promise<{
        status: string;
        pending_tx_count: number;
    }>;
    /**
     * A block's data availability root and shard layout (the tip by default).
     * Check samples against the da_root of a header you hold under a QC, not
     * against this response. B478: the layout is a hint too. Draw the first
     * index from `total_shards`, every later one from the `totalShards` a
     * verified sample returns (the count the root commits to), and take a
     * `total_shards` below that count as a lie: a server holding 2 shards of
     * 256 answered 2, and every draw from it verified.
     */
    getDaStatus(height?: number): Promise<{
        height: number;
        block_hash: string;
        da_root: string;
        body_len: number;
        data_shards: number;
        total_shards: number;
        shard_size: number;
    }>;
    /**
     * Shard `index` of a block's body extension with its inclusion proof.
     * Pick indices uniformly at random yourself and check each answer with
     * `verifyDaSample(daRoot, index, sample)`, passing the index you drew
     * (B455: a server may answer with another index's genuine shard). B478:
     * draw from `[0, totalShards)` of a verified sample (the first index from
     * `getDaStatus`'s hint), and pass `sample` as it came: it is unchecked
     * here, and `verifyDaSample` refuses a mis-shaped one. s samples that all
     * verify leave a withheld body undetected with probability below 2^-s.
     */
    sampleDA(height: number, index: number): Promise<{
        height: number;
        block_hash: string;
        da_root: string;
        sample: {
            body_len: number;
            index: number;
            shard: string;
            proof: string[];
        };
    }>;
    /**
     * Get delegation info for a delegator to a specific validator
     * @param delegatorAddress - Delegator's address
     * @param validatorAddress - Validator's address
     * @returns Object with amount delegated and pending rewards
     */
    getDelegation(delegatorAddress: string, validatorAddress: string): Promise<{
        amount: string;
        pendingRewards: string;
    }>;
    /**
     * Get validator pool info
     * @param validatorAddress - Validator's address
     * @returns Pool info including total delegated, commission rate, and delegator count
     */
    getValidatorPool(validatorAddress: string): Promise<{
        totalDelegated: string;
        commissionRate: number;
        delegatorCount: number;
        isAcceptingDelegations: boolean;
    }>;
    /**
     * Get all delegations for a delegator
     * @param delegatorAddress - Delegator's address
     * @returns Array of all delegations with validator addresses and amounts
     */
    getDelegations(delegatorAddress: string): Promise<Array<{
        validator: string;
        amount: string;
        pendingRewards: string;
    }>>;
    /**
     * Get unbonding delegations for a delegator
     * @param delegatorAddress - Delegator's address
     * @returns Array of unbonding delegations with unlock times
     */
    getUnbondingDelegations(delegatorAddress: string): Promise<Array<{
        validator: string;
        amount: string;
        unlockTime: number;
    }>>;
    /**
     * Get list of validators accepting delegations
     * @returns Array of validator addresses with their pool info
     */
    getValidatorsWithDelegation(): Promise<Array<{
        address: string;
        totalDelegated: string;
        commissionRate: number;
        delegatorCount: number;
    }>>;
    /**
     * Get token info by token ID
     * @param tokenId - Token ID: the hex of the symbol's bytes followed by the
     * creator's 32-byte address (`tokenIdOf`)
     * @returns Token info or null if not found
     */
    getToken(tokenId: string): Promise<TokenInfo | null>;
    /**
     * Get the tokens a creator made (the node keeps a registry per creator;
     * there is no network-wide list)
     * @param creator - The creator's address (A1n or 64 hex)
     * @returns Array of token info
     */
    getTokens(creator: string): Promise<TokenInfo[]>;
    /**
     * Get token balance for an address
     * @param address - Wallet address
     * @param tokenId - Token ID (`tokenIdOf`)
     * @returns Token balance
     */
    getTokenBalance(address: string, tokenId: string): Promise<string>;
}
