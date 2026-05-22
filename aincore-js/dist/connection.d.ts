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
export declare class Connection {
    private rpcUrl;
    private client;
    private indexerUrl?;
    constructor(endpoint: string, indexerEndpoint?: string);
    /**
     * Generic JSON-RPC call
     */
    request(method: string, params?: any[]): Promise<any>;
    /**
     * Get account data (balance, sequence number)
     */
    getAccount(address: string): Promise<{
        balance: number;
        sequence_number: number;
        move_balance: string;
        balance_source: string;
    }>;
    /**
     * Get native AIN balance from Move CoinStore.
     */
    getBalance(address: string): Promise<number>;
    /**
     * Get exact native AIN balance from Move CoinStore as a decimal string.
     */
    getMoveBalance(address: string): Promise<string>;
    /**
     * Request local/testnet faucet funds. Node must run with AINCORE_ENABLE_FAUCET=1.
     */
    requestFaucet(address: string, amount?: string | number, publicKey?: string): Promise<{
        address: string;
        amount: string;
        move_balance: string;
        balance_source: string;
    }>;
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
     * Send a signed transaction
     */
    sendTransaction(signedTxJson: string): Promise<string>;
    /**
     * Get transaction history from Indexer
     */
    getHistory(address: string): Promise<any[]>;
    /**
     * Get current gas price
     * Note: Returns default value as backend uses fixed gas pricing
     */
    getGasPrice(): Promise<number>;
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
        peers_count: number;
        latest_height: string;
    }>;
    /**
     * Get DAG vertices (for explorer/debugging)
     */
    getDag(): Promise<any[]>;
    /**
     * Get connected peers list
     */
    getPeers(): Promise<Array<{
        peer_id: string;
        multiaddr: string;
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
     * Wait for transaction confirmation
     * @param txHash - Transaction hash to wait for
     * @param timeout - Timeout in milliseconds (default 30000)
     * @param pollInterval - Polling interval in milliseconds (default 1000)
     */
    waitForConfirmation(txHash: string, timeout?: number, pollInterval?: number): Promise<{
        confirmed: boolean;
        transaction?: any;
    }>;
    /**
     * Get the latest block height
     */
    getLatestBlockHeight(): Promise<number>;
    /**
     * Get list of validators with their stake
     */
    getValidators(): Promise<Array<{
        address: string;
        stake: number;
        voting_power: number;
    }>>;
    /**
     * Get network information (supply, stats, etc.)
     */
    getNetworkInfo(): Promise<{
        chain_id: string;
        total_supply: number;
        circulating_supply: number;
        total_staked: number;
        validator_count: number;
        block_height: number;
        tps: number;
    }>;
    /**
     * Check if node is healthy
     */
    checkHealth(): Promise<boolean>;
    /**
     * Create a governance proposal
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
     * @param proposalId - Proposal ID
     * @param voter - Voter address
     * @param approve - true = approve, false = reject
     */
    vote(proposalId: string, voter: string, approve: boolean): Promise<{
        status: string;
    }>;
    /**
     * Get proposal details
     * @param proposalId - Proposal ID
     */
    getProposal(proposalId: string): Promise<any>;
    /**
     * Tally votes for a proposal
     * @param proposalId - Proposal ID
     */
    tally(proposalId: string): Promise<any>;
    /**
     * Get mining statistics
     */
    getMiningStats(): Promise<{
        active_miners: number;
        avg_bqi: number;
        network_hashrate: string;
        difficulty: number;
    }>;
    /**
     * Get mempool status (pending transactions)
     */
    getMempoolStatus(): Promise<{
        status: string;
        pending_tx_count: number;
    }>;
    /**
     * Get FHE (Fully Homomorphic Encryption) public key
     */
    getFheKey(): Promise<{
        public_key: string;
    }>;
    /**
     * Get Data Availability (DA) layer status
     */
    getDaStatus(): Promise<{
        da_mode: string;
        sequencer_id: string;
        erasure_coding: string;
        da_epoch: string;
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
     * @param tokenId - Token ID (symbol)
     * @returns Token info or null if not found
     */
    getToken(tokenId: string): Promise<{
        tokenId: string;
        name: string;
        symbol: string;
        decimals: number;
        maxSupply: string;
        currentSupply: string;
        creator: string;
        isMintable: boolean;
    } | null>;
    /**
     * Get all tokens created on the network
     * @returns Array of token info
     */
    getTokens(): Promise<Array<{
        tokenId: string;
        name: string;
        symbol: string;
        decimals: number;
        currentSupply: string;
    }>>;
    /**
     * Get token balance for an address
     * @param address - Wallet address
     * @param tokenId - Token ID (symbol)
     * @returns Token balance
     */
    getTokenBalance(address: string, tokenId: string): Promise<string>;
}
