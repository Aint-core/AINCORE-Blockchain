import axios, { AxiosInstance } from 'axios';

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

export class Connection {
    private rpcUrl: string;
    private client: AxiosInstance;
    private indexerUrl?: string;

    constructor(endpoint: string, indexerEndpoint?: string) {
        this.rpcUrl = endpoint;
        this.indexerUrl = indexerEndpoint;
        this.client = axios.create({
            baseURL: endpoint,
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    /**
     * Generic JSON-RPC call
     */
    async request(method: string, params: any[] = []): Promise<any> {
        const payload = {
            jsonrpc: '2.0',
            id: 1,
            method,
            params,
        };

        try {
            const response = await this.client.post('', payload);
            if (response.data.error) {
                throw new Error(`RPC Error: ${response.data.error.message}`);
            }
            return response.data.result;
        } catch (error: any) {
            console.error("RPC Request Failed:", error.message);
            if (error.response) {
                console.error("Status:", error.response.status);
                console.error("Data:", error.response.data);
            }
            throw new Error(`Connection Error: ${error.message}`);
        }
    }

    /**
     * Get account data (balance, sequence number)
     */
    async getAccount(address: string): Promise<{ balance: number, sequence_number: number, move_balance: string, balance_source: string }> {
        const account = await this.request('aincore_getBalance', [address]);
        if (!account) {
            return { balance: 0, sequence_number: 0, move_balance: '0', balance_source: 'move_coin_store' };
        }

        const moveBalance = String(account.move_balance ?? '0');
        const balanceSource = String(account.balance_source ?? 'move_coin_store');
        let sequenceNumber = 0;

        if (account && account.data) {
            try {
                const data = typeof account.data === 'string'
                    ? Buffer.from(account.data, /^[0-9a-fA-F]+$/.test(account.data) ? 'hex' : 'utf-8')
                    : Buffer.from(account.data);
                const jsonString = data.toString('utf-8');
                const accountData = JSON.parse(jsonString);
                sequenceNumber = accountData.sequence_number || 0;
            } catch (e) {
                console.warn('Failed to parse account data', e);
            }
        }

        return {
            balance: Number(moveBalance),
            sequence_number: sequenceNumber,
            move_balance: moveBalance,
            balance_source: balanceSource,
        };
    }

    /**
     * Get native AIN balance from Move CoinStore.
     */
    async getBalance(address: string): Promise<number> {
        const account = await this.getAccount(address);
        return account.balance;
    }

    /**
     * Get exact native AIN balance from Move CoinStore as a decimal string.
     */
    async getMoveBalance(address: string): Promise<string> {
        const account = await this.getAccount(address);
        return account.move_balance;
    }

    /**
     * Get account nonce/sequence number directly from the node wallet RPC.
     */
    async getAccountNonce(address: string): Promise<number> {
        const result = await this.request('aincore_getAccountNonce', [address]);
        return Number(result?.sequence_number ?? result?.nonce ?? 0);
    }

    /**
     * Get an exact Move CoinStore balance for native AIN or synthetic test WBTC.
     */
    async getCoinBalance(address: string, token: 'AIN' | 'WBTC' | string): Promise<{
        address: string;
        token: string;
        balance: string;
        decimals: number;
        balance_source: string;
        market_mode?: string;
    }> {
        return await this.request('aincore_getCoinBalance', [address, token]);
    }

    /**
     * Request local/testnet faucet funds. Node must run with AINCORE_ENABLE_FAUCET=1.
     */
    async requestFaucet(address: string, amount?: string | number, publicKey?: string): Promise<{
        address: string;
        amount: string;
        move_balance: string;
        balance_source: string;
    }> {
        const params: any[] = [address];
        if (amount !== undefined) params.push(String(amount));
        if (publicKey !== undefined) {
            if (amount === undefined) params.push('1000000000000000000');
            params.push(publicKey);
        }
        return await this.request('aincore_faucet', params);
    }

    /**
     * Mint synthetic WBTC for local/testnet DEX smoke tests.
     * This does not represent real BTC backing.
     */
    async requestTestMintWbtc(address: string, amount: string | number, publicKey?: string): Promise<{
        address: string;
        amount: string;
        wbtc_balance: string;
        balance_source: string;
        faucet_mode: string;
    }> {
        const params: any[] = [address, String(amount)];
        if (publicKey !== undefined) params.push(publicKey);
        return await this.request('aincore_testMintWbtc', params);
    }

    /**
     * Get latest blocks
     */
    async getBlocks(limit: number = 10): Promise<any[]> {
        return await this.request('aincore_getBlocks', [limit]);
    }

    /**
     * Get a forward block range in ascending order.
     */
    async getBlocksRange(startHeight: number, limit: number = 100): Promise<any[]> {
        return await this.request('aincore_getBlocks', [limit, startHeight]);
    }

    /**
     * Get transaction details
     */
    async getTransaction(hash: string): Promise<any> {
        return await this.request('aincore_getTransaction', [hash]);
    }

    /**
     * Get transaction receipt/status from the node.
     */
    async getTransactionReceipt(hash: string): Promise<TransactionReceipt> {
        return await this.request('aincore_getTransactionReceipt', [hash]);
    }

    /**
     * Send a signed transaction
     */
    async sendTransaction(signedTxJson: string): Promise<string> {
        const res = await this.request('aincore_sendTransaction', [signedTxJson]);
        return res.tx_hash;
    }

    /**
     * Alias for browser/native wallet integrations that already produce tx JSON.
     */
    async submitSignedTransaction(signedTxJson: string | Record<string, unknown>): Promise<string> {
        const res = await this.request('aincore_sendTransaction', [signedTxJson]);
        return res.tx_hash;
    }

    /**
     * Get transaction history from Indexer
     */
    async getHistory(address: string): Promise<any[]> {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty history.");
            return [];
        }
        try {
            const response = await axios.get(`${this.indexerUrl}/history/${address}`);
            return response.data;
        } catch (e) {
            console.error("Failed to fetch history from indexer", e);
            return [];
        }
    }

    /**
     * Get current gas price
     * Note: Returns default value as backend uses fixed gas pricing
     */
    async getGasPrice(): Promise<number> {
        // AINCORE uses fixed gas pricing, return default
        return 1;
    }

    /**
     * Get any object by ID
     */
    async getObject(objectId: string): Promise<any> {
        return await this.request('aincore_getObject', [objectId]);
    }

    /**
     * Get node status (round, peers, height)
     */
    async getNodeStatus(): Promise<{
        node_id: string;
        current_round: number;
        peers_count: number;
        latest_height: string;
    }> {
        return await this.request('aincore_nodeStatus', []);
    }

    /**
     * Get DAG vertices (for explorer/debugging)
     */
    async getDag(): Promise<any[]> {
        return await this.request('aincore_getDag', []);
    }

    /**
     * Get connected peers list
     */
    async getPeers(): Promise<Array<{ peer_id: string; multiaddr: string }>> {
        return await this.request('aincore_getPeers', []);
    }

    /**
     * Get a single block by height
     */
    async getBlock(height: number): Promise<any> {
        const blocks = await this.getBlocksRange(height, 1);
        return blocks.find((b: any) => b?.header?.height === height) || null;
    }

    // =====================
    // DEX METHODS
    // =====================

    /**
     * Get all canonical DEX pools from the on-chain Move registry.
     */
    async getDexPools(): Promise<DexPool[]> {
        const result = await this.request('aincore_getDexPools', []);
        return result || [];
    }

    /**
     * Get a single DEX pool by canonical pool key or token pair.
     */
    async getDexPool(poolKeyOrTokenX: string, tokenY?: string): Promise<DexPool | null> {
        const params = tokenY === undefined
            ? [poolKeyOrTokenX]
            : [poolKeyOrTokenX, tokenY];
        const result = await this.request('aincore_getDexPool', params);
        return result || null;
    }

    /**
     * Quote a CPMM swap using the canonical on-chain pool state.
     */
    async getDexQuote(tokenIn: string, tokenOut: string, amountIn: string | number): Promise<DexQuote> {
        return await this.request('aincore_getDexQuote', [tokenIn, tokenOut, String(amountIn)]);
    }

    /**
     * Read a provider's native Move LPToken balance for a DEX pool.
     *
     * When `poolAddrOrTokenX` is omitted, the node defaults to the Phase DEX
     * AIN/WBTC market. Passing a pool address reads that pool directly; passing
     * `poolAddrOrTokenX` + `tokenY` resolves a canonical token pair.
     */
    async getDexLpBalance(
        address: string,
        poolAddrOrTokenX?: string,
        tokenY?: string,
    ): Promise<DexLpBalance> {
        const params = tokenY === undefined
            ? poolAddrOrTokenX === undefined
                ? [address]
                : [address, poolAddrOrTokenX]
            : [address, poolAddrOrTokenX, tokenY];
        return await this.request('aincore_getDexLpBalance', params);
    }

    /**
     * Compute spot price from current reserves for a canonical pool.
     * Returns how many `tokenOut` units back one whole `tokenIn` unit.
     */
    async getDexSpotPrice(
        tokenIn: string,
        tokenOut: string,
        unitAmountIn: string | number = '1000000000000000000',
    ): Promise<DexSpotPrice> {
        return await this.request('aincore_getDexSpotPrice', [
            tokenIn,
            tokenOut,
            String(unitAmountIn),
        ]);
    }

    /**
     * Read recent native DEX trades from the indexer.
     */
    async getDexTrades(tokenIn: string, tokenOut: string, limit: number = 100): Promise<DexTrade[]> {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty DEX trades.");
            return [];
        }
        try {
            const response = await axios.get(`${this.indexerUrl}/api/v1/trades`, {
                params: { base: tokenIn, quote: tokenOut, limit },
            });
            return response.data || [];
        } catch (e) {
            console.error("Failed to fetch DEX trades from indexer", e);
            return [];
        }
    }

    /**
     * Read native OHLC candles aggregated from DEX swap history.
     */
    async getDexOhlc(
        tokenIn: string,
        tokenOut: string,
        resolution: number = 15,
        limit: number = 5000,
    ): Promise<DexOhlcCandle[]> {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty OHLC.");
            return [];
        }
        try {
            const response = await axios.get(`${this.indexerUrl}/api/v1/ohlc`, {
                params: { base: tokenIn, quote: tokenOut, resolution, limit },
            });
            return response.data || [];
        } catch (e) {
            console.error("Failed to fetch DEX OHLC from indexer", e);
            return [];
        }
    }

    /**
     * Read a market summary for one canonical pair from the indexer.
     */
    async getDexPairSummary(tokenIn: string, tokenOut: string): Promise<DexPairSummary | null> {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning null DEX pair summary.");
            return null;
        }
        try {
            const response = await axios.get(`${this.indexerUrl}/api/v1/pair_summary`, {
                params: { base: tokenIn, quote: tokenOut },
            });
            return response.data || null;
        } catch (e) {
            console.error("Failed to fetch DEX pair summary from indexer", e);
            return null;
        }
    }

    /**
     * Read market summaries across all indexed canonical pools.
     */
    async getDexMarkets(limit: number = 50): Promise<DexMarketSummary[]> {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty DEX market list.");
            return [];
        }
        try {
            const response = await axios.get(`${this.indexerUrl}/api/v1/markets`, {
                params: { limit },
            });
            return response.data || [];
        } catch (e) {
            console.error("Failed to fetch DEX markets from indexer", e);
            return [];
        }
    }

    /**
     * Wait for transaction confirmation
     * @param txHash - Transaction hash to wait for
     * @param timeout - Timeout in milliseconds (default 30000)
     * @param pollInterval - Polling interval in milliseconds (default 1000)
     */
    async waitForConfirmation(
        txHash: string,
        timeout: number = 30000,
        pollInterval: number = 1000
    ): Promise<{ confirmed: boolean; transaction?: any }> {
        const startTime = Date.now();

        while (Date.now() - startTime < timeout) {
            try {
                const tx = await this.getTransaction(txHash);
                if (tx && tx !== null) {
                    return { confirmed: true, transaction: tx };
                }
            } catch {
                // Transaction not found yet, continue polling
            }

            await new Promise(resolve => setTimeout(resolve, pollInterval));
        }

        return { confirmed: false };
    }

    /**
     * Get the latest block height
     */
    async getLatestBlockHeight(): Promise<number> {
        const status = await this.getNodeStatus();
        return parseInt(status.latest_height) || 0;
    }

    /**
     * Get list of validators with their stake
     */
    async getValidators(): Promise<Array<{
        address: string;
        stake: number;
        voting_power: number;
    }>> {
        // Use REST endpoint for validators
        try {
            const baseUrl = this.rpcUrl.replace('/rpc', '');
            const response = await axios.get(`${baseUrl}/get_validators`);
            return response.data.validators || [];
        } catch {
            // Fallback: return empty if endpoint not available
            return [];
        }
    }

    /**
     * Get network information (supply, stats, etc.)
     */
    async getNetworkInfo(): Promise<{
        chain_id: string;
        total_supply: number;
        circulating_supply: number;
        total_staked: number;
        validator_count: number;
        block_height: number;
        tps: number;
    }> {
        try {
            const baseUrl = this.rpcUrl.replace('/rpc', '');
            const response = await axios.get(`${baseUrl}/get_network_info`);
            return response.data;
        } catch {
            // Fallback with defaults
            const status = await this.getNodeStatus();
            return {
                chain_id: 'AINCORE-MAINNET-1',
                total_supply: 0,
                circulating_supply: 0,
                total_staked: 0,
                validator_count: status.peers_count + 1,
                block_height: parseInt(status.latest_height) || 0,
                tps: 0,
            };
        }
    }

    /**
     * Check if node is healthy
     */
    async checkHealth(): Promise<boolean> {
        try {
            const baseUrl = this.rpcUrl.replace('/rpc', '');
            const response = await axios.get(`${baseUrl}/health`, { timeout: 5000 });
            return response.status === 200;
        } catch {
            return false;
        }
    }

    // =====================
    // GOVERNANCE METHODS
    // =====================

    /**
     * Create a governance proposal
     * @param id - Unique proposal ID
     * @param title - Proposal title
     * @param description - Proposal description
     * @param proposer - Proposer address
     * @param durationSeconds - Voting duration in seconds
     */
    async createProposal(
        id: string,
        title: string,
        description: string,
        proposer: string,
        durationSeconds: number
    ): Promise<{ status: string; proposal_id: string }> {
        return await this.request('aincore_createProposal', [id, title, description, proposer, durationSeconds]);
    }

    /**
     * Vote on a governance proposal
     * @param proposalId - Proposal ID
     * @param voter - Voter address
     * @param approve - true = approve, false = reject
     */
    async vote(proposalId: string, voter: string, approve: boolean): Promise<{ status: string }> {
        return await this.request('aincore_vote', [proposalId, voter, approve]);
    }

    /**
     * Get proposal details
     * @param proposalId - Proposal ID
     */
    async getProposal(proposalId: string): Promise<any> {
        return await this.request('aincore_getProposal', [proposalId]);
    }

    /**
     * Tally votes for a proposal
     * @param proposalId - Proposal ID
     */
    async tally(proposalId: string): Promise<any> {
        return await this.request('aincore_tally', [proposalId]);
    }

    // =====================
    // MINING & SYSTEM METHODS
    // =====================

    /**
     * Get mining statistics
     */
    async getMiningStats(): Promise<{
        active_miners: number;
        avg_bqi: number;
        network_hashrate: string;
        difficulty: number;
    }> {
        return await this.request('aincore_getMiningStats', []);
    }

    /**
     * Get mempool status (pending transactions)
     */
    async getMempoolStatus(): Promise<{
        status: string;
        pending_tx_count: number;
    }> {
        return await this.request('aincore_getMempoolStatus', []);
    }

    /**
     * Get FHE (Fully Homomorphic Encryption) public key
     */
    async getFheKey(): Promise<{ public_key: string }> {
        return await this.request('aincore_getFheKey', []);
    }

    /**
     * Get Data Availability (DA) layer status
     */
    async getDaStatus(): Promise<{
        da_mode: string;
        sequencer_id: string;
        erasure_coding: string;
        da_epoch: string;
    }> {
        return await this.request('aincore_getDaStatus', []);
    }

    // =====================
    // DELEGATION METHODS
    // =====================

    /**
     * Get delegation info for a delegator to a specific validator
     * @param delegatorAddress - Delegator's address
     * @param validatorAddress - Validator's address
     * @returns Object with amount delegated and pending rewards
     */
    async getDelegation(
        delegatorAddress: string,
        validatorAddress: string
    ): Promise<{ amount: string; pendingRewards: string }> {
        const result = await this.request('aincore_getDelegation', [delegatorAddress, validatorAddress]);
        return {
            amount: result?.amount || '0',
            pendingRewards: result?.pending_rewards || '0'
        };
    }

    /**
     * Get validator pool info
     * @param validatorAddress - Validator's address
     * @returns Pool info including total delegated, commission rate, and delegator count
     */
    async getValidatorPool(validatorAddress: string): Promise<{
        totalDelegated: string;
        commissionRate: number;
        delegatorCount: number;
        isAcceptingDelegations: boolean;
    }> {
        const result = await this.request('aincore_getValidatorPool', [validatorAddress]);
        return {
            totalDelegated: result?.total_delegated || '0',
            commissionRate: result?.commission_rate || 0,
            delegatorCount: result?.delegator_count || 0,
            isAcceptingDelegations: result?.is_accepting || false
        };
    }

    /**
     * Get all delegations for a delegator
     * @param delegatorAddress - Delegator's address
     * @returns Array of all delegations with validator addresses and amounts
     */
    async getDelegations(delegatorAddress: string): Promise<Array<{
        validator: string;
        amount: string;
        pendingRewards: string;
    }>> {
        const result = await this.request('aincore_getDelegations', [delegatorAddress]);
        return result || [];
    }

    /**
     * Get unbonding delegations for a delegator
     * @param delegatorAddress - Delegator's address
     * @returns Array of unbonding delegations with unlock times
     */
    async getUnbondingDelegations(delegatorAddress: string): Promise<Array<{
        validator: string;
        amount: string;
        unlockTime: number;
    }>> {
        const result = await this.request('aincore_getUnbondingDelegations', [delegatorAddress]);
        return result || [];
    }

    /**
     * Get list of validators accepting delegations
     * @returns Array of validator addresses with their pool info
     */
    async getValidatorsWithDelegation(): Promise<Array<{
        address: string;
        totalDelegated: string;
        commissionRate: number;
        delegatorCount: number;
    }>> {
        const result = await this.request('aincore_getValidatorsWithDelegation', []);
        return result || [];
    }

    // =====================
    // TOKEN FACTORY METHODS
    // =====================

    /**
     * Get token info by token ID
     * @param tokenId - Token ID (symbol)
     * @returns Token info or null if not found
     */
    async getToken(tokenId: string): Promise<{
        tokenId: string;
        name: string;
        symbol: string;
        decimals: number;
        maxSupply: string;
        currentSupply: string;
        creator: string;
        isMintable: boolean;
    } | null> {
        const result = await this.request('aincore_getToken', [tokenId]);
        if (!result) return null;
        return {
            tokenId: result.token_id || tokenId,
            name: result.name || '',
            symbol: result.symbol || '',
            decimals: result.decimals || 18,
            maxSupply: result.max_supply || '0',
            currentSupply: result.current_supply || '0',
            creator: result.creator || '',
            isMintable: result.is_mintable !== false
        };
    }

    /**
     * Get all tokens created on the network
     * @returns Array of token info
     */
    async getTokens(): Promise<Array<{
        tokenId: string;
        name: string;
        symbol: string;
        decimals: number;
        currentSupply: string;
    }>> {
        const result = await this.request('aincore_getTokens', []);
        return result || [];
    }

    /**
     * Get token balance for an address
     * @param address - Wallet address
     * @param tokenId - Token ID (symbol)
     * @returns Token balance
     */
    async getTokenBalance(address: string, tokenId: string): Promise<string> {
        const result = await this.request('aincore_getTokenBalance', [address, tokenId]);
        return result?.balance || '0';
    }
}
