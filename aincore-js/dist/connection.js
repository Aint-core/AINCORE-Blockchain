"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Connection = void 0;
const axios_1 = __importDefault(require("axios"));
/** Why `requestFaucet` and `requestTestMintWbtc` throw (G3 FX-8). */
const FAUCET_REMOVED = 'aincore_faucet and aincore_testMintWbtc were removed from the node: they wrote ' +
    'balances outside consensus. Fund the account with a signed transfer from a funded account.';
/** B177: the node's answer as a `TokenInfo`; only a missing field defaults
 * (a token of 0 decimals was reported as 18). */
function toTokenInfo(result, tokenId) {
    return {
        tokenId: result.token_id ?? tokenId ?? '',
        name: result.name ?? '',
        symbol: result.symbol ?? '',
        decimals: result.decimals ?? 18,
        maxSupply: result.max_supply ?? '0',
        currentSupply: result.current_supply ?? '0',
        creator: result.creator ?? '',
        isMintable: result.is_mintable !== false,
    };
}
/**
 * B479: an amount the node answers as a decimal string (a u128 of quanta),
 * exactly. `Number` rounded every amount past 2^53 quanta (about 0.009 AIN):
 * 1 AIN plus one quantum read as 1 AIN. Anything but the 1 to 39 decimal
 * digits a u128 takes is an error, not a guess (`BigInt` alone takes "0x10",
 * "" and " 7 ", and parses a million digits).
 */
function exactQuanta(text, method) {
    if (!/^[0-9]{1,39}$/.test(text)) {
        throw new Error(`${method} answered an amount that is not a decimal integer`);
    }
    return BigInt(text);
}
/** B260: the node's JSON-RPC code for a call refused for now (busy). */
const BUSY_CODE = -32005;
/**
 * B267: the calls the node runs one at a time a client (its reads and dry
 * runs: `READ_METHODS` and `DRY_METHODS` in the node's api_local.rs). A
 * Connection sends them one at a time, so a dapp's parallel calls queue
 * here instead of being refused as busy by the node.
 */
const HEAVY_METHODS = new Set([
    'aincore_getBlocks',
    'aincore_getBlockByHash',
    'aincore_getTransactionsByAddress',
    'aincore_getDag',
    'aincore_getTransaction',
    'aincore_getDaStatus',
    'aincore_sampleDA',
    'aincore_getStateProof',
    'aincore_estimateGas',
    'aincore_verifyQuorumCertificate',
]);
class Connection {
    constructor(endpoint, indexerEndpoint) {
        /**
         * B260: busy answers (-32005: the node's heavy-call slots are taken, or
         * this client's last heavy call still runs: one at a time a client) are
         * asked again this many times, after a wait doubling from
         * `busyBackoffMs`. They failed at once, so a dapp's parallel receipts
         * failed against the node's admission rules.
         */
        this.busyRetries = 4;
        this.busyBackoffMs = 250;
        /**
         * B267: how long one request may take before it fails (axios had no
         * timeout, so a stalled node held a call, and `waitForConfirmation`'s
         * own timeout, for good).
         */
        this.timeoutMs = 30000;
        /** B267: the heavy call this Connection sent last (`HEAVY_METHODS`). */
        this.heavyTail = Promise.resolve();
        this.rpcUrl = endpoint;
        this.indexerUrl = indexerEndpoint;
        this.client = axios_1.default.create({
            baseURL: endpoint,
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }
    /**
     * B267: the wait before busy retry `attempt`: half of
     * `busyBackoffMs * 2^attempt`, plus up to as much again at random, so
     * clients refused together do not all ask again at the same instant.
     */
    backoffMs(attempt) {
        const wait = this.busyBackoffMs * 2 ** attempt;
        return wait / 2 + Math.random() * (wait / 2);
    }
    /**
     * B329: a GET asked again on a rate limit (HTTP 429) or a busy answer
     * (HTTP 503), as `send` asks a busy JSON-RPC call again; any other
     * failure throws. The REST reads threw at the first 429, so a wallet took
     * a busy node for one that runs no chain or holds no validators.
     */
    async getWithRetry(url, config = {}) {
        for (let attempt = 0;; attempt++) {
            try {
                return await axios_1.default.get(url, { timeout: this.timeoutMs, ...config });
            }
            catch (error) {
                const status = error?.response?.status;
                if ((status === 429 || status === 503) && attempt < this.busyRetries) {
                    await new Promise((resolve) => setTimeout(resolve, this.backoffMs(attempt)));
                    continue;
                }
                throw error;
            }
        }
    }
    /**
     * Generic JSON-RPC call. B267: heavy calls one at a time.
     */
    async request(method, params = []) {
        if (!HEAVY_METHODS.has(method)) {
            return this.send(method, params);
        }
        const run = () => this.send(method, params);
        const result = this.heavyTail.then(run, run);
        this.heavyTail = result.then(() => undefined, () => undefined);
        return result;
    }
    async send(method, params) {
        const payload = {
            jsonrpc: '2.0',
            id: 1,
            method,
            params,
        };
        for (let attempt = 0;; attempt++) {
            let response;
            try {
                response = await this.client.post('', payload, { timeout: this.timeoutMs });
            }
            catch (error) {
                // B308: a rate limit (HTTP 429) is asked again, as a busy
                // answer is (it was thrown at once).
                if (error.response?.status === 429 && attempt < this.busyRetries) {
                    await new Promise((resolve) => setTimeout(resolve, this.backoffMs(attempt)));
                    continue;
                }
                console.error("RPC Request Failed:", error.message);
                if (error.response) {
                    console.error("Status:", error.response.status);
                    console.error("Data:", error.response.data);
                }
                throw new Error(`Connection Error: ${error.message}`);
            }
            const error = response.data.error;
            if (error) {
                if (error.code === BUSY_CODE && attempt < this.busyRetries) {
                    await new Promise((resolve) => setTimeout(resolve, this.backoffMs(attempt)));
                    continue;
                }
                throw new Error(`Connection Error: RPC Error: ${error.message}`);
            }
            return response.data.result;
        }
    }
    /**
     * Get account data (balance, sequence number). B479: `balance` is the
     * Move CoinStore balance in quanta, exactly, as a bigint (`move_balance`
     * is the same as a decimal string); it was a `number`, rounded past 2^53
     * quanta. A balance that is not a decimal integer throws.
     */
    async getAccount(address) {
        const account = await this.request('aincore_getBalance', [address]);
        if (!account) {
            return { balance: 0n, sequence_number: 0, move_balance: '0', balance_source: 'move_coin_store' };
        }
        const moveBalance = String(account.move_balance ?? '0');
        const balance = exactQuanta(moveBalance, 'aincore_getBalance');
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
            }
            catch (e) {
                console.warn('Failed to parse account data', e);
            }
        }
        return {
            balance,
            sequence_number: sequenceNumber,
            move_balance: moveBalance,
            balance_source: balanceSource,
        };
    }
    /**
     * The native AIN balance from the Move CoinStore, in quanta (10^18 to
     * the coin), exactly. B479: a bigint, the type transfer amounts take, so
     * `balance - fee` is exact. It was a `number`, which rounded every
     * balance past 2^53 quanta (about 0.009 AIN), and a "send max" built
     * from it could sign more than the account holds (included, aborted and
     * charged). For JSON, which carries no bigint, use `getMoveBalance`.
     */
    async getBalance(address) {
        const account = await this.getAccount(address);
        return account.balance;
    }
    /**
     * Get exact native AIN balance from Move CoinStore as a decimal string.
     */
    async getMoveBalance(address) {
        const account = await this.getAccount(address);
        return account.move_balance;
    }
    /**
     * Get account nonce/sequence number directly from the node wallet RPC.
     */
    async getAccountNonce(address) {
        const result = await this.request('aincore_getAccountNonce', [address]);
        return Number(result?.sequence_number ?? result?.nonce ?? 0);
    }
    /**
     * Get an exact Move CoinStore balance for native AIN or synthetic test WBTC.
     */
    async getCoinBalance(address, token) {
        return await this.request('aincore_getCoinBalance', [address, token]);
    }
    /**
     * G3 PF-1: the value of a consensus-state key (or its absence) with a
     * Merkle proof, plus that height's header and quorum certificate. Check
     * it with `verifyStateProof` against a root you trust, taken from a
     * verified quorum certificate, never from `state_root` in the answer.
     */
    async getStateProof(key, height) {
        const params = [key];
        if (height !== undefined)
            params.push(height);
        return await this.request('aincore_getStateProof', params);
    }
    /**
     * @deprecated Removed from the node (G3 FX-8). The faucet wrote balances
     * straight into one node's database, outside consensus. Fund an account
     * with a signed transfer from a funded account instead. Kept so callers
     * fail with the reason rather than a missing method.
     */
    async requestFaucet(_address, _amount, _publicKey) {
        throw new Error(FAUCET_REMOVED);
    }
    /**
     * @deprecated Removed from the node (G3 FX-8), like `requestFaucet`. WBTC
     * is minted by the bridge authority through a signed `wbtc::mint`.
     */
    async requestTestMintWbtc(_address, _amount, _publicKey) {
        throw new Error(FAUCET_REMOVED);
    }
    /**
     * Get latest blocks
     */
    async getBlocks(limit = 10) {
        return await this.request('aincore_getBlocks', [limit]);
    }
    /**
     * Get a forward block range in ascending order.
     */
    async getBlocksRange(startHeight, limit = 100) {
        return await this.request('aincore_getBlocks', [limit, startHeight]);
    }
    /**
     * Get transaction details
     */
    async getTransaction(hash) {
        return await this.request('aincore_getTransaction', [hash]);
    }
    /**
     * Get transaction receipt/status from the node.
     */
    async getTransactionReceipt(hash) {
        return await this.request('aincore_getTransactionReceipt', [hash]);
    }
    /**
     * B65: the execution gas `tx` needs, the state its writes add included:
     * the node runs it against the current state. Set `tx.executionGas` to
     * the answer, then `sign`.
     */
    async estimateExecutionGas(tx, publicKey) {
        const res = await this.request('aincore_estimateGas', [tx.estimateDraft(publicKey)]);
        return Number(res.execution_gas);
    }
    /**
     * Send a signed transaction
     */
    async sendTransaction(signedTxJson) {
        const res = await this.request('aincore_sendTransaction', [signedTxJson]);
        return res.tx_hash;
    }
    /**
     * Alias for browser/native wallet integrations that already produce tx JSON.
     */
    async submitSignedTransaction(signedTxJson) {
        const res = await this.request('aincore_sendTransaction', [signedTxJson]);
        return res.tx_hash;
    }
    /**
     * Get transaction history from Indexer
     */
    async getHistory(address) {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty history.");
            return [];
        }
        // B329: retried when busy, and an error is an error: every failure,
        // the indexer's own busy answer included, read as "no history".
        const response = await this.getWithRetry(`${this.indexerUrl}/history/${address}`);
        return response.data;
    }
    /**
     * The node's base fee (B15), quanta per gas, as a decimal string (it can
     * pass 2^53). A transaction's gasPrice must be at least this.
     */
    async getGasPrice() {
        const res = await this.request('aincore_getGasPrice', []);
        return String(res);
    }
    /**
     * Get any object by ID
     */
    async getObject(objectId) {
        return await this.request('aincore_getObject', [objectId]);
    }
    /**
     * Get node status (round, peers, height)
     */
    async getNodeStatus() {
        return await this.request('aincore_getStatus', []);
    }
    /**
     * Get DAG vertices (for explorer/debugging)
     */
    async getDag() {
        return await this.request('aincore_getDag', []);
    }
    /**
     * Get connected peers list
     */
    /** The node's sessions: PeerId and whether a committee key names it (B90: no addresses). */
    async getPeers() {
        return await this.request('aincore_getPeers', []);
    }
    /**
     * Get a single block by height
     */
    async getBlock(height) {
        const blocks = await this.getBlocksRange(height, 1);
        return blocks.find((b) => b?.header?.height === height) || null;
    }
    // =====================
    // DEX METHODS
    // =====================
    /**
     * Get all canonical DEX pools from the on-chain Move registry.
     */
    async getDexPools() {
        const result = await this.request('aincore_getDexPools', []);
        return result || [];
    }
    /**
     * Get a single DEX pool by canonical pool key or token pair.
     */
    async getDexPool(poolKeyOrTokenX, tokenY) {
        const params = tokenY === undefined
            ? [poolKeyOrTokenX]
            : [poolKeyOrTokenX, tokenY];
        const result = await this.request('aincore_getDexPool', params);
        return result || null;
    }
    /**
     * Quote a CPMM swap using the canonical on-chain pool state.
     */
    async getDexQuote(tokenIn, tokenOut, amountIn) {
        return await this.request('aincore_getDexQuote', [tokenIn, tokenOut, String(amountIn)]);
    }
    /**
     * Read a provider's native Move LPToken balance for a DEX pool.
     *
     * When `poolAddrOrTokenX` is omitted, the node defaults to the Phase DEX
     * AIN/WBTC market. Passing a pool address reads that pool directly; passing
     * `poolAddrOrTokenX` + `tokenY` resolves a canonical token pair.
     */
    async getDexLpBalance(address, poolAddrOrTokenX, tokenY) {
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
    async getDexSpotPrice(tokenIn, tokenOut, unitAmountIn = '1000000000000000000') {
        return await this.request('aincore_getDexSpotPrice', [
            tokenIn,
            tokenOut,
            String(unitAmountIn),
        ]);
    }
    /**
     * Read recent native DEX trades from the indexer.
     */
    async getDexTrades(tokenIn, tokenOut, limit = 100) {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty DEX trades.");
            return [];
        }
        const response = await this.getWithRetry(`${this.indexerUrl}/api/v1/trades`, {
            params: { base: tokenIn, quote: tokenOut, limit },
        });
        return response.data || [];
    }
    /**
     * Read native OHLC candles aggregated from DEX swap history.
     */
    async getDexOhlc(tokenIn, tokenOut, resolution = 15, limit = 5000) {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty OHLC.");
            return [];
        }
        const response = await this.getWithRetry(`${this.indexerUrl}/api/v1/ohlc`, {
            params: { base: tokenIn, quote: tokenOut, resolution, limit },
        });
        return response.data || [];
    }
    /**
     * Read a market summary for one canonical pair from the indexer.
     */
    async getDexPairSummary(tokenIn, tokenOut) {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning null DEX pair summary.");
            return null;
        }
        const response = await this.getWithRetry(`${this.indexerUrl}/api/v1/pair_summary`, {
            params: { base: tokenIn, quote: tokenOut },
        });
        return response.data || null;
    }
    /**
     * Read market summaries across all indexed canonical pools.
     */
    async getDexMarkets(limit = 50) {
        if (!this.indexerUrl) {
            console.warn("Indexer URL not configured. Returning empty DEX market list.");
            return [];
        }
        const response = await this.getWithRetry(`${this.indexerUrl}/api/v1/markets`, {
            params: { limit },
        });
        return response.data || [];
    }
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
    async waitForConfirmation(txHash, timeout = 30000, pollInterval = 1000) {
        const startTime = Date.now();
        let status = 'not_found';
        while (Date.now() - startTime < timeout) {
            try {
                const receipt = await this.getTransactionReceipt(txHash);
                if (receipt && typeof receipt.status === 'string') {
                    status = receipt.execution_receipt?.status ?? receipt.status;
                    const included = receipt.block_height !== undefined && receipt.block_height !== null;
                    if (included && status === 'success') {
                        const transaction = await this.getTransaction(txHash).catch(() => undefined);
                        return { confirmed: true, status, receipt, transaction };
                    }
                    if (included && status === 'aborted') {
                        return { confirmed: false, status, receipt };
                    }
                }
            }
            catch {
                // Not answered yet: keep polling.
            }
            await new Promise(resolve => setTimeout(resolve, pollInterval));
        }
        return { confirmed: false, status };
    }
    /**
     * Get the latest block height
     */
    async getLatestBlockHeight() {
        const status = await this.getNodeStatus();
        return parseInt(status.latest_height) || 0;
    }
    /**
     * Get list of validators with their stake
     */
    /**
     * The node's active validators, as `/get_validators` answers them
     * (B236): it throws when the node cannot be reached or answers no list.
     * It used to answer [] on any failure, and typed a `voting_power` the
     * node never sends.
     */
    async getValidators() {
        const response = await this.getWithRetry(`${this.restBase()}/get_validators`);
        const validators = response.data?.validators;
        if (!Array.isArray(validators)) {
            throw new Error('get_validators answered no validator list');
        }
        return validators;
    }
    /**
     * B236: the node's REST root: the RPC endpoint without a trailing
     * `/rpc`. Cutting the first "/rpc" anywhere in it turned
     * `https://rpc.example/rpc` into `https:/.example/rpc`.
     */
    restBase() {
        return this.rpcUrl.replace(/\/rpc\/?$/, '');
    }
    /**
     * The node's network information, as the node answers it (B223): the
     * chain it runs (`chain_id`, the node's `network`), its latest block,
     * its peers and committee sessions, the recent TPS. It throws when the
     * node cannot be reached: it used to answer a guessed object instead,
     * with `chain_id` 'AINCORE-MAINNET-1' whatever the node runs, so a
     * client that took its chain id from here signed for mainnet.
     */
    async getNetworkInfo() {
        const response = await this.getWithRetry(`${this.restBase()}/get_network_info`);
        const info = response.data;
        if (typeof info?.network !== 'string' || info.network === '') {
            throw new Error('get_network_info answered no chain id');
        }
        return {
            chain_id: info.network,
            node_id: info.node_id ?? null,
            block_height: Number(info.latest_block),
            current_round: info.current_round == null ? null : Number(info.current_round),
            peer_count: Number(info.peer_count),
            committee_sessions: Number(info.committee_sessions),
            tps: Number(info.tps),
            protocol_version: Number(info.protocol_version),
        };
    }
    /**
     * Check if node is healthy
     */
    async checkHealth() {
        try {
            const response = await this.getWithRetry(`${this.restBase()}/health`, { timeout: 5000 });
            return response.status === 200;
        }
        catch (error) {
            // B329: a node that answers "too many requests" is up.
            return error?.response?.status === 429;
        }
    }
    // =====================
    // GOVERNANCE METHODS
    // =====================
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
    async createProposal(id, title, description, proposer, durationSeconds) {
        return await this.request('aincore_createProposal', [id, title, description, proposer, durationSeconds]);
    }
    /**
     * Vote on a governance proposal
     * @deprecated The node refuses `aincore_vote`: submit a signed transaction
     * calling `0x1::governance::vote` (sendTransaction).
     * @param proposalId - Proposal ID
     * @param voter - Voter address
     * @param approve - true = approve, false = reject
     */
    async vote(proposalId, voter, approve) {
        return await this.request('aincore_vote', [proposalId, voter, approve]);
    }
    /**
     * A proposal as `0x1::governance` holds it on chain (B194): `id`,
     * `proposer`, `description`, `votes_for` / `votes_against` (decimal
     * strings), `executed`, `action_type`, `voting_ends` (consensus time,
     * seconds). `null` when there is no such proposal.
     * @param proposalId - Proposal id (a number, or its decimal string)
     */
    async getProposal(proposalId) {
        return await this.request('aincore_getProposal', [proposalId]);
    }
    /**
     * The votes of a proposal as the chain holds them (B194): `id`,
     * `votes_for`, `votes_against`, `executed`, `voting_ends`. Read-only.
     * @param proposalId - Proposal id (a number, or its decimal string)
     */
    async tally(proposalId) {
        return await this.request('aincore_tally', [proposalId]);
    }
    // =====================
    // MINING & SYSTEM METHODS
    // =====================
    /**
     * Get mempool status (pending transactions)
     */
    async getMempoolStatus() {
        return await this.request('aincore_getMempoolStatus', []);
    }
    /**
     * A block's data availability root and shard layout (the tip by default).
     * Check samples against the da_root of a header you hold under a QC, not
     * against this response. B478: the layout is a hint too. Draw the first
     * index from `total_shards`, every later one from the `totalShards` a
     * verified sample returns (the count the root commits to), and take a
     * `total_shards` below that count as a lie: a server holding 2 shards of
     * 256 answered 2, and every draw from it verified.
     */
    async getDaStatus(height) {
        return await this.request('aincore_getDaStatus', height === undefined ? [] : [height]);
    }
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
    async sampleDA(height, index) {
        return await this.request('aincore_sampleDA', [height, index]);
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
    async getDelegation(delegatorAddress, validatorAddress) {
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
    async getValidatorPool(validatorAddress) {
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
    async getDelegations(delegatorAddress) {
        // B329: the node names the fields in snake_case; they were passed on
        // as they came, so `pendingRewards` was always undefined.
        const result = await this.request('aincore_getDelegations', [delegatorAddress]);
        return (result || []).map((d) => ({
            validator: d.validator,
            amount: String(d.amount ?? '0'),
            pendingRewards: String(d.pending_rewards ?? '0'),
        }));
    }
    /**
     * Get unbonding delegations for a delegator
     * @param delegatorAddress - Delegator's address
     * @returns Array of unbonding delegations with unlock times
     */
    async getUnbondingDelegations(delegatorAddress) {
        const result = await this.request('aincore_getUnbondingDelegations', [delegatorAddress]);
        return (result || []).map((d) => ({
            validator: d.validator,
            amount: String(d.amount ?? '0'),
            unlockTime: Number(d.unlock_time ?? 0),
        }));
    }
    /**
     * Get list of validators accepting delegations
     * @returns Array of validator addresses with their pool info
     */
    async getValidatorsWithDelegation() {
        const result = await this.request('aincore_getValidatorsWithDelegation', []);
        return (result || []).map((v) => ({
            address: v.address,
            totalDelegated: String(v.total_delegated ?? '0'),
            commissionRate: Number(v.commission_rate ?? 0),
            delegatorCount: Number(v.delegator_count ?? 0),
        }));
    }
    // =====================
    // TOKEN FACTORY METHODS
    // =====================
    /**
     * Get token info by token ID
     * @param tokenId - Token ID: the hex of the symbol's bytes followed by the
     * creator's 32-byte address (`tokenIdOf`)
     * @returns Token info or null if not found
     */
    async getToken(tokenId) {
        const result = await this.request('aincore_getToken', [tokenId]);
        if (!result)
            return null;
        return toTokenInfo(result, tokenId);
    }
    /**
     * Get the tokens a creator made (the node keeps a registry per creator;
     * there is no network-wide list)
     * @param creator - The creator's address (A1n or 64 hex)
     * @returns Array of token info
     */
    async getTokens(creator) {
        const result = await this.request('aincore_getTokens', [creator]);
        return (result || []).map((token) => toTokenInfo(token));
    }
    /**
     * Get token balance for an address
     * @param address - Wallet address
     * @param tokenId - Token ID (`tokenIdOf`)
     * @returns Token balance
     */
    async getTokenBalance(address, tokenId) {
        const result = await this.request('aincore_getTokenBalance', [address, tokenId]);
        return result?.balance || '0';
    }
}
exports.Connection = Connection;
