"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Connection = void 0;
const axios_1 = __importDefault(require("axios"));
class Connection {
    constructor(endpoint, indexerEndpoint) {
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
     * Generic JSON-RPC call
     */
    async request(method, params = []) {
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
        }
        catch (error) {
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
    async getAccount(address) {
        const account = await this.request('aincore_getBalance', [address]);
        if (!account)
            return { balance: 0, sequence_number: 0 };
        if (account && account.data) {
            try {
                // Convert byte array to string
                const jsonString = Buffer.from(account.data).toString('utf-8');
                const accountData = JSON.parse(jsonString);
                return {
                    balance: accountData.balance || 0,
                    sequence_number: accountData.sequence_number || 0
                };
            }
            catch (e) {
                console.warn('Failed to parse account data', e);
                return { balance: 0, sequence_number: 0 };
            }
        }
        return { balance: 0, sequence_number: 0 };
    }
    /**
     * Get balance of an address
     */
    async getBalance(address) {
        const account = await this.getAccount(address);
        return account.balance;
    }
    /**
     * Get latest blocks
     */
    async getBlocks(limit = 10) {
        return await this.request('aincore_getBlocks', [limit]);
    }
    /**
     * Get transaction details
     */
    async getTransaction(hash) {
        return await this.request('aincore_getTransaction', [hash]);
    }
    /**
     * Send a signed transaction
     */
    async sendTransaction(signedTxJson) {
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
        try {
            const response = await axios_1.default.get(`${this.indexerUrl}/history/${address}`);
            return response.data;
        }
        catch (e) {
            console.error("Failed to fetch history from indexer", e);
            return [];
        }
    }
    /**
     * Get current gas price
     * Note: Returns default value as backend uses fixed gas pricing
     */
    async getGasPrice() {
        // AINCORE uses fixed gas pricing, return default
        return 1;
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
        return await this.request('aincore_nodeStatus', []);
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
    async getPeers() {
        return await this.request('aincore_getPeers', []);
    }
    /**
     * Get a single block by height
     */
    async getBlock(height) {
        const blocks = await this.request('aincore_getBlocks', [1]);
        // Backend returns latest blocks, so we need to fetch specific height
        // For now, use the block storage key pattern
        const allBlocks = await this.getBlocks(Math.max(height + 10, 100));
        return allBlocks.find((b) => b?.header?.height === height) || null;
    }
    /**
     * Wait for transaction confirmation
     * @param txHash - Transaction hash to wait for
     * @param timeout - Timeout in milliseconds (default 30000)
     * @param pollInterval - Polling interval in milliseconds (default 1000)
     */
    async waitForConfirmation(txHash, timeout = 30000, pollInterval = 1000) {
        const startTime = Date.now();
        while (Date.now() - startTime < timeout) {
            try {
                const tx = await this.getTransaction(txHash);
                if (tx && tx !== null) {
                    return { confirmed: true, transaction: tx };
                }
            }
            catch {
                // Transaction not found yet, continue polling
            }
            await new Promise(resolve => setTimeout(resolve, pollInterval));
        }
        return { confirmed: false };
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
    async getValidators() {
        // Use REST endpoint for validators
        try {
            const baseUrl = this.rpcUrl.replace('/rpc', '');
            const response = await axios_1.default.get(`${baseUrl}/get_validators`);
            return response.data.validators || [];
        }
        catch {
            // Fallback: return empty if endpoint not available
            return [];
        }
    }
    /**
     * Get network information (supply, stats, etc.)
     */
    async getNetworkInfo() {
        try {
            const baseUrl = this.rpcUrl.replace('/rpc', '');
            const response = await axios_1.default.get(`${baseUrl}/get_network_info`);
            return response.data;
        }
        catch {
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
    async checkHealth() {
        try {
            const baseUrl = this.rpcUrl.replace('/rpc', '');
            const response = await axios_1.default.get(`${baseUrl}/health`, { timeout: 5000 });
            return response.status === 200;
        }
        catch {
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
    async createProposal(id, title, description, proposer, durationSeconds) {
        return await this.request('aincore_createProposal', [id, title, description, proposer, durationSeconds]);
    }
    /**
     * Vote on a governance proposal
     * @param proposalId - Proposal ID
     * @param voter - Voter address
     * @param approve - true = approve, false = reject
     */
    async vote(proposalId, voter, approve) {
        return await this.request('aincore_vote', [proposalId, voter, approve]);
    }
    /**
     * Get proposal details
     * @param proposalId - Proposal ID
     */
    async getProposal(proposalId) {
        return await this.request('aincore_getProposal', [proposalId]);
    }
    /**
     * Tally votes for a proposal
     * @param proposalId - Proposal ID
     */
    async tally(proposalId) {
        return await this.request('aincore_tally', [proposalId]);
    }
    // =====================
    // MINING & SYSTEM METHODS
    // =====================
    /**
     * Get mining statistics
     */
    async getMiningStats() {
        return await this.request('aincore_getMiningStats', []);
    }
    /**
     * Get mempool status (pending transactions)
     */
    async getMempoolStatus() {
        return await this.request('aincore_getMempoolStatus', []);
    }
    /**
     * Get FHE (Fully Homomorphic Encryption) public key
     */
    async getFheKey() {
        return await this.request('aincore_getFheKey', []);
    }
    /**
     * Get Data Availability (DA) layer status
     */
    async getDaStatus() {
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
        const result = await this.request('aincore_getDelegations', [delegatorAddress]);
        return result || [];
    }
    /**
     * Get unbonding delegations for a delegator
     * @param delegatorAddress - Delegator's address
     * @returns Array of unbonding delegations with unlock times
     */
    async getUnbondingDelegations(delegatorAddress) {
        const result = await this.request('aincore_getUnbondingDelegations', [delegatorAddress]);
        return result || [];
    }
    /**
     * Get list of validators accepting delegations
     * @returns Array of validator addresses with their pool info
     */
    async getValidatorsWithDelegation() {
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
    async getToken(tokenId) {
        const result = await this.request('aincore_getToken', [tokenId]);
        if (!result)
            return null;
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
    async getTokens() {
        const result = await this.request('aincore_getTokens', []);
        return result || [];
    }
    /**
     * Get token balance for an address
     * @param address - Wallet address
     * @param tokenId - Token ID (symbol)
     * @returns Token balance
     */
    async getTokenBalance(address, tokenId) {
        const result = await this.request('aincore_getTokenBalance', [address, tokenId]);
        return result?.balance || '0';
    }
}
exports.Connection = Connection;
