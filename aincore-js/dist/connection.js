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
}
exports.Connection = Connection;
