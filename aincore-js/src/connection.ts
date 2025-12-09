import axios, { AxiosInstance } from 'axios';

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
    async getAccount(address: string): Promise<{ balance: number, sequence_number: number }> {
        const account = await this.request('aincore_getBalance', [address]);
        if (!account) return { balance: 0, sequence_number: 0 };

        if (account && account.data) {
            try {
                // Convert byte array to string
                const jsonString = Buffer.from(account.data).toString('utf-8');
                const accountData = JSON.parse(jsonString);
                return {
                    balance: accountData.balance || 0,
                    sequence_number: accountData.sequence_number || 0
                };
            } catch (e) {
                console.warn('Failed to parse account data', e);
                return { balance: 0, sequence_number: 0 };
            }
        }
        return { balance: 0, sequence_number: 0 };
    }

    /**
     * Get balance of an address
     */
    async getBalance(address: string): Promise<number> {
        const account = await this.getAccount(address);
        return account.balance;
    }

    /**
     * Get latest blocks
     */
    async getBlocks(limit: number = 10): Promise<any[]> {
        return await this.request('aincore_getBlocks', [limit]);
    }

    /**
     * Get transaction details
     */
    async getTransaction(hash: string): Promise<any> {
        return await this.request('aincore_getTransaction', [hash]);
    }

    /**
     * Send a signed transaction
     */
    async sendTransaction(signedTxJson: string): Promise<string> {
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
     */
    async getGasPrice(): Promise<number> {
        return await this.request('aincore_getGasPrice', []);
    }
}
