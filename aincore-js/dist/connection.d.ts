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
    }>;
    /**
     * Get balance of an address
     */
    getBalance(address: string): Promise<number>;
    /**
     * Get latest blocks
     */
    getBlocks(limit?: number): Promise<any[]>;
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
}
