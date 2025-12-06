import { Keypair } from './keypair';
export declare class Transaction {
    sender: string;
    inputObjects: string[];
    payload: string;
    gasLimit: number;
    gasPrice: number;
    sequenceNumber: number;
    signature: string;
    constructor();
    /**
     * Create a transfer transaction
     */
    static createTransfer(sender: Keypair, to: string, amount: number, sequenceNumber?: number): Transaction;
    /**
     * Sign the transaction
     */
    sign(signer: Keypair): void;
    /**
     * Convert to JSON string for API
     */
    toString(): string;
}
