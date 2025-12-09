import { Keypair } from './keypair';

export class Transaction {
    sender: string;
    inputObjects: string[];
    payload: string;
    gasLimit: number;
    gasPrice: number;
    sequenceNumber: number; // Replay Protection
    publicKey: string;
    signature: string;
    chainId: string; // Replay Protection
    paymaster?: string;
    paymasterSignature?: string;

    constructor() {
        this.sender = '';
        this.inputObjects = [];
        this.payload = '';
        this.gasLimit = 10000;
        this.gasPrice = 1;
        this.sequenceNumber = 0;
        this.publicKey = '';
        this.signature = '';
        this.chainId = 'AINCORE-MAINNET-1';
    }

    /**
     * Create a transfer transaction
     */
    static createTransfer(sender: Keypair, to: string, amount: number, sequenceNumber: number = 0): Transaction {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `transfer:${to}:${amount}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }

    /**
     * Set Chain ID (e.g. for Testnet)
     */
    setChainId(chainId: string) {
        this.chainId = chainId;
    }

    /**
     * Sign the transaction
     */
    sign(signer: Keypair) {
        if (signer.address !== this.sender) {
            throw new Error('Signer does not match sender');
        }
        // Include sequence number AND Chain ID in signature payload (REPLAY PROTECTION)
        const message = `${this.chainId}:${this.payload}:${this.sequenceNumber}`;
        this.signature = signer.sign(Buffer.from(message));
        this.publicKey = signer.publicKey;
    }

    /**
     * Set Paymaster details
     */
    setPaymaster(paymasterAddress: string, signature: string) {
        this.paymaster = paymasterAddress;
        this.paymasterSignature = signature;
    }

    /**
     * Convert to JSON string for API
     */
    toString(): string {
        const json: any = {
            chain_id: this.chainId,
            sender: this.sender,
            input_objects: this.inputObjects,
            payload: this.payload,
            gas_limit: this.gasLimit,
            gas_price: this.gasPrice,
            sequence_number: this.sequenceNumber,
            public_key: this.publicKey,
            signature: this.signature,
        };

        if (this.paymaster) {
            json.paymaster = this.paymaster;
            json.paymaster_signature = this.paymasterSignature;
        }

        return JSON.stringify(json);
    }
}
