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
     * Sign the transaction
     */
    sign(signer: Keypair) {
        if (signer.address !== this.sender) {
            throw new Error('Signer does not match sender');
        }
        // Include sequence number in signature payload
        // Note: In a real system, we should serialize the whole struct.
        // For now, we just sign the payload as before, BUT the Executor checks the sequence number separately.
        // WAIT! If we don't sign the sequence number, an attacker can change it!
        // We MUST include sequence number in the signed message.
        // Let's update the sign method to sign "payload + sequence_number"
        const message = `${this.payload}:${this.sequenceNumber}`;
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
