"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = void 0;
class Transaction {
    constructor() {
        this.sender = '';
        this.inputObjects = [];
        this.payload = '';
        this.gasLimit = 10000;
        this.gasPrice = 1;
        this.sequenceNumber = 0;
        this.signature = '';
    }
    /**
     * Create a transfer transaction
     */
    static createTransfer(sender, to, amount, sequenceNumber = 0) {
        const tx = new Transaction();
        tx.sender = sender.address;
        tx.payload = `transfer:${to}:${amount}`;
        tx.sequenceNumber = sequenceNumber;
        return tx;
    }
    /**
     * Sign the transaction
     */
    sign(signer) {
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
    }
    /**
     * Convert to JSON string for API
     */
    toString() {
        return JSON.stringify({
            sender: this.sender,
            input_objects: this.inputObjects,
            payload: this.payload,
            gas_limit: this.gasLimit,
            gas_price: this.gasPrice,
            sequence_number: this.sequenceNumber,
            signature: this.signature,
        });
    }
}
exports.Transaction = Transaction;
