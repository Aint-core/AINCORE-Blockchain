// B123 and B129 witnesses: the SDK refuses input it cannot encode exactly,
// and reports a transaction confirmed only once a block executed it.
import { Keypair } from './src/keypair';
import { Transaction } from './src/transaction';
import { Connection } from './src/connection';
import { bcsU64, bcsU128, hexToBytes } from './src/bcs';

function throws(what: string, f: () => unknown): void {
    try {
        f();
    } catch {
        return;
    }
    throw new Error(`${what}: accepted`);
}

async function main(): Promise<void> {
    const sender = Keypair.fromSeed(new Uint8Array(32).fill(7));
    const recipient = Keypair.fromSeed(new Uint8Array(32).fill(8));
    // B129: a typo in an address, a negative amount, an amount past u128.
    const typo = recipient.address.slice(0, 63) + 'g';
    throws('a non-hex address', () => Transaction.createTransfer(sender, typo, 1n));
    throws('an odd hex string', () => hexToBytes('abc'));
    throws('a negative amount', () => Transaction.createTransfer(sender, recipient.address, -1n));
    throws('an amount past u128', () => Transaction.createTransfer(sender, recipient.address, 1n << 128n));
    throws('a u64 past its range', () => bcsU64(1n << 64n));
    throws('a fractional u64', () => bcsU64(1.5));
    // Control: the largest values encode.
    bcsU128((1n << 128n) - 1n);
    Transaction.createTransfer(sender, recipient.address, 100n);

    // B123: pending and aborted are not confirmed; success in a block is.
    const connection = new Connection('http://127.0.0.1:1');
    let answer: any = { tx_hash: 'h', status: 'pending', confirmations: 0 };
    (connection as any).request = async (method: string) => {
        if (method === 'aincore_getTransactionReceipt') return answer;
        if (method === 'aincore_getTransaction') return { sender: sender.address };
        throw new Error(`unexpected RPC call: ${method}`);
    };
    let got = await connection.waitForConfirmation('h', 50, 5);
    if (got.confirmed || got.status !== 'pending') {
        throw new Error(`a pending transaction: ${JSON.stringify(got)}`);
    }
    answer = {
        tx_hash: 'h',
        status: 'aborted',
        confirmations: 1,
        block_height: 7,
        execution_receipt: { status: 'aborted', error: 'insufficient balance' },
    };
    got = await connection.waitForConfirmation('h', 50, 5);
    if (got.confirmed || got.status !== 'aborted') {
        throw new Error(`an aborted transaction: ${JSON.stringify(got)}`);
    }
    answer = { ...answer, status: 'success', execution_receipt: { status: 'success' } };
    got = await connection.waitForConfirmation('h', 50, 5);
    if (!got.confirmed || got.status !== 'success') {
        throw new Error(`a successful transaction: ${JSON.stringify(got)}`);
    }
}

main()
    .then(() => console.log('SDK input and confirmation tests passed'))
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });
