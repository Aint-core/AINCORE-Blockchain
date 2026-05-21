import { Connection } from './src/connection';
import { Keypair } from './src/keypair';
import { Transaction } from './src/transaction';

const rpcUrl = process.env.AINCORE_RPC_URL || 'http://127.0.0.1:18102/rpc';
const chainId = process.env.AINCORE_CHAIN_ID || 'AINCORE-MAINNET-1';

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForBalance(
    connection: Connection,
    address: string,
    expected: bigint,
    label: string,
    timeoutMs = 60000
): Promise<string> {
    const start = Date.now();
    let last = '0';

    while (Date.now() - start < timeoutMs) {
        last = await connection.getMoveBalance(address);
        if (BigInt(last) === expected) {
            return last;
        }
        await sleep(1000);
    }

    throw new Error(`${label} balance did not reach ${expected}; last=${last}`);
}

async function main() {
    const connection = new Connection(rpcUrl);
    const sender = Keypair.fromSeed(new Uint8Array(32).fill(51));
    const recipient = Keypair.fromSeed(new Uint8Array(32).fill(52));

    const faucetAmount = 1_000_000n;
    const transferAmount = 123n;
    const gasLimit = 100_000;
    const gasPrice = 1;
    const gasCost = BigInt(gasLimit * gasPrice);

    console.log(`[phase0.5] rpc=${rpcUrl}`);
    console.log(`[phase0.5] sender=${sender.address}`);
    console.log(`[phase0.5] recipient=${recipient.address}`);

    await connection.requestFaucet(sender.address, faucetAmount.toString(), sender.publicKey);
    await connection.requestFaucet(recipient.address, '0', recipient.publicKey);

    const senderBefore = await waitForBalance(connection, sender.address, faucetAmount, 'sender faucet');
    const recipientBefore = await waitForBalance(connection, recipient.address, 0n, 'recipient faucet');
    console.log(`[phase0.5] before sender=${senderBefore} recipient=${recipientBefore}`);

    const tx = Transaction.createTransfer(sender, recipient.address, transferAmount, 0);
    tx.gasLimit = gasLimit;
    tx.gasPrice = gasPrice;
    tx.setChainId(chainId);
    tx.sign(sender);

    const txHash = await connection.sendTransaction(tx.toString());
    console.log(`[phase0.5] tx_hash=${txHash}`);

    const expectedSender = faucetAmount - transferAmount - gasCost;
    const expectedRecipient = transferAmount;

    const senderAfter = await waitForBalance(connection, sender.address, expectedSender, 'sender transfer');
    const recipientAfter = await waitForBalance(connection, recipient.address, expectedRecipient, 'recipient transfer');

    console.log(`[phase0.5] after sender=${senderAfter} recipient=${recipientAfter}`);
    console.log('[phase0.5] PASS: faucet, BCS transfer, gas debit, and Move CoinStore balances are live');
}

main().catch((error) => {
    console.error(`[phase0.5] FAIL: ${error.message}`);
    process.exit(1);
});
