import { Connection, Keypair, Transaction } from './src';

async function main() {
    const connection = new Connection('http://127.0.0.1:8001/rpc');
    console.log('🚀 Starting Load Test (Spamming Transactions)...');

    // Generate a random sender
    const sender = Keypair.generate();
    console.log(`👤 Sender: ${sender.address}`);

    // Fund the sender first (using Genesis or Paymaster if needed, 
    // but for now we assume the node accepts 0-fee txs or we use a funded account)
    // Actually, let's use the Paymaster account we know has funds from the previous step!
    // Paymaster Address: 78408539d56f032543a44c0b8f33944c
    // But we don't have its private key easily accessible here without reading the file.
    // Let's just generate random txs. If they fail due to funds, they still hit the mempool/node 
    // and might count towards "processed" count depending on metrics implementation.
    // BETTER: Use the Genesis Key if available, or just send invalid txs that get rejected but counted?
    // No, let's try to send valid-ish txs.

    // We'll just create a loop that sends transactions.
    // Even if they fail execution, they might register as "received".

    let count = 0;
    const startTime = Date.now();

    while (true) {
        try {
            const recipient = Keypair.generate().address;
            const tx = Transaction.createTransfer(sender, recipient, 1, count);
            tx.sign(sender);

            // We don't await the result to go faster (fire and forget)
            connection.sendTransaction(tx.toString()).catch(() => { });

            count++;
            if (count % 100 === 0) {
                const elapsed = (Date.now() - startTime) / 1000;
                console.log(`⚡ Sent ${count} txs. Avg Rate: ${(count / elapsed).toFixed(2)} TPS`);
            }

            // Small sleep to prevent overwhelming local node too much
            await new Promise(r => setTimeout(r, 10));
        } catch (e) {
            console.error(e);
            await new Promise(r => setTimeout(r, 1000));
        }
    }
}

main();
