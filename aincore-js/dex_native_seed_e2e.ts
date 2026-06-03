import { Connection } from './src/connection';
import { Keypair } from './src/keypair';
import { Transaction } from './src/transaction';
import { AINCORE_COIN_TYPE, structTypeTag } from './src/bcs';

const rpcUrl = process.env.AINCORE_RPC_URL || 'http://192.168.18.202:8012/rpc';
const indexerUrl = process.env.AINCORE_INDEXER_URL || 'http://192.168.18.202:3012';
const chainId = process.env.AINCORE_CHAIN_ID || 'AINCORE-MAINNET-1';

const AIN = 10n ** 18n;
const WBTC = 10n ** 8n;
const gasLimit = Number(process.env.AINCORE_DEX_GAS_LIMIT || '100000');
const gasPrice = Number(process.env.AINCORE_DEX_GAS_PRICE || '1');

const faucetAin = BigInt(process.env.AINCORE_DEX_FAUCET_AIN_RAW || (20_000n * AIN).toString());
const faucetWbtc = BigInt(process.env.AINCORE_DEX_FAUCET_WBTC_RAW || (20n * WBTC).toString());
const addAin = BigInt(process.env.AINCORE_DEX_ADD_AIN_RAW || (10_000n * AIN).toString());
const addWbtc = BigInt(process.env.AINCORE_DEX_ADD_WBTC_RAW || (10n * WBTC).toString());
const swapAin = BigInt(process.env.AINCORE_DEX_SWAP_AIN_RAW || (1n * AIN).toString());

const wbtcType = structTypeTag('0x1', 'wbtc', 'WBTC');

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function keypairFromEnv(): Keypair {
    const secretHex = process.env.AINCORE_DEX_SEED_SECRET_KEY;
    if (secretHex) {
        return Keypair.fromSecretKey(Uint8Array.from(Buffer.from(secretHex.replace(/^0x/, ''), 'hex')));
    }

    const seedHex = process.env.AINCORE_DEX_SEED;
    if (seedHex) {
        return Keypair.fromSeed(Uint8Array.from(Buffer.from(seedHex.replace(/^0x/, ''), 'hex')));
    }

    // Deterministic local/testnet-only wallet so the seed path is repeatable.
    return Keypair.fromSeed(new Uint8Array(32).fill(73));
}

function assertOk(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(message);
    }
}

function isSuccessReceipt(receipt: any): boolean {
    return receipt?.status === 'success' || receipt?.status === 'confirmed' || receipt?.execution_receipt?.status === 'success';
}

async function waitForReceipt(connection: Connection, txHash: string, label: string, timeoutMs = 90_000): Promise<any> {
    const start = Date.now();
    let last: any = undefined;

    while (Date.now() - start < timeoutMs) {
        last = await connection.getTransactionReceipt(txHash);
        if (last?.status && last.status !== 'pending' && last.status !== 'not_found') {
            if (!isSuccessReceipt(last)) {
                throw new Error(`${label} aborted: ${JSON.stringify(last)}`);
            }
            return last;
        }
        await sleep(2_000);
    }

    throw new Error(`${label} receipt timeout; last=${JSON.stringify(last)}`);
}

async function submitTx(
    connection: Connection,
    signer: Keypair,
    build: (sequenceNumber: number) => Transaction,
    label: string,
): Promise<{ txHash: string; receipt: any }> {
    const sequence = await connection.getAccountNonce(signer.address);
    const tx = build(sequence);
    tx.gasLimit = gasLimit;
    tx.gasPrice = gasPrice;
    tx.setChainId(chainId);
    tx.sign(signer);

    const txHash = await connection.sendTransaction(tx.toString());
    console.log(`[dex-seed] ${label} tx=${txHash} nonce=${sequence}`);
    const receipt = await waitForReceipt(connection, txHash, label);
    return { txHash, receipt };
}

async function waitForIndexerTrade(
    connection: Connection,
    txHash: string,
    previousTradeCount: number,
    timeoutMs = 120_000,
): Promise<void> {
    const start = Date.now();

    while (Date.now() - start < timeoutMs) {
        const trades = await connection.getDexTrades('AIN', 'WBTC', 25);
        if (trades.some(trade => trade.tx_hash === txHash) || trades.length > previousTradeCount) {
            console.log(`[dex-seed] indexer saw swap tx=${txHash}; trades=${trades.length}`);
            return;
        }
        await sleep(3_000);
    }

    throw new Error(`Indexer did not expose swap ${txHash} within ${timeoutMs}ms`);
}

async function main() {
    const connection = new Connection(rpcUrl, indexerUrl);
    const seed = keypairFromEnv();

    console.log(`[dex-seed] rpc=${rpcUrl}`);
    console.log(`[dex-seed] indexer=${indexerUrl}`);
    console.log(`[dex-seed] wallet=${seed.address}`);
    console.log('[dex-seed] market=AIN/synthetic WBTC (test market only, not BTC-backed)');

    await connection.requestFaucet(seed.address, faucetAin.toString(), seed.publicKey);
    await connection.requestTestMintWbtc(seed.address, faucetWbtc.toString(), seed.publicKey);

    const [ainBalance, wbtcBalance] = await Promise.all([
        connection.getCoinBalance(seed.address, 'AIN'),
        connection.getCoinBalance(seed.address, 'WBTC'),
    ]);

    console.log(`[dex-seed] balances AIN=${ainBalance.balance} WBTC=${wbtcBalance.balance}`);
    assertOk(BigInt(ainBalance.balance) >= addAin + swapAin + BigInt(gasLimit * gasPrice * 4), 'AIN seed balance too low');
    assertOk(BigInt(wbtcBalance.balance) >= addWbtc, 'WBTC seed balance too low');

    let pool = await connection.getDexPool('AIN', 'WBTC').catch(() => null);
    if (!pool) {
        console.log('[dex-seed] no AIN/WBTC pool found; creating canonical pool');
        await submitTx(
            connection,
            seed,
            sequence => Transaction.createDexPool(seed, AINCORE_COIN_TYPE, wbtcType, sequence),
            'create_pool',
        );
        pool = await connection.getDexPool('AIN', 'WBTC');
    } else {
        console.log(`[dex-seed] existing pool=${pool.pool_addr}`);
    }

    assertOk(pool?.pool_addr, 'AIN/WBTC pool not found after create');
    const poolAddr = pool.pool_addr;

    console.log(`[dex-seed] add_liquidity pool=${poolAddr} ain=${addAin} wbtc=${addWbtc}`);
    await submitTx(
        connection,
        seed,
        sequence => Transaction.addDexLiquidity(
            seed,
            poolAddr,
            AINCORE_COIN_TYPE,
            wbtcType,
            addAin,
            addWbtc,
            1n,
            sequence,
        ),
        'add_liquidity',
    );

    const quote = await connection.getDexQuote('AIN', 'WBTC', swapAin.toString());
    assertOk(quote.status === 'ok', `quote failed: ${JSON.stringify(quote)}`);
    assertOk(quote.pool_addr, 'quote did not return pool address');
    const amountOut = BigInt(String(quote.amount_out || '0'));
    assertOk(amountOut > 0n, `quote returned zero output: ${JSON.stringify(quote)}`);
    const minOut = amountOut * 99n / 100n;
    const previousTrades = await connection.getDexTrades('AIN', 'WBTC', 25).catch(() => []);

    console.log(`[dex-seed] swap AIN->WBTC amount_in=${swapAin} quote_out=${amountOut} min_out=${minOut}`);
    const { txHash } = await submitTx(
        connection,
        seed,
        sequence => Transaction.createDexSwapXToY(
            seed,
            quote.pool_addr || poolAddr,
            AINCORE_COIN_TYPE,
            wbtcType,
            swapAin,
            minOut,
            sequence,
        ),
        'swap_x_to_y',
    );

    await waitForIndexerTrade(connection, txHash, previousTrades.length);

    const [summary, markets, ohlc, trades] = await Promise.all([
        connection.getDexPairSummary('AIN', 'WBTC'),
        connection.getDexMarkets(5),
        connection.getDexOhlc('AIN', 'WBTC', 60, 10),
        connection.getDexTrades('AIN', 'WBTC', 10),
    ]);

    assertOk(summary, 'pair_summary missing after seed swap');
    assertOk(markets.length > 0, 'markets empty after seed swap');
    assertOk(ohlc.length > 0, 'OHLC empty after seed swap');
    assertOk(trades.length > 0, 'trades empty after seed swap');

    console.log(`[dex-seed] summary last_price=${summary.last_price} trades_24h=${summary.trades_24h} volume_base_24h=${summary.volume_base_24h}`);
    console.log(`[dex-seed] markets=${markets.length} ohlc=${ohlc.length} trades=${trades.length}`);
    console.log('[dex-seed] PASS: faucet, synthetic WBTC mint, pool, liquidity, swap, receipt, and indexer are live');
}

main().catch((error) => {
    console.error(`[dex-seed] FAIL: ${error.message}`);
    process.exit(1);
});
