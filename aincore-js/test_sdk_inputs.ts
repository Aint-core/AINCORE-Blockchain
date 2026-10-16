// B123 and B129 witnesses: the SDK refuses input it cannot encode exactly,
// and reports a transaction confirmed only once a block executed it.
import { Keypair } from './src/keypair';
import { Transaction, tokenIdOf } from './src/transaction';
import { Connection } from './src/connection';
import axios from 'axios';
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

    // B135: a token id is its symbol's bytes and its creator's 32 address
    // bytes, passed as hex (UTF-8 text cannot carry the address bytes).
    const id = tokenIdOf('SYM', sender.address);
    if (id !== Buffer.from('SYM').toString('hex') + sender.address) {
        throw new Error(`token id: ${id}`);
    }
    const mint = Transaction.mintToken(sender, id, recipient.address, 5n).payload;
    if (!mint.includes(id)) {
        throw new Error('mint does not carry the token id bytes');
    }
    // Burned by a holder that did not create it, so the creator argument
    // cannot be mistaken for the signer's.
    const theirs = tokenIdOf('SYM', recipient.address);
    const burn = Transaction.burnToken(sender, recipient.address, theirs, 5n).payload;
    // The creator's address argument, then the id: a 36-byte argument (0x24)
    // holding a 35-byte vector (0x23).
    if (!burn.includes(recipient.address + '2423' + theirs)) {
        throw new Error('burn does not carry the creator, then the token id');
    }
    throws('a token id that is not hex', () => Transaction.mintToken(sender, 'SYM', recipient.address, 1n));

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

    // B177: the token RPCs as the node answers them: a creator's tokens are
    // asked for by its address, and a token of 0 decimals stays 0.
    const token = { token_id: id, name: 'S', symbol: 'SYM', decimals: 0, max_supply: '9', current_supply: '1', creator: sender.address, is_mintable: true };
    const asked: Array<[string, any[]]> = [];
    (connection as any).request = async (method: string, params: any[]) => {
        asked.push([method, params]);
        if (method === 'aincore_getToken') return token;
        if (method === 'aincore_getTokens') return [token];
        throw new Error(`unexpected RPC call: ${method}`);
    };
    const one = await connection.getToken(id);
    if (one?.decimals !== 0) {
        throw new Error(`a token of 0 decimals: ${JSON.stringify(one)}`);
    }
    const made = await connection.getTokens(sender.address);
    const [method, params] = asked[asked.length - 1];
    if (method !== 'aincore_getTokens' || params[0] !== sender.address || made[0]?.tokenId !== id || made[0]?.decimals !== 0) {
        throw new Error(`a creator's tokens: ${JSON.stringify([asked, made])}`);
    }

    // B223: the network info is the node's: its chain id is the node's
    // `network`, and a node that cannot be reached is an error. It answered
    // a guessed object with chain id 'AINCORE-MAINNET-1' instead.
    const get = axios.get;
    let reply: any = { network: 'AINCORE-TESTNET-V9', node_id: null, latest_block: 12, current_round: null, peer_count: 3, committee_sessions: 2, tps: 0.5, protocol_version: 1 };
    (axios as any).get = async (url: string) => {
        if (!url.endsWith('/get_network_info')) throw new Error(`unexpected GET ${url}`);
        return { status: 200, data: reply };
    };
    try {
        const info = await connection.getNetworkInfo();
        if (info.chain_id !== 'AINCORE-TESTNET-V9' || info.block_height !== 12 || info.current_round !== null || info.peer_count !== 3) {
            throw new Error(`the node's network info: ${JSON.stringify(info)}`);
        }
        reply = { latest_block: 12 };
        if (await connection.getNetworkInfo().then(() => true, () => false)) {
            throw new Error('network info without a chain id was answered');
        }
        (axios as any).get = async () => { throw new Error('ECONNREFUSED'); };
        if (await connection.getNetworkInfo().then(() => true, () => false)) {
            throw new Error('network info was answered without a node');
        }
    } finally {
        (axios as any).get = get;
    }

    // B236: the REST root is the endpoint without a trailing /rpc (the
    // first /rpc anywhere was cut: https://rpc.example/rpc became
    // https:/.example/rpc), and the validator list is the node's or an
    // error, never a silent [].
    const hosted = new Connection('https://rpc.example/rpc');
    if (hosted.restBase() !== 'https://rpc.example' || new Connection('http://127.0.0.1:8002/rpc/').restBase() !== 'http://127.0.0.1:8002') {
        throw new Error(`the REST root: ${hosted.restBase()}`);
    }
    const urls: string[] = [];
    (axios as any).get = async (url: string) => {
        urls.push(url);
        return { status: 200, data: { validators: [{ address: 'ab', stake: 5, status: 'Active' }] } };
    };
    try {
        const validators = await hosted.getValidators();
        if (urls[0] !== 'https://rpc.example/get_validators' || validators[0]?.stake !== 5) {
            throw new Error(`the validator list: ${JSON.stringify([urls, validators])}`);
        }
        (axios as any).get = async () => ({ status: 200, data: { error: 'busy' } });
        if (await hosted.getValidators().then(() => true, () => false)) {
            throw new Error('a validator list was answered from an answer without one');
        }
        (axios as any).get = async () => { throw new Error('ECONNREFUSED'); };
        if (await hosted.getValidators().then(() => true, () => false)) {
            throw new Error('a validator list was answered without a node');
        }
    } finally {
        (axios as any).get = get;
    }

    // B329: a REST read is asked again on a rate limit or a busy answer
    // (it threw at the first 429), a rate-limited node is up, an indexer's
    // failure is an error (it read as "no trades"), and the delegation
    // reads name the node's snake_case fields in camelCase (they were
    // passed on as they came, always undefined).
    {
        const limited = (status: number) => {
            const e: any = new Error(`Request failed with status code ${status}`);
            e.response = { status, data: '' };
            return e;
        };
        const slow = new Connection('http://127.0.0.1:8002/rpc', 'http://127.0.0.1:3001');
        slow.busyBackoffMs = 0;
        let gets = 0;
        (axios as any).get = async () => {
            gets += 1;
            if (gets < 3) throw limited(gets === 1 ? 429 : 503);
            return { status: 200, data: { network: 'AINCORE-TESTNET-V9', latest_block: 1 } };
        };
        try {
            const info = await slow.getNetworkInfo();
            if (info.chain_id !== 'AINCORE-TESTNET-V9' || gets !== 3) {
                throw new Error(`a rate-limited REST read was not asked again: ${JSON.stringify([info, gets])}`);
            }
            (axios as any).get = async () => { throw limited(429); };
            if (!(await slow.checkHealth())) {
                throw new Error('a rate-limited node read as down');
            }
            (axios as any).get = async () => { throw new Error('ECONNREFUSED'); };
            if (await slow.getDexMarkets().then(() => true, () => false)) {
                throw new Error("an indexer's failure read as no markets");
            }
        } finally {
            (axios as any).get = get;
        }
        (slow as any).client.post = async () => ({
            status: 200,
            data: { result: [{ validator: 'ab', amount: '5', pending_rewards: '7' }] },
        });
        const delegations = await slow.getDelegations('cd');
        if (delegations[0]?.pendingRewards !== '7' || delegations[0]?.amount !== '5') {
            throw new Error(`the delegation fields: ${JSON.stringify(delegations)}`);
        }
        (slow as any).client.post = async () => ({
            status: 200,
            data: { result: [{ validator: 'ab', amount: '5', unlock_time: 99 }] },
        });
        const unbonding = await slow.getUnbondingDelegations('cd');
        if (unbonding[0]?.unlockTime !== 99) {
            throw new Error(`the unbonding fields: ${JSON.stringify(unbonding)}`);
        }
        (slow as any).client.post = async () => ({
            status: 200,
            data: { result: [{ address: 'ab', total_delegated: '9', commission_rate: 5, delegator_count: 2 }] },
        });
        const pools = await slow.getValidatorsWithDelegation();
        if (pools[0]?.totalDelegated !== '9' || pools[0]?.delegatorCount !== 2) {
            throw new Error(`the pool fields: ${JSON.stringify(pools)}`);
        }
    }

    // B260: a busy answer is asked again (one heavy call at a time a
    // client, so a dapp's parallel receipts failed at once), at most
    // `busyRetries` times; any other error is not.
    const busy = new Connection('http://127.0.0.1:8002/rpc');
    busy.busyBackoffMs = 0;
    let posts = 0;
    const busyAnswer = (data: any) => async () => {
        posts += 1;
        return { status: 200, data: typeof data === 'function' ? data() : data };
    };
    (busy as any).client.post = busyAnswer(() => (posts < 3 ? { error: { code: -32005, message: 'busy; retry' } } : { result: 'done' }));
    const answered = await busy.request('aincore_getTransactionReceipt', ['ab']);
    if (answered !== 'done' || posts !== 3) {
        throw new Error(`a busy answer was not asked again: ${JSON.stringify([answered, posts])}`);
    }
    posts = 0;
    (busy as any).client.post = busyAnswer({ error: { code: -32005, message: 'busy; retry' } });
    if ((await busy.request('aincore_getTransactionReceipt', ['ab']).then(() => true, () => false)) || posts !== busy.busyRetries + 1) {
        throw new Error(`a busy node was asked ${posts} times`);
    }
    posts = 0;
    (busy as any).client.post = busyAnswer({ error: { code: -32602, message: 'Invalid params' } });
    if ((await busy.request('aincore_getTransactionReceipt', []).then(() => true, () => false)) || posts !== 1) {
        throw new Error(`a refused call was asked ${posts} times`);
    }
    // B308: a rate limit (HTTP 429) is asked again too; another HTTP error
    // is not.
    posts = 0;
    (busy as any).client.post = async () => {
        posts += 1;
        if (posts < 3) {
            const limited: any = new Error('Request failed with status code 429');
            limited.response = { status: 429, data: 'Too Many Requests' };
            throw limited;
        }
        return { status: 200, data: { result: 'done' } };
    };
    const limitedAnswer = await busy.request('aincore_getTransactionReceipt', ['ab']);
    if (limitedAnswer !== 'done' || posts !== 3) {
        throw new Error(`a rate-limited call was not asked again: ${JSON.stringify([limitedAnswer, posts])}`);
    }
    posts = 0;
    (busy as any).client.post = async () => {
        posts += 1;
        const failed: any = new Error('Request failed with status code 500');
        failed.response = { status: 500, data: 'boom' };
        throw failed;
    };
    if ((await busy.request('aincore_getTransactionReceipt', ['ab']).then(() => true, () => false)) || posts !== 1) {
        throw new Error(`a failed call was asked ${posts} times`);
    }

    // B267: a Connection sends heavy calls one at a time (the node refused a
    // client's second at once, so a dapp's parallel reads failed), light
    // ones beside them; every request carries a timeout (a stalled node held
    // a call for good); a failed heavy call does not hold the next; busy
    // retries wait a jittered time.
    const serial = new Connection('http://127.0.0.1:8002/rpc');
    let heavyNow = 0;
    let lightNow = 0;
    let heavyMost = 0;
    let beside = false;
    const timeouts: any[] = [];
    (serial as any).client.post = async (_url: string, payload: any, config: any) => {
        timeouts.push(config?.timeout);
        const heavy = payload.method !== 'aincore_getBalance';
        if (heavy) {
            heavyNow += 1;
            heavyMost = Math.max(heavyMost, heavyNow);
            beside ||= lightNow > 0;
        } else {
            lightNow += 1;
            beside ||= heavyNow > 0;
        }
        await new Promise((resolve) => setTimeout(resolve, 20));
        if (heavy) {
            heavyNow -= 1;
        } else {
            lightNow -= 1;
        }
        return { status: 200, data: { result: payload.method } };
    };
    const results = await Promise.all([
        serial.request('aincore_getBlocks', [1]),
        serial.request('aincore_getTransaction', ['ab']),
        serial.request('aincore_estimateGas', [{}]),
        serial.request('aincore_getBalance', ['ab']),
    ]);
    if (heavyMost !== 1 || !beside || results[0] !== 'aincore_getBlocks' || results[3] !== 'aincore_getBalance') {
        throw new Error(`heavy calls at once: ${JSON.stringify([heavyMost, beside, results])}`);
    }
    if (timeouts.length !== 4 || !timeouts.every((t) => t === serial.timeoutMs && t > 0)) {
        throw new Error(`a request without a timeout: ${JSON.stringify(timeouts)}`);
    }
    (serial as any).client.post = async (_url: string, payload: any) => {
        if (payload.method === 'aincore_getBlocks') {
            throw new Error('ECONNRESET');
        }
        return { status: 200, data: { result: payload.method } };
    };
    const failed = serial.request('aincore_getBlocks', [1]).then(() => 'answered', () => 'failed');
    const next = serial.request('aincore_getDag', []).then((r) => r, () => 'failed');
    if ((await failed) !== 'failed' || (await next) !== 'aincore_getDag') {
        throw new Error('a failed heavy call held the next');
    }
    const random = Math.random;
    try {
        serial.busyBackoffMs = 100;
        Math.random = () => 0;
        const least = serial.backoffMs(2);
        Math.random = () => 0.5;
        const middle = serial.backoffMs(2);
        if (least !== 200 || middle !== 300) {
            throw new Error(`busy retries are not jittered: ${least}, ${middle}`);
        }
    } finally {
        Math.random = random;
    }
}

main()
    .then(() => console.log('SDK input and confirmation tests passed'))
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });
