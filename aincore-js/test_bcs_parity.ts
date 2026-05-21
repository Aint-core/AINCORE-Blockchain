import { Keypair } from './src/keypair';
import { Transaction } from './src/transaction';
import { Connection } from './src/connection';
import { AINCORE_COIN_TYPE, structTypeTag } from './src/bcs';

const sender = Keypair.fromSeed(new Uint8Array(32).fill(7));
const recipient = Keypair.fromSeed(new Uint8Array(32).fill(8));
const wbtcType = structTypeTag('0x1', 'wbtc', 'WBTC');

const cases: Array<[string, string, string]> = [
    [
        'transfer',
        Transaction.createTransfer(sender, recipient.address, 100n).payload,
        '010000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000001077374616b696e670b41696e636f7265436f696e000310fe812c12f3ab4ce6ac5db69ac352f906105c29b78f10a35a49a6231d08ee840a041064000000000000000000000000000000',
    ],
    [
        'publish',
        Transaction.createPublish(sender, 'cafebabe').payload,
        '020104cafebabe',
    ],
    [
        'register_validator',
        Transaction.createRegisterValidator(sender, 123456789n).payload,
        '0100000000000000000000000000000001077374616b696e67126a6f696e5f76616c696461746f725f736574000310fe812c12f3ab4ce6ac5db69ac352f9061015cd5b070000000000000000000000002120ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c',
    ],
    [
        'create_token',
        Transaction.createToken(
            sender,
            'Ain Token',
            'AINX',
            8,
            1_000_000_000_000n,
            12_345n,
            'ipfs://icon',
            'https://aincore.test',
        ).payload,
        '01000000000000000000000000000000010d746f6b656e5f666163746f72790c6372656174655f746f6b656e000810fe812c12f3ab4ce6ac5db69ac352f9060a0941696e20546f6b656e050441494e580108100010a5d4e8000000000000000000000010393000000000000000000000000000000c0b697066733a2f2f69636f6e151468747470733a2f2f61696e636f72652e74657374',
    ],
    [
        'delegate',
        Transaction.createDelegate(sender, recipient.address, 555n).payload,
        '01000000000000000000000000000000010a64656c65676174696f6e0864656c6567617465000310fe812c12f3ab4ce6ac5db69ac352f906105c29b78f10a35a49a6231d08ee840a04102b020000000000000000000000000000',
    ],
    [
        'dex_create_pool',
        Transaction.createDexPool(sender, AINCORE_COIN_TYPE, wbtcType).payload,
        '0100000000000000000000000000000001036465780b6372656174655f706f6f6c020700000000000000000000000000000001077374616b696e670b41696e636f7265436f696e00070000000000000000000000000000000104776274630457425443000110fe812c12f3ab4ce6ac5db69ac352f906',
    ],
    [
        'dex_add_liquidity',
        Transaction.addDexLiquidity(sender, sender.address, AINCORE_COIN_TYPE, wbtcType, 10000n, 10000n, 9000n).payload,
        '0100000000000000000000000000000001036465780d6164645f6c6971756964697479020700000000000000000000000000000001077374616b696e670b41696e636f7265436f696e00070000000000000000000000000000000104776274630457425443000510fe812c12f3ab4ce6ac5db69ac352f90610fe812c12f3ab4ce6ac5db69ac352f906101027000000000000000000000000000010102700000000000000000000000000001028230000000000000000000000000000',
    ],
    [
        'dex_swap_x_to_y',
        Transaction.createDexSwapXToY(sender, sender.address, AINCORE_COIN_TYPE, wbtcType, 1000n, 900n).payload,
        '0100000000000000000000000000000001036465780b737761705f785f746f5f79020700000000000000000000000000000001077374616b696e670b41696e636f7265436f696e00070000000000000000000000000000000104776274630457425443000410fe812c12f3ab4ce6ac5db69ac352f90610fe812c12f3ab4ce6ac5db69ac352f90610e80300000000000000000000000000001084030000000000000000000000000000',
    ],
];

for (const [name, actual, expected] of cases) {
    if (actual !== expected) {
        throw new Error(`${name} BCS mismatch\nexpected: ${expected}\nactual:   ${actual}`);
    }
}

console.log(`BCS parity vectors passed (${cases.length} cases)`);

async function testMoveBalanceIsSourceOfTruth() {
    const connection = new Connection('http://unused.local');
    const accountData = Buffer.from(JSON.stringify({
        balance: 999,
        sequence_number: 7,
        btc_balance: 0,
        public_key: '00',
    }), 'utf-8');

    (connection as any).request = async (method: string) => {
        if (method !== 'aincore_getBalance') {
            throw new Error(`unexpected RPC method: ${method}`);
        }
        return {
            id: sender.address,
            data: Array.from(accountData),
            move_balance: '123456789',
            balance_source: 'move_coin_store',
        };
    };

    const account = await connection.getAccount(sender.address);
    if (account.sequence_number !== 7) {
        throw new Error(`sequence_number mismatch: ${account.sequence_number}`);
    }
    if (account.move_balance !== '123456789') {
        throw new Error(`move_balance mismatch: ${account.move_balance}`);
    }
    if (await connection.getMoveBalance(sender.address) !== '123456789') {
        throw new Error('getMoveBalance did not use Move CoinStore balance');
    }
    if (await connection.getBalance(sender.address) !== 123456789) {
        throw new Error('getBalance did not use Move CoinStore balance');
    }

    let faucetParams: any[] | undefined;
    (connection as any).request = async (method: string, params: any[]) => {
        if (method !== 'aincore_faucet') {
            throw new Error(`unexpected RPC method: ${method}`);
        }
        faucetParams = params;
        return {
            address: params[0],
            amount: params[1],
            move_balance: params[1],
            balance_source: 'move_coin_store',
        };
    };
    const faucet = await connection.requestFaucet(sender.address, '5000', sender.publicKey);
    if (!faucetParams || faucetParams[0] !== sender.address || faucetParams[1] !== '5000' || faucetParams[2] !== sender.publicKey) {
        throw new Error('requestFaucet did not build expected RPC params');
    }
    if (faucet.move_balance !== '5000') {
        throw new Error(`requestFaucet returned unexpected balance: ${faucet.move_balance}`);
    }
}

testMoveBalanceIsSourceOfTruth()
    .then(() => console.log('Move balance source-of-truth test passed'))
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });
