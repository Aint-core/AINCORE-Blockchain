/**
 * AINCORE BCS (Binary Canonical Serialization) Module
 * 
 * Produces byte-identical output to Rust's `bcs::to_bytes()` for
 * the TransactionPayload enum. This is critical — a single byte
 * difference will cause signature mismatch or payload rejection.
 * 
 * BCS encoding rules:
 * - u8/u16/u32/u64/u128: little-endian fixed-width
 * - bool: 0x00 (false) or 0x01 (true)
 * - vector<T>: ULEB128 length prefix + elements
 * - string: ULEB128 length prefix + UTF-8 bytes
 * - enum: ULEB128 variant index + variant data
 * - struct: fields serialized in declaration order (no tags)
 */

// ============================================================
// Low-level BCS primitives
// ============================================================

function writeULEB128(value: number): Uint8Array {
    const bytes: number[] = [];
    while (value >= 0x80) {
        bytes.push((value & 0x7f) | 0x80);
        value >>>= 7;
    }
    bytes.push(value & 0x7f);
    return new Uint8Array(bytes);
}

function writeU8(value: number): Uint8Array {
    return new Uint8Array([value & 0xff]);
}

function writeU16(value: number): Uint8Array {
    const buf = new Uint8Array(2);
    buf[0] = value & 0xff;
    buf[1] = (value >>> 8) & 0xff;
    return buf;
}

function writeU32(value: number): Uint8Array {
    const buf = new Uint8Array(4);
    buf[0] = value & 0xff;
    buf[1] = (value >>> 8) & 0xff;
    buf[2] = (value >>> 16) & 0xff;
    buf[3] = (value >>> 24) & 0xff;
    return buf;
}

function writeU64(value: bigint): Uint8Array {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return buf;
}

function writeU128(value: bigint): Uint8Array {
    const buf = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        buf[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return buf;
}

function writeBytes(data: Uint8Array): Uint8Array {
    const len = writeULEB128(data.length);
    return concat(len, data);
}

function writeString(s: string): Uint8Array {
    const encoded = new TextEncoder().encode(s);
    return writeBytes(encoded);
}

const ADDRESS_BYTES = 32;
const ADDRESS_HEX_CHARS = ADDRESS_BYTES * 2;

function writeAddress(hex: string): Uint8Array {
    // A Move AccountAddress is 32 bytes. This used to emit 16, which every node
    // rejects with "Invalid BCS TransactionPayload: remaining input" because the
    // args deserialize short. Addresses are hex(sha256(pubkey)) -- the FULL
    // digest, not a truncation.
    const clean = hex.replace(/^0x/, '');
    if (clean.length !== ADDRESS_HEX_CHARS) {
        throw new Error(
            `Invalid address length: expected ${ADDRESS_HEX_CHARS} hex chars, got ${clean.length}`
        );
    }
    const bytes = new Uint8Array(ADDRESS_BYTES);
    for (let i = 0; i < ADDRESS_BYTES; i++) {
        bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        result.set(a, offset);
        offset += a.length;
    }
    return result;
}

// ============================================================
// Move Type Serialization
// ============================================================

/**
 * Serialize a Move AccountAddress (32 bytes, raw, no length prefix)
 */
function serializeAccountAddress(hex: string): Uint8Array {
    return writeAddress(hex);
}

/**
 * Serialize a Move Identifier (BCS string)
 */
function serializeIdentifier(name: string): Uint8Array {
    return writeString(name);
}

/**
 * Serialize a Move ModuleId = { address: AccountAddress, name: Identifier }
 */
function serializeModuleId(address: string, moduleName: string): Uint8Array {
    return concat(
        serializeAccountAddress(address),
        serializeIdentifier(moduleName)
    );
}

/**
 * TypeTag enum variants in Move BCS:
 * 0 = Bool
 * 1 = U8
 * 2 = U64
 * 3 = U128
 * 4 = Address
 * 5 = Signer
 * 6 = Vector(TypeTag)
 * 7 = Struct(StructTag)
 */
export interface StructTag {
    address: string;  // hex, no 0x prefix, 32 chars
    module: string;
    name: string;
    typeParams: TypeTag[];
}

export type TypeTag =
    | { kind: 'Bool' }
    | { kind: 'U8' }
    | { kind: 'U64' }
    | { kind: 'U128' }
    | { kind: 'Address' }
    | { kind: 'Signer' }
    | { kind: 'Vector'; inner: TypeTag }
    | { kind: 'Struct'; value: StructTag };

function serializeTypeTag(tag: TypeTag): Uint8Array {
    switch (tag.kind) {
        case 'Bool':    return writeULEB128(0);
        case 'U8':      return writeULEB128(1);
        case 'U64':     return writeULEB128(2);
        case 'U128':    return writeULEB128(3);
        case 'Address': return writeULEB128(4);
        case 'Signer':  return writeULEB128(5);
        case 'Vector':
            return concat(writeULEB128(6), serializeTypeTag(tag.inner));
        case 'Struct':
            return concat(writeULEB128(7), serializeStructTag(tag.value));
    }
}

function serializeStructTag(st: StructTag): Uint8Array {
    const parts = [
        serializeAccountAddress(st.address),
        serializeIdentifier(st.module),
        serializeIdentifier(st.name),
        writeULEB128(st.typeParams.length),
    ];
    for (const tp of st.typeParams) {
        parts.push(serializeTypeTag(tp));
    }
    return concat(...parts);
}

// ============================================================
// TransactionPayload Serialization
// ============================================================

export interface EntryFunctionCall {
    module: { address: string; name: string };
    function: string;
    tyArgs: TypeTag[];
    args: Uint8Array[];
}

/**
 * Serialize an EntryFunctionCall struct:
 * { module: ModuleId, function: String, ty_args: Vec<TypeTag>, args: Vec<Vec<u8>> }
 */
function serializeEntryFunctionCall(call: EntryFunctionCall): Uint8Array {
    const parts: Uint8Array[] = [
        serializeModuleId(call.module.address, call.module.name),
        serializeString(call.function),
        writeULEB128(call.tyArgs.length),
    ];
    for (const ty of call.tyArgs) {
        parts.push(serializeTypeTag(ty));
    }
    parts.push(writeULEB128(call.args.length));
    for (const arg of call.args) {
        parts.push(writeBytes(arg));
    }
    return concat(...parts);
}

function serializeString(s: string): Uint8Array {
    return writeString(s);
}

/**
 * TransactionPayload enum (BCS):
 * 0 = Script(Vec<u8>)          — DISABLED
 * 1 = EntryFunction(EntryFunctionCall)
 * 2 = PublishModule(Vec<Vec<u8>>)
 */
export type TransactionPayload =
    | { kind: 'EntryFunction'; call: EntryFunctionCall }
    | { kind: 'PublishModule'; modules: Uint8Array[] };

export function serializeTransactionPayload(payload: TransactionPayload): Uint8Array {
    switch (payload.kind) {
        case 'EntryFunction':
            return concat(
                writeULEB128(1), // variant index
                serializeEntryFunctionCall(payload.call)
            );
        case 'PublishModule': {
            const parts: Uint8Array[] = [
                writeULEB128(2), // variant index
                writeULEB128(payload.modules.length),
            ];
            for (const mod of payload.modules) {
                parts.push(writeBytes(mod));
            }
            return concat(...parts);
        }
    }
}

// ============================================================
// BCS Argument Serializers (for call.args)
// ============================================================

/** Serialize an AccountAddress as a BCS argument (32 bytes raw) */
export function bcsAddress(hex: string): Uint8Array {
    return writeAddress(hex);
}

/** Serialize a u64 as a BCS argument (8 bytes LE) */
export function bcsU64(value: bigint | number): Uint8Array {
    return writeU64(BigInt(value));
}

/** Serialize a u128 as a BCS argument (16 bytes LE) */
export function bcsU128(value: bigint): Uint8Array {
    return writeU128(value);
}

/** Serialize a u8 as a BCS argument */
export function bcsU8(value: number): Uint8Array {
    return writeU8(value);
}

/** Serialize a bool as a BCS argument */
export function bcsBool(value: boolean): Uint8Array {
    return new Uint8Array([value ? 1 : 0]);
}

/** Serialize a string as a BCS argument (length-prefixed UTF-8) */
export function bcsString(value: string): Uint8Array {
    return writeString(value);
}

/** Serialize raw bytes as a BCS vector<u8> argument */
export function bcsVectorU8(data: Uint8Array): Uint8Array {
    return writeBytes(data);
}

/** Convert hex string to Uint8Array */
export function hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/^0x/, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/** Convert Uint8Array to hex string */
export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================
// AINCORE Constants
// ============================================================

export const SYSTEM_ADDRESS =
    '0000000000000000000000000000000000000000000000000000000000000001';

export const AINCORE_COIN_TYPE: TypeTag = {
    kind: 'Struct',
    value: {
        address: SYSTEM_ADDRESS,
        module: 'staking',
        name: 'AincoreCoin',
        typeParams: [],
    }
};

export function structTypeTag(
    address: string,
    module: string,
    name: string,
    typeParams: TypeTag[] = []
): TypeTag {
    return {
        kind: 'Struct',
        value: {
            address: address.replace(/^0x/, '').padStart(ADDRESS_HEX_CHARS, '0'),
            module,
            name,
            typeParams,
        },
    };
}
