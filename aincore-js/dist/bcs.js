"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AINCORE_COIN_TYPE = exports.SYSTEM_ADDRESS = void 0;
exports.serializeTransactionPayload = serializeTransactionPayload;
exports.bcsAddress = bcsAddress;
exports.bcsU64 = bcsU64;
exports.bcsU128 = bcsU128;
exports.bcsU8 = bcsU8;
exports.bcsBool = bcsBool;
exports.bcsString = bcsString;
exports.bcsVectorU8 = bcsVectorU8;
exports.hexToBytes = hexToBytes;
exports.bytesToHex = bytesToHex;
exports.structTypeTag = structTypeTag;
// ============================================================
// Low-level BCS primitives
// ============================================================
// B129: an encoder throws on input it cannot encode exactly. Non-hex
// characters used to become 0 bytes and out-of-range integers wrapped, so a
// typo in an address sent funds to an address nobody controls.
function checkUint(value, bits, what) {
    if (!Number.isSafeInteger(value) || value < 0 || (bits < 53 && value >= 2 ** bits)) {
        throw new Error(`Invalid ${what}: ${value} is not a u${bits}`);
    }
}
function checkUintBig(value, bits, what) {
    if (typeof value !== 'bigint' || value < 0n || value >= (1n << BigInt(bits))) {
        throw new Error(`Invalid ${what}: ${value} is not a u${bits}`);
    }
}
function writeULEB128(value) {
    checkUint(value, 32, 'length');
    const bytes = [];
    while (value >= 0x80) {
        bytes.push((value & 0x7f) | 0x80);
        value >>>= 7;
    }
    bytes.push(value & 0x7f);
    return new Uint8Array(bytes);
}
function writeU8(value) {
    checkUint(value, 8, 'u8');
    return new Uint8Array([value & 0xff]);
}
function writeU16(value) {
    checkUint(value, 16, 'u16');
    const buf = new Uint8Array(2);
    buf[0] = value & 0xff;
    buf[1] = (value >>> 8) & 0xff;
    return buf;
}
function writeU32(value) {
    checkUint(value, 32, 'u32');
    const buf = new Uint8Array(4);
    buf[0] = value & 0xff;
    buf[1] = (value >>> 8) & 0xff;
    buf[2] = (value >>> 16) & 0xff;
    buf[3] = (value >>> 24) & 0xff;
    return buf;
}
function writeU64(value) {
    checkUintBig(value, 64, 'u64');
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return buf;
}
function writeU128(value) {
    checkUintBig(value, 128, 'u128');
    const buf = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        buf[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return buf;
}
function writeBytes(data) {
    const len = writeULEB128(data.length);
    return concat(len, data);
}
function writeString(s) {
    const encoded = new TextEncoder().encode(s);
    return writeBytes(encoded);
}
const ADDRESS_BYTES = 32;
const ADDRESS_HEX_CHARS = ADDRESS_BYTES * 2;
function writeAddress(hex) {
    // A Move AccountAddress is 32 bytes. This used to emit 16, which every node
    // rejects with "Invalid BCS TransactionPayload: remaining input" because the
    // args deserialize short. Addresses are hex(sha256(pubkey)) -- the FULL
    // digest, not a truncation.
    const clean = hex.replace(/^0x/, '');
    if (clean.length !== ADDRESS_HEX_CHARS) {
        throw new Error(`Invalid address length: expected ${ADDRESS_HEX_CHARS} hex chars, got ${clean.length}`);
    }
    return hexToBytes(clean);
}
function concat(...arrays) {
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
function serializeAccountAddress(hex) {
    return writeAddress(hex);
}
/**
 * Serialize a Move Identifier (BCS string)
 */
function serializeIdentifier(name) {
    return writeString(name);
}
/**
 * Serialize a Move ModuleId = { address: AccountAddress, name: Identifier }
 */
function serializeModuleId(address, moduleName) {
    return concat(serializeAccountAddress(address), serializeIdentifier(moduleName));
}
function serializeTypeTag(tag) {
    switch (tag.kind) {
        case 'Bool': return writeULEB128(0);
        case 'U8': return writeULEB128(1);
        case 'U64': return writeULEB128(2);
        case 'U128': return writeULEB128(3);
        case 'Address': return writeULEB128(4);
        case 'Signer': return writeULEB128(5);
        case 'Vector':
            return concat(writeULEB128(6), serializeTypeTag(tag.inner));
        case 'Struct':
            return concat(writeULEB128(7), serializeStructTag(tag.value));
    }
}
function serializeStructTag(st) {
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
/**
 * Serialize an EntryFunctionCall struct:
 * { module: ModuleId, function: String, ty_args: Vec<TypeTag>, args: Vec<Vec<u8>> }
 */
function serializeEntryFunctionCall(call) {
    const parts = [
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
function serializeString(s) {
    return writeString(s);
}
function serializeTransactionPayload(payload) {
    switch (payload.kind) {
        case 'EntryFunction':
            return concat(writeULEB128(1), // variant index
            serializeEntryFunctionCall(payload.call));
        case 'PublishModule': {
            const parts = [
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
function bcsAddress(hex) {
    return writeAddress(hex);
}
/** Serialize a u64 as a BCS argument (8 bytes LE) */
function bcsU64(value) {
    return writeU64(BigInt(value));
}
/** Serialize a u128 as a BCS argument (16 bytes LE) */
function bcsU128(value) {
    return writeU128(value);
}
/** Serialize a u8 as a BCS argument */
function bcsU8(value) {
    return writeU8(value);
}
/** Serialize a bool as a BCS argument */
function bcsBool(value) {
    return new Uint8Array([value ? 1 : 0]);
}
/** Serialize a string as a BCS argument (length-prefixed UTF-8) */
function bcsString(value) {
    return writeString(value);
}
/** Serialize raw bytes as a BCS vector<u8> argument */
function bcsVectorU8(data) {
    return writeBytes(data);
}
/** Convert hex string to Uint8Array; throws on anything but hex digits in
 *  pairs (B129). */
function hexToBytes(hex) {
    const clean = hex.replace(/^0x/, '');
    if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
        throw new Error(`Invalid hex: ${JSON.stringify(hex.slice(0, 80))}`);
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
/** Convert Uint8Array to hex string */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
// ============================================================
// AINCORE Constants
// ============================================================
exports.SYSTEM_ADDRESS = '0000000000000000000000000000000000000000000000000000000000000001';
exports.AINCORE_COIN_TYPE = {
    kind: 'Struct',
    value: {
        address: exports.SYSTEM_ADDRESS,
        module: 'staking',
        name: 'AincoreCoin',
        typeParams: [],
    }
};
function structTypeTag(address, module, name, typeParams = []) {
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
