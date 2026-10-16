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
    address: string;
    module: string;
    name: string;
    typeParams: TypeTag[];
}
export type TypeTag = {
    kind: 'Bool';
} | {
    kind: 'U8';
} | {
    kind: 'U64';
} | {
    kind: 'U128';
} | {
    kind: 'Address';
} | {
    kind: 'Signer';
} | {
    kind: 'Vector';
    inner: TypeTag;
} | {
    kind: 'Struct';
    value: StructTag;
};
export interface EntryFunctionCall {
    module: {
        address: string;
        name: string;
    };
    function: string;
    tyArgs: TypeTag[];
    args: Uint8Array[];
}
/**
 * TransactionPayload enum (BCS):
 * 0 = Script(Vec<u8>)          — DISABLED
 * 1 = EntryFunction(EntryFunctionCall)
 * 2 = PublishModule(Vec<Vec<u8>>)
 */
export type TransactionPayload = {
    kind: 'EntryFunction';
    call: EntryFunctionCall;
} | {
    kind: 'PublishModule';
    modules: Uint8Array[];
};
export declare function serializeTransactionPayload(payload: TransactionPayload): Uint8Array;
/** Serialize an AccountAddress as a BCS argument (32 bytes raw) */
export declare function bcsAddress(hex: string): Uint8Array;
/** Serialize a u64 as a BCS argument (8 bytes LE) */
export declare function bcsU64(value: bigint | number): Uint8Array;
/** Serialize a u128 as a BCS argument (16 bytes LE) */
export declare function bcsU128(value: bigint): Uint8Array;
/** Serialize a u8 as a BCS argument */
export declare function bcsU8(value: number): Uint8Array;
/** Serialize a bool as a BCS argument */
export declare function bcsBool(value: boolean): Uint8Array;
/** Serialize a string as a BCS argument (length-prefixed UTF-8) */
export declare function bcsString(value: string): Uint8Array;
/** Serialize raw bytes as a BCS vector<u8> argument */
export declare function bcsVectorU8(data: Uint8Array): Uint8Array;
/** Convert hex string to Uint8Array; throws on anything but hex digits in
 *  pairs (B129). */
export declare function hexToBytes(hex: string): Uint8Array;
/** Convert Uint8Array to hex string */
export declare function bytesToHex(bytes: Uint8Array): string;
export declare const SYSTEM_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001";
export declare const AINCORE_COIN_TYPE: TypeTag;
export declare function structTypeTag(address: string, module: string, name: string, typeParams?: TypeTag[]): TypeTag;
