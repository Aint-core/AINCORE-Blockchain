"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_SIBLINGS = exports.PLACEHOLDER = void 0;
exports.keyHash = keyHash;
exports.verifyStateProof = verifyStateProof;
const crypto = __importStar(require("crypto"));
const LEAF_DOMAIN = Buffer.from('JMT::LeafNode');
const INTERNAL_DOMAIN = Buffer.from('JMT::IntrnalNode');
exports.PLACEHOLDER = Buffer.from('SPARSE_MERKLE_PLACEHOLDER_HASH__');
exports.MAX_SIBLINGS = 256;
function sha256(...parts) {
    const h = crypto.createHash('sha256');
    for (const p of parts)
        h.update(p);
    return h.digest();
}
/**
 * The exact UTF-8 bytes of `s`. A string with a lone surrogate has none: its
 * encoding substitutes U+FFFD, so two different strings would hash alike and
 * one could pass for the other. It is refused.
 */
function utf8(s, what) {
    const bytes = Buffer.from(s, 'utf8');
    if (bytes.toString('utf8') !== s) {
        throw new Error(`the ${what} is not well-formed Unicode (a lone surrogate)`);
    }
    return bytes;
}
function keyHash(key) {
    return sha256(utf8(key, 'key'));
}
function parseHash(hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error(`malformed proof: not a 32-byte hex hash: ${hex}`);
    }
    return Buffer.from(hex, 'hex');
}
function bit(hash, index) {
    return (hash[index >> 3] & (0x80 >> (index & 7))) !== 0;
}
function commonPrefixBits(a, b) {
    let n = 0;
    while (n < 256 && bit(a, n) === bit(b, n))
        n++;
    return n;
}
/**
 * Verify that `key` has `value` (a string: stored values are UTF-8) or is
 * absent (`null`) in the tree whose root is `rootHex`. Throws on failure.
 */
function verifyStateProof(rootHex, key, value, proof) {
    if (proof.siblings.length > exports.MAX_SIBLINGS) {
        throw new Error(`malformed proof: ${proof.siblings.length} siblings`);
    }
    const root = parseHash(rootHex);
    const kh = keyHash(key);
    const leaf = proof.leaf
        ? { key: parseHash(proof.leaf.key_hash), value: parseHash(proof.leaf.value_hash) }
        : null;
    if (value !== null) {
        if (!leaf)
            throw new Error('the proof shows the key absent');
        if (!leaf.key.equals(kh))
            throw new Error('the proof is for another key');
        if (!leaf.value.equals(sha256(utf8(value, 'value')))) {
            throw new Error('the value does not match the proof');
        }
    }
    else if (leaf) {
        if (leaf.key.equals(kh))
            throw new Error('the proof shows the key present');
        if (commonPrefixBits(kh, leaf.key) < proof.siblings.length) {
            throw new Error("the proof's leaf is not on the key's path");
        }
    }
    let hash = leaf ? sha256(LEAF_DOMAIN, leaf.key, leaf.value) : exports.PLACEHOLDER;
    const n = proof.siblings.length;
    proof.siblings.forEach((siblingHex, i) => {
        const sibling = parseHash(siblingHex);
        hash = bit(kh, n - 1 - i)
            ? sha256(INTERNAL_DOMAIN, sibling, hash)
            : sha256(INTERNAL_DOMAIN, hash, sibling);
    });
    if (!hash.equals(root))
        throw new Error('the proof does not reach the trusted root');
}
