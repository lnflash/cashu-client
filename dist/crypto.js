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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.unblindSignature = exports.createBlindedMessage = exports.buildP2PKSecret = exports.splitIntoDenominations = exports.hashToCurve = void 0;
const crypto_1 = __importDefault(require("crypto"));
const secp = __importStar(require("tiny-secp256k1"));
const errors_1 = require("./errors");
const DOMAIN_SEPARATOR = Buffer.from("Secp256k1_HashToCurve_Cashu_", "utf8");
/**
 * NUT-00: hash_to_curve
 * Deterministically maps a secret (as UTF-8 bytes or raw buffer) to a secp256k1 point.
 */
const hashToCurve = (secret) => {
    const msgHash = crypto_1.default
        .createHash("sha256")
        .update(Buffer.concat([DOMAIN_SEPARATOR, secret]))
        .digest();
    for (let counter = 0; counter < 2 ** 16; counter++) {
        const counterBuf = Buffer.alloc(4);
        counterBuf.writeUInt32BE(counter);
        const candidate = Buffer.concat([
            Buffer.from([0x02]),
            crypto_1.default.createHash("sha256").update(Buffer.concat([msgHash, counterBuf])).digest(),
        ]);
        if (secp.isPoint(candidate))
            return candidate;
    }
    throw new Error("hash_to_curve: no valid point found after 2^16 iterations");
};
exports.hashToCurve = hashToCurve;
/**
 * Split an amount (in the keyset's base unit) into Cashu power-of-2 denominations.
 * Returns an array of amounts summing to `total`, each a power of 2.
 *
 * @param total      Total amount to split
 * @param maxSlots   Optional upper bound on the number of denominations produced.
 *                   Throws CashuInsufficientSlotsError if the split would require more.
 */
const splitIntoDenominations = (total, maxSlots) => {
    const denominations = [];
    let remaining = total;
    for (let bit = 15; bit >= 0; bit--) {
        const denom = 1 << bit;
        while (remaining >= denom) {
            denominations.push(denom);
            remaining -= denom;
        }
    }
    if (maxSlots !== undefined && denominations.length > maxSlots) {
        throw new errors_1.CashuInsufficientSlotsError(`Amount ${total} requires ${denominations.length} denominations but only ${maxSlots} slots available`);
    }
    return denominations;
};
exports.splitIntoDenominations = splitIntoDenominations;
/**
 * Build the canonical NUT-10 P2PK secret JSON string for a card proof.
 * Serialization MUST have no spaces and fixed key order.
 *
 * secret = ["P2PK", {"nonce": "<hex>", "data": "<cardPubkey>", "tags": [["sigflag", "SIG_INPUTS"]]}]
 */
const buildP2PKSecret = (nonce, cardPubkey) => {
    return `["P2PK",{"nonce":"${nonce}","data":"${cardPubkey}","tags":[["sigflag","SIG_INPUTS"]]}]`;
};
exports.buildP2PKSecret = buildP2PKSecret;
/**
 * NUT-03: Create a blinded message for a given denomination.
 * Returns the blinding data needed to unblind the mint's response.
 *
 * B_ = hash_to_curve(secret) + r*G
 */
const createBlindedMessage = (keysetId, amount, cardPubkey) => {
    const nonce = crypto_1.default.randomBytes(32);
    const nonceHex = nonce.toString("hex");
    const secretStr = (0, exports.buildP2PKSecret)(nonceHex, cardPubkey);
    const secretBytes = Buffer.from(secretStr, "utf8");
    const Y = (0, exports.hashToCurve)(secretBytes);
    let r;
    do {
        r = crypto_1.default.randomBytes(32);
    } while (!secp.isPrivate(r));
    const rG = secp.pointFromScalar(r, true);
    if (!rG)
        throw new Error("pointFromScalar failed");
    const B_ = secp.pointAdd(Y, rG, true);
    if (!B_)
        throw new Error("pointAdd failed for B_");
    // keysetId is accepted for API completeness; callers include it in the BlindedMessage themselves
    void keysetId;
    return {
        nonce: nonceHex,
        secretStr,
        r,
        B_: Buffer.from(B_).toString("hex"),
        amount,
    };
};
exports.createBlindedMessage = createBlindedMessage;
/**
 * NUT-03: Unblind a mint signature.
 * C = C_ - r*K  where K is the mint's public key for this keyset/denomination.
 */
const unblindSignature = (C_hex, r, mintPubkeyHex) => {
    const C_ = Buffer.from(C_hex, "hex");
    const K = Buffer.from(mintPubkeyHex, "hex");
    const rK = secp.pointMultiply(K, r, true);
    if (!rK)
        throw new Error("pointMultiply failed for r*K");
    // Negate compressed point: flip parity byte (0x02 ↔ 0x03)
    const rKNeg = Buffer.from(rK);
    rKNeg[0] = rKNeg[0] === 0x02 ? 0x03 : 0x02;
    const C = secp.pointAdd(C_, rKNeg, true);
    if (!C)
        throw new Error("pointAdd failed for C = C_ - r*K");
    return Buffer.from(C).toString("hex");
};
exports.unblindSignature = unblindSignature;
