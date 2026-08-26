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
exports.findUnsignedProofs = exports.requiresWitness = exports.verifyP2PKWitness = exports.parseWitnessSignatures = exports.attachP2PKWitness = exports.p2pkMessageToSign = exports.parseP2PKSecret = void 0;
const crypto_1 = __importDefault(require("crypto"));
const secp = __importStar(require("tiny-secp256k1"));
/**
 * Parse a NUT-10 secret string: `["P2PK", {"nonce":..., "data":..., "tags":[...]}]`.
 * Returns null for a plain (non-P2PK) secret, which is not an error — an
 * unlocked proof simply needs no witness.
 */
const parseP2PKSecret = (secret) => {
    let parsed;
    try {
        parsed = JSON.parse(secret);
    }
    catch {
        return null; // a plain string secret, not a well-known secret
    }
    if (!Array.isArray(parsed) || parsed.length < 2)
        return null;
    const [kind, body] = parsed;
    if (kind !== "P2PK" || typeof body !== "object" || body === null)
        return null;
    const b = body;
    if (typeof b.nonce !== "string" || typeof b.data !== "string")
        return null;
    const tags = Array.isArray(b.tags)
        ? b.tags.filter(t => Array.isArray(t) && t.every(x => typeof x === "string"))
        : [];
    return { kind, nonce: b.nonce, data: b.data, tags };
};
exports.parseP2PKSecret = parseP2PKSecret;
/**
 * The 32-byte message a P2PK proof must be signed over: SHA-256 of the secret
 * string's UTF-8 bytes.
 *
 * Hand this to the card as the SPEND_PROOF payload. Getting it wrong produces a
 * signature that is valid BIP-340 and still rejected by every mint, which is a
 * confusing failure to debug from the card side — so it is computed here, once.
 */
const p2pkMessageToSign = (proof) => crypto_1.default.createHash("sha256").update(Buffer.from(proof.secret, "utf8")).digest();
exports.p2pkMessageToSign = p2pkMessageToSign;
/**
 * Attach one or more signatures to a proof as a NUT-11 witness.
 * Returns a new proof; the input is not mutated.
 */
const attachP2PKWitness = (proof, signatures) => {
    if (signatures.length === 0) {
        throw new Error("attachP2PKWitness: no signatures supplied");
    }
    for (const sig of signatures) {
        if (!/^[0-9a-fA-F]{128}$/.test(sig)) {
            throw new Error(`attachP2PKWitness: signature must be 64 bytes of hex, got ${sig.length / 2} bytes`);
        }
    }
    return { ...proof, witness: JSON.stringify({ signatures: signatures.map(s => s.toLowerCase()) }) };
};
exports.attachP2PKWitness = attachP2PKWitness;
/** Read the signatures back out of a proof's witness field. */
const parseWitnessSignatures = (witness) => {
    if (!witness)
        return [];
    try {
        const parsed = JSON.parse(witness);
        if (typeof parsed !== "object" || parsed === null)
            return [];
        const sigs = parsed.signatures;
        if (!Array.isArray(sigs))
            return [];
        return sigs.filter((s) => typeof s === "string");
    }
    catch {
        return [];
    }
};
exports.parseWitnessSignatures = parseWitnessSignatures;
/**
 * Verify a proof's witness against the key its secret is locked to.
 *
 * Worth doing before submitting: a mint rejects a bad witness with a generic
 * error *after* the card has already marked the proof spent, so the failure is
 * unrecoverable at exactly the point it is least recoverable. Checking here
 * turns that into a local error with the proof still intact.
 */
const verifyP2PKWitness = (proof) => {
    const parsedSecret = (0, exports.parseP2PKSecret)(proof.secret);
    if (!parsedSecret)
        return false;
    const sigs = (0, exports.parseWitnessSignatures)(proof.witness);
    if (sigs.length === 0)
        return false;
    let lockedKey;
    try {
        lockedKey = Buffer.from(parsedSecret.data, "hex");
    }
    catch {
        return false;
    }
    // NUT-11 keys are compressed (33 bytes); BIP-340 verifies against x-only.
    if (lockedKey.length !== 33 || !secp.isPoint(lockedKey))
        return false;
    const xOnly = lockedKey.subarray(1);
    const msg = (0, exports.p2pkMessageToSign)(proof);
    return sigs.some(sig => {
        try {
            return secp.verifySchnorr(msg, xOnly, Buffer.from(sig, "hex"));
        }
        catch {
            return false;
        }
    });
};
exports.verifyP2PKWitness = verifyP2PKWitness;
/**
 * True when this proof needs a witness before the mint will accept it.
 * A plain-secret proof does not.
 */
const requiresWitness = (proof) => (0, exports.parseP2PKSecret)(proof.secret) !== null;
exports.requiresWitness = requiresWitness;
/**
 * Check every proof in a set carries a valid witness, returning the indices
 * that do not. Callers should treat a non-empty result as "do not submit":
 * the mint fails the whole request atomically, so one bad witness wastes the
 * spend attempt for all of them.
 */
const findUnsignedProofs = (proofs) => proofs.reduce((bad, proof, i) => {
    if ((0, exports.requiresWitness)(proof) && !(0, exports.verifyP2PKWitness)(proof))
        bad.push(i);
    return bad;
}, []);
exports.findUnsignedProofs = findUnsignedProofs;
