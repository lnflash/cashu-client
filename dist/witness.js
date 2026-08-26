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
exports.findUnsignedProofs = exports.requiresWitness = exports.verifyP2PKWitness = exports.parseWitnessSignatures = exports.attachP2PKWitness = exports.p2pkMessageToSign = exports.parseP2PKSecret = exports.isWellKnownSecret = exports.parseWellKnownSecret = void 0;
const crypto_1 = __importDefault(require("crypto"));
const secp = __importStar(require("tiny-secp256k1"));
/**
 * Parse the NUT-10 envelope only: `[kind, {...}]`.
 *
 * Deliberately separate from {@link parseP2PKSecret}. "Is this a well-known
 * secret at all?" and "is this a P2PK secret this module can verify?" are
 * different questions, and collapsing them is how an HTLC — or a P2PK secret
 * whose body is malformed — gets waved through as a plain, unlocked secret that
 * needs no witness. Returns null only when the secret is not a `[kind, {...}]`
 * pair, i.e. when it really is a plain string secret.
 */
const parseWellKnownSecret = (secret) => {
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
    if (typeof kind !== "string" || kind.length === 0)
        return null;
    if (typeof body !== "object" || body === null || Array.isArray(body))
        return null;
    return { kind, body: body };
};
exports.parseWellKnownSecret = parseWellKnownSecret;
/**
 * True when `secret` is a NUT-10 well-known secret of any kind — P2PK, HTLC, or
 * something this library has never heard of. Anything that is one carries a
 * spending condition, so it needs a witness the mint will accept.
 */
const isWellKnownSecret = (secret) => (0, exports.parseWellKnownSecret)(secret) !== null;
exports.isWellKnownSecret = isWellKnownSecret;
/**
 * Parse a NUT-10 secret string: `["P2PK", {"nonce":..., "data":..., "tags":[...]}]`.
 *
 * Returns null for a plain (non-P2PK) secret, for a well-known secret of
 * another kind, and for a P2PK secret whose body is malformed. Callers deciding
 * whether a witness is needed must use {@link isWellKnownSecret} instead — a
 * null here means "this verifier cannot vouch for it", not "it is unlocked".
 *
 * Malformed `tags` are rejected outright rather than filtered out. A dropped
 * tag is indistinguishable from an absent one, so filtering would let anyone
 * bypass the strict-tag policy in {@link verifyP2PKWitness} by making a tag
 * malformed (`[["n_sigs", 2]]` — a JSON number, which the mint reads as 2)
 * instead of unknown.
 */
const parseP2PKSecret = (secret) => {
    const envelope = (0, exports.parseWellKnownSecret)(secret);
    if (!envelope || envelope.kind !== "P2PK")
        return null;
    const b = envelope.body;
    if (typeof b.nonce !== "string" || typeof b.data !== "string")
        return null;
    if (b.tags !== undefined) {
        if (!Array.isArray(b.tags) ||
            !b.tags.every(t => Array.isArray(t) && t.every(x => typeof x === "string"))) {
            return null;
        }
    }
    const tags = (b.tags ?? []);
    return { kind: envelope.kind, nonce: b.nonce, data: b.data, tags };
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
 * NUT-11 spending-condition tags this verifier actually implements.
 *
 * Anything else — `locktime`, `refund`, `pubkeys` — changes what makes a
 * witness valid in a way the check below does not model, so a secret carrying
 * one is rejected rather than accepted on the strength of the parts we do
 * understand. `swapProofs` exists to receive a *sender's* proofs, i.e. secrets
 * this library did not construct, so these are reachable in practice.
 */
const SUPPORTED_TAGS = new Set(["sigflag", "n_sigs"]);
/** The spending conditions read off a P2PK secret, or null if unsupported. */
const readSpendingConditions = (parsedSecret) => {
    let requiredSigs = 1;
    for (const tag of parsedSecret.tags) {
        const key = tag[0];
        if (key === undefined || !SUPPORTED_TAGS.has(key))
            return null;
        if (key === "sigflag") {
            // SIG_ALL signs over every input and output of the request, so a
            // SIG_INPUTS-shaped signature verifies here and is still refused by the
            // mint. Absent means SIG_INPUTS by default.
            if (tag[1] !== "SIG_INPUTS")
                return null;
        }
        if (key === "n_sigs") {
            const n = Number(tag[1]);
            if (!Number.isInteger(n) || n < 1)
                return null;
            requiredSigs = Math.max(requiredSigs, n);
        }
    }
    return { requiredSigs };
};
/**
 * Verify a proof's witness against the key its secret is locked to, and against
 * the spending conditions its secret declares.
 *
 * Worth doing before submitting: a mint rejects a bad witness with a generic
 * error *after* the card has already marked the proof spent, so the failure is
 * unrecoverable at exactly the point it is least recoverable. Checking here
 * turns that into a local error with the proof still intact — but only if the
 * check is the same one the mint runs, which means honouring `sigflag` and
 * `n_sigs` rather than accepting on any one valid signature.
 */
const verifyP2PKWitness = (proof) => {
    const parsedSecret = (0, exports.parseP2PKSecret)(proof.secret);
    if (!parsedSecret)
        return false;
    const conditions = readSpendingConditions(parsedSecret);
    if (!conditions)
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
    // Count *distinct* valid signatures: repeating one signature n times must not
    // satisfy an n_sigs requirement.
    const valid = new Set();
    for (const sig of sigs) {
        const normalised = sig.toLowerCase();
        if (valid.has(normalised))
            continue;
        try {
            if (secp.verifySchnorr(msg, xOnly, Buffer.from(sig, "hex")))
                valid.add(normalised);
        }
        catch {
            // Malformed signature — not a match, keep checking the rest.
        }
    }
    return valid.size >= conditions.requiredSigs;
};
exports.verifyP2PKWitness = verifyP2PKWitness;
/**
 * True when this proof needs a witness before the mint will accept it.
 * A plain-secret proof does not.
 *
 * Keyed on "is this a well-known secret" rather than "did the P2PK parser
 * succeed". Those differ for an HTLC secret and for a malformed P2PK one, and
 * reading either as "plain, needs no witness" submits a proof the mint will
 * refuse — after the card has already burned the slot. Anything carrying a
 * NUT-10 spending condition this module cannot verify is reported by
 * {@link findUnsignedProofs} instead of waved through.
 */
const requiresWitness = (proof) => (0, exports.isWellKnownSecret)(proof.secret);
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
