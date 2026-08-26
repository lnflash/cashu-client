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
exports.hasDLEQ = exports.proofDLEQFromBlindSignature = exports.verifyProofDLEQ = exports.verifyBlindSignatureDLEQ = exports.hashE = void 0;
const crypto_1 = __importDefault(require("crypto"));
const secp = __importStar(require("tiny-secp256k1"));
const crypto_2 = require("./crypto");
/**
 * NUT-12: discrete-log equality proofs.
 *
 * Without this, a mint can sign a particular user's outputs with a key unique
 * to them and later recognise those proofs when they come back — breaking the
 * unlinkability that is the whole point of ecash. DLEQ closes that: it proves
 * the signature was made with the same key the mint publishes to everyone,
 * and the check is purely local arithmetic.
 *
 * That local part matters twice over for cards. An offline terminal cannot ask
 * the mint whether a proof is genuine, but it *can* verify DLEQ on the spot,
 * which is the difference between accepting a tap on faith and accepting it on
 * arithmetic.
 */
const negate = (compressedPoint) => {
    const negated = Buffer.from(compressedPoint);
    negated[0] = negated[0] === 0x02 ? 0x03 : 0x02;
    return negated;
};
/** Uncompressed (65-byte, 0x04-prefixed) hex — the form NUT-12 hashes over. */
const uncompressedHex = (point) => {
    const full = secp.pointCompress(point, false);
    return Buffer.from(full).toString("hex");
};
/**
 * NUT-12 hash_e: sha256 over the concatenated *uncompressed* hex of each point.
 *
 * The uncompressed form is not incidental — hashing the compressed form
 * produces a different challenge and every verification fails, which looks
 * exactly like a hostile mint rather than an encoding mistake.
 */
const hashE = (points) => {
    const joined = points.map(uncompressedHex).join("");
    return crypto_1.default.createHash("sha256").update(Buffer.from(joined, "utf8")).digest();
};
exports.hashE = hashE;
const parseScalars = (dleq) => {
    const e = Buffer.from(dleq.e, "hex");
    const s = Buffer.from(dleq.s, "hex");
    if (e.length !== 32 || s.length !== 32)
        return null;
    return { e, s };
};
/**
 * Verify the DLEQ on a blind signature, before unblinding.
 *
 *   R1 = s*G - e*A
 *   R2 = s*B_ - e*C_
 *   e == hash_e(R1, R2, A, C_)
 *
 * @param mintPubkeyHex the mint's public key `A` for this amount and keyset
 * @param B_hex         the blinded message that was sent
 */
const verifyBlindSignatureDLEQ = (signature, mintPubkeyHex, B_hex) => {
    if (!signature.dleq)
        return false;
    try {
        const scalars = parseScalars(signature.dleq);
        if (!scalars)
            return false;
        const { e, s } = scalars;
        const A = Buffer.from(mintPubkeyHex, "hex");
        const B_ = Buffer.from(B_hex, "hex");
        const C_ = Buffer.from(signature.C_, "hex");
        if (!secp.isPoint(A) || !secp.isPoint(B_) || !secp.isPoint(C_))
            return false;
        // R1 = s*G - e*A
        const sG = secp.pointFromScalar(s, true);
        const eA = secp.pointMultiply(A, e, true);
        if (!sG || !eA)
            return false;
        const R1 = secp.pointAdd(sG, negate(eA), true);
        // R2 = s*B_ - e*C_
        const sB = secp.pointMultiply(B_, s, true);
        const eC = secp.pointMultiply(C_, e, true);
        if (!sB || !eC)
            return false;
        const R2 = secp.pointAdd(sB, negate(eC), true);
        // A null here is the point at infinity, which is not a valid R — reject
        // rather than treating it as a match.
        if (!R1 || !R2)
            return false;
        return (0, exports.hashE)([R1, R2, A, C_]).equals(e);
    }
    catch {
        return false;
    }
};
exports.verifyBlindSignatureDLEQ = verifyBlindSignatureDLEQ;
/**
 * Verify the DLEQ carried on an unblinded proof.
 *
 * The proof stores the blinding factor `r`, which lets the original blinded
 * pair be reconstructed:
 *
 *   B_ = Y + r*G     (Y = hash_to_curve(secret))
 *   C_ = C + r*A
 *
 * and then the same check applies. This is the one a receiving terminal runs:
 * it needs no network and no trust in whoever handed over the proof.
 */
const verifyProofDLEQ = (proof, mintPubkeyHex) => {
    if (!proof.dleq || !proof.dleq.r)
        return false;
    try {
        const scalars = parseScalars(proof.dleq);
        if (!scalars)
            return false;
        const { e, s } = scalars;
        const r = Buffer.from(proof.dleq.r, "hex");
        if (r.length !== 32 || !secp.isPrivate(r))
            return false;
        const A = Buffer.from(mintPubkeyHex, "hex");
        const C = Buffer.from(proof.C, "hex");
        if (!secp.isPoint(A) || !secp.isPoint(C))
            return false;
        // Reconstruct B_ = Y + r*G
        const Y = (0, crypto_2.hashToCurve)(Buffer.from(proof.secret, "utf8"));
        const rG = secp.pointFromScalar(r, true);
        if (!rG)
            return false;
        const B_ = secp.pointAdd(Y, rG, true);
        // Reconstruct C_ = C + r*A
        const rA = secp.pointMultiply(A, r, true);
        if (!rA)
            return false;
        const C_ = secp.pointAdd(C, rA, true);
        if (!B_ || !C_)
            return false;
        const sG = secp.pointFromScalar(s, true);
        const eA = secp.pointMultiply(A, e, true);
        if (!sG || !eA)
            return false;
        const R1 = secp.pointAdd(sG, negate(eA), true);
        const sB = secp.pointMultiply(B_, s, true);
        const eC = secp.pointMultiply(C_, e, true);
        if (!sB || !eC)
            return false;
        const R2 = secp.pointAdd(sB, negate(eC), true);
        if (!R1 || !R2)
            return false;
        return (0, exports.hashE)([R1, R2, A, C_]).equals(e);
    }
    catch {
        return false;
    }
};
exports.verifyProofDLEQ = verifyProofDLEQ;
/**
 * Carry a blind signature's DLEQ onto the proof it unblinds into.
 *
 * This is the missing link in the card lifecycle. The mint returns `e`/`s` on
 * the blind signature; `verifyProofDLEQ` additionally needs `r`, the blinding
 * factor, which only the client has (it is on the `CashuBlindingData` returned
 * by `createBlindedMessage`). Pair them here when building the proof:
 *
 * ```ts
 * const proof = {
 *   id: sig.id,
 *   amount: sig.amount,
 *   secret: blindingData[i].secretStr,
 *   C: unblindSignature(sig.C_, blindingData[i].r, keys[String(sig.amount)]),
 *   dleq: proofDLEQFromBlindSignature(sig, blindingData[i].r),
 * }
 * ```
 *
 * Returns undefined when the mint emitted no DLEQ, which is a policy decision
 * for the caller rather than an error — see {@link hasDLEQ}.
 */
const proofDLEQFromBlindSignature = (signature, r) => {
    if (!signature.dleq)
        return undefined;
    return {
        e: signature.dleq.e,
        s: signature.dleq.s,
        r: Buffer.from(r).toString("hex"),
    };
};
exports.proofDLEQFromBlindSignature = proofDLEQFromBlindSignature;
/**
 * True when the proof carries a complete DLEQ (`e`, `s` and `r`) to check.
 *
 * Distinguishing "absent" from "invalid" matters: not every mint emits DLEQ,
 * so a missing proof is a policy decision for the caller, whereas a present
 * but failing one means the mint is misbehaving and should be refused. The
 * response parsers enforce the other half of that split — a present-but-
 * malformed `dleq` is rejected at parse time rather than quietly dropped.
 */
const hasDLEQ = (proof) => Boolean(proof.dleq && proof.dleq.e && proof.dleq.s && proof.dleq.r);
exports.hasDLEQ = hasDLEQ;
