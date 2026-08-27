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
exports.reconstructProofFromCard = void 0;
exports.reconstructProofsFromCard = reconstructProofsFromCard;
/**
 * Card proof reconstruction.
 *
 * A card cannot store a NUT-10 P2PK secret. The secret is a JSON string of
 * roughly 150 bytes and a proof slot is 78 bytes total, so the card stores only
 * the 32-byte nonce. Everything else the secret needs — the card's public key
 * and the fixed tag set — is recoverable, which is what makes the slot layout
 * work at all.
 *
 * This module turns what `GET_PROOF` returns into a spendable `CashuProof`.
 * Without it the card's contents are inert: a terminal can read a slot and
 * still have no proof to hand the mint.
 *
 * See `spec/NUT-XX.md` in lnflash/cashu-javacard —
 * *Reconstructing the full Proof from card storage*.
 */
const secp = __importStar(require("tiny-secp256k1"));
const crypto_1 = require("./crypto");
const errors_1 = require("./errors");
const HEX = /^[0-9a-f]+$/;
/**
 * Which error class each field's rejection carries.
 *
 * A terminal has to tell "this card's key is bad, abort the whole card" apart
 * from "slot 3 is corrupt, skip it", and regex-matching error messages is not a
 * way to do that. `cardPubkey` belongs to the card; every other field belongs to
 * the single slot being read, so the two get different classes — and different
 * NUT error codes — rather than a bare `Error` each.
 *
 * The mapping is a `Record` over the field union rather than a comparison
 * against the literal `"cardPubkey"`. That class is part of the contract
 * callers depend on, and a string comparison would let a typo or a renamed
 * field silently downgrade a card-key failure to `CashuInvalidProofError` with
 * no compiler complaint; a `Record` makes both the typo and a new field a
 * compile error.
 */
const FIELD_ERROR = {
    cardPubkey: errors_1.CashuInvalidCardPubkeyError,
    keysetId: errors_1.CashuInvalidProofError,
    nonce: errors_1.CashuInvalidProofError,
    C: errors_1.CashuInvalidProofError,
    amount: errors_1.CashuInvalidProofError,
};
const rejection = (field, message) => new FIELD_ERROR[field](message);
const requireHex = (value, bytes, field) => {
    // Checked before `.trim()`. A JS caller or a native reader bridge that omits a
    // field otherwise gets `Cannot read properties of undefined (reading 'trim')`
    // — the one input shape where this module produces a stack trace instead of
    // the diagnosis it exists to produce.
    if (typeof value !== "string") {
        throw rejection(field, `${field} must be a hex string, got ${typeof value}`);
    }
    const v = value.trim().toLowerCase();
    if (!HEX.test(v)) {
        throw rejection(field, `${field} must be hex, got ${JSON.stringify(value)}`);
    }
    if (v.length !== bytes * 2) {
        throw rejection(field, `${field} must be ${bytes} bytes (${bytes * 2} hex chars), got ${v.length}`);
    }
    return v;
};
/**
 * Reject anything that is not an actual point on secp256k1.
 *
 * A prefix test is not enough: `02`/`03` is necessary but not sufficient, and an
 * on-prefix but off-curve value produces a secret locked to a non-point — the
 * card burns the slot on SPEND_PROOF and the mint then rejects a proof that was
 * never spendable. `secp.isPoint` is how the rest of this package validates
 * points (crypto.ts, dleq.ts, witness.ts), and the 33-byte length check in
 * `requireHex` has already rejected uncompressed keys by the time we get here.
 *
 * The two failures are reported separately because they send an operator to
 * different places. A bad prefix is a reader that encoded the point wrong. An
 * on-prefix, off-curve value is a corrupted or truncated point, and quoting
 * only its (valid) prefix byte would point at the one part that is *not* the
 * problem — the misdiagnosis this module exists to eliminate.
 */
const requirePoint = (value, field) => {
    const bytes = Buffer.from(value, "hex");
    if (bytes[0] !== 0x02 && bytes[0] !== 0x03) {
        throw rejection(field, `${field} must be a compressed secp256k1 point, got prefix 0x${value.slice(0, 2)}`);
    }
    if (!secp.isPoint(bytes)) {
        throw rejection(field, `${field} is not on the secp256k1 curve: ${value}`);
    }
};
/**
 * The pre-0.4.0 P2PK serialization, frozen.
 *
 * `buildP2PKSecret` lower-cases the nonce and pubkey as of 0.4.0. A proof minted
 * by 0.3.0 or earlier from an upper-case reader value committed to
 * `Y = hash_to_curve(secret-with-upper-case-hex)`, so the canonical secret is a
 * *different* proof that the mint has never signed — and the card burns the slot
 * on SPEND_PROOF before the mint ever objects. This reproduces exactly what
 * those cards were funded with so they stay redeemable.
 *
 * **Only `data` can differ in case.** Pre-0.4.0 `createBlindedMessage` generated
 * the nonce itself (`crypto.randomBytes(32).toString("hex")`), which is always
 * lower case, so the reader's hex case could only ever reach a mint-time secret
 * through `cardPubkey`. Freezing the *nonce*'s case too would emit a secret no
 * version of this library has ever minted — a proof the mint has never signed,
 * discovered only after SPEND_PROOF has burned the slot. The caller therefore
 * passes the already-lower-cased nonce and the raw-cased pubkey.
 *
 * Do not "fix" this to normalise `data`: its whole value is being byte-identical
 * to what the old code emitted. New proofs must use `buildP2PKSecret`.
 */
const legacyP2PKSecret = (nonce, cardPubkey) => JSON.stringify([
    "P2PK",
    { nonce, data: cardPubkey, tags: [["sigflag", "SIG_INPUTS"]] },
]);
/**
 * Rebuild a spendable proof from a card slot and the card's public key.
 *
 * The returned proof carries no witness. It is not spendable until the card
 * signs `p2pkMessageToSign(proof)` via SPEND_PROOF and the signature is
 * attached with `attachP2PKWitness`.
 *
 * Throws rather than returning a malformed proof: a wrong-length keyset id or
 * nonce produces a proof the mint will reject, and failing at the mint is a far
 * worse place to discover it than here — by then the card may already have
 * burned the slot.
 */
const reconstructProofFromCard = (slot, cardPubkey, options = {}) => {
    // The card key is checked first, and completely, because it is the only
    // card-level input here: if it is bad, every slot on the card is unusable and
    // the answer is "abort the card", not "skip this slot". Checked after a slot
    // field it would be masked by whichever slot also happened to be corrupt, and
    // a caller scanning `failures` would read a dead card as one bad slot.
    const pubkey = requireHex(cardPubkey, 33, "cardPubkey");
    requirePoint(pubkey, "cardPubkey");
    // A NUT-02 keyset id is 16 hex chars. Anything shorter is usually an id that
    // was ASCII-encoded into the card's 8-byte field, which truncates it to half
    // an id and matches no keyset at the mint.
    const keysetId = requireHex(slot.keysetId, 8, "keysetId");
    const nonce = requireHex(slot.nonce, 32, "nonce");
    const C = requireHex(slot.C, 33, "C");
    // A NUT-02 v0 id is a 0x00 version byte plus 7 bytes of hash, and 8 bytes is
    // the only id version that fits the card's field — so a first byte other than
    // 00 is a corrupted id, which matches no keyset just like a truncated one.
    if (!keysetId.startsWith("00")) {
        throw rejection("keysetId", `keysetId must be a NUT-02 v0 id (00 version byte), got 0x${keysetId.slice(0, 2)}`);
    }
    requirePoint(C, "C");
    // Reported before the range check so a string `"8"` from an untyped reader
    // bridge does not render as `got 8` — a message that looks like a valid value
    // and hides the type error. Mirrors requireHex's `typeof` message.
    if (typeof slot.amount !== "number") {
        throw rejection("amount", `amount must be a number, got ${typeof slot.amount}`);
    }
    // Cashu denominations are powers of two — splitIntoDenominations never emits
    // anything else and a mint keyset has no key for amount 3 — so a corrupted
    // amount byte (8 → 9) yields a proof the mint rejects after the slot is burned.
    if (!Number.isSafeInteger(slot.amount) ||
        slot.amount <= 0 ||
        Math.log2(slot.amount) % 1 !== 0) {
        throw rejection("amount", 
        // Quoted the way requireHex quotes, so a rejected value never renders as
        // something that looks valid. JSON.stringify renders NaN and Infinity as
        // `null` — which is precisely that failure — so those keep their names.
        `amount must be a positive power of two, got ${Number.isFinite(slot.amount) ? JSON.stringify(slot.amount) : String(slot.amount)}`);
    }
    return {
        id: keysetId,
        amount: slot.amount,
        // Byte-identical to what was signed at mint time — buildP2PKSecret is the
        // single source of that serialization *and* of its canonical hex case, so
        // the two cannot drift apart. The normalisation above is therefore a no-op
        // on the secret rather than a second, competing canonical form.
        //
        // The legacy path passes `nonce` (already lower-cased) rather than the raw
        // slot value, and only `cardPubkey` verbatim: pre-0.4.0 nonces were generated
        // here as lower-case hex, so freezing the reader's case on that field would
        // fabricate a secret no mint has ever signed. See legacyP2PKSecret.
        secret: options.legacyHexCase
            ? legacyP2PKSecret(nonce, cardPubkey.trim())
            : (0, crypto_1.buildP2PKSecret)(nonce, pubkey),
        C,
    };
};
exports.reconstructProofFromCard = reconstructProofFromCard;
/**
 * Re-label a slot failure with its index without throwing away what it was.
 *
 * Building a fresh bare `Error` would drop both the original stack — pointing
 * the trace at this wrapper rather than the failing check — and the error class,
 * so the batch path would erase the very "bad card key" / "bad slot" distinction
 * {@link rejection} exists to draw. Every `CashuError` subclass takes
 * `(message, code?)` with the code defaulted, so reconstructing from the
 * constructor preserves the NUT code too.
 */
const withSlotIndex = (e, i) => {
    const message = `slot ${i}: ${e instanceof Error ? e.message : String(e)}`;
    const Ctor = e instanceof errors_1.CashuError ? e.constructor : Error;
    // `cause` is assigned rather than passed to the constructor: this package
    // compiles against lib ES2020, whose Error constructor is typed without an
    // options bag. Readers see the same `.cause` either way (Node >= 18).
    const wrapped = new Ctor(message);
    wrapped.cause = e;
    return wrapped;
};
function reconstructProofsFromCard(slots, cardPubkey, options = {}) {
    const { skipInvalid = false, ...slotOptions } = options;
    const proofs = [];
    const failures = [];
    slots.forEach((slot, i) => {
        try {
            proofs.push((0, exports.reconstructProofFromCard)(slot, cardPubkey, slotOptions));
        }
        catch (e) {
            const error = withSlotIndex(e, i);
            if (!skipInvalid)
                throw error;
            failures.push({ index: i, error });
        }
    });
    return skipInvalid ? { proofs, failures } : proofs;
}
