"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reconstructProofsFromCard = exports.reconstructProofFromCard = void 0;
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
const crypto_1 = require("./crypto");
const HEX = /^[0-9a-f]+$/;
const requireHex = (value, bytes, field) => {
    const v = value.trim().toLowerCase();
    if (!HEX.test(v)) {
        throw new Error(`${field} must be hex, got ${JSON.stringify(value)}`);
    }
    if (v.length !== bytes * 2) {
        throw new Error(`${field} must be ${bytes} bytes (${bytes * 2} hex chars), got ${v.length}`);
    }
    return v;
};
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
const reconstructProofFromCard = (slot, cardPubkey) => {
    // A NUT-02 keyset id is 16 hex chars. Anything shorter is usually an id that
    // was ASCII-encoded into the card's 8-byte field, which truncates it to half
    // an id and matches no keyset at the mint.
    const keysetId = requireHex(slot.keysetId, 8, "keysetId");
    const nonce = requireHex(slot.nonce, 32, "nonce");
    const C = requireHex(slot.C, 33, "C");
    const pubkey = requireHex(cardPubkey, 33, "cardPubkey");
    if (pubkey[1] !== "2" && pubkey[1] !== "3") {
        throw new Error(`cardPubkey must be a compressed secp256k1 point (02/03 prefix), got 0x${pubkey.slice(0, 2)}`);
    }
    if (C[1] !== "2" && C[1] !== "3") {
        throw new Error(`C must be a compressed secp256k1 point (02/03 prefix), got 0x${C.slice(0, 2)}`);
    }
    if (!Number.isInteger(slot.amount) || slot.amount <= 0) {
        throw new Error(`amount must be a positive integer, got ${slot.amount}`);
    }
    return {
        id: keysetId,
        amount: slot.amount,
        // Byte-identical to what was signed at mint time — buildP2PKSecret is the
        // single source of that serialization, so the two cannot drift apart.
        secret: (0, crypto_1.buildP2PKSecret)(nonce, pubkey),
        C,
    };
};
exports.reconstructProofFromCard = reconstructProofFromCard;
/** Reconstruct every slot on a card, preserving order. */
const reconstructProofsFromCard = (slots, cardPubkey) => slots.map(slot => (0, exports.reconstructProofFromCard)(slot, cardPubkey));
exports.reconstructProofsFromCard = reconstructProofsFromCard;
