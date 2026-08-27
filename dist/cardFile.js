"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cardFileTotal = exports.serializeCardFile = exports.parseCardFile = exports.parseCardSlot = exports.CARD_FILE_VERSION = void 0;
/**
 * The card file — the interchange format between the mint side and the card side.
 *
 * This project is deliberately split across two toolchains: the mint protocol
 * is TypeScript (this library), and the card driver is Python
 * (`tools/cardctl` in lnflash/cashu-javacard, which stays dependency-free so it
 * can run anywhere a reader does). They cannot call each other, so proofs cross
 * the boundary as a file.
 *
 * Defining that file here rather than in either CLI is the point. Both sides
 * validate against this one schema, so a field that drifts fails at the
 * boundary instead of at the mint — where the card may already have burned the
 * slot.
 *
 * Two directions:
 *
 *   mint → card   `serializeCardFile` writes proofs to be loaded onto a card
 *   card → mint   `parseCardFile` reads slots dumped from a card, ready for
 *                 `reconstructProofsFromCard`
 *
 * Validation here is *structural* — shapes, lengths, encodings, point prefixes.
 * Cryptographic checks (is `C` actually on the curve?) belong to
 * `reconstructProofFromCard`, which already does them; duplicating them here
 * would give two places to drift apart. A file can therefore parse and still be
 * rejected at reconstruction, which is the correct order: cheap checks first.
 *
 * The wire shape carries the *card's* vocabulary — `nonce`, not `secret`, and
 * `keysetId` as 16 hex chars — because that is what the card actually stores. A
 * file that said `secret` would invite someone to put ~150 bytes of P2PK JSON
 * in a field that holds 32 bytes.
 */
const errors_1 = require("./errors");
/** Bumped only for a breaking change to the shape below. */
exports.CARD_FILE_VERSION = 1;
const HEX = /^[0-9a-f]+$/;
const hexField = (value, bytes, field, Err, where) => {
    if (typeof value !== "string") {
        throw new Err(`${where}${field} must be a hex string, got ${typeof value}`);
    }
    const v = value.trim().toLowerCase();
    if (!HEX.test(v)) {
        throw new Err(`${where}${field} must be hex, got ${JSON.stringify(value)}`);
    }
    if (v.length !== bytes * 2) {
        throw new Err(`${where}${field} must be ${bytes} bytes (${bytes * 2} hex chars), got ${v.length}`);
    }
    return v;
};
const compressedPoint = (value, field, Err, where) => {
    const v = hexField(value, 33, field, Err, where);
    if (v[1] !== "2" && v[1] !== "3") {
        throw new Err(`${where}${field} must be a compressed secp256k1 point (02/03 prefix), got 0x${v.slice(0, 2)}`);
    }
    return v;
};
/**
 * Validate one slot from a file.
 *
 * Strict on purpose, and it throws the same classes `reconstructProofFromCard`
 * does, so a caller can tell "this card's key is wrong" from "slot 3 is
 * corrupt" without matching on message text.
 */
const parseCardSlot = (value, index) => {
    const where = `slot ${index}: `;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new errors_1.CashuInvalidProofError(`${where}expected an object, got ${typeof value}`);
    }
    const raw = value;
    // A file that spells this `secret` was written against the wrong mental
    // model: a NUT-10 P2PK secret is ~150 bytes of JSON and cannot be a slot
    // field. Say so, rather than failing on a missing `nonce`.
    if (raw.nonce === undefined && raw.secret !== undefined) {
        throw new errors_1.CashuInvalidProofError(`${where}has "secret" but no "nonce" — the card stores the 32-byte P2PK ` +
            `nonce, not the secret string (which is ~150 bytes of JSON). See NUT-XX.`);
    }
    const amount = raw.amount;
    if (typeof amount !== "number" || !Number.isInteger(amount) || amount <= 0) {
        throw new errors_1.CashuInvalidProofError(`${where}amount must be a positive integer, got ${JSON.stringify(amount)}`);
    }
    return {
        keysetId: hexField(raw.keysetId, 8, "keysetId", errors_1.CashuInvalidProofError, where),
        amount,
        nonce: hexField(raw.nonce, 32, "nonce", errors_1.CashuInvalidProofError, where),
        C: compressedPoint(raw.C, "C", errors_1.CashuInvalidProofError, where),
    };
};
exports.parseCardSlot = parseCardSlot;
/**
 * Parse and validate a card file.
 *
 * Accepts a JSON string or an already-parsed object. Throws on anything
 * malformed — a card file is an instruction to move money onto or off a bearer
 * card, so there is no useful partial success here.
 */
const parseCardFile = (input) => {
    let doc = input;
    if (typeof input === "string") {
        try {
            doc = JSON.parse(input);
        }
        catch (error) {
            throw new errors_1.CashuInvalidProofError(`card file is not valid JSON: ${error.message}`);
        }
    }
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
        throw new errors_1.CashuInvalidProofError("card file must be a JSON object");
    }
    const raw = doc;
    if (raw.version !== exports.CARD_FILE_VERSION) {
        throw new errors_1.CashuInvalidProofError(`unsupported card file version ${JSON.stringify(raw.version)}, expected ${exports.CARD_FILE_VERSION}`);
    }
    for (const field of ["mint", "unit"]) {
        if (typeof raw[field] !== "string" || raw[field] === "") {
            throw new errors_1.CashuInvalidProofError(`card file ${field} must be a non-empty string`);
        }
    }
    if (!Array.isArray(raw.slots)) {
        throw new errors_1.CashuInvalidProofError("card file slots must be an array");
    }
    return {
        version: exports.CARD_FILE_VERSION,
        mint: raw.mint,
        unit: raw.unit,
        cardPubkey: compressedPoint(raw.cardPubkey, "cardPubkey", errors_1.CashuInvalidCardPubkeyError, "card file "),
        slots: raw.slots.map(exports.parseCardSlot),
        ...(typeof raw.note === "string" ? { note: raw.note } : {}),
    };
};
exports.parseCardFile = parseCardFile;
/**
 * Serialize a card file.
 *
 * Round-trips through `parseCardFile` before writing, so a malformed file is
 * caught here rather than by whatever reads it next — which, on the load path,
 * is a card.
 */
const serializeCardFile = (file, { pretty = true } = {}) => {
    const validated = (0, exports.parseCardFile)({ ...file, version: exports.CARD_FILE_VERSION });
    return JSON.stringify(validated, null, pretty ? 2 : undefined);
};
exports.serializeCardFile = serializeCardFile;
/** Total value in a card file, in the file's `unit`. */
const cardFileTotal = (file) => file.slots.reduce((sum, s) => sum + s.amount, 0);
exports.cardFileTotal = cardFileTotal;
