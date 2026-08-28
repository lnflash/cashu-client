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
 * Nothing here restates a rule `card.ts` already owns: the hex, point, keyset-id
 * and denomination checks are imported from it, and `serializeCardFile` runs the
 * redeem path itself and discards the result. Do not reintroduce local copies
 * "to keep this module structural". A second copy of the prefix test that reads
 * the wrong nibble, or of the amount check that lets 3 through, does not fail
 * loudly — it writes a file that loads onto a card and is rejected by the mint
 * only after SPEND_PROOF has burned the slot, which is the single failure this
 * format exists to prevent.
 *
 * That bites hardest on the mint → card direction, where `serializeCardFile` is
 * the only gate: cardctl is dependency-free Python and will not do curve math,
 * so whatever is written here is what reaches the card.
 *
 * The wire shape carries the *card's* vocabulary — `nonce`, not `secret`, and
 * `keysetId` as 16 hex chars — because that is what the card actually stores. A
 * file that said `secret` would invite someone to put ~150 bytes of P2PK JSON
 * in a field that holds 32 bytes.
 */
const card_1 = require("./card");
/**
 * The card's `LOAD_PROOF` amount field is a 4-byte unsigned integer, so a
 * larger amount cannot be written even though it is a valid denomination
 * elsewhere. Checked at the file boundary because that is the last point
 * before a card sees it.
 */
const MAX_CARD_AMOUNT = 2 ** 32;
const errors_1 = require("./errors");
const http_1 = require("./http");
/** Bumped only for a breaking change to the shape below. */
exports.CARD_FILE_VERSION = 1;
const SLOT_FIELDS = ["keysetId", "amount", "nonce", "C", "spent"];
const FILE_FIELDS = ["version", "mint", "unit", "cardPubkey", "slots", "note"];
/**
 * Refuse a field this version does not know about.
 *
 * The format's whole claim is that "a field that drifts fails at the boundary".
 * Silently dropping an unrecognised field is that drift: a future cardctl adds
 * one, forgets to bump `version`, and this side discards it without a word —
 * the failure then surfaces at the mint, or as money that quietly went nowhere.
 * `version` exists precisely so an additive change announces itself.
 */
const rejectUnknownFields = (raw, known, where) => {
    const extra = Object.keys(raw).filter(k => !known.includes(k));
    if (extra.length > 0) {
        throw new errors_1.CashuInvalidProofError(`${where}unknown field(s): ${extra.join(", ")} — bump the card file ` +
            `version rather than adding fields silently`);
    }
};
/**
 * Validate one slot from a file.
 *
 * Strict on purpose, and it throws the same classes `reconstructProofFromCard`
 * does — because it runs the same checks — so a caller can tell "this card's
 * key is wrong" from "slot 3 is corrupt" without matching on message text.
 */
const parseCardSlot = (value, index) => {
    const where = `slot ${index}: `;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new errors_1.CashuInvalidProofError(`${where}expected an object, got ${typeof value}`);
    }
    const raw = value;
    // A file that spells this `secret` was written against the wrong mental
    // model: a NUT-10 P2PK secret is ~150 bytes of JSON and cannot be a slot
    // field. Say so, rather than reporting it as an unknown field.
    if (raw.nonce === undefined && raw.secret !== undefined) {
        throw new errors_1.CashuInvalidProofError(`${where}has "secret" but no "nonce" — the card stores the 32-byte P2PK ` +
            `nonce, not the secret string (which is ~150 bytes of JSON). See NUT-XX.`);
    }
    rejectUnknownFields(raw, SLOT_FIELDS, where);
    const keysetId = (0, card_1.requireHex)(raw.keysetId, 8, "keysetId", where);
    (0, card_1.requireKeysetV0)(keysetId, where);
    const C = (0, card_1.requireHex)(raw.C, 33, "C", where);
    (0, card_1.requirePoint)(C, "C", where);
    const amount = (0, card_1.requireAmount)(raw.amount, where);
    if (amount >= MAX_CARD_AMOUNT) {
        throw new errors_1.CashuInvalidProofError(`${where}amount must be below 2^32 — LOAD_PROOF carries it as a 4-byte ` +
            `unsigned integer — got ${amount}`);
    }
    // Required, never defaulted. Defaulting to false would silently resurrect a
    // spent proof as spendable on the next load.
    if (typeof raw.spent !== "boolean") {
        throw new errors_1.CashuInvalidProofError(`${where}spent must be a boolean, got ${typeof raw.spent}`);
    }
    return {
        keysetId,
        amount,
        nonce: (0, card_1.requireHex)(raw.nonce, 32, "nonce", where),
        C,
        spent: raw.spent,
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
    rejectUnknownFields(raw, FILE_FIELDS, "");
    for (const field of ["mint", "unit"]) {
        if (typeof raw[field] !== "string" || raw[field] === "") {
            throw new errors_1.CashuInvalidProofError(`card file ${field} must be a non-empty string`);
        }
    }
    // Stored canonical, through the same sanitiser every network path uses. A
    // file is third-party data off a bearer instrument: unsanitised it can carry
    // a link-local or metadata URL, and even a benign trailing slash breaks the
    // `mint === expected` comparison that is the only guard against loading a
    // card from the wrong mint.
    let mint;
    try {
        mint = (0, http_1.sanitizeMintUrl)(raw.mint);
    }
    catch (error) {
        throw new errors_1.CashuInvalidProofError(`card file mint: ${error.message}`);
    }
    // `unit` gets the same treatment, because it has the same job. A caller's
    // only use for it is `file.unit === keyset.unit`, and a mint declares its
    // keyset units trimmed and lower case — so `"SAT "` stored verbatim makes
    // that comparison return false against a keyset that is in fact the right
    // one, silently, exactly the way an untrimmed mint URL did.
    const unit = raw.unit.trim().toLowerCase();
    if (unit === "") {
        throw new errors_1.CashuInvalidProofError("card file unit must be a non-empty string");
    }
    // A known field with the wrong type is checked, not dropped. Discarding it
    // silently is the drift `rejectUnknownFields` refuses two fields up — and
    // `note` is the file's only provenance record, so losing it without a word
    // is how "loaded at till 2" becomes an unattributable card.
    if (raw.note !== undefined && typeof raw.note !== "string") {
        throw new errors_1.CashuInvalidProofError("card file note must be a string when present");
    }
    if (!Array.isArray(raw.slots)) {
        throw new errors_1.CashuInvalidProofError("card file slots must be an array");
    }
    // The card's key is checked before any slot, and completely: if it is bad
    // every slot is unusable and the answer is "reject the card", not "slot 0 is
    // corrupt". Same ordering, and the same reason, as reconstructProofFromCard.
    const cardPubkey = (0, card_1.requireHex)(raw.cardPubkey, 33, "cardPubkey", "card file ");
    (0, card_1.requirePoint)(cardPubkey, "cardPubkey", "card file ");
    const slots = raw.slots.map(exports.parseCardSlot);
    // The same proof twice. Every per-slot check passes — both copies are
    // well-formed, on-curve and reconstruct fine — which makes this the one
    // malformed file the writer would otherwise hand to a card, and the failure
    // it produces is the one this format exists to prevent: slot 0 burns and
    // redeems, slot 1 burns on SPEND_PROOF and the mint refuses it as already
    // spent, while `cardFileTotal` told the holder the card was worth double.
    //
    // `C` is the mint's unblinded signature over a per-proof secret, so it is
    // unique per proof and a repeat is never a coincidence. Checked here rather
    // than in `serializeCardFile` so a card *dumped* with a duplicated slot is
    // caught on the read direction too, before anything is redeemed.
    const seen = new Set();
    slots.forEach((s, i) => {
        if (seen.has(s.C)) {
            throw new errors_1.CashuInvalidProofError(`slot ${i}: duplicates an earlier slot's C — the same proof twice burns a ` +
                `slot the mint will reject as already spent`);
        }
        seen.add(s.C);
    });
    return {
        version: exports.CARD_FILE_VERSION,
        mint,
        unit,
        cardPubkey,
        slots,
        ...(raw.note !== undefined ? { note: raw.note } : {}),
    };
};
exports.parseCardFile = parseCardFile;
/**
 * Serialize a card file.
 *
 * Round-trips through `parseCardFile` and then through the *redeem* path —
 * `reconstructProofsFromCard`, whose result is discarded — before writing. This
 * is the only place the mint → card direction is checked at all, and the
 * checks it adds over parsing (curve membership above all) are exactly the ones
 * that cannot be caught later: cardctl does no curve math, so an on-prefix,
 * off-curve `C` reaches the card, burns the slot on SPEND_PROOF, and only then
 * is rejected by the mint as a proof that was never spendable.
 *
 * Reusing the redeem path rather than restating its rules is the point: what
 * this writes is, by construction, what that reads.
 */
const serializeCardFile = (file, { pretty = true } = {}) => {
    const validated = (0, exports.parseCardFile)({ ...file, version: exports.CARD_FILE_VERSION });
    (0, card_1.reconstructProofsFromCard)(validated.slots, validated.cardPubkey);
    return JSON.stringify(validated, null, pretty ? 2 : undefined);
};
exports.serializeCardFile = serializeCardFile;
/** Total value in a card file, in the file's `unit`. */
const cardFileTotal = (file) => file.slots.reduce((sum, s) => sum + s.amount, 0);
exports.cardFileTotal = cardFileTotal;
