import type { CardProofSlot } from "./card";
/**
 * A slot as it appears in a card file: everything reconstruction needs, plus
 * the one bit reconstruction does not care about and a redeemer cannot live
 * without.
 *
 * `spent` is not on `CardProofSlot` because rebuilding a proof is identical
 * either way. It is on the *file* because `LOAD_PROOF` has no spent bit: a
 * spent proof written back onto a card returns as unspent and inflates the
 * balance with money that is already gone. See `spec/CARD-FILE.md` in
 * lnflash/cashu-javacard.
 */
export type CardFileSlot = CardProofSlot & {
    /** Whether the card has already marked this slot spent. */
    spent: boolean;
};
/** Bumped only for a breaking change to the shape below. */
export declare const CARD_FILE_VERSION = 1;
export type CardFile = {
    version: number;
    /** Mint the proofs belong to. Loading a card from the wrong mint is silent. */
    mint: string;
    /**
     * Keyset unit, e.g. `sat` or `usd`. Carried so amounts are unambiguous.
     *
     * Canonicalised on read — trimmed and lower-cased — for the same reason
     * `mint` is: its only use is a `file.unit === keyset.unit` comparison.
     */
    unit: string;
    /** Compressed secp256k1 pubkey of the card these proofs are locked to. */
    cardPubkey: string;
    slots: CardFileSlot[];
    /** Free-form; ignored on read. Provenance for a human, never trusted. */
    note?: string;
};
/**
 * Validate one slot from a file.
 *
 * Strict on purpose, and it throws the same classes `reconstructProofFromCard`
 * does — because it runs the same checks — so a caller can tell "this card's
 * key is wrong" from "slot 3 is corrupt" without matching on message text.
 */
export declare const parseCardSlot: (value: unknown, index: number) => CardFileSlot;
/**
 * Parse and validate a card file.
 *
 * Accepts a JSON string or an already-parsed object. Throws on anything
 * malformed — a card file is an instruction to move money onto or off a bearer
 * card, so there is no useful partial success here.
 */
export declare const parseCardFile: (input: unknown) => CardFile;
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
 *
 * A `spent: true` slot is refused here, and only here. `parseCardFile` keeps
 * the bit because a card *dump* is where it comes from — that is the whole
 * reason the field exists. But this direction ends at `LOAD_PROOF`, which has
 * no spent bit, so a spent slot written back onto a card returns as unspent
 * and inflates the balance with money that is already gone. Filter the spent
 * slots out before calling this; dropping them silently here would be the same
 * repair-instead-of-refuse the rest of the module declines to do.
 */
export declare const serializeCardFile: (file: Omit<CardFile, "version">, { pretty }?: {
    pretty?: boolean;
}) => string;
/**
 * Spendable value in a card file, in the file's `unit`.
 *
 * Spent slots are excluded. They are money that is already gone, and this
 * number is what a terminal shows a holder as the card's worth — counting them
 * is the same overstatement the duplicate-`C` check exists to prevent.
 */
export declare const cardFileTotal: (file: CardFile) => number;
