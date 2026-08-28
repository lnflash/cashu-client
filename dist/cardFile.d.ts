import type { CardProofSlot } from "./card";
/** Bumped only for a breaking change to the shape below. */
export declare const CARD_FILE_VERSION = 1;
export type CardFile = {
    version: number;
    /** Mint the proofs belong to. Loading a card from the wrong mint is silent. */
    mint: string;
    /** Keyset unit, e.g. `sat` or `usd`. Carried so amounts are unambiguous. */
    unit: string;
    /** Compressed secp256k1 pubkey of the card these proofs are locked to. */
    cardPubkey: string;
    slots: CardProofSlot[];
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
export declare const parseCardSlot: (value: unknown, index: number) => CardProofSlot;
/**
 * Parse and validate a card file.
 *
 * Accepts a JSON string or an already-parsed object. Throws on anything
 * malformed — a card file is an instruction to move money onto or off a bearer
 * card, so there is no useful partial success here.
 */
export declare const parseCardFile: (input: string | unknown) => CardFile;
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
export declare const serializeCardFile: (file: Omit<CardFile, "version">, { pretty }?: {
    pretty?: boolean;
}) => string;
/** Total value in a card file, in the file's `unit`. */
export declare const cardFileTotal: (file: CardFile) => number;
