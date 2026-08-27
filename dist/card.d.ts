import type { CashuProof } from "./types";
/**
 * One proof slot as read from the card, hex-encoded.
 *
 * Field names deliberately mirror the on-card layout rather than `CashuProof`:
 * `nonce` is not `secret`, and conflating them is the mistake this module
 * exists to prevent.
 */
export type CardProofSlot = {
    /** NUT-02 keyset id — 16 hex chars (the 8 raw bytes at offset 1). */
    keysetId: string;
    /** Denomination in the keyset's base unit. */
    amount: number;
    /** The 32-byte P2PK nonce at offset 13 — 64 hex chars. NOT the secret. */
    nonce: string;
    /** The mint's unblinded signature at offset 45 — 33 bytes, 66 hex chars. */
    C: string;
};
/** Options shared by the single-slot and batch reconstruction paths. */
export type ReconstructCardOptions = {
    /**
     * Serialize the secret's `data` with the card key's hex case as supplied,
     * instead of the canonical lower case — the pre-0.4.0 behaviour.
     *
     * Only for redeeming a card funded by <= 0.3.0 through a reader that emitted
     * upper-case hex (`String.format("%02X")` is the idiomatic Java bytes-to-hex).
     * The nonce is lower-cased either way: pre-0.4.0 it was generated as lower-case
     * hex on this side, never read off the card, so it could not carry a reader's
     * case into a minted secret. Try the default first; fall back to this only if
     * the mint rejects the proof as unknown. Never mint with it.
     */
    legacyHexCase?: boolean;
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
export declare const reconstructProofFromCard: (slot: CardProofSlot, cardPubkey: string, options?: ReconstructCardOptions) => CashuProof;
/** A slot the batch path could not reconstruct, with its position on the card. */
export type CardSlotFailure = {
    /** Index into the `slots` array as passed in. */
    index: number;
    /** The rejection, class and `cause` preserved, prefixed with `slot <i>: `. */
    error: Error;
};
/** What the batch path returns when `skipInvalid` is set. */
export type CardReconstructionResult = {
    /** Every slot that reconstructed, in card order. */
    proofs: CashuProof[];
    /** Every slot that did not. Empty when the whole card read cleanly. */
    failures: CardSlotFailure[];
};
export type ReconstructCardBatchOptions = ReconstructCardOptions & {
    /**
     * Collect failures instead of throwing on the first one.
     *
     * Defaults to `false` — one bad slot fails the batch, which is the right
     * default for spending a card, since a caller that quietly drops a slot spends
     * less than the holder handed over.
     *
     * Set it for the "slot 3 is corrupt, skip it" case: without it, one corrupt
     * slot makes every other slot on the card unreadable through this API and the
     * caller has to abandon the batch helper and hand-roll the loop. Check the
     * failures' error *class* before treating them as per-slot damage — a bad card
     * key (`CashuInvalidCardPubkeyError`) fails every slot and means abort the
     * card, not skip a slot.
     */
    skipInvalid?: boolean;
};
/**
 * Reconstruct every slot on a card, preserving order.
 *
 * A failing slot is reported with its index: `nonce must be 32 bytes` on its own
 * tells an operator nothing about which of N slots is bad.
 *
 * Throws on the first bad slot by default; pass `{skipInvalid: true}` to get
 * `{proofs, failures}` back instead.
 */
export declare function reconstructProofsFromCard(slots: CardProofSlot[], cardPubkey: string, options?: ReconstructCardOptions & {
    skipInvalid?: false;
}): CashuProof[];
export declare function reconstructProofsFromCard(slots: CardProofSlot[], cardPubkey: string, options: ReconstructCardOptions & {
    skipInvalid: true;
}): CardReconstructionResult;
/**
 * Non-literal `skipInvalid`, returning the union.
 *
 * Reading a card around corrupt slots is exactly the mode a terminal drives from
 * config, or from a retry after the strict pass threw — so `skipInvalid` is
 * routinely a runtime `boolean`. With only the two literal overloads that call
 * fails to compile (`Type 'boolean' is not assignable to type 'false'`) and the
 * caller is pushed into an `as any`, which throws away every other type in the
 * call. This one is listed last so a literal `true`/`false` still matches its
 * precise overload first and keeps the narrow return type.
 */
export declare function reconstructProofsFromCard(slots: CardProofSlot[], cardPubkey: string, options: ReconstructCardBatchOptions): CashuProof[] | CardReconstructionResult;
