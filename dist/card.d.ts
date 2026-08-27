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
export declare const reconstructProofFromCard: (slot: CardProofSlot, cardPubkey: string) => CashuProof;
/** Reconstruct every slot on a card, preserving order. */
export declare const reconstructProofsFromCard: (slots: CardProofSlot[], cardPubkey: string) => CashuProof[];
