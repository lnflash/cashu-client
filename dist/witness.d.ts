import type { CashuProof } from "./types";
/**
 * NUT-11 P2PK witnesses.
 *
 * A card proof is locked to the card's public key, so the mint will not accept
 * it without a signature from that key. The card produces the signature
 * (SPEND_PROOF returns 64 bytes of BIP-340); this module is the other half —
 * it computes the exact message the card must sign, attaches the resulting
 * signature to the proof in the shape the mint expects, and can verify the
 * pair locally before anything is submitted.
 *
 * The library previously wrote the P2PK *lock* and had no way to produce the
 * *unlock*, which meant a card could be funded and never redeemed.
 */
/** The parsed form of a NUT-10 well-known secret. */
export type ParsedP2PKSecret = {
    kind: string;
    nonce: string;
    /** The public key the proof is locked to — for a card proof, the card's key. */
    data: string;
    tags: string[][];
};
/**
 * Parse a NUT-10 secret string: `["P2PK", {"nonce":..., "data":..., "tags":[...]}]`.
 * Returns null for a plain (non-P2PK) secret, which is not an error — an
 * unlocked proof simply needs no witness.
 */
export declare const parseP2PKSecret: (secret: string) => ParsedP2PKSecret | null;
/**
 * The 32-byte message a P2PK proof must be signed over: SHA-256 of the secret
 * string's UTF-8 bytes.
 *
 * Hand this to the card as the SPEND_PROOF payload. Getting it wrong produces a
 * signature that is valid BIP-340 and still rejected by every mint, which is a
 * confusing failure to debug from the card side — so it is computed here, once.
 */
export declare const p2pkMessageToSign: (proof: Pick<CashuProof, "secret">) => Buffer;
/**
 * Attach one or more signatures to a proof as a NUT-11 witness.
 * Returns a new proof; the input is not mutated.
 */
export declare const attachP2PKWitness: (proof: CashuProof, signatures: string[]) => CashuProof;
/** Read the signatures back out of a proof's witness field. */
export declare const parseWitnessSignatures: (witness: string | undefined) => string[];
/**
 * Verify a proof's witness against the key its secret is locked to.
 *
 * Worth doing before submitting: a mint rejects a bad witness with a generic
 * error *after* the card has already marked the proof spent, so the failure is
 * unrecoverable at exactly the point it is least recoverable. Checking here
 * turns that into a local error with the proof still intact.
 */
export declare const verifyP2PKWitness: (proof: CashuProof) => boolean;
/**
 * True when this proof needs a witness before the mint will accept it.
 * A plain-secret proof does not.
 */
export declare const requiresWitness: (proof: CashuProof) => boolean;
/**
 * Check every proof in a set carries a valid witness, returning the indices
 * that do not. Callers should treat a non-empty result as "do not submit":
 * the mint fails the whole request atomically, so one bad witness wastes the
 * spend attempt for all of them.
 */
export declare const findUnsignedProofs: (proofs: CashuProof[]) => number[];
