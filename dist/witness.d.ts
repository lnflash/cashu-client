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
/** The NUT-10 envelope a well-known secret is carried in. */
export type WellKnownSecret = {
    kind: string;
    body: Record<string, unknown>;
};
/**
 * Parse the NUT-10 envelope only: `[kind, {...}]`.
 *
 * Deliberately separate from {@link parseP2PKSecret}. "Is this a well-known
 * secret at all?" and "is this a P2PK secret this module can verify?" are
 * different questions, and collapsing them is how an HTLC — or a P2PK secret
 * whose body is malformed — gets waved through as a plain, unlocked secret that
 * needs no witness. Returns null only when the secret is not a `[kind, {...}]`
 * pair, i.e. when it really is a plain string secret.
 */
export declare const parseWellKnownSecret: (secret: string) => WellKnownSecret | null;
/**
 * True when `secret` is a NUT-10 well-known secret of any kind — P2PK, HTLC, or
 * something this library has never heard of. Anything that is one carries a
 * spending condition, so it needs a witness the mint will accept.
 */
export declare const isWellKnownSecret: (secret: string) => boolean;
/**
 * Parse a NUT-10 secret string: `["P2PK", {"nonce":..., "data":..., "tags":[...]}]`.
 *
 * Returns null for a plain (non-P2PK) secret, for a well-known secret of
 * another kind, and for a P2PK secret whose body is malformed. Callers deciding
 * whether a witness is needed must use {@link isWellKnownSecret} instead — a
 * null here means "this verifier cannot vouch for it", not "it is unlocked".
 *
 * Malformed `tags` are rejected outright rather than filtered out. A dropped
 * tag is indistinguishable from an absent one, so filtering would let anyone
 * bypass the strict-tag policy in {@link verifyP2PKWitness} by making a tag
 * malformed (`[["n_sigs", 2]]` — a JSON number, which the mint reads as 2)
 * instead of unknown.
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
 * Verify a proof's witness against the key its secret is locked to, and against
 * the spending conditions its secret declares.
 *
 * Worth doing before submitting: a mint rejects a bad witness with a generic
 * error *after* the card has already marked the proof spent, so the failure is
 * unrecoverable at exactly the point it is least recoverable. Checking here
 * turns that into a local error with the proof still intact — but only if the
 * check is the same one the mint runs, which means honouring `sigflag` and
 * `n_sigs` rather than accepting on any one valid signature.
 */
export declare const verifyP2PKWitness: (proof: CashuProof) => boolean;
/**
 * True when this proof needs a witness before the mint will accept it.
 * A plain-secret proof does not.
 *
 * Keyed on "is this a well-known secret" rather than "did the P2PK parser
 * succeed". Those differ for an HTLC secret and for a malformed P2PK one, and
 * reading either as "plain, needs no witness" submits a proof the mint will
 * refuse — after the card has already burned the slot. Anything carrying a
 * NUT-10 spending condition this module cannot verify is reported by
 * {@link findUnsignedProofs} instead of waved through.
 */
export declare const requiresWitness: (proof: CashuProof) => boolean;
/**
 * Check every proof in a set carries a valid witness, returning the indices
 * that do not. Callers should treat a non-empty result as "do not submit":
 * the mint fails the whole request atomically, so one bad witness wastes the
 * spend attempt for all of them.
 */
export declare const findUnsignedProofs: (proofs: CashuProof[]) => number[];
