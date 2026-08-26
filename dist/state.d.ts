import type { CashuProof, CashuProofState } from "./types";
import { CashuMintError } from "./errors";
/**
 * NUT-07: asking the mint whether proofs are still spendable.
 *
 * This is the double-spend check. A card is a bearer instrument and its
 * on-card SPENT flag only stops the *card* from signing again — it says
 * nothing about whether those proofs were already melted at the mint from a
 * copy of the data. An offline terminal genuinely cannot detect that; an
 * online one has no excuse not to check.
 *
 * Also the correct recovery step after a melt or swap whose response was lost:
 * ask what happened rather than resubmitting and risking a second payment.
 */
/**
 * The mint's identifier for a proof: Y = hash_to_curve(secret), compressed hex.
 * Note this is derived from the secret only — it does not reveal the signature.
 */
export declare const proofIdentifier: (proof: Pick<CashuProof, "secret">) => string;
/**
 * NUT-07: look up the state of each proof.
 *
 * Results are returned in the same order as `proofs`. A mint that returns a
 * different number of states, or reorders them, is rejected rather than
 * silently mapped — pairing a SPENT verdict against the wrong proof is worse
 * than no answer.
 */
export declare const checkProofStates: (mintUrl: string, proofs: CashuProof[]) => Promise<CashuProofState[] | CashuMintError>;
/**
 * The verdict of {@link allProofsUnspent}.
 *
 * Deliberately not a boolean. `boolean | CashuMintError` type-checks but fails
 * open at runtime: a CashuMintError is a truthy object, so
 * `if (await allProofsUnspent(...)) acceptPayment()` reads a mint timeout, a
 * 5xx, or a malformed checkstate response as "all proofs unspent" — the exact
 * inverse of what this module is for. A string verdict has no truthy shortcut.
 */
export type CashuUnspentVerdict = "UNSPENT" | "NOT_UNSPENT";
/**
 * Convenience: are all of these proofs still unspent?
 *
 * Treats PENDING as not-spendable. A pending proof is committed to an in-flight
 * operation, and accepting it as payment is how the same value gets counted
 * twice.
 *
 * Callers must compare explicitly and handle the error case:
 *
 * ```ts
 * const verdict = await allProofsUnspent(url, proofs)
 * if (verdict instanceof CashuMintError) return refuse(verdict)
 * if (verdict !== "UNSPENT") return refuse("already spent or pending")
 * ```
 */
export declare const allProofsUnspent: (mintUrl: string, proofs: CashuProof[]) => Promise<CashuUnspentVerdict | CashuMintError>;
