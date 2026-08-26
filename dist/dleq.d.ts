import type { CashuBlindSignature, CashuDLEQ, CashuProof } from "./types";
/**
 * NUT-12 hash_e: sha256 over the concatenated *uncompressed* hex of each point.
 *
 * The uncompressed form is not incidental — hashing the compressed form
 * produces a different challenge and every verification fails, which looks
 * exactly like a hostile mint rather than an encoding mistake.
 */
export declare const hashE: (points: Uint8Array[]) => Buffer;
/**
 * Verify the DLEQ on a blind signature, before unblinding.
 *
 *   R1 = s*G - e*A
 *   R2 = s*B_ - e*C_
 *   e == hash_e(R1, R2, A, C_)
 *
 * @param mintPubkeyHex the mint's public key `A` for this amount and keyset
 * @param B_hex         the blinded message that was sent
 */
export declare const verifyBlindSignatureDLEQ: (signature: CashuBlindSignature & {
    dleq?: CashuDLEQ;
}, mintPubkeyHex: string, B_hex: string) => boolean;
/**
 * Verify the DLEQ carried on an unblinded proof.
 *
 * The proof stores the blinding factor `r`, which lets the original blinded
 * pair be reconstructed:
 *
 *   B_ = Y + r*G     (Y = hash_to_curve(secret))
 *   C_ = C + r*A
 *
 * and then the same check applies. This is the one a receiving terminal runs:
 * it needs no network and no trust in whoever handed over the proof.
 */
export declare const verifyProofDLEQ: (proof: CashuProof, mintPubkeyHex: string) => boolean;
/**
 * True when the proof carries no DLEQ at all.
 *
 * Distinguishing "absent" from "invalid" matters: not every mint emits DLEQ,
 * so a missing proof is a policy decision for the caller, whereas a present
 * but failing one means the mint is misbehaving and should be refused.
 */
export declare const hasDLEQ: (proof: CashuProof) => boolean;
