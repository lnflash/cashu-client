import type { CashuBlindingData } from "./types";
/**
 * NUT-00: hash_to_curve
 * Deterministically maps a secret (as UTF-8 bytes or raw buffer) to a secp256k1 point.
 */
export declare const hashToCurve: (secret: Buffer) => Uint8Array;
/**
 * Split an amount (in the keyset's base unit) into Cashu power-of-2 denominations.
 * Returns an array of amounts summing to `total`, each a power of 2.
 *
 * @param total      Total amount to split
 * @param maxSlots   Optional upper bound on the number of denominations produced.
 *                   Throws CashuInsufficientSlotsError if the split would require more.
 */
export declare const splitIntoDenominations: (total: number, maxSlots?: number) => number[];
/**
 * Build the canonical NUT-10 P2PK secret JSON string for a card proof.
 * Serialization MUST have no spaces, fixed key order, and lower-case hex.
 *
 * secret = ["P2PK", {"nonce": "<hex>", "data": "<cardPubkey>", "tags": [["sigflag", "SIG_INPUTS"]]}]
 *
 * Hex case is canonicalised here, in the one place that owns this serialization.
 * The secret is committed to at mint time as a UTF-8 byte string —
 * `Y = hash_to_curve(secret)` — so an upper-case pubkey at mint time and a
 * lower-case one at reconstruction time are two different secrets and therefore
 * two different proofs, only one of which the mint has ever signed. Upper-case
 * hex is not hypothetical: the counterparty is a Javacard reader and
 * `String.format("%02X")` is the idiomatic Java bytes-to-hex. Normalising in
 * every caller instead would put the canonical form in more than one place,
 * which is exactly how the two paths drift apart.
 *
 * BREAKING in 0.4.0: this lower-casing changes the output for upper-case input,
 * so proofs minted by <= 0.3.0 with an upper-case pubkey are locked to a secret
 * this function no longer produces. (Only the pubkey: `createBlindedMessage`
 * generated the nonce itself as lower-case hex, so no caller's case ever reached
 * that field at mint time.) Those cards are redeemed with
 * `reconstructProofFromCard(slot, cardPubkey, {legacyHexCase: true})`. See
 * CHANGELOG.md.
 */
export declare const buildP2PKSecret: (nonce: string, cardPubkey: string) => string;
/**
 * NUT-03: Create a blinded message for a given denomination.
 * Returns the blinding data needed to unblind the mint's response.
 *
 * B_ = hash_to_curve(secret) + r*G
 */
export declare const createBlindedMessage: (keysetId: string, amount: number, cardPubkey: string) => CashuBlindingData;
/**
 * NUT-03: Unblind a mint signature.
 * C = C_ - r*K  where K is the mint's public key for this keyset/denomination.
 */
export declare const unblindSignature: (C_hex: string, r: Uint8Array, mintPubkeyHex: string) => string;
