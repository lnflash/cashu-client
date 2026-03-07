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
 * Serialization MUST have no spaces and fixed key order.
 *
 * secret = ["P2PK", {"nonce": "<hex>", "data": "<cardPubkey>", "tags": [["sigflag", "SIG_INPUTS"]]}]
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
