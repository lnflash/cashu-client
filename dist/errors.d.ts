import type { CashuBlindSignature } from "./types";
/**
 * Base error for all Cashu client errors.
 * Uses numeric codes compatible with Cashu NUT error codes.
 */
export declare class CashuError extends Error {
    code: number;
    constructor(message: string, code?: number);
}
/** Generic mint communication or protocol error */
export declare class CashuMintError extends CashuError {
    constructor(message?: string, code?: number);
}
/** Quote was not paid when minting was attempted */
export declare class CashuMintQuoteNotPaidError extends CashuError {
    constructor(message?: string, code?: number);
}
/** Card public key is invalid or not a valid secp256k1 point */
export declare class CashuInvalidCardPubkeyError extends CashuError {
    constructor(message?: string, code?: number);
}
/** Blinding or unblinding operation failed */
export declare class CashuBlindingError extends CashuError {
    constructor(message?: string, code?: number);
}
/** Proof signature is invalid */
export declare class CashuInvalidProofError extends CashuError {
    constructor(message?: string, code?: number);
}
/** Not enough card slots available for the requested denominations */
export declare class CashuInsufficientSlotsError extends CashuError {
    constructor(message?: string, code?: number);
}
/**
 * A melt was executed but its quote fields could not be parsed.
 *
 * The inputs are already consumed and blind signatures cannot be re-fetched, so
 * whatever change the mint did return is carried on the error rather than
 * dropped — one malformed quote field must not cost the caller their change.
 * Extends CashuMintError so existing `instanceof CashuMintError` checks still
 * catch it.
 */
export declare class CashuMeltResponseError extends CashuMintError {
    /** Change signatures recovered from the same response. May be empty. */
    change: CashuBlindSignature[];
    /** Per-entry messages for change the mint returned that could not be parsed. */
    changeErrors: string[];
    constructor(message: string, change?: CashuBlindSignature[], changeErrors?: string[], code?: number);
}
