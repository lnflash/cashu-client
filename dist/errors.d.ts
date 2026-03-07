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
