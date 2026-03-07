"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CashuInsufficientSlotsError = exports.CashuInvalidProofError = exports.CashuBlindingError = exports.CashuInvalidCardPubkeyError = exports.CashuMintQuoteNotPaidError = exports.CashuMintError = exports.CashuError = void 0;
/**
 * Base error for all Cashu client errors.
 * Uses numeric codes compatible with Cashu NUT error codes.
 */
class CashuError extends Error {
    constructor(message, code = 0) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
        // Maintains proper prototype chain in TypeScript
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
exports.CashuError = CashuError;
/** Generic mint communication or protocol error */
class CashuMintError extends CashuError {
    constructor(message = "Mint error", code = 10000) {
        super(message, code);
    }
}
exports.CashuMintError = CashuMintError;
/** Quote was not paid when minting was attempted */
class CashuMintQuoteNotPaidError extends CashuError {
    constructor(message = "Mint quote not paid", code = 10001) {
        super(message, code);
    }
}
exports.CashuMintQuoteNotPaidError = CashuMintQuoteNotPaidError;
/** Card public key is invalid or not a valid secp256k1 point */
class CashuInvalidCardPubkeyError extends CashuError {
    constructor(message = "Invalid card public key", code = 10002) {
        super(message, code);
    }
}
exports.CashuInvalidCardPubkeyError = CashuInvalidCardPubkeyError;
/** Blinding or unblinding operation failed */
class CashuBlindingError extends CashuError {
    constructor(message = "Blinding error", code = 10003) {
        super(message, code);
    }
}
exports.CashuBlindingError = CashuBlindingError;
/** Proof signature is invalid */
class CashuInvalidProofError extends CashuError {
    constructor(message = "Invalid proof", code = 10004) {
        super(message, code);
    }
}
exports.CashuInvalidProofError = CashuInvalidProofError;
/** Not enough card slots available for the requested denominations */
class CashuInsufficientSlotsError extends CashuError {
    constructor(message = "Insufficient card slots", code = 10005) {
        super(message, code);
    }
}
exports.CashuInsufficientSlotsError = CashuInsufficientSlotsError;
