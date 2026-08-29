"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CashuMeltResponseError = exports.CashuVerificationError = exports.CashuInsufficientSlotsError = exports.CashuInvalidProofError = exports.CashuBlindingError = exports.CashuInvalidCardPubkeyError = exports.CashuMintQuoteNotPaidError = exports.CashuMintError = exports.CashuError = void 0;
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
/**
 * Quote was not paid when minting was attempted.
 *
 * Extends CashuMintError so existing `instanceof CashuMintError` checks still
 * catch it, while callers polling for payment can match the type instead of
 * regexing the message.
 */
class CashuMintQuoteNotPaidError extends CashuMintError {
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
/**
 * A deterministic verification refusal from `completeFunding`: DLEQ
 * verification failed, `requireDleq` refused a signature with no DLEQ, or the
 * keyset published no key for an output amount.
 *
 * Unlike transport blips, retrying with the same pending state will fail
 * identically — callers polling with retry loops should fail fast on this
 * instead of re-minting and re-verifying. Extends CashuMintError so existing
 * `instanceof CashuMintError` checks still catch it.
 */
class CashuVerificationError extends CashuMintError {
    constructor(message = "Verification failed", code = 10007) {
        super(message, code);
    }
}
exports.CashuVerificationError = CashuVerificationError;
/**
 * A melt was executed but its quote fields could not be parsed.
 *
 * The inputs are already consumed and blind signatures cannot be re-fetched, so
 * whatever change the mint did return is carried on the error rather than
 * dropped — one malformed quote field must not cost the caller their change.
 * Extends CashuMintError so existing `instanceof CashuMintError` checks still
 * catch it.
 */
class CashuMeltResponseError extends CashuMintError {
    constructor(message, change = [], changeErrors = [], code = 10006) {
        super(message, code);
        this.change = change;
        this.changeErrors = changeErrors;
    }
}
exports.CashuMeltResponseError = CashuMeltResponseError;
