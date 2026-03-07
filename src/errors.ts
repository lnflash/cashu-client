/**
 * Base error for all Cashu client errors.
 * Uses numeric codes compatible with Cashu NUT error codes.
 */
export class CashuError extends Error {
  code: number

  constructor(message: string, code = 0) {
    super(message)
    this.name = this.constructor.name
    this.code = code
    // Maintains proper prototype chain in TypeScript
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/** Generic mint communication or protocol error */
export class CashuMintError extends CashuError {
  constructor(message = "Mint error", code = 10000) {
    super(message, code)
  }
}

/** Quote was not paid when minting was attempted */
export class CashuMintQuoteNotPaidError extends CashuError {
  constructor(message = "Mint quote not paid", code = 10001) {
    super(message, code)
  }
}

/** Card public key is invalid or not a valid secp256k1 point */
export class CashuInvalidCardPubkeyError extends CashuError {
  constructor(message = "Invalid card public key", code = 10002) {
    super(message, code)
  }
}

/** Blinding or unblinding operation failed */
export class CashuBlindingError extends CashuError {
  constructor(message = "Blinding error", code = 10003) {
    super(message, code)
  }
}

/** Proof signature is invalid */
export class CashuInvalidProofError extends CashuError {
  constructor(message = "Invalid proof", code = 10004) {
    super(message, code)
  }
}

/** Not enough card slots available for the requested denominations */
export class CashuInsufficientSlotsError extends CashuError {
  constructor(message = "Insufficient card slots", code = 10005) {
    super(message, code)
  }
}
