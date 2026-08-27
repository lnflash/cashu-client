import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import type { CashuBlindingData } from "./types"
import { CashuInsufficientSlotsError } from "./errors"

const DOMAIN_SEPARATOR = Buffer.from("Secp256k1_HashToCurve_Cashu_", "utf8")

/**
 * NUT-00: hash_to_curve
 * Deterministically maps a secret (as UTF-8 bytes or raw buffer) to a secp256k1 point.
 */
export const hashToCurve = (secret: Buffer): Uint8Array => {
  const msgHash = crypto
    .createHash("sha256")
    .update(Buffer.concat([DOMAIN_SEPARATOR, secret]))
    .digest()

  for (let counter = 0; counter < 2 ** 16; counter++) {
    const counterBuf = Buffer.alloc(4)
    counterBuf.writeUInt32LE(counter)
    const candidate = Buffer.concat([
      Buffer.from([0x02]),
      crypto.createHash("sha256").update(Buffer.concat([msgHash, counterBuf])).digest(),
    ])
    if (secp.isPoint(candidate)) return candidate
  }
  throw new Error("hash_to_curve: no valid point found after 2^16 iterations")
}

/**
 * Split an amount (in the keyset's base unit) into Cashu power-of-2 denominations.
 * Returns an array of amounts summing to `total`, each a power of 2.
 *
 * @param total      Total amount to split
 * @param maxSlots   Optional upper bound on the number of denominations produced.
 *                   Throws CashuInsufficientSlotsError if the split would require more.
 */
export const splitIntoDenominations = (total: number, maxSlots?: number): number[] => {
  // Input validation — reject non-finite, negative, or fractional values
  if (!Number.isFinite(total) || total < 0 || !Number.isInteger(total)) {
    throw new Error(`splitIntoDenominations: invalid amount ${total}`)
  }

  const denominations: number[] = []
  let remaining = total
  // Decompose into powers of two, high bit first. Use 2**bit (not 1<<bit): JS
  // bitwise ops are 32-bit, so 1<<bit silently wraps for bit>=31 and the old
  // 0..15 range dropped every bit above 2^15 — a fund-loss bug for amounts
  // >= 65536. 52 covers the full safe-integer range.
  for (let bit = 52; bit >= 0 && remaining > 0; bit--) {
    const denom = 2 ** bit
    if (remaining >= denom) {
      denominations.push(denom)
      remaining -= denom
    }
  }
  if (maxSlots !== undefined && denominations.length > maxSlots) {
    throw new CashuInsufficientSlotsError(
      `Amount ${total} requires ${denominations.length} denominations but only ${maxSlots} slots available`,
    )
  }
  return denominations
}

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
 */
export const buildP2PKSecret = (nonce: string, cardPubkey: string): string => {
  // Use structured serialization to prevent injection via raw string interpolation
  const secret = ["P2PK", {
    nonce: nonce.toLowerCase(),
    data: cardPubkey.toLowerCase(),
    tags: [["sigflag", "SIG_INPUTS"]],
  }]
  return JSON.stringify(secret)
}

/**
 * NUT-03: Create a blinded message for a given denomination.
 * Returns the blinding data needed to unblind the mint's response.
 *
 * B_ = hash_to_curve(secret) + r*G
 */
export const createBlindedMessage = (
  keysetId: string,
  amount: number,
  cardPubkey: string,
): CashuBlindingData => {
  const nonce = crypto.randomBytes(32)
  const nonceHex = nonce.toString("hex")

  // Validate card pubkey is a valid compressed secp256k1 point
  const cardPubBytes = Buffer.from(cardPubkey, "hex")
  if (!secp.isPoint(cardPubBytes)) {
    throw new Error(`createBlindedMessage: cardPubkey is not a valid secp256k1 point`)
  }

  const secretStr = buildP2PKSecret(nonceHex, cardPubkey)
  const secretBytes = Buffer.from(secretStr, "utf8")

  const Y = hashToCurve(secretBytes)

  let r: Uint8Array
  do {
    r = crypto.randomBytes(32)
  } while (!secp.isPrivate(r))

  const rG = secp.pointFromScalar(r, true)
  if (!rG) throw new Error("pointFromScalar failed")

  const B_ = secp.pointAdd(Y, rG, true)
  if (!B_) throw new Error("pointAdd failed for B_")

  // keysetId is accepted for API completeness; callers include it in the BlindedMessage themselves
  void keysetId

  return {
    nonce: nonceHex,
    secretStr,
    r,
    B_: Buffer.from(B_).toString("hex"),
    amount,
  }
}

/**
 * NUT-03: Unblind a mint signature.
 * C = C_ - r*K  where K is the mint's public key for this keyset/denomination.
 */
export const unblindSignature = (
  C_hex: string,
  r: Uint8Array,
  mintPubkeyHex: string,
): string => {
  const C_ = Buffer.from(C_hex, "hex")
  const K = Buffer.from(mintPubkeyHex, "hex")

  // Validate inputs are valid compressed secp256k1 points
  if (!secp.isPoint(C_)) {
    throw new Error("unblindSignature: C_ is not a valid secp256k1 point")
  }
  if (!secp.isPoint(K)) {
    throw new Error("unblindSignature: mintPubkey is not a valid secp256k1 point")
  }
  // Validate the blinding factor (checked after the points so callers passing a
  // bad point still get the point error the tests expect). A zero/out-of-range r
  // would yield C = C_ (no unblinding) — a silent correctness failure.
  if (!secp.isPrivate(r)) {
    throw new Error("unblindSignature: invalid blinding factor r")
  }

  const rK = secp.pointMultiply(K, r, true)
  if (!rK) throw new Error("pointMultiply failed for r*K")

  // Negate compressed point: flip parity byte (0x02 ↔ 0x03)
  const rKNeg = Buffer.from(rK)
  rKNeg[0] = rKNeg[0] === 0x02 ? 0x03 : 0x02

  const C = secp.pointAdd(C_, rKNeg, true)
  if (!C) throw new Error("pointAdd failed for C = C_ - r*K")

  return Buffer.from(C).toString("hex")
}
