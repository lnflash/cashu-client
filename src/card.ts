/**
 * Card proof reconstruction.
 *
 * A card cannot store a NUT-10 P2PK secret. The secret is a JSON string of
 * roughly 150 bytes and a proof slot is 78 bytes total, so the card stores only
 * the 32-byte nonce. Everything else the secret needs — the card's public key
 * and the fixed tag set — is recoverable, which is what makes the slot layout
 * work at all.
 *
 * This module turns what `GET_PROOF` returns into a spendable `CashuProof`.
 * Without it the card's contents are inert: a terminal can read a slot and
 * still have no proof to hand the mint.
 *
 * See `spec/NUT-XX.md` in lnflash/cashu-javacard —
 * *Reconstructing the full Proof from card storage*.
 */
import * as secp from "tiny-secp256k1"

import { buildP2PKSecret } from "./crypto"
import {
  CashuError,
  CashuInvalidCardPubkeyError,
  CashuInvalidProofError,
} from "./errors"
import type { CashuProof } from "./types"

/**
 * One proof slot as read from the card, hex-encoded.
 *
 * Field names deliberately mirror the on-card layout rather than `CashuProof`:
 * `nonce` is not `secret`, and conflating them is the mistake this module
 * exists to prevent.
 */
export type CardProofSlot = {
  /** NUT-02 keyset id — 16 hex chars (the 8 raw bytes at offset 1). */
  keysetId: string
  /** Denomination in the keyset's base unit. */
  amount: number
  /** The 32-byte P2PK nonce at offset 13 — 64 hex chars. NOT the secret. */
  nonce: string
  /** The mint's unblinded signature at offset 45 — 33 bytes, 66 hex chars. */
  C: string
}

const HEX = /^[0-9a-f]+$/

/**
 * The typed error for a rejected field.
 *
 * A terminal has to tell "this card's key is bad, abort the whole card" apart
 * from "slot 3 is corrupt, skip it", and regex-matching error messages is not a
 * way to do that. `cardPubkey` belongs to the card; every other field belongs to
 * the single slot being read, so the two get different classes — and different
 * NUT error codes — rather than a bare `Error` each.
 */
const rejection = (field: string, message: string): CashuError =>
  field === "cardPubkey"
    ? new CashuInvalidCardPubkeyError(message)
    : new CashuInvalidProofError(message)

const requireHex = (value: string, bytes: number, field: string): string => {
  // Checked before `.trim()`. A JS caller or a native reader bridge that omits a
  // field otherwise gets `Cannot read properties of undefined (reading 'trim')`
  // — the one input shape where this module produces a stack trace instead of
  // the diagnosis it exists to produce.
  if (typeof value !== "string") {
    throw rejection(field, `${field} must be a hex string, got ${typeof value}`)
  }
  const v = value.trim().toLowerCase()
  if (!HEX.test(v)) {
    throw rejection(field, `${field} must be hex, got ${JSON.stringify(value)}`)
  }
  if (v.length !== bytes * 2) {
    throw rejection(
      field,
      `${field} must be ${bytes} bytes (${bytes * 2} hex chars), got ${v.length}`,
    )
  }
  return v
}

/**
 * Reject anything that is not an actual point on secp256k1.
 *
 * A prefix test is not enough: `02`/`03` is necessary but not sufficient, and an
 * on-prefix but off-curve value produces a secret locked to a non-point — the
 * card burns the slot on SPEND_PROOF and the mint then rejects a proof that was
 * never spendable. `secp.isPoint` is how the rest of this package validates
 * points (crypto.ts, dleq.ts, witness.ts); the 33-byte length check above
 * already rejects uncompressed keys, so this subsumes the prefix intent.
 */
const requirePoint = (value: string, field: string): void => {
  if (!secp.isPoint(Buffer.from(value, "hex"))) {
    throw rejection(
      field,
      `${field} must be a compressed secp256k1 point on the curve, got 0x${value.slice(0, 2)}…`,
    )
  }
}

/**
 * Rebuild a spendable proof from a card slot and the card's public key.
 *
 * The returned proof carries no witness. It is not spendable until the card
 * signs `p2pkMessageToSign(proof)` via SPEND_PROOF and the signature is
 * attached with `attachP2PKWitness`.
 *
 * Throws rather than returning a malformed proof: a wrong-length keyset id or
 * nonce produces a proof the mint will reject, and failing at the mint is a far
 * worse place to discover it than here — by then the card may already have
 * burned the slot.
 */
export const reconstructProofFromCard = (
  slot: CardProofSlot,
  cardPubkey: string,
): CashuProof => {
  // A NUT-02 keyset id is 16 hex chars. Anything shorter is usually an id that
  // was ASCII-encoded into the card's 8-byte field, which truncates it to half
  // an id and matches no keyset at the mint.
  const keysetId = requireHex(slot.keysetId, 8, "keysetId")
  const nonce = requireHex(slot.nonce, 32, "nonce")
  const C = requireHex(slot.C, 33, "C")
  const pubkey = requireHex(cardPubkey, 33, "cardPubkey")

  // A NUT-02 v0 id is a 0x00 version byte plus 7 bytes of hash, and 8 bytes is
  // the only id version that fits the card's field — so a first byte other than
  // 00 is a corrupted id, which matches no keyset just like a truncated one.
  if (!keysetId.startsWith("00")) {
    throw rejection(
      "keysetId",
      `keysetId must be a NUT-02 v0 id (00 version byte), got 0x${keysetId.slice(0, 2)}`,
    )
  }
  requirePoint(pubkey, "cardPubkey")
  requirePoint(C, "C")
  // Cashu denominations are powers of two — splitIntoDenominations never emits
  // anything else and a mint keyset has no key for amount 3 — so a corrupted
  // amount byte (8 → 9) yields a proof the mint rejects after the slot is burned.
  if (
    !Number.isSafeInteger(slot.amount) ||
    slot.amount <= 0 ||
    Math.log2(slot.amount) % 1 !== 0
  ) {
    throw rejection(
      "amount",
      `amount must be a positive power of two, got ${slot.amount}`,
    )
  }

  return {
    id: keysetId,
    amount: slot.amount,
    // Byte-identical to what was signed at mint time — buildP2PKSecret is the
    // single source of that serialization *and* of its canonical hex case, so
    // the two cannot drift apart. The normalisation above is therefore a no-op
    // on the secret rather than a second, competing canonical form.
    secret: buildP2PKSecret(nonce, pubkey),
    C,
  }
}

/**
 * Re-label a slot failure with its index without throwing away what it was.
 *
 * Building a fresh bare `Error` would drop both the original stack — pointing
 * the trace at this wrapper rather than the failing check — and the error class,
 * so the batch path would erase the very "bad card key" / "bad slot" distinction
 * {@link rejection} exists to draw. Every `CashuError` subclass takes
 * `(message, code?)` with the code defaulted, so reconstructing from the
 * constructor preserves the NUT code too.
 */
const withSlotIndex = (e: unknown, i: number): Error => {
  const message = `slot ${i}: ${e instanceof Error ? e.message : String(e)}`
  const Ctor = e instanceof CashuError ? (e.constructor as new (m: string) => Error) : Error
  // `cause` is assigned rather than passed to the constructor: this package
  // compiles against lib ES2020, whose Error constructor is typed without an
  // options bag. Readers see the same `.cause` either way (Node >= 18).
  const wrapped: Error & { cause?: unknown } = new Ctor(message)
  wrapped.cause = e
  return wrapped
}

/**
 * Reconstruct every slot on a card, preserving order.
 *
 * A failing slot is reported with its index: `nonce must be 32 bytes` on its own
 * tells an operator nothing about which of N slots is bad.
 */
export const reconstructProofsFromCard = (
  slots: CardProofSlot[],
  cardPubkey: string,
): CashuProof[] =>
  slots.map((slot, i) => {
    try {
      return reconstructProofFromCard(slot, cardPubkey)
    } catch (e) {
      throw withSlotIndex(e, i)
    }
  })
