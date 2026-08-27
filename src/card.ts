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

const requireHex = (value: string, bytes: number, field: string): string => {
  const v = value.trim().toLowerCase()
  if (!HEX.test(v)) {
    throw new Error(`${field} must be hex, got ${JSON.stringify(value)}`)
  }
  if (v.length !== bytes * 2) {
    throw new Error(
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
    throw new Error(
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
    throw new Error(
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
    throw new Error(`amount must be a positive power of two, got ${slot.amount}`)
  }

  return {
    id: keysetId,
    amount: slot.amount,
    // Byte-identical to what was signed at mint time — buildP2PKSecret is the
    // single source of that serialization, so the two cannot drift apart.
    secret: buildP2PKSecret(nonce, pubkey),
    C,
  }
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
      throw new Error(`slot ${i}: ${(e as Error).message}`)
    }
  })
