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
 * Every field this module validates.
 *
 * Exported because `cardFile.ts` validates these same fields on the way in from
 * a file and reuses the checks below rather than restating them.
 */
export type CardField = "cardPubkey" | "keysetId" | "nonce" | "C" | "amount"

/**
 * Which error class each field's rejection carries.
 *
 * A terminal has to tell "this card's key is bad, abort the whole card" apart
 * from "slot 3 is corrupt, skip it", and regex-matching error messages is not a
 * way to do that. `cardPubkey` belongs to the card; every other field belongs to
 * the single slot being read, so the two get different classes — and different
 * NUT error codes — rather than a bare `Error` each.
 *
 * The mapping is a `Record` over the field union rather than a comparison
 * against the literal `"cardPubkey"`. That class is part of the contract
 * callers depend on, and a string comparison would let a typo or a renamed
 * field silently downgrade a card-key failure to `CashuInvalidProofError` with
 * no compiler complaint; a `Record` makes both the typo and a new field a
 * compile error.
 */
const FIELD_ERROR: Record<CardField, new (message: string) => CashuError> = {
  cardPubkey: CashuInvalidCardPubkeyError,
  keysetId: CashuInvalidProofError,
  nonce: CashuInvalidProofError,
  C: CashuInvalidProofError,
  amount: CashuInvalidProofError,
}

const rejection = (field: CardField, message: string): CashuError =>
  new FIELD_ERROR[field](message)

/**
 * Lower-cased, length-checked hex, or the field's own rejection class.
 *
 * `where` prefixes the message with the caller's context (`"slot 3: "`), which
 * is what lets `cardFile.ts` reuse this verbatim instead of keeping a second
 * copy that drifts. Empty by default, so the messages this module produces are
 * unchanged and the batch path keeps adding its own `slot <i>: ` prefix.
 *
 * `value` is `unknown` rather than `string` on purpose: the typeof check below
 * is the whole reason a caller reaches for this, and typing the parameter as
 * `string` would push every caller holding parsed-JSON data into a cast.
 */
export const requireHex = (
  value: unknown,
  bytes: number,
  field: CardField,
  where = "",
): string => {
  // Checked before `.trim()`. A JS caller or a native reader bridge that omits a
  // field otherwise gets `Cannot read properties of undefined (reading 'trim')`
  // — the one input shape where this module produces a stack trace instead of
  // the diagnosis it exists to produce.
  if (typeof value !== "string") {
    throw rejection(field, `${where}${field} must be a hex string, got ${typeof value}`)
  }
  const v = value.trim().toLowerCase()
  if (!HEX.test(v)) {
    throw rejection(field, `${where}${field} must be hex, got ${JSON.stringify(value)}`)
  }
  if (v.length !== bytes * 2) {
    throw rejection(
      field,
      `${where}${field} must be ${bytes} bytes (${bytes * 2} hex chars), got ${v.length}`,
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
 * points (crypto.ts, dleq.ts, witness.ts), and the 33-byte length check in
 * `requireHex` has already rejected uncompressed keys by the time we get here.
 *
 * The two failures are reported separately because they send an operator to
 * different places. A bad prefix is a reader that encoded the point wrong. An
 * on-prefix, off-curve value is a corrupted or truncated point, and quoting
 * only its (valid) prefix byte would point at the one part that is *not* the
 * problem — the misdiagnosis this module exists to eliminate.
 */
export const requirePoint = (value: string, field: CardField, where = ""): void => {
  const bytes = Buffer.from(value, "hex")
  if (bytes[0] !== 0x02 && bytes[0] !== 0x03) {
    throw rejection(
      field,
      `${where}${field} must be a compressed secp256k1 point, got prefix 0x${value.slice(0, 2)}`,
    )
  }
  if (!secp.isPoint(bytes)) {
    throw rejection(field, `${where}${field} is not on the secp256k1 curve: ${value}`)
  }
}

/**
 * A NUT-02 v0 id is a 0x00 version byte plus 7 bytes of hash, and 8 bytes is
 * the only id version that fits the card's field — so a first byte other than
 * 00 is a corrupted id, which matches no keyset just like a truncated one.
 *
 * Split out of {@link reconstructProofFromCard} so the file parser applies the
 * same rule; the caller has already run the value through {@link requireHex}.
 */
export const requireKeysetV0 = (keysetId: string, where = ""): void => {
  if (!keysetId.startsWith("00")) {
    throw rejection(
      "keysetId",
      `${where}keysetId must be a NUT-02 v0 id (00 version byte), got 0x${keysetId.slice(0, 2)}`,
    )
  }
}

/**
 * A Cashu denomination: a positive power of two, safely representable.
 *
 * `splitIntoDenominations` never emits anything else and a mint keyset has no
 * key for amount 3, so a corrupted amount byte (8 → 9) yields a proof the mint
 * rejects after the slot is burned. Shared with the file parser for exactly
 * that reason — a file is written before anything is loaded onto a card, which
 * is the last place the bad amount can be caught for free.
 */
export const requireAmount = (value: unknown, where = ""): number => {
  // Reported before the range check so a string `"8"` from an untyped reader
  // bridge does not render as `got 8` — a message that looks like a valid value
  // and hides the type error. Mirrors requireHex's `typeof` message.
  if (typeof value !== "number") {
    throw rejection("amount", `${where}amount must be a number, got ${typeof value}`)
  }
  if (!Number.isSafeInteger(value) || value <= 0 || Math.log2(value) % 1 !== 0) {
    throw rejection(
      "amount",
      // Quoted the way requireHex quotes, so a rejected value never renders as
      // something that looks valid. JSON.stringify renders NaN and Infinity as
      // `null` — which is precisely that failure — so those keep their names.
      `${where}amount must be a positive power of two, got ${
        Number.isFinite(value) ? JSON.stringify(value) : String(value)
      }`,
    )
  }
  return value
}

/**
 * The pre-0.4.0 P2PK serialization, frozen.
 *
 * `buildP2PKSecret` lower-cases the nonce and pubkey as of 0.4.0. A proof minted
 * by 0.3.0 or earlier from an upper-case reader value committed to
 * `Y = hash_to_curve(secret-with-upper-case-hex)`, so the canonical secret is a
 * *different* proof that the mint has never signed — and the card burns the slot
 * on SPEND_PROOF before the mint ever objects. This reproduces exactly what
 * those cards were funded with so they stay redeemable.
 *
 * **Only `data` can differ in case.** Pre-0.4.0 `createBlindedMessage` generated
 * the nonce itself (`crypto.randomBytes(32).toString("hex")`), which is always
 * lower case, so the reader's hex case could only ever reach a mint-time secret
 * through `cardPubkey`. Freezing the *nonce*'s case too would emit a secret no
 * version of this library has ever minted — a proof the mint has never signed,
 * discovered only after SPEND_PROOF has burned the slot. The caller therefore
 * passes the already-lower-cased nonce and the raw-cased pubkey.
 *
 * Do not "fix" this to normalise `data`: its whole value is being byte-identical
 * to what the old code emitted. New proofs must use `buildP2PKSecret`.
 */
const legacyP2PKSecret = (nonce: string, cardPubkey: string): string =>
  JSON.stringify([
    "P2PK",
    {nonce, data: cardPubkey, tags: [["sigflag", "SIG_INPUTS"]]},
  ])

/** Options shared by the single-slot and batch reconstruction paths. */
export type ReconstructCardOptions = {
  /**
   * Serialize the secret's `data` with the card key's hex case as supplied,
   * instead of the canonical lower case — the pre-0.4.0 behaviour.
   *
   * Only for redeeming a card funded by <= 0.3.0 through a reader that emitted
   * upper-case hex (`String.format("%02X")` is the idiomatic Java bytes-to-hex).
   * The nonce is lower-cased either way: pre-0.4.0 it was generated as lower-case
   * hex on this side, never read off the card, so it could not carry a reader's
   * case into a minted secret. Try the default first; fall back to this only if
   * the mint rejects the proof as unknown. Never mint with it.
   */
  legacyHexCase?: boolean
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
  options: ReconstructCardOptions = {},
): CashuProof => {
  // The card key is checked first, and completely, because it is the only
  // card-level input here: if it is bad, every slot on the card is unusable and
  // the answer is "abort the card", not "skip this slot". Checked after a slot
  // field it would be masked by whichever slot also happened to be corrupt, and
  // a caller scanning `failures` would read a dead card as one bad slot.
  const pubkey = requireHex(cardPubkey, 33, "cardPubkey")
  requirePoint(pubkey, "cardPubkey")

  // A NUT-02 keyset id is 16 hex chars. Anything shorter is usually an id that
  // was ASCII-encoded into the card's 8-byte field, which truncates it to half
  // an id and matches no keyset at the mint.
  const keysetId = requireHex(slot.keysetId, 8, "keysetId")
  const nonce = requireHex(slot.nonce, 32, "nonce")
  const C = requireHex(slot.C, 33, "C")

  requireKeysetV0(keysetId)
  requirePoint(C, "C")
  requireAmount(slot.amount)

  return {
    id: keysetId,
    amount: slot.amount,
    // Byte-identical to what was signed at mint time — buildP2PKSecret is the
    // single source of that serialization *and* of its canonical hex case, so
    // the two cannot drift apart. The normalisation above is therefore a no-op
    // on the secret rather than a second, competing canonical form.
    //
    // The legacy path passes `nonce` (already lower-cased) rather than the raw
    // slot value, and only `cardPubkey` verbatim: pre-0.4.0 nonces were generated
    // here as lower-case hex, so freezing the reader's case on that field would
    // fabricate a secret no mint has ever signed. See legacyP2PKSecret.
    secret: options.legacyHexCase
      ? legacyP2PKSecret(nonce, cardPubkey.trim())
      : buildP2PKSecret(nonce, pubkey),
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

/** A slot the batch path could not reconstruct, with its position on the card. */
export type CardSlotFailure = {
  /** Index into the `slots` array as passed in. */
  index: number
  /** The rejection, class and `cause` preserved, prefixed with `slot <i>: `. */
  error: Error
}

/** What the batch path returns when `skipInvalid` is set. */
export type CardReconstructionResult = {
  /** Every slot that reconstructed, in card order. */
  proofs: CashuProof[]
  /** Every slot that did not. Empty when the whole card read cleanly. */
  failures: CardSlotFailure[]
}

export type ReconstructCardBatchOptions = ReconstructCardOptions & {
  /**
   * Collect failures instead of throwing on the first one.
   *
   * Defaults to `false` — one bad slot fails the batch, which is the right
   * default for spending a card, since a caller that quietly drops a slot spends
   * less than the holder handed over.
   *
   * Set it for the "slot 3 is corrupt, skip it" case: without it, one corrupt
   * slot makes every other slot on the card unreadable through this API and the
   * caller has to abandon the batch helper and hand-roll the loop. Check the
   * failures' error *class* before treating them as per-slot damage — a bad card
   * key (`CashuInvalidCardPubkeyError`) fails every slot and means abort the
   * card, not skip a slot.
   */
  skipInvalid?: boolean
}

/**
 * Reconstruct every slot on a card, preserving order.
 *
 * A failing slot is reported with its index: `nonce must be 32 bytes` on its own
 * tells an operator nothing about which of N slots is bad.
 *
 * Throws on the first bad slot by default; pass `{skipInvalid: true}` to get
 * `{proofs, failures}` back instead.
 */
export function reconstructProofsFromCard(
  slots: CardProofSlot[],
  cardPubkey: string,
  options?: ReconstructCardOptions & {skipInvalid?: false},
): CashuProof[]
export function reconstructProofsFromCard(
  slots: CardProofSlot[],
  cardPubkey: string,
  options: ReconstructCardOptions & {skipInvalid: true},
): CardReconstructionResult
/**
 * Non-literal `skipInvalid`, returning the union.
 *
 * Reading a card around corrupt slots is exactly the mode a terminal drives from
 * config, or from a retry after the strict pass threw — so `skipInvalid` is
 * routinely a runtime `boolean`. With only the two literal overloads that call
 * fails to compile (`Type 'boolean' is not assignable to type 'false'`) and the
 * caller is pushed into an `as any`, which throws away every other type in the
 * call. This one is listed last so a literal `true`/`false` still matches its
 * precise overload first and keeps the narrow return type.
 */
export function reconstructProofsFromCard(
  slots: CardProofSlot[],
  cardPubkey: string,
  options: ReconstructCardBatchOptions,
): CashuProof[] | CardReconstructionResult
export function reconstructProofsFromCard(
  slots: CardProofSlot[],
  cardPubkey: string,
  options: ReconstructCardBatchOptions = {},
): CashuProof[] | CardReconstructionResult {
  const {skipInvalid = false, ...slotOptions} = options
  const proofs: CashuProof[] = []
  const failures: CardSlotFailure[] = []

  slots.forEach((slot, i) => {
    try {
      proofs.push(reconstructProofFromCard(slot, cardPubkey, slotOptions))
    } catch (e) {
      const error = withSlotIndex(e, i)
      if (!skipInvalid) throw error
      failures.push({index: i, error})
    }
  })

  return skipInvalid ? {proofs, failures} : proofs
}
