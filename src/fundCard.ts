/**
 * Fund a card: turn money at the mint into a card file.
 *
 * This is the missing first link of the chain — everything downstream exists
 * (`cardctl load-file` → tap → SPEND_PROOF → settlement queue → swap), but
 * nothing composed the minting primitives into "here is a file of P2PK-locked
 * proofs for this card". This module does, in two phases with a serializable
 * state between them:
 *
 *   prepareFunding    quote + blinded messages — everything that must survive
 *                     a crash, BEFORE any money moves
 *   completeFunding   after the invoice is paid: mint, unblind, verify DLEQ,
 *                     write the card file
 *
 * The split is the money-safety design, not a convenience. Once the invoice is
 * paid, the blinding data in `PendingFunding` is the ONLY thing that can turn
 * the mint's signatures into spendable proofs — lose it and the payment is
 * gone. A caller must persist the pending state to disk before showing the
 * invoice, exactly as the settlement queue persists a spend before showing an
 * approval. `completeFunding` is idempotent: NUT-04 lets the same quote and
 * the same outputs be re-submitted, so a crash between payment and minting is
 * recovered by calling it again with the same pending state.
 */
import {
  createBlindedMessage,
  splitIntoDenominations,
  unblindSignature,
} from "./crypto"
import {
  getMintKeyset,
  getMintKeysets,
  getMintQuoteState,
  mintProofs,
  requestMintQuote,
} from "./mint"
import { proofDLEQFromBlindSignature, verifyProofDLEQ } from "./dleq"
import { buildP2PKSecret } from "./crypto"
import { serializeCardFile } from "./cardFile"
import { CashuMintError } from "./errors"
import type { CashuProof } from "./types"

/** One blinded output, hex-only so the whole structure survives JSON. */
export type PendingOutput = {
  amount: number
  /** The 32-byte P2PK nonce — this becomes the card's slot field. */
  nonce: string
  /** The blinding factor. With the nonce, the only copy that can unblind. */
  r: string
  B_: string
}

/**
 * Everything needed to finish funding after the invoice is paid.
 *
 * Serializable by design: persist it before showing the invoice. After payment
 * this is the only artifact that can turn the mint's response into proofs.
 */
export type PendingFunding = {
  version: 1
  mintUrl: string
  unit: string
  cardPubkey: string
  keysetId: string
  quoteId: string
  paymentRequest: string
  /** Unix seconds; after this the unpaid quote is dead. */
  expiry: number
  outputs: PendingOutput[]
}

export type PrepareOptions = {
  /** Card slot budget. The card has 32 slots; leave room for change. */
  maxSlots?: number
}

/**
 * Phase 1: pick the keyset, split the amount, request a quote, blind.
 *
 * Nothing has moved yet when this returns — the caller must persist the result
 * and only then present `paymentRequest` for payment.
 */
export const prepareFunding = async (
  mintUrl: string,
  amount: number,
  unit: string,
  cardPubkey: string,
  { maxSlots = 32 }: PrepareOptions = {},
): Promise<PendingFunding | CashuMintError> => {
  const keysets = await getMintKeysets(mintUrl)
  if (keysets instanceof CashuMintError) return keysets

  const active = keysets.filter(k => k.active && k.unit === unit)
  if (active.length === 0) {
    return new CashuMintError(
      `mint has no active keyset for unit ${JSON.stringify(unit)} — ` +
        `it offers: ${[...new Set(keysets.map(k => k.unit))].join(", ") || "none"}`,
    )
  }
  const keysetId = active[0].id

  let denominations: number[]
  try {
    denominations = splitIntoDenominations(amount, maxSlots)
  } catch (error) {
    return new CashuMintError((error as Error).message)
  }

  const quote = await requestMintQuote(mintUrl, amount, unit)
  if (quote instanceof CashuMintError) return quote

  // Blind AFTER the quote so a quote failure leaves nothing to persist. Each
  // output is locked to the card's key; the nonce is what the card will store.
  let outputs: PendingOutput[]
  try {
    outputs = denominations.map(d => {
      const b = createBlindedMessage(keysetId, d, cardPubkey)
      return {
        amount: d,
        nonce: b.nonce,
        r: Buffer.from(b.r).toString("hex"),
        B_: b.B_,
      }
    })
  } catch (error) {
    return new CashuMintError((error as Error).message)
  }

  return {
    version: 1,
    mintUrl,
    unit,
    cardPubkey,
    keysetId,
    quoteId: quote.quoteId,
    paymentRequest: quote.paymentRequest,
    expiry: quote.expiry,
    outputs,
  }
}

export type CompleteOptions = {
  /**
   * Refuse proofs whose signatures carry no DLEQ. Default false: not every
   * mint emits NUT-12, so absence is a policy decision — but a DLEQ that IS
   * present and fails verification is always refused, options or not, because
   * that is a mint signing with a key it did not publish.
   */
  requireDleq?: boolean
}

export type FundingResult = {
  /** The card file, ready to write to disk and `cardctl load-file`. */
  cardFile: string
  /** Total minted, in the keyset's unit. */
  total: number
  /** Denominations minted, for the operator's summary. */
  amounts: number[]
  /** Outputs whose signature carried no DLEQ (0 when the mint emits NUT-12). */
  missingDleq: number
}

/**
 * Phase 2: after payment, mint the signatures and assemble the card file.
 *
 * Idempotent on the pending state: NUT-04 permits re-submitting the same quote
 * with the same outputs, so calling this again after a crash or a network
 * failure re-fetches the same signatures rather than double-spending the
 * quote. Returns an error — with the pending state untouched and reusable —
 * on any failure, including an unpaid quote.
 */
export const completeFunding = async (
  pending: PendingFunding,
  { requireDleq = false }: CompleteOptions = {},
): Promise<FundingResult | CashuMintError> => {
  const state = await getMintQuoteState(pending.mintUrl, pending.quoteId)
  if (state instanceof CashuMintError) return state
  if (state.state !== "PAID" && state.state !== "ISSUED") {
    return new CashuMintError(
      `quote ${pending.quoteId} is ${state.state}, not PAID — pay the invoice first ` +
        `(it expires at unix ${pending.expiry})`,
    )
  }

  const keyset = await getMintKeyset(pending.mintUrl, pending.keysetId)
  if (keyset instanceof CashuMintError) return keyset

  const signatures = await mintProofs(
    pending.mintUrl,
    pending.quoteId,
    pending.outputs.map(o => ({
      id: pending.keysetId,
      amount: o.amount,
      B_: o.B_,
    })),
  )
  if (signatures instanceof CashuMintError) return signatures

  const slots = []
  let missingDleq = 0
  for (let i = 0; i < signatures.length; i++) {
    const sig = signatures[i]
    const output = pending.outputs[i]
    const mintKey = keyset.keys[String(output.amount)]
    if (!mintKey) {
      return new CashuMintError(
        `mint keyset ${pending.keysetId} publishes no key for amount ${output.amount}`,
      )
    }

    const r = Buffer.from(output.r, "hex")
    let C: string
    try {
      C = unblindSignature(sig.C_, r, mintKey)
    } catch (error) {
      return new CashuMintError(
        `output ${i} (amount ${output.amount}): ${(error as Error).message}`,
      )
    }

    // DLEQ: absent is policy, present-but-invalid is always a refusal — a
    // failing proof means the mint signed with a key it did not publish, and a
    // proof like that can be linked to this card at redemption.
    const dleq = proofDLEQFromBlindSignature(sig, r)
    if (dleq) {
      const proof: CashuProof = {
        id: pending.keysetId,
        amount: output.amount,
        secret: buildP2PKSecret(output.nonce, pending.cardPubkey),
        C,
        dleq,
      }
      if (!verifyProofDLEQ(proof, mintKey)) {
        return new CashuMintError(
          `output ${i} (amount ${output.amount}): DLEQ verification failed — ` +
            `the mint signed with a key it did not publish. Refusing the whole batch.`,
        )
      }
    } else {
      missingDleq += 1
      if (requireDleq) {
        return new CashuMintError(
          `output ${i} (amount ${output.amount}) carries no DLEQ and requireDleq is set`,
        )
      }
    }

    slots.push({
      keysetId: pending.keysetId,
      amount: output.amount,
      nonce: output.nonce,
      C,
      spent: false,
    })
  }

  // serializeCardFile re-validates everything (curve membership, duplicates,
  // powers of two) — the last free place to catch a bad proof before a card
  // burns a slot on it.
  let cardFile: string
  try {
    cardFile = serializeCardFile({
      mint: pending.mintUrl,
      unit: pending.unit,
      cardPubkey: pending.cardPubkey,
      slots,
      note: `funded via quote ${pending.quoteId}`,
    })
  } catch (error) {
    return new CashuMintError(`assembled card file failed validation: ${(error as Error).message}`)
  }

  return {
    cardFile,
    total: slots.reduce((sum, s) => sum + s.amount, 0),
    amounts: slots.map(s => s.amount),
    missingDleq,
  }
}
