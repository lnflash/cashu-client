import axios from "axios"

import type {
  CashuBlindSignature,
  CashuBlindedMessage,
  CashuMeltQuote,
  CashuProof,
} from "./types"
import { CashuMintError } from "./errors"
import {
  axiosConfig,
  describeAxiosError,
  isCompressedPointHex,
  isSafePathId,
  sanitizeMintUrl,
} from "./http"
import { findUnsignedProofs } from "./witness"

/**
 * NUT-05: melting — spending proofs to pay a bolt11 invoice.
 *
 * This is the redemption half of the card flow. A terminal reads proofs off a
 * card, has the card sign them (NUT-11 witness), and melts them here to settle
 * a Lightning invoice. Without it a card could be loaded and never spent.
 */

const parseQuoteResponse = (data: Record<string, unknown>): CashuMeltQuote | CashuMintError => {
  const quoteId = data.quote
  const amount = data.amount
  const feeReserve = data.fee_reserve

  if (typeof quoteId !== "string" || quoteId.length === 0) {
    return new CashuMintError("Melt quote response missing quote id")
  }
  if (!Number.isInteger(amount) || (amount as number) < 0) {
    return new CashuMintError(`Melt quote returned a non-integer amount: ${String(amount)}`)
  }
  if (!Number.isInteger(feeReserve) || (feeReserve as number) < 0) {
    return new CashuMintError(`Melt quote returned a non-integer fee_reserve: ${String(feeReserve)}`)
  }

  // Older mints report `paid: bool` instead of `state`. Normalise, because a
  // caller branching on `state === "PAID"` against such a mint would treat a
  // settled payment as unpaid and could pay twice.
  let state = data.state
  if (typeof state !== "string") {
    state = data.paid === true ? "PAID" : "UNPAID"
  }
  if (state !== "UNPAID" && state !== "PENDING" && state !== "PAID") {
    return new CashuMintError(`Melt quote returned an unknown state: ${String(state)}`)
  }

  return {
    quoteId,
    amount: amount as number,
    feeReserve: feeReserve as number,
    state,
    expiry: typeof data.expiry === "number" ? data.expiry : 0,
    paymentPreimage:
      typeof data.payment_preimage === "string" ? data.payment_preimage : null,
  }
}

/**
 * NUT-05: ask the mint what it will cost to pay `paymentRequest`.
 *
 * The returned `amount + feeReserve` is what must be covered by the inputs;
 * any unused fee reserve is only returned if change outputs are supplied to
 * {@link meltProofs}.
 */
export const requestMeltQuote = async (
  mintUrl: string,
  paymentRequest: string,
  unit: string,
): Promise<CashuMeltQuote | CashuMintError> => {
  try {
    if (typeof paymentRequest !== "string" || paymentRequest.length === 0) {
      return new CashuMintError("Melt quote requires a bolt11 payment request")
    }
    if (paymentRequest.length > 8192) {
      return new CashuMintError("Payment request is implausibly long")
    }
    if (!/^[a-z]{3,4}$/.test(unit)) {
      return new CashuMintError(`Invalid unit: ${unit}`)
    }
    const url = sanitizeMintUrl(mintUrl)
    const {data} = await axios.post(
      `${url}/v1/melt/quote/bolt11`,
      {request: paymentRequest, unit},
      axiosConfig,
    )
    return parseQuoteResponse(data)
  } catch (err) {
    return new CashuMintError(`Melt quote request failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-05: re-read a melt quote.
 *
 * The state to watch for is PENDING: the mint has an in-flight Lightning
 * payment and the inputs are already committed. Retrying the melt in that
 * window is how a double payment happens — poll until PAID or UNPAID instead.
 */
export const getMeltQuoteState = async (
  mintUrl: string,
  quoteId: string,
): Promise<CashuMeltQuote | CashuMintError> => {
  try {
    if (!isSafePathId(quoteId)) {
      return new CashuMintError("Invalid quote ID format")
    }
    const url = sanitizeMintUrl(mintUrl)
    const {data} = await axios.get(`${url}/v1/melt/quote/bolt11/${quoteId}`, axiosConfig)
    return parseQuoteResponse(data)
  } catch (err) {
    return new CashuMintError(`Melt quote state check failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-05: execute the melt — hand the mint the proofs and have it pay.
 *
 * @param changeOutputs Optional blinded messages for the unused fee reserve.
 *                      Omit them and any overpaid reserve is kept by the mint.
 *
 * Note this is not idempotent at the protocol level: the inputs are consumed
 * when the mint accepts them. On a network error the correct move is
 * {@link getMeltQuoteState}, never a blind retry.
 */
export const meltProofs = async (
  mintUrl: string,
  quoteId: string,
  proofs: CashuProof[],
  changeOutputs?: CashuBlindedMessage[],
): Promise<CashuMeltQuote | CashuMintError> => {
  try {
    if (!isSafePathId(quoteId)) {
      return new CashuMintError("Invalid quote ID format")
    }
    if (!Array.isArray(proofs) || proofs.length === 0) {
      return new CashuMintError("Melt requires at least one proof")
    }

    // Refuse to burn proofs on a request the mint will reject anyway. The mint
    // fails a melt atomically, but the card has already marked its slots spent
    // by the time we get here, so a rejected submission is not free.
    const unsigned = findUnsignedProofs(proofs)
    if (unsigned.length > 0) {
      return new CashuMintError(
        `Proofs at index [${unsigned.join(", ")}] are P2PK-locked with a missing or invalid witness`,
      )
    }

    const url = sanitizeMintUrl(mintUrl)
    const body: Record<string, unknown> = {
      quote: quoteId,
      inputs: proofs.map(p => ({
        id: p.id,
        amount: p.amount,
        secret: p.secret,
        C: p.C,
        ...(p.witness ? {witness: p.witness} : {}),
      })),
    }
    if (changeOutputs && changeOutputs.length > 0) {
      body.outputs = changeOutputs.map(bm => ({id: bm.id, amount: bm.amount, B_: bm.B_}))
    }

    const {data} = await axios.post(`${url}/v1/melt/bolt11`, body, axiosConfig)

    const quote = parseQuoteResponse({...data, quote: data.quote ?? quoteId})
    if (quote instanceof CashuMintError) return quote

    if (Array.isArray(data.change)) {
      const change: CashuBlindSignature[] = []
      for (const [i, sig] of (data.change as Array<Record<string, unknown>>).entries()) {
        if (!isCompressedPointHex(sig.C_)) {
          return new CashuMintError(`Melt change signature ${i}: malformed C_`)
        }
        if (typeof sig.id !== "string" || !Number.isInteger(sig.amount)) {
          return new CashuMintError(`Melt change signature ${i}: malformed id/amount`)
        }
        change.push({id: sig.id, amount: sig.amount as number, C_: sig.C_})
      }
      quote.change = change
    }

    return quote
  } catch (err) {
    return new CashuMintError(`Melt failed: ${describeAxiosError(err)}`)
  }
}

/**
 * Total input value required to satisfy a quote.
 * Inputs must cover the invoice amount plus the mint's fee reserve.
 */
export const meltAmountRequired = (quote: CashuMeltQuote): number =>
  quote.amount + quote.feeReserve

/** Sum of proof denominations. */
export const sumProofs = (proofs: CashuProof[]): number =>
  proofs.reduce((total, p) => total + p.amount, 0)

/**
 * Pick enough proofs to cover a melt, largest first.
 *
 * Returns null when the set cannot cover it — deliberately, rather than
 * returning a short selection that the mint would reject after the card had
 * already burned the slots.
 */
export const selectProofsForMelt = (
  proofs: CashuProof[],
  quote: CashuMeltQuote,
): CashuProof[] | null => {
  const required = meltAmountRequired(quote)
  if (sumProofs(proofs) < required) return null

  const sorted = [...proofs].sort((a, b) => b.amount - a.amount)
  const chosen: CashuProof[] = []
  let total = 0
  for (const proof of sorted) {
    if (total >= required) break
    chosen.push(proof)
    total += proof.amount
  }
  return total >= required ? chosen : null
}
