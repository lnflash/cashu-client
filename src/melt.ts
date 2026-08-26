import axios from "axios"

import type {
  CashuBlindSignature,
  CashuBlindedMessage,
  CashuMeltQuote,
  CashuProof,
} from "./types"
import { CashuMeltResponseError, CashuMintError } from "./errors"
import {
  axiosConfig,
  describeAxiosError,
  isCompressedPointHex,
  isSafePathId,
  parseResponseDLEQ,
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

/**
 * Parse a melt quote body.
 *
 * The two endpoints are not the same shape, and conflating them is a real
 * fund-visibility bug. `amount`/`fee_reserve` are the whole point of the quote
 * endpoints — without them a caller cannot select proofs — so they are
 * required there. But the legacy mints this parser deliberately supports (the
 * ones reporting `paid: bool` instead of `state`) answer POST /v1/melt/bolt11
 * with only `{paid, change}`; requiring the amounts there would report a melt
 * that actually settled the invoice as an error. Hence `requireAmounts`.
 *
 * A field that is *present* but malformed is rejected in both modes.
 */
const parseQuoteResponse = (
  data: Record<string, unknown>,
  {requireAmounts}: {requireAmounts: boolean},
): CashuMeltQuote | CashuMintError => {
  const quoteId = data.quote
  const amount = data.amount
  const feeReserve = data.fee_reserve

  if (typeof quoteId !== "string" || quoteId.length === 0) {
    return new CashuMintError("Melt quote response missing quote id")
  }

  // Absent is acceptable only on the execute response; present-but-malformed
  // never is.
  const amountOk =
    amount === undefined
      ? !requireAmounts
      : Number.isInteger(amount) && (amount as number) >= 0
  if (!amountOk) {
    return new CashuMintError(`Melt quote returned a non-integer amount: ${String(amount)}`)
  }

  const feeReserveOk =
    feeReserve === undefined
      ? !requireAmounts
      : Number.isInteger(feeReserve) && (feeReserve as number) >= 0
  if (!feeReserveOk) {
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
    // Absent only on a legacy execute response, where the caller already knows
    // them from the quote it is executing.
    amount: amount === undefined ? 0 : (amount as number),
    feeReserve: feeReserve === undefined ? 0 : (feeReserve as number),
    state,
    expiry: typeof data.expiry === "number" ? data.expiry : 0,
    paymentPreimage:
      typeof data.payment_preimage === "string" ? data.payment_preimage : null,
  }
}

/**
 * Parse the `change` array of a melt-execute response, independently of the
 * quote fields.
 *
 * Independence is the point: the inputs are consumed by the time this runs and
 * blind signatures cannot be re-fetched, so a malformed entry — or a malformed
 * field elsewhere in the response — must not take the recoverable change down
 * with it. Bad entries are reported, good ones are returned.
 */
const parseChange = (
  raw: unknown,
): {change: CashuBlindSignature[]; changeErrors: string[]} => {
  const change: CashuBlindSignature[] = []
  const changeErrors: string[] = []
  if (!Array.isArray(raw)) return {change, changeErrors}

  for (const [i, entry] of (raw as Array<Record<string, unknown>>).entries()) {
    if (!entry || typeof entry !== "object") {
      changeErrors.push(`Melt change signature ${i}: malformed entry`)
      continue
    }
    if (!isCompressedPointHex(entry.C_)) {
      changeErrors.push(`Melt change signature ${i}: malformed C_`)
      continue
    }
    if (typeof entry.id !== "string" || !Number.isInteger(entry.amount)) {
      changeErrors.push(`Melt change signature ${i}: malformed id/amount`)
      continue
    }
    const dleq = parseResponseDLEQ(entry.dleq)
    if (dleq === null) {
      changeErrors.push(`Melt change signature ${i}: malformed DLEQ`)
      continue
    }
    change.push({
      id: entry.id,
      amount: entry.amount as number,
      C_: entry.C_,
      ...(dleq ? {dleq} : {}),
    })
  }
  return {change, changeErrors}
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
    return parseQuoteResponse(data, {requireAmounts: true})
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
    return parseQuoteResponse(data, {requireAmounts: true})
  } catch (err) {
    return new CashuMintError(`Melt quote state check failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-05: execute the melt — hand the mint the proofs and have it pay.
 *
 * @param changeOutputs Optional blinded messages for the unused fee reserve.
 *                      Omit them and any overpaid reserve is kept by the mint —
 *                      so supply them whenever the selection overpays. See
 *                      {@link selectProofsForMelt}, which minimises the overpay
 *                      in the first place.
 *
 * If the quote portion of the response cannot be parsed the result is a
 * {@link CashuMeltResponseError}, which still carries whatever change was
 * recovered: the inputs are gone by then and blind signatures cannot be
 * re-fetched, so dropping them would destroy the caller's change outright.
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

    // Parse change first and independently. By this point the inputs are spent
    // and these blind signatures are the only copy in existence — a malformed
    // field in the quote portion must not take them with it.
    const {change, changeErrors} = parseChange(data.change)

    const quote = parseQuoteResponse(
      {...data, quote: data.quote ?? quoteId},
      {requireAmounts: false},
    )
    if (quote instanceof CashuMintError) {
      return new CashuMeltResponseError(quote.message, change, changeErrors)
    }

    if (Array.isArray(data.change)) {
      quote.change = change
      if (changeErrors.length > 0) quote.changeErrors = changeErrors
    }

    return quote
  } catch (err) {
    return new CashuMintError(`Melt failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-02 input fee for a request with `nInputs` proofs, in the keyset's base
 * unit. The mint charges `input_fee_ppk` parts per thousand *per input*, and it
 * comes out of the inputs — so it is part of what the selection must cover.
 */
export const inputFee = (nInputs: number, inputFeePpk = 0): number =>
  inputFeePpk > 0 ? Math.ceil((nInputs * inputFeePpk) / 1000) : 0

/**
 * Total input value required to satisfy a quote.
 *
 * Inputs must cover the invoice amount, the mint's fee reserve, and the NUT-02
 * per-input fee. The fee depends on how many proofs are submitted, so pass the
 * count (and the keyset's `input_fee_ppk`) when the mint charges one; against a
 * zero-fee mint the defaults reproduce the old behaviour.
 */
export const meltAmountRequired = (
  quote: CashuMeltQuote,
  nInputs = 0,
  inputFeePpk = 0,
): number => quote.amount + quote.feeReserve + inputFee(nInputs, inputFeePpk)

/** Sum of proof denominations. */
export const sumProofs = (proofs: CashuProof[]): number =>
  proofs.reduce((total, p) => total + p.amount, 0)

const sortDescending = (proofs: CashuProof[]): CashuProof[] =>
  [...proofs].sort((a, b) => b.amount - a.amount)

/**
 * Accumulate proofs in the given order until the requirement is met, then drop
 * any that turn out to be unnecessary.
 *
 * Pruning walks the chosen set largest-first: removing the largest redundant
 * proof cuts the overpay by more than removing the smallest, and dropping a
 * proof also lowers the input fee, so a drop can never make the selection
 * short. Returns null when the order cannot cover the requirement at all.
 */
const accumulate = (
  ordered: CashuProof[],
  base: number,
  inputFeePpk: number,
): {proofs: CashuProof[]; total: number} | null => {
  const chosen: CashuProof[] = []
  let total = 0
  for (const proof of ordered) {
    chosen.push(proof)
    total += proof.amount
    if (total >= base + inputFee(chosen.length, inputFeePpk)) break
  }
  if (total < base + inputFee(chosen.length, inputFeePpk)) return null

  for (const proof of [...chosen].sort((a, b) => b.amount - a.amount)) {
    const idx = chosen.indexOf(proof)
    if (idx === -1) continue
    const without = total - proof.amount
    if (without >= base + inputFee(chosen.length - 1, inputFeePpk)) {
      chosen.splice(idx, 1)
      total = without
    }
  }
  return {proofs: chosen, total}
}

/**
 * Pick proofs to cover a melt, minimising what the mint keeps.
 *
 * Largest-first alone silently loses money: a card holding [64, 4, 1] paying a
 * 4-sat invoice with a 1-sat reserve selects the 64 and — since `changeOutputs`
 * is optional — hands the mint 60 sats of overpay. So two selections are built,
 * ascending and descending, and the cheaper one wins. Ascending finds the exact
 * [4, 1]; descending stays available for callers whose real constraint is the
 * number of card slots or input fees rather than the total, and wins on a tie.
 *
 * Returns null when the set cannot cover the melt — deliberately, rather than
 * returning a short selection that the mint would reject after the card had
 * already burned the slots.
 *
 * @param inputFeePpk the keyset's NUT-02 `input_fee_ppk`, if it charges one
 */
export const selectProofsForMelt = (
  proofs: CashuProof[],
  quote: CashuMeltQuote,
  inputFeePpk = 0,
): CashuProof[] | null => {
  const base = quote.amount + quote.feeReserve

  const ascending = accumulate(
    [...proofs].sort((a, b) => a.amount - b.amount),
    base,
    inputFeePpk,
  )
  const descending = accumulate(
    [...proofs].sort((a, b) => b.amount - a.amount),
    base,
    inputFeePpk,
  )

  if (!ascending) return descending ? sortDescending(descending.proofs) : null
  if (!descending) return sortDescending(ascending.proofs)

  // Smaller total is strictly less value surrendered to the mint. On an exact
  // tie the cheaper option is the one using fewer proofs — fewer card slots and
  // a smaller input fee for the same cost.
  if (descending.total !== ascending.total) {
    return sortDescending(
      descending.total < ascending.total ? descending.proofs : ascending.proofs,
    )
  }
  return sortDescending(
    descending.proofs.length <= ascending.proofs.length
      ? descending.proofs
      : ascending.proofs,
  )
}
