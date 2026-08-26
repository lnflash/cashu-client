import axios from "axios"

import type {
  CashuMintQuote,
  CashuBlindedMessage,
  CashuBlindSignature,
  CashuKeyset,
  CashuKeysetDetail,
} from "./types"
import { CashuMintError } from "./errors"
import {
  axiosConfig,
  describeAxiosError,
  isCompressedPointHex,
  parseResponseDLEQ,
  sanitizeMintUrl,
} from "./http"

/**
 * NUT-04: Request a mint quote.
 */
export const requestMintQuote = async (
  mintUrl: string,
  amount: number,
  unit: string,
): Promise<CashuMintQuote | CashuMintError> => {
  try {
    if (!Number.isInteger(amount) || amount <= 0) {
      return new CashuMintError(`Invalid amount: ${amount} (must be a positive integer)`)
    }
    if (!/^[a-z]{3,4}$/.test(unit)) {
      return new CashuMintError(`Invalid unit: ${unit}`)
    }
    const url = sanitizeMintUrl(mintUrl)
    const {data} = await axios.post(
      `${url}/v1/mint/quote/bolt11`,
      {amount, unit},
      axiosConfig,
    )
    return {
      quoteId: data.quote,
      paymentRequest: data.request,
      state: data.state,
      expiry: data.expiry,
    }
  } catch (err) {
    return new CashuMintError(`Mint quote request failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-04: Check the state of a mint quote.
 */
export const getMintQuoteState = async (
  mintUrl: string,
  quoteId: string,
): Promise<CashuMintQuote | CashuMintError> => {
  try {
    const url = sanitizeMintUrl(mintUrl)
    // Sanitize quoteId — only allow alphanumeric + hyphens
    if (!/^[a-zA-Z0-9_-]+$/.test(quoteId)) {
      return new CashuMintError("Invalid quote ID format")
    }
    const {data} = await axios.get(
      `${url}/v1/mint/quote/bolt11/${quoteId}`,
      axiosConfig,
    )
    return {
      quoteId: data.quote,
      paymentRequest: data.request,
      state: data.state,
      expiry: data.expiry,
    }
  } catch (err) {
    return new CashuMintError(`Mint quote state check failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-01: Fetch all active keysets from the mint.
 */
export const getMintKeysets = async (
  mintUrl: string,
): Promise<CashuKeyset[] | CashuMintError> => {
  try {
    const url = sanitizeMintUrl(mintUrl)
    const {data} = await axios.get(`${url}/v1/keysets`, axiosConfig)

    if (!Array.isArray(data.keysets)) {
      return new CashuMintError("Mint keyset response missing keysets array")
    }

    // Carry NUT-02 `input_fee_ppk` through rather than discarding it. Against a
    // mint charging a per-input fee, a melt or swap assembled without it is
    // short by exactly that fee and is rejected — after the card has already
    // burned its slots.
    const keysets: CashuKeyset[] = []
    for (const [i, raw] of (data.keysets as Array<Record<string, unknown>>).entries()) {
      if (!raw || typeof raw !== "object") {
        return new CashuMintError(`Mint keyset ${i}: malformed entry`)
      }
      if (typeof raw.id !== "string" || typeof raw.unit !== "string") {
        return new CashuMintError(`Mint keyset ${i}: malformed id/unit`)
      }
      const ppk = raw.input_fee_ppk
      if (ppk !== undefined && (!Number.isInteger(ppk) || (ppk as number) < 0)) {
        return new CashuMintError(
          `Mint keyset ${i}: malformed input_fee_ppk: ${String(ppk)}`,
        )
      }
      keysets.push({
        id: raw.id,
        unit: raw.unit,
        active: raw.active === true,
        ...(ppk === undefined ? {} : {input_fee_ppk: ppk as number}),
      })
    }
    return keysets
  } catch (err) {
    return new CashuMintError(`Mint keyset fetch failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-01: Fetch the public keys for a specific keyset.
 */
export const getMintKeyset = async (
  mintUrl: string,
  keysetId: string,
): Promise<CashuKeysetDetail | CashuMintError> => {
  try {
    const url = sanitizeMintUrl(mintUrl)
    // Sanitize keysetId — only allow hex characters
    if (!/^[0-9a-fA-F]+$/.test(keysetId)) {
      return new CashuMintError("Invalid keyset ID format")
    }
    const {data} = await axios.get(`${url}/v1/keys/${keysetId}`, axiosConfig)

    const ks = (data.keysets?.[0] ?? data) as CashuKeysetDetail
    // Bind the response to the request: a mint returning keys for a different
    // (or malformed) keyset would otherwise be used as `K` during unblinding,
    // silently producing unspendable proofs.
    if (!ks || ks.id !== keysetId || typeof ks.keys !== "object" || ks.keys === null) {
      return new CashuMintError("Mint returned a keyset that does not match the requested ID")
    }
    return ks
  } catch (err) {
    return new CashuMintError(`Mint keyset keys fetch failed: ${describeAxiosError(err)}`)
  }
}

/**
 * NUT-04: Submit blinded messages to the mint and receive blind signatures.
 */
export const mintProofs = async (
  mintUrl: string,
  quoteId: string,
  blindedMessages: CashuBlindedMessage[],
): Promise<CashuBlindSignature[] | CashuMintError> => {
  try {
    const url = sanitizeMintUrl(mintUrl)
    const {data} = await axios.post(
      `${url}/v1/mint/bolt11`,
      {
        quote: quoteId,
        outputs: blindedMessages.map(bm => ({id: bm.id, amount: bm.amount, B_: bm.B_})),
      },
      axiosConfig,
    )

    // Validate response shape
    if (!Array.isArray(data.signatures)) {
      return new CashuMintError("Mint response missing signatures array")
    }

    if (data.signatures.length !== blindedMessages.length) {
      return new CashuMintError(
        `Mint returned ${data.signatures.length} signatures for ${blindedMessages.length} outputs`,
      )
    }

    // Bind each returned signature to the output that was requested. The mint
    // could otherwise reorder or relabel amounts/keysets, producing proofs worth
    // less than paid or unspendable. The NUT-12 DLEQ is carried through here so
    // the caller can pair it with the blinding factor `r` and verify offline
    // (see `proofDLEQFromBlindSignature`); stripping it would leave the whole
    // dleq module unreachable from the only flow that loads a card.
    const rawSigs = data.signatures as Array<Record<string, unknown>>
    const result: CashuBlindSignature[] = []
    for (let i = 0; i < rawSigs.length; i++) {
      const sig = rawSigs[i]
      const bm = blindedMessages[i]
      if (sig.id !== bm.id) {
        return new CashuMintError(`Mint signature ${i}: keyset ID mismatch (expected ${bm.id}, got ${String(sig.id)})`)
      }
      if (sig.amount !== bm.amount) {
        return new CashuMintError(`Mint signature ${i}: amount mismatch (expected ${bm.amount}, got ${String(sig.amount)})`)
      }
      if (!isCompressedPointHex(sig.C_)) {
        return new CashuMintError(`Mint signature ${i}: malformed C_`)
      }
      const dleq = parseResponseDLEQ(sig.dleq)
      if (dleq === null) {
        return new CashuMintError(`Mint signature ${i}: malformed DLEQ`)
      }
      result.push({
        id: sig.id as string,
        amount: sig.amount as number,
        C_: sig.C_,
        ...(dleq ? {dleq} : {}),
      })
    }
    return result
  } catch (err) {
    return new CashuMintError(`Mint proof issuance failed: ${describeAxiosError(err)}`)
  }
}
