import axios from "axios"

import type { CashuMintQuote, CashuBlindedMessage, CashuBlindSignature, CashuKeyset, CashuKeysetDetail } from "./types"
import { CashuMintError } from "./errors"

/**
 * NUT-04: Request a mint quote.
 * Returns a bolt11 invoice the caller must pay before minting.
 *
 * @param mintUrl    Base URL of the Nutshell mint (e.g. "https://forge.flashapp.me")
 * @param amount     Amount in the keyset's base unit (e.g. cents for "usd")
 * @param unit       Keyset unit string (e.g. "usd", "sat")
 */
export const requestMintQuote = async (
  mintUrl: string,
  amount: number,
  unit: string,
): Promise<CashuMintQuote | CashuMintError> => {
  try {
    const { data } = await axios.post(`${mintUrl}/v1/mint/quote/bolt11`, { amount, unit })
    return {
      quoteId: data.quote,
      paymentRequest: data.request,
      state: data.state,
      expiry: data.expiry,
    }
  } catch (err) {
    return new CashuMintError(`Mint quote request failed: ${(err as Error).message}`)
  }
}

/**
 * NUT-04: Check the state of a mint quote.
 *
 * @param mintUrl  Base URL of the Nutshell mint
 * @param quoteId  Quote ID returned by requestMintQuote
 */
export const getMintQuoteState = async (
  mintUrl: string,
  quoteId: string,
): Promise<CashuMintQuote | CashuMintError> => {
  try {
    const { data } = await axios.get(`${mintUrl}/v1/mint/quote/bolt11/${quoteId}`)
    return {
      quoteId: data.quote,
      paymentRequest: data.request,
      state: data.state,
      expiry: data.expiry,
    }
  } catch (err) {
    return new CashuMintError(`Mint quote state check failed: ${(err as Error).message}`)
  }
}

/**
 * NUT-01: Fetch all active keysets from the mint.
 *
 * @param mintUrl  Base URL of the Nutshell mint
 */
export const getMintKeysets = async (
  mintUrl: string,
): Promise<CashuKeyset[] | CashuMintError> => {
  try {
    const { data } = await axios.get(`${mintUrl}/v1/keysets`)
    return data.keysets as CashuKeyset[]
  } catch (err) {
    return new CashuMintError(`Mint keyset fetch failed: ${(err as Error).message}`)
  }
}

/**
 * NUT-01: Fetch the public keys for a specific keyset.
 * Returns { id, unit, keys: { "1": pubkeyHex, "2": pubkeyHex, ... } }
 *
 * @param mintUrl   Base URL of the Nutshell mint
 * @param keysetId  Keyset ID (hex string)
 */
export const getMintKeyset = async (
  mintUrl: string,
  keysetId: string,
): Promise<CashuKeysetDetail | CashuMintError> => {
  try {
    const { data } = await axios.get(`${mintUrl}/v1/keys/${keysetId}`)
    // Nutshell wraps response in { keysets: [{ id, unit, keys }] }
    const ks = data.keysets?.[0] ?? data
    return ks as CashuKeysetDetail
  } catch (err) {
    return new CashuMintError(`Mint keyset keys fetch failed: ${(err as Error).message}`)
  }
}

/**
 * NUT-04: Submit blinded messages to the mint and receive blind signatures.
 * The quote MUST be in PAID state before calling this.
 *
 * @param mintUrl         Base URL of the Nutshell mint
 * @param quoteId         Quote ID (must be PAID)
 * @param blindedMessages Array of blinded messages to sign
 */
export const mintProofs = async (
  mintUrl: string,
  quoteId: string,
  blindedMessages: CashuBlindedMessage[],
): Promise<CashuBlindSignature[] | CashuMintError> => {
  try {
    const { data } = await axios.post(`${mintUrl}/v1/mint/bolt11`, {
      quote: quoteId,
      outputs: blindedMessages.map((bm) => ({ id: bm.id, amount: bm.amount, B_: bm.B_ })),
    })
    return data.signatures.map((sig: { id: string; amount: number; C_: string }) => ({
      id: sig.id,
      amount: sig.amount,
      C_: sig.C_,
    }))
  } catch (err) {
    // Preserve the mint's error message (e.g. "quote not paid") for caller retry logic
    const msg = axios.isAxiosError(err) && err.response?.data?.detail
      ? err.response.data.detail
      : (err as Error).message
    return new CashuMintError(`Mint proof issuance failed: ${msg}`)
  }
}
