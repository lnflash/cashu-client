import axios from "axios"

import type {
  CashuMintQuote,
  CashuBlindedMessage,
  CashuBlindSignature,
  CashuKeyset,
  CashuKeysetDetail,
} from "./types"
import { CashuMintError } from "./errors"

// HTTP timeout for all mint requests (5 seconds)
const HTTP_TIMEOUT = 5000

// Validate a mint URL is well-formed and uses HTTPS (or localhost for dev)
const sanitizeMintUrl = (mintUrl: string): string => {
  const trimmed = mintUrl.replace(/\/+$/, "") // strip trailing slashes

  if (!trimmed) {
    throw new Error("Mint URL is empty")
  }

  // Allow http:// only for localhost dev; require https otherwise
  if (trimmed.startsWith("http://")) {
    const host = trimmed.slice(7).split("/")[0].split(":")[0]
    if (host !== "localhost" && host !== "127.0.0.1") {
      throw new Error("Mint URL must use HTTPS")
    }
  } else if (!trimmed.startsWith("https://")) {
    throw new Error("Mint URL must start with https:// (or http:// for localhost)")
  }

  return trimmed
}

const axiosConfig = {
  timeout: HTTP_TIMEOUT,
  maxRedirects: 0,
  headers: {"Content-Type": "application/json"},
  validateStatus: (status: number) => status >= 200 && status < 300,
} as const

/**
 * NUT-04: Request a mint quote.
 */
export const requestMintQuote = async (
  mintUrl: string,
  amount: number,
  unit: string,
): Promise<CashuMintQuote | CashuMintError> => {
  try {
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
    return new CashuMintError(`Mint quote request failed: ${(err as Error).message}`)
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
    return new CashuMintError(`Mint quote state check failed: ${(err as Error).message}`)
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

    return data.keysets as CashuKeyset[]
  } catch (err) {
    return new CashuMintError(`Mint keyset fetch failed: ${(err as Error).message}`)
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

    const ks = data.keysets?.[0] ?? data
    return ks as CashuKeysetDetail
  } catch (err) {
    return new CashuMintError(`Mint keyset keys fetch failed: ${(err as Error).message}`)
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

    return data.signatures.map(
      (sig: {id: string; amount: number; C_: string}) => ({
        id: sig.id,
        amount: sig.amount,
        C_: sig.C_,
      }),
    )
  } catch (err) {
    const msg =
      axios.isAxiosError(err) && err.response?.data?.detail
        ? err.response.data.detail
        : (err as Error).message
    return new CashuMintError(`Mint proof issuance failed: ${msg}`)
  }
}
