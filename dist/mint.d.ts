import type { CashuMintQuote, CashuBlindedMessage, CashuBlindSignature, CashuKeyset, CashuKeysetDetail } from "./types";
import { CashuMintError } from "./errors";
/**
 * NUT-04: Request a mint quote.
 * Returns a bolt11 invoice the caller must pay before minting.
 *
 * @param mintUrl    Base URL of the Nutshell mint (e.g. "https://forge.flashapp.me")
 * @param amount     Amount in the keyset's base unit (e.g. cents for "usd")
 * @param unit       Keyset unit string (e.g. "usd", "sat")
 */
export declare const requestMintQuote: (mintUrl: string, amount: number, unit: string) => Promise<CashuMintQuote | CashuMintError>;
/**
 * NUT-04: Check the state of a mint quote.
 *
 * @param mintUrl  Base URL of the Nutshell mint
 * @param quoteId  Quote ID returned by requestMintQuote
 */
export declare const getMintQuoteState: (mintUrl: string, quoteId: string) => Promise<CashuMintQuote | CashuMintError>;
/**
 * NUT-01: Fetch all active keysets from the mint.
 *
 * @param mintUrl  Base URL of the Nutshell mint
 */
export declare const getMintKeysets: (mintUrl: string) => Promise<CashuKeyset[] | CashuMintError>;
/**
 * NUT-01: Fetch the public keys for a specific keyset.
 * Returns { id, unit, keys: { "1": pubkeyHex, "2": pubkeyHex, ... } }
 *
 * @param mintUrl   Base URL of the Nutshell mint
 * @param keysetId  Keyset ID (hex string)
 */
export declare const getMintKeyset: (mintUrl: string, keysetId: string) => Promise<CashuKeysetDetail | CashuMintError>;
/**
 * NUT-04: Submit blinded messages to the mint and receive blind signatures.
 * The quote MUST be in PAID state before calling this.
 *
 * @param mintUrl         Base URL of the Nutshell mint
 * @param quoteId         Quote ID (must be PAID)
 * @param blindedMessages Array of blinded messages to sign
 */
export declare const mintProofs: (mintUrl: string, quoteId: string, blindedMessages: CashuBlindedMessage[]) => Promise<CashuBlindSignature[] | CashuMintError>;
