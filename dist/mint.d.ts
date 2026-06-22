import type { CashuMintQuote, CashuBlindedMessage, CashuBlindSignature, CashuKeyset, CashuKeysetDetail } from "./types";
import { CashuMintError } from "./errors";
/**
 * NUT-04: Request a mint quote.
 */
export declare const requestMintQuote: (mintUrl: string, amount: number, unit: string) => Promise<CashuMintQuote | CashuMintError>;
/**
 * NUT-04: Check the state of a mint quote.
 */
export declare const getMintQuoteState: (mintUrl: string, quoteId: string) => Promise<CashuMintQuote | CashuMintError>;
/**
 * NUT-01: Fetch all active keysets from the mint.
 */
export declare const getMintKeysets: (mintUrl: string) => Promise<CashuKeyset[] | CashuMintError>;
/**
 * NUT-01: Fetch the public keys for a specific keyset.
 */
export declare const getMintKeyset: (mintUrl: string, keysetId: string) => Promise<CashuKeysetDetail | CashuMintError>;
/**
 * NUT-04: Submit blinded messages to the mint and receive blind signatures.
 */
export declare const mintProofs: (mintUrl: string, quoteId: string, blindedMessages: CashuBlindedMessage[]) => Promise<CashuBlindSignature[] | CashuMintError>;
