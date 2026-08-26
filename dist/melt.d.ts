import type { CashuBlindedMessage, CashuMeltQuote, CashuProof } from "./types";
import { CashuMintError } from "./errors";
/**
 * NUT-05: ask the mint what it will cost to pay `paymentRequest`.
 *
 * The returned `amount + feeReserve` is what must be covered by the inputs;
 * any unused fee reserve is only returned if change outputs are supplied to
 * {@link meltProofs}.
 */
export declare const requestMeltQuote: (mintUrl: string, paymentRequest: string, unit: string) => Promise<CashuMeltQuote | CashuMintError>;
/**
 * NUT-05: re-read a melt quote.
 *
 * The state to watch for is PENDING: the mint has an in-flight Lightning
 * payment and the inputs are already committed. Retrying the melt in that
 * window is how a double payment happens — poll until PAID or UNPAID instead.
 */
export declare const getMeltQuoteState: (mintUrl: string, quoteId: string) => Promise<CashuMeltQuote | CashuMintError>;
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
export declare const meltProofs: (mintUrl: string, quoteId: string, proofs: CashuProof[], changeOutputs?: CashuBlindedMessage[]) => Promise<CashuMeltQuote | CashuMintError>;
/**
 * Total input value required to satisfy a quote.
 * Inputs must cover the invoice amount plus the mint's fee reserve.
 */
export declare const meltAmountRequired: (quote: CashuMeltQuote) => number;
/** Sum of proof denominations. */
export declare const sumProofs: (proofs: CashuProof[]) => number;
/**
 * Pick enough proofs to cover a melt, largest first.
 *
 * Returns null when the set cannot cover it — deliberately, rather than
 * returning a short selection that the mint would reject after the card had
 * already burned the slots.
 */
export declare const selectProofsForMelt: (proofs: CashuProof[], quote: CashuMeltQuote) => CashuProof[] | null;
