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
export declare const meltProofs: (mintUrl: string, quoteId: string, proofs: CashuProof[], changeOutputs?: CashuBlindedMessage[]) => Promise<CashuMeltQuote | CashuMintError>;
/**
 * NUT-02 input fee for a request with `nInputs` proofs, in the keyset's base
 * unit. The mint charges `input_fee_ppk` parts per thousand *per input*, and it
 * comes out of the inputs — so it is part of what the selection must cover.
 */
export declare const inputFee: (nInputs: number, inputFeePpk?: number) => number;
/**
 * Total input value required to satisfy a quote.
 *
 * Inputs must cover the invoice amount, the mint's fee reserve, and the NUT-02
 * per-input fee. The fee depends on how many proofs are submitted, so pass the
 * count (and the keyset's `input_fee_ppk`) when the mint charges one; against a
 * zero-fee mint the defaults reproduce the old behaviour.
 */
export declare const meltAmountRequired: (quote: CashuMeltQuote, nInputs?: number, inputFeePpk?: number) => number;
/** Sum of proof denominations. */
export declare const sumProofs: (proofs: CashuProof[]) => number;
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
export declare const selectProofsForMelt: (proofs: CashuProof[], quote: CashuMeltQuote, inputFeePpk?: number) => CashuProof[] | null;
