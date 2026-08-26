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
 * NUT-02 `input_fee_ppk` keyed by keyset id.
 *
 * A wallet that has lived through a keyset rotation holds proofs from more than
 * one keyset, and NUT-02 declares the rate *per keyset* — so the fee is the sum
 * of each input's own rate, rounded once.
 *
 * Build one with {@link inputFeeRatesFromKeysets} from the mint's `/v1/keysets`
 * response rather than by hand — a keyset missing from the map is treated as
 * unpriceable and refused, which is a safety net only if the map is complete.
 */
export type InputFeeRates = Record<string, number>;
/**
 * NUT-02 input fee for a request, in the keyset's base unit. The mint charges
 * `input_fee_ppk` parts per thousand *per input*, and it comes out of the
 * inputs — so it is part of what the selection must cover.
 *
 * Two forms. Pass the proofs plus an {@link InputFeeRates} map when the inputs
 * may span keysets: the fee is `ceil(sum of each input's own ppk / 1000)`, which
 * is what the mint computes. Pass a count (or the proofs) plus a single rate
 * only for the uniform case — applying one keyset's rate to another's proofs
 * over-charges (the balance check then demands outputs that are short) or
 * under-charges (the mint rejects), and either way the card has already burned
 * its slots. A mixed-keyset proof set with a scalar rate is therefore refused
 * rather than silently mispriced.
 */
export declare function inputFee(nInputs: number, inputFeePpk?: number): number;
export declare function inputFee(inputs: Pick<CashuProof, "id">[], rates: number | InputFeeRates): number;
/**
 * Build an {@link InputFeeRates} map from the mint's advertised keysets.
 *
 * Use this rather than hand-assembling the map: it guarantees every keyset the
 * mint declares is present, which is what makes {@link inputFee}'s
 * "absent means unpriceable" refusal a safety net rather than a nuisance. A
 * keyset the mint does not advertise stays absent on purpose — proofs from it
 * cannot be priced and should not be silently treated as free.
 */
export declare const inputFeeRatesFromKeysets: (keysets: Array<{
    id: string;
    input_fee_ppk?: number;
}>) => InputFeeRates;
/**
 * Total input value required to satisfy a quote.
 *
 * Inputs must cover the invoice amount, the mint's fee reserve, and the NUT-02
 * per-input fee. The fee depends on which proofs are submitted, so pass them
 * (with the keyset rates) when the mint charges one; against a zero-fee mint
 * the defaults reproduce the old behaviour. A bare count is still accepted for
 * the single-keyset case.
 */
export declare const meltAmountRequired: (quote: CashuMeltQuote, inputs?: number | Pick<CashuProof, "id">[], rates?: number | InputFeeRates) => number;
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
 * @param rates the keyset's NUT-02 `input_fee_ppk` if a single keyset is in
 *              play, or an {@link InputFeeRates} map keyed by keyset id when
 *              the proofs span keysets (a rotation leaves a card holding both)
 *
 * @throws if `rates` cannot price the proofs — a scalar rate against inputs
 *         spanning keysets, or a map missing one of their keysets. That is a
 *         caller error rather than a runtime condition (hence a throw and not
 *         the `null` return, which means "these proofs cannot cover the melt"),
 *         and it is raised before any proof is selected. Omitting `rates`
 *         entirely means "this mint charges no input fee" and never throws.
 */
export declare const selectProofsForMelt: (proofs: CashuProof[], quote: CashuMeltQuote, rates?: number | InputFeeRates) => CashuProof[] | null;
