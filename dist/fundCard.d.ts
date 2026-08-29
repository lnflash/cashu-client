import { CashuMintError } from "./errors";
/** One blinded output, hex-only so the whole structure survives JSON. */
export type PendingOutput = {
    amount: number;
    /** The 32-byte P2PK nonce — this becomes the card's slot field. */
    nonce: string;
    /** The blinding factor. With the nonce, the only copy that can unblind. */
    r: string;
    B_: string;
};
/**
 * Everything needed to finish funding after the invoice is paid.
 *
 * Serializable by design: persist it before showing the invoice. After payment
 * this is the only artifact that can turn the mint's response into proofs.
 */
export type PendingFunding = {
    version: 1;
    mintUrl: string;
    unit: string;
    cardPubkey: string;
    keysetId: string;
    quoteId: string;
    paymentRequest: string;
    /** Unix seconds; after this the unpaid quote is dead. */
    expiry: number;
    outputs: PendingOutput[];
};
export type PrepareOptions = {
    /** Card slot budget. The card has 32 slots; leave room for change. */
    maxSlots?: number;
};
/**
 * Phase 1: pick the keyset, split the amount, request a quote, blind.
 *
 * Nothing has moved yet when this returns — the caller must persist the result
 * and only then present `paymentRequest` for payment.
 */
export declare const prepareFunding: (mintUrl: string, amount: number, unit: string, cardPubkey: string, { maxSlots }?: PrepareOptions) => Promise<PendingFunding | CashuMintError>;
export type CompleteOptions = {
    /**
     * Refuse proofs whose signatures carry no DLEQ. Default false: not every
     * mint emits NUT-12, so absence is a policy decision — but a DLEQ that IS
     * present and fails verification is always refused, options or not, because
     * that is a mint signing with a key it did not publish.
     */
    requireDleq?: boolean;
};
export type FundingResult = {
    /** The card file, ready to write to disk and `cardctl load-file`. */
    cardFile: string;
    /** Total minted, in the keyset's unit. */
    total: number;
    /** Denominations minted, for the operator's summary. */
    amounts: number[];
    /** Outputs whose signature carried no DLEQ (0 when the mint emits NUT-12). */
    missingDleq: number;
};
/**
 * Phase 2: after payment, mint the signatures and assemble the card file.
 *
 * Idempotent on the pending state: NUT-04 permits re-submitting the same quote
 * with the same outputs, so calling this again after a crash or a network
 * failure re-fetches the same signatures rather than double-spending the
 * quote. Returns an error — with the pending state untouched and reusable —
 * on any failure, including an unpaid quote.
 */
export declare const completeFunding: (pending: PendingFunding, { requireDleq }?: CompleteOptions) => Promise<FundingResult | CashuMintError>;
