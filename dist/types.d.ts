export type CashuProof = {
    id: string;
    amount: number;
    secret: string;
    C: string;
    /**
     * NUT-11 witness: JSON string of {"signatures": ["<64-byte schnorr hex>"]}.
     * A P2PK-locked proof is only spendable with this attached — for a card
     * proof the signature comes from the card's SPEND_PROOF response.
     */
    witness?: string;
    /** NUT-12 DLEQ proof, carried through from the blind signature. */
    dleq?: CashuDLEQ;
};
/**
 * NUT-12 discrete-log equality proof. On a blind signature it proves the mint
 * used the advertised key `K`; carried onto a proof (with the blinding factor
 * `r`) it lets a receiver verify the same offline, without asking the mint.
 */
export type CashuDLEQ = {
    e: string;
    s: string;
    r?: string;
};
/** NUT-05: a quote to pay a bolt11 invoice by melting proofs. */
export type CashuMeltQuote = {
    quoteId: string;
    amount: number;
    feeReserve: number;
    state: "UNPAID" | "PENDING" | "PAID";
    expiry: number;
    /** Present once state is PAID — proof the Lightning payment settled. */
    paymentPreimage?: string | null;
    /** Overpaid fee returned as blind signatures when change outputs were supplied. */
    change?: CashuBlindSignature[];
};
/** NUT-07: the mint's view of a single proof. */
export type CashuProofState = {
    Y: string;
    state: "UNSPENT" | "PENDING" | "SPENT";
    witness?: string | null;
};
export type CashuMintQuote = {
    quoteId: string;
    paymentRequest: string;
    state: "UNPAID" | "PAID" | "ISSUED" | "EXPIRED";
    expiry: number;
};
export type CashuBlindedMessage = {
    id: string;
    amount: number;
    B_: string;
};
export type CashuBlindSignature = {
    id: string;
    amount: number;
    C_: string;
};
export type CashuBlindingData = {
    nonce: string;
    secretStr: string;
    r: Uint8Array;
    B_: string;
    amount: number;
};
export type CashuKeyset = {
    id: string;
    unit: string;
    active: boolean;
};
export type CashuKeysetDetail = {
    id: string;
    unit: string;
    keys: Record<string, string>;
};
