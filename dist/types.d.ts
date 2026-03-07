export type CashuProof = {
    id: string;
    amount: number;
    secret: string;
    C: string;
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
