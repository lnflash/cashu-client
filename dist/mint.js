"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.mintProofs = exports.getMintKeyset = exports.getMintKeysets = exports.getMintQuoteState = exports.requestMintQuote = void 0;
const axios_1 = __importDefault(require("axios"));
const errors_1 = require("./errors");
// HTTP timeout for all mint requests (5 seconds)
const HTTP_TIMEOUT = 5000;
// Validate a mint URL is well-formed and uses HTTPS (or localhost for dev)
const sanitizeMintUrl = (mintUrl) => {
    const trimmed = mintUrl.replace(/\/+$/, ""); // strip trailing slashes
    if (!trimmed) {
        throw new Error("Mint URL is empty");
    }
    // Allow http:// only for localhost dev; require https otherwise
    if (trimmed.startsWith("http://")) {
        const host = trimmed.slice(7).split("/")[0].split(":")[0];
        if (host !== "localhost" && host !== "127.0.0.1") {
            throw new Error("Mint URL must use HTTPS");
        }
    }
    else if (!trimmed.startsWith("https://")) {
        throw new Error("Mint URL must start with https:// (or http:// for localhost)");
    }
    return trimmed;
};
const axiosConfig = {
    timeout: HTTP_TIMEOUT,
    maxRedirects: 0,
    headers: { "Content-Type": "application/json" },
    validateStatus: (status) => status >= 200 && status < 300,
};
/**
 * NUT-04: Request a mint quote.
 */
const requestMintQuote = async (mintUrl, amount, unit) => {
    try {
        const url = sanitizeMintUrl(mintUrl);
        const { data } = await axios_1.default.post(`${url}/v1/mint/quote/bolt11`, { amount, unit }, axiosConfig);
        return {
            quoteId: data.quote,
            paymentRequest: data.request,
            state: data.state,
            expiry: data.expiry,
        };
    }
    catch (err) {
        return new errors_1.CashuMintError(`Mint quote request failed: ${err.message}`);
    }
};
exports.requestMintQuote = requestMintQuote;
/**
 * NUT-04: Check the state of a mint quote.
 */
const getMintQuoteState = async (mintUrl, quoteId) => {
    try {
        const url = sanitizeMintUrl(mintUrl);
        // Sanitize quoteId — only allow alphanumeric + hyphens
        if (!/^[a-zA-Z0-9_-]+$/.test(quoteId)) {
            return new errors_1.CashuMintError("Invalid quote ID format");
        }
        const { data } = await axios_1.default.get(`${url}/v1/mint/quote/bolt11/${quoteId}`, axiosConfig);
        return {
            quoteId: data.quote,
            paymentRequest: data.request,
            state: data.state,
            expiry: data.expiry,
        };
    }
    catch (err) {
        return new errors_1.CashuMintError(`Mint quote state check failed: ${err.message}`);
    }
};
exports.getMintQuoteState = getMintQuoteState;
/**
 * NUT-01: Fetch all active keysets from the mint.
 */
const getMintKeysets = async (mintUrl) => {
    try {
        const url = sanitizeMintUrl(mintUrl);
        const { data } = await axios_1.default.get(`${url}/v1/keysets`, axiosConfig);
        if (!Array.isArray(data.keysets)) {
            return new errors_1.CashuMintError("Mint keyset response missing keysets array");
        }
        return data.keysets;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Mint keyset fetch failed: ${err.message}`);
    }
};
exports.getMintKeysets = getMintKeysets;
/**
 * NUT-01: Fetch the public keys for a specific keyset.
 */
const getMintKeyset = async (mintUrl, keysetId) => {
    try {
        const url = sanitizeMintUrl(mintUrl);
        // Sanitize keysetId — only allow hex characters
        if (!/^[0-9a-fA-F]+$/.test(keysetId)) {
            return new errors_1.CashuMintError("Invalid keyset ID format");
        }
        const { data } = await axios_1.default.get(`${url}/v1/keys/${keysetId}`, axiosConfig);
        const ks = data.keysets?.[0] ?? data;
        return ks;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Mint keyset keys fetch failed: ${err.message}`);
    }
};
exports.getMintKeyset = getMintKeyset;
/**
 * NUT-04: Submit blinded messages to the mint and receive blind signatures.
 */
const mintProofs = async (mintUrl, quoteId, blindedMessages) => {
    try {
        const url = sanitizeMintUrl(mintUrl);
        const { data } = await axios_1.default.post(`${url}/v1/mint/bolt11`, {
            quote: quoteId,
            outputs: blindedMessages.map(bm => ({ id: bm.id, amount: bm.amount, B_: bm.B_ })),
        }, axiosConfig);
        // Validate response shape
        if (!Array.isArray(data.signatures)) {
            return new errors_1.CashuMintError("Mint response missing signatures array");
        }
        if (data.signatures.length !== blindedMessages.length) {
            return new errors_1.CashuMintError(`Mint returned ${data.signatures.length} signatures for ${blindedMessages.length} outputs`);
        }
        return data.signatures.map((sig) => ({
            id: sig.id,
            amount: sig.amount,
            C_: sig.C_,
        }));
    }
    catch (err) {
        const msg = axios_1.default.isAxiosError(err) && err.response?.data?.detail
            ? err.response.data.detail
            : err.message;
        return new errors_1.CashuMintError(`Mint proof issuance failed: ${msg}`);
    }
};
exports.mintProofs = mintProofs;
