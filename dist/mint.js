"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.mintProofs = exports.getMintKeyset = exports.getMintKeysets = exports.getMintQuoteState = exports.requestMintQuote = void 0;
const axios_1 = __importDefault(require("axios"));
const errors_1 = require("./errors");
const http_1 = require("./http");
/**
 * NUT-04: Request a mint quote.
 */
const requestMintQuote = async (mintUrl, amount, unit) => {
    try {
        if (!Number.isInteger(amount) || amount <= 0) {
            return new errors_1.CashuMintError(`Invalid amount: ${amount} (must be a positive integer)`);
        }
        if (!/^[a-z]{3,4}$/.test(unit)) {
            return new errors_1.CashuMintError(`Invalid unit: ${unit}`);
        }
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const { data } = await axios_1.default.post(`${url}/v1/mint/quote/bolt11`, { amount, unit }, http_1.axiosConfig);
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
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        // Sanitize quoteId — only allow alphanumeric + hyphens
        if (!/^[a-zA-Z0-9_-]+$/.test(quoteId)) {
            return new errors_1.CashuMintError("Invalid quote ID format");
        }
        const { data } = await axios_1.default.get(`${url}/v1/mint/quote/bolt11/${quoteId}`, http_1.axiosConfig);
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
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const { data } = await axios_1.default.get(`${url}/v1/keysets`, http_1.axiosConfig);
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
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        // Sanitize keysetId — only allow hex characters
        if (!/^[0-9a-fA-F]+$/.test(keysetId)) {
            return new errors_1.CashuMintError("Invalid keyset ID format");
        }
        const { data } = await axios_1.default.get(`${url}/v1/keys/${keysetId}`, http_1.axiosConfig);
        const ks = (data.keysets?.[0] ?? data);
        // Bind the response to the request: a mint returning keys for a different
        // (or malformed) keyset would otherwise be used as `K` during unblinding,
        // silently producing unspendable proofs.
        if (!ks || ks.id !== keysetId || typeof ks.keys !== "object" || ks.keys === null) {
            return new errors_1.CashuMintError("Mint returned a keyset that does not match the requested ID");
        }
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
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const { data } = await axios_1.default.post(`${url}/v1/mint/bolt11`, {
            quote: quoteId,
            outputs: blindedMessages.map(bm => ({ id: bm.id, amount: bm.amount, B_: bm.B_ })),
        }, http_1.axiosConfig);
        // Validate response shape
        if (!Array.isArray(data.signatures)) {
            return new errors_1.CashuMintError("Mint response missing signatures array");
        }
        if (data.signatures.length !== blindedMessages.length) {
            return new errors_1.CashuMintError(`Mint returned ${data.signatures.length} signatures for ${blindedMessages.length} outputs`);
        }
        // Bind each returned signature to the output that was requested. The mint
        // could otherwise reorder or relabel amounts/keysets, producing proofs worth
        // less than paid or unspendable. (Full NUT-12 DLEQ verification — proving the
        // mint signed with the advertised key — is tracked as a follow-up.)
        const rawSigs = data.signatures;
        const result = [];
        for (let i = 0; i < rawSigs.length; i++) {
            const sig = rawSigs[i];
            const bm = blindedMessages[i];
            if (sig.id !== bm.id) {
                return new errors_1.CashuMintError(`Mint signature ${i}: keyset ID mismatch (expected ${bm.id}, got ${sig.id})`);
            }
            if (sig.amount !== bm.amount) {
                return new errors_1.CashuMintError(`Mint signature ${i}: amount mismatch (expected ${bm.amount}, got ${sig.amount})`);
            }
            if (typeof sig.C_ !== "string" || !/^0[23][0-9a-fA-F]{64}$/.test(sig.C_)) {
                return new errors_1.CashuMintError(`Mint signature ${i}: malformed C_`);
            }
            result.push({ id: sig.id, amount: sig.amount, C_: sig.C_ });
        }
        return result;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Mint proof issuance failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.mintProofs = mintProofs;
