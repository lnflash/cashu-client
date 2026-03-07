"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.mintProofs = exports.getMintKeyset = exports.getMintKeysets = exports.getMintQuoteState = exports.requestMintQuote = void 0;
const axios_1 = __importDefault(require("axios"));
const errors_1 = require("./errors");
/**
 * NUT-04: Request a mint quote.
 * Returns a bolt11 invoice the caller must pay before minting.
 *
 * @param mintUrl    Base URL of the Nutshell mint (e.g. "https://forge.flashapp.me")
 * @param amount     Amount in the keyset's base unit (e.g. cents for "usd")
 * @param unit       Keyset unit string (e.g. "usd", "sat")
 */
const requestMintQuote = async (mintUrl, amount, unit) => {
    try {
        const { data } = await axios_1.default.post(`${mintUrl}/v1/mint/quote/bolt11`, { amount, unit });
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
 *
 * @param mintUrl  Base URL of the Nutshell mint
 * @param quoteId  Quote ID returned by requestMintQuote
 */
const getMintQuoteState = async (mintUrl, quoteId) => {
    try {
        const { data } = await axios_1.default.get(`${mintUrl}/v1/mint/quote/bolt11/${quoteId}`);
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
 *
 * @param mintUrl  Base URL of the Nutshell mint
 */
const getMintKeysets = async (mintUrl) => {
    try {
        const { data } = await axios_1.default.get(`${mintUrl}/v1/keysets`);
        return data.keysets;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Mint keyset fetch failed: ${err.message}`);
    }
};
exports.getMintKeysets = getMintKeysets;
/**
 * NUT-01: Fetch the public keys for a specific keyset.
 * Returns { id, unit, keys: { "1": pubkeyHex, "2": pubkeyHex, ... } }
 *
 * @param mintUrl   Base URL of the Nutshell mint
 * @param keysetId  Keyset ID (hex string)
 */
const getMintKeyset = async (mintUrl, keysetId) => {
    try {
        const { data } = await axios_1.default.get(`${mintUrl}/v1/keys/${keysetId}`);
        // Nutshell wraps response in { keysets: [{ id, unit, keys }] }
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
 * The quote MUST be in PAID state before calling this.
 *
 * @param mintUrl         Base URL of the Nutshell mint
 * @param quoteId         Quote ID (must be PAID)
 * @param blindedMessages Array of blinded messages to sign
 */
const mintProofs = async (mintUrl, quoteId, blindedMessages) => {
    try {
        const { data } = await axios_1.default.post(`${mintUrl}/v1/mint/bolt11`, {
            quote: quoteId,
            outputs: blindedMessages.map((bm) => ({ id: bm.id, amount: bm.amount, B_: bm.B_ })),
        });
        return data.signatures.map((sig) => ({
            id: sig.id,
            amount: sig.amount,
            C_: sig.C_,
        }));
    }
    catch (err) {
        // Preserve the mint's error message (e.g. "quote not paid") for caller retry logic
        const msg = axios_1.default.isAxiosError(err) && err.response?.data?.detail
            ? err.response.data.detail
            : err.message;
        return new errors_1.CashuMintError(`Mint proof issuance failed: ${msg}`);
    }
};
exports.mintProofs = mintProofs;
