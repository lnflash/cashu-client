"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.selectProofsForMelt = exports.sumProofs = exports.meltAmountRequired = exports.meltProofs = exports.getMeltQuoteState = exports.requestMeltQuote = void 0;
const axios_1 = __importDefault(require("axios"));
const errors_1 = require("./errors");
const http_1 = require("./http");
const witness_1 = require("./witness");
/**
 * NUT-05: melting — spending proofs to pay a bolt11 invoice.
 *
 * This is the redemption half of the card flow. A terminal reads proofs off a
 * card, has the card sign them (NUT-11 witness), and melts them here to settle
 * a Lightning invoice. Without it a card could be loaded and never spent.
 */
const parseQuoteResponse = (data) => {
    const quoteId = data.quote;
    const amount = data.amount;
    const feeReserve = data.fee_reserve;
    if (typeof quoteId !== "string" || quoteId.length === 0) {
        return new errors_1.CashuMintError("Melt quote response missing quote id");
    }
    if (!Number.isInteger(amount) || amount < 0) {
        return new errors_1.CashuMintError(`Melt quote returned a non-integer amount: ${String(amount)}`);
    }
    if (!Number.isInteger(feeReserve) || feeReserve < 0) {
        return new errors_1.CashuMintError(`Melt quote returned a non-integer fee_reserve: ${String(feeReserve)}`);
    }
    // Older mints report `paid: bool` instead of `state`. Normalise, because a
    // caller branching on `state === "PAID"` against such a mint would treat a
    // settled payment as unpaid and could pay twice.
    let state = data.state;
    if (typeof state !== "string") {
        state = data.paid === true ? "PAID" : "UNPAID";
    }
    if (state !== "UNPAID" && state !== "PENDING" && state !== "PAID") {
        return new errors_1.CashuMintError(`Melt quote returned an unknown state: ${String(state)}`);
    }
    return {
        quoteId,
        amount: amount,
        feeReserve: feeReserve,
        state,
        expiry: typeof data.expiry === "number" ? data.expiry : 0,
        paymentPreimage: typeof data.payment_preimage === "string" ? data.payment_preimage : null,
    };
};
/**
 * NUT-05: ask the mint what it will cost to pay `paymentRequest`.
 *
 * The returned `amount + feeReserve` is what must be covered by the inputs;
 * any unused fee reserve is only returned if change outputs are supplied to
 * {@link meltProofs}.
 */
const requestMeltQuote = async (mintUrl, paymentRequest, unit) => {
    try {
        if (typeof paymentRequest !== "string" || paymentRequest.length === 0) {
            return new errors_1.CashuMintError("Melt quote requires a bolt11 payment request");
        }
        if (paymentRequest.length > 8192) {
            return new errors_1.CashuMintError("Payment request is implausibly long");
        }
        if (!/^[a-z]{3,4}$/.test(unit)) {
            return new errors_1.CashuMintError(`Invalid unit: ${unit}`);
        }
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const { data } = await axios_1.default.post(`${url}/v1/melt/quote/bolt11`, { request: paymentRequest, unit }, http_1.axiosConfig);
        return parseQuoteResponse(data);
    }
    catch (err) {
        return new errors_1.CashuMintError(`Melt quote request failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.requestMeltQuote = requestMeltQuote;
/**
 * NUT-05: re-read a melt quote.
 *
 * The state to watch for is PENDING: the mint has an in-flight Lightning
 * payment and the inputs are already committed. Retrying the melt in that
 * window is how a double payment happens — poll until PAID or UNPAID instead.
 */
const getMeltQuoteState = async (mintUrl, quoteId) => {
    try {
        if (!(0, http_1.isSafePathId)(quoteId)) {
            return new errors_1.CashuMintError("Invalid quote ID format");
        }
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const { data } = await axios_1.default.get(`${url}/v1/melt/quote/bolt11/${quoteId}`, http_1.axiosConfig);
        return parseQuoteResponse(data);
    }
    catch (err) {
        return new errors_1.CashuMintError(`Melt quote state check failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.getMeltQuoteState = getMeltQuoteState;
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
const meltProofs = async (mintUrl, quoteId, proofs, changeOutputs) => {
    try {
        if (!(0, http_1.isSafePathId)(quoteId)) {
            return new errors_1.CashuMintError("Invalid quote ID format");
        }
        if (!Array.isArray(proofs) || proofs.length === 0) {
            return new errors_1.CashuMintError("Melt requires at least one proof");
        }
        // Refuse to burn proofs on a request the mint will reject anyway. The mint
        // fails a melt atomically, but the card has already marked its slots spent
        // by the time we get here, so a rejected submission is not free.
        const unsigned = (0, witness_1.findUnsignedProofs)(proofs);
        if (unsigned.length > 0) {
            return new errors_1.CashuMintError(`Proofs at index [${unsigned.join(", ")}] are P2PK-locked with a missing or invalid witness`);
        }
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const body = {
            quote: quoteId,
            inputs: proofs.map(p => ({
                id: p.id,
                amount: p.amount,
                secret: p.secret,
                C: p.C,
                ...(p.witness ? { witness: p.witness } : {}),
            })),
        };
        if (changeOutputs && changeOutputs.length > 0) {
            body.outputs = changeOutputs.map(bm => ({ id: bm.id, amount: bm.amount, B_: bm.B_ }));
        }
        const { data } = await axios_1.default.post(`${url}/v1/melt/bolt11`, body, http_1.axiosConfig);
        const quote = parseQuoteResponse({ ...data, quote: data.quote ?? quoteId });
        if (quote instanceof errors_1.CashuMintError)
            return quote;
        if (Array.isArray(data.change)) {
            const change = [];
            for (const [i, sig] of data.change.entries()) {
                if (!(0, http_1.isCompressedPointHex)(sig.C_)) {
                    return new errors_1.CashuMintError(`Melt change signature ${i}: malformed C_`);
                }
                if (typeof sig.id !== "string" || !Number.isInteger(sig.amount)) {
                    return new errors_1.CashuMintError(`Melt change signature ${i}: malformed id/amount`);
                }
                change.push({ id: sig.id, amount: sig.amount, C_: sig.C_ });
            }
            quote.change = change;
        }
        return quote;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Melt failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.meltProofs = meltProofs;
/**
 * Total input value required to satisfy a quote.
 * Inputs must cover the invoice amount plus the mint's fee reserve.
 */
const meltAmountRequired = (quote) => quote.amount + quote.feeReserve;
exports.meltAmountRequired = meltAmountRequired;
/** Sum of proof denominations. */
const sumProofs = (proofs) => proofs.reduce((total, p) => total + p.amount, 0);
exports.sumProofs = sumProofs;
/**
 * Pick enough proofs to cover a melt, largest first.
 *
 * Returns null when the set cannot cover it — deliberately, rather than
 * returning a short selection that the mint would reject after the card had
 * already burned the slots.
 */
const selectProofsForMelt = (proofs, quote) => {
    const required = (0, exports.meltAmountRequired)(quote);
    if ((0, exports.sumProofs)(proofs) < required)
        return null;
    const sorted = [...proofs].sort((a, b) => b.amount - a.amount);
    const chosen = [];
    let total = 0;
    for (const proof of sorted) {
        if (total >= required)
            break;
        chosen.push(proof);
        total += proof.amount;
    }
    return total >= required ? chosen : null;
};
exports.selectProofsForMelt = selectProofsForMelt;
