"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.selectProofsForMelt = exports.sumProofs = exports.meltAmountRequired = exports.meltProofs = exports.getMeltQuoteState = exports.requestMeltQuote = void 0;
exports.inputFee = inputFee;
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
/**
 * Parse a melt quote body.
 *
 * The two endpoints are not the same shape, and conflating them is a real
 * fund-visibility bug. `amount`/`fee_reserve` are the whole point of the quote
 * endpoints — without them a caller cannot select proofs — so they are
 * required there. But the legacy mints this parser deliberately supports (the
 * ones reporting `paid: bool` instead of `state`) answer POST /v1/melt/bolt11
 * with only `{paid, change}`; requiring the amounts there would report a melt
 * that actually settled the invoice as an error. Hence `requireAmounts`.
 *
 * A field that is *present* but malformed is rejected in both modes.
 */
const parseQuoteResponse = (data, { requireAmounts }) => {
    const quoteId = data.quote;
    const amount = data.amount;
    const feeReserve = data.fee_reserve;
    if (typeof quoteId !== "string" || quoteId.length === 0) {
        return new errors_1.CashuMintError("Melt quote response missing quote id");
    }
    // Absent is acceptable only on the execute response; present-but-malformed
    // never is.
    const amountOk = amount === undefined
        ? !requireAmounts
        : Number.isInteger(amount) && amount >= 0;
    if (!amountOk) {
        return new errors_1.CashuMintError(`Melt quote returned a non-integer amount: ${String(amount)}`);
    }
    const feeReserveOk = feeReserve === undefined
        ? !requireAmounts
        : Number.isInteger(feeReserve) && feeReserve >= 0;
    if (!feeReserveOk) {
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
        // Absent only on a legacy execute response, where the caller already knows
        // them from the quote it is executing.
        amount: amount === undefined ? 0 : amount,
        feeReserve: feeReserve === undefined ? 0 : feeReserve,
        state,
        expiry: typeof data.expiry === "number" ? data.expiry : 0,
        paymentPreimage: typeof data.payment_preimage === "string" ? data.payment_preimage : null,
    };
};
/**
 * Parse the `change` array of a melt-execute response, independently of the
 * quote fields.
 *
 * Independence is the point: the inputs are consumed by the time this runs and
 * blind signatures cannot be re-fetched, so a malformed entry — or a malformed
 * field elsewhere in the response — must not take the recoverable change down
 * with it. Bad entries are reported, good ones are returned.
 */
const parseChange = (raw) => {
    const change = [];
    const changeErrors = [];
    // Absent is legitimate — a melt with no overpay, or one submitted without
    // change outputs. Present-but-not-an-array is not, and returning silently
    // empty for it would make a mint that mangled the whole field
    // indistinguishable from one that owed no change at all.
    if (raw === undefined || raw === null)
        return { change, changeErrors };
    if (!Array.isArray(raw)) {
        changeErrors.push("Melt change: response field is not an array");
        return { change, changeErrors };
    }
    for (const [i, entry] of raw.entries()) {
        if (!entry || typeof entry !== "object") {
            changeErrors.push(`Melt change signature ${i}: malformed entry`);
            continue;
        }
        if (!(0, http_1.isCompressedPointHex)(entry.C_)) {
            changeErrors.push(`Melt change signature ${i}: malformed C_`);
            continue;
        }
        // Change amounts are the one value here that is not bound to anything the
        // client sent, so the lower bound has to come from us: a negative amount
        // would flow straight into the caller's proof set and quietly subtract from
        // `sumProofs`.
        if (typeof entry.id !== "string" ||
            !Number.isInteger(entry.amount) ||
            entry.amount < 0) {
            changeErrors.push(`Melt change signature ${i}: malformed id/amount`);
            continue;
        }
        const dleq = (0, http_1.parseResponseDLEQ)(entry.dleq);
        if (dleq === null) {
            changeErrors.push(`Melt change signature ${i}: malformed DLEQ`);
            continue;
        }
        change.push({
            id: entry.id,
            amount: entry.amount,
            C_: entry.C_,
            ...(dleq ? { dleq } : {}),
        });
    }
    return { change, changeErrors };
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
        return parseQuoteResponse(data, { requireAmounts: true });
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
        return parseQuoteResponse(data, { requireAmounts: true });
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
        // Parse change first and independently. By this point the inputs are spent
        // and these blind signatures are the only copy in existence — a malformed
        // field in the quote portion must not take them with it.
        const { change, changeErrors } = parseChange(data.change);
        const quote = parseQuoteResponse({ ...data, quote: data.quote ?? quoteId }, { requireAmounts: false });
        if (quote instanceof errors_1.CashuMintError) {
            return new errors_1.CashuMeltResponseError(quote.message, change, changeErrors);
        }
        if (Array.isArray(data.change))
            quote.change = change;
        // Reported independently of the shape of `data.change`: the errors are the
        // only signal that a change field arrived and could not be used.
        if (changeErrors.length > 0)
            quote.changeErrors = changeErrors;
        return quote;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Melt failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.meltProofs = meltProofs;
function inputFee(inputs, rates = 0) {
    if (typeof inputs === "number") {
        if (typeof rates !== "number") {
            throw new Error("inputFee: a per-keyset input_fee_ppk map needs the input proofs, not a count");
        }
        return rates > 0 ? Math.ceil((inputs * rates) / 1000) : 0;
    }
    if (typeof rates === "number") {
        const ids = new Set(inputs.map(p => p.id));
        if (ids.size > 1) {
            throw new Error(`inputFee: inputs span ${ids.size} keysets ([${[...ids].join(", ")}]) — ` +
                "supply a per-keyset input_fee_ppk map, not a single rate");
        }
        return rates > 0 ? Math.ceil((inputs.length * rates) / 1000) : 0;
    }
    // One ceil over the summed ppk, not a ceil per input: rounding each input up
    // separately over-charges a mint that only ever rounds the total.
    const totalPpk = inputs.reduce((sum, p) => sum + (rates[p.id] ?? 0), 0);
    return totalPpk > 0 ? Math.ceil(totalPpk / 1000) : 0;
}
/** Dispatch to the right {@link inputFee} form from a union-typed caller. */
const feeFor = (inputs, rates) => typeof inputs === "number"
    ? inputFee(inputs, rates)
    : inputFee(inputs, rates);
/**
 * Total input value required to satisfy a quote.
 *
 * Inputs must cover the invoice amount, the mint's fee reserve, and the NUT-02
 * per-input fee. The fee depends on which proofs are submitted, so pass them
 * (with the keyset rates) when the mint charges one; against a zero-fee mint
 * the defaults reproduce the old behaviour. A bare count is still accepted for
 * the single-keyset case.
 */
const meltAmountRequired = (quote, inputs = 0, rates = 0) => quote.amount + quote.feeReserve + feeFor(inputs, rates);
exports.meltAmountRequired = meltAmountRequired;
/** Sum of proof denominations. */
const sumProofs = (proofs) => proofs.reduce((total, p) => total + p.amount, 0);
exports.sumProofs = sumProofs;
const sortDescending = (proofs) => [...proofs].sort((a, b) => b.amount - a.amount);
/**
 * Accumulate proofs in the given order until the requirement is met, then drop
 * any that turn out to be unnecessary.
 *
 * Pruning walks the chosen set largest-first: removing the largest redundant
 * proof cuts the overpay by more than removing the smallest, and dropping a
 * proof also lowers the input fee, so a drop can never make the selection
 * short. Returns null when the order cannot cover the requirement at all.
 */
const accumulate = (ordered, base, rates) => {
    const chosen = [];
    let total = 0;
    for (const proof of ordered) {
        chosen.push(proof);
        total += proof.amount;
        if (total >= base + inputFee(chosen, rates))
            break;
    }
    if (total < base + inputFee(chosen, rates))
        return null;
    for (const proof of [...chosen].sort((a, b) => b.amount - a.amount)) {
        const idx = chosen.indexOf(proof);
        if (idx === -1)
            continue;
        const without = total - proof.amount;
        // The fee of the set *without this proof*, not of "one fewer input" — with
        // per-keyset rates those are different numbers.
        const remaining = chosen.filter((_, k) => k !== idx);
        if (without >= base + inputFee(remaining, rates)) {
            chosen.splice(idx, 1);
            total = without;
        }
    }
    return { proofs: chosen, total };
};
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
 */
const selectProofsForMelt = (proofs, quote, rates = 0) => {
    const base = quote.amount + quote.feeReserve;
    const ascending = accumulate([...proofs].sort((a, b) => a.amount - b.amount), base, rates);
    const descending = accumulate([...proofs].sort((a, b) => b.amount - a.amount), base, rates);
    if (!ascending)
        return descending ? sortDescending(descending.proofs) : null;
    if (!descending)
        return sortDescending(ascending.proofs);
    // Smaller total is strictly less value surrendered to the mint. On an exact
    // tie the cheaper option is the one using fewer proofs — fewer card slots and
    // a smaller input fee for the same cost.
    if (descending.total !== ascending.total) {
        return sortDescending(descending.total < ascending.total ? descending.proofs : ascending.proofs);
    }
    return sortDescending(descending.proofs.length <= ascending.proofs.length
        ? descending.proofs
        : ascending.proofs);
};
exports.selectProofsForMelt = selectProofsForMelt;
