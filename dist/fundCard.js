"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.completeFunding = exports.prepareFunding = void 0;
/**
 * Fund a card: turn money at the mint into a card file.
 *
 * This is the missing first link of the chain — everything downstream exists
 * (`cardctl load-file` → tap → SPEND_PROOF → settlement queue → swap), but
 * nothing composed the minting primitives into "here is a file of P2PK-locked
 * proofs for this card". This module does, in two phases with a serializable
 * state between them:
 *
 *   prepareFunding    quote + blinded messages — everything that must survive
 *                     a crash, BEFORE any money moves
 *   completeFunding   after the invoice is paid: mint, unblind, verify DLEQ,
 *                     write the card file
 *
 * The split is the money-safety design, not a convenience. Once the invoice is
 * paid, the blinding data in `PendingFunding` is the ONLY thing that can turn
 * the mint's signatures into spendable proofs — lose it and the payment is
 * gone. A caller must persist the pending state to disk before showing the
 * invoice, exactly as the settlement queue persists a spend before showing an
 * approval. `completeFunding` is idempotent: NUT-04 lets the same quote and
 * the same outputs be re-submitted, so a crash between payment and minting is
 * recovered by calling it again with the same pending state.
 */
const crypto_1 = require("./crypto");
const mint_1 = require("./mint");
const dleq_1 = require("./dleq");
const crypto_2 = require("./crypto");
const cardFile_1 = require("./cardFile");
const errors_1 = require("./errors");
/**
 * Phase 1: pick the keyset, split the amount, request a quote, blind.
 *
 * Nothing has moved yet when this returns — the caller must persist the result
 * and only then present `paymentRequest` for payment.
 */
const prepareFunding = async (mintUrl, amount, unit, cardPubkey, { maxSlots = 32 } = {}) => {
    const keysets = await (0, mint_1.getMintKeysets)(mintUrl);
    if (keysets instanceof errors_1.CashuMintError)
        return keysets;
    const active = keysets.filter(k => k.active && k.unit === unit);
    if (active.length === 0) {
        return new errors_1.CashuMintError(`mint has no active keyset for unit ${JSON.stringify(unit)} — ` +
            `it offers: ${[...new Set(keysets.map(k => k.unit))].join(", ") || "none"}`);
    }
    const keysetId = active[0].id;
    let denominations;
    try {
        denominations = (0, crypto_1.splitIntoDenominations)(amount, maxSlots);
    }
    catch (error) {
        return new errors_1.CashuMintError(error.message);
    }
    const quote = await (0, mint_1.requestMintQuote)(mintUrl, amount, unit);
    if (quote instanceof errors_1.CashuMintError)
        return quote;
    // Blind AFTER the quote so a quote failure leaves nothing to persist. Each
    // output is locked to the card's key; the nonce is what the card will store.
    let outputs;
    try {
        outputs = denominations.map(d => {
            const b = (0, crypto_1.createBlindedMessage)(keysetId, d, cardPubkey);
            return {
                amount: d,
                nonce: b.nonce,
                r: Buffer.from(b.r).toString("hex"),
                B_: b.B_,
            };
        });
    }
    catch (error) {
        return new errors_1.CashuMintError(error.message);
    }
    return {
        version: 1,
        mintUrl,
        unit,
        cardPubkey,
        keysetId,
        quoteId: quote.quoteId,
        paymentRequest: quote.paymentRequest,
        expiry: quote.expiry,
        outputs,
    };
};
exports.prepareFunding = prepareFunding;
/**
 * Phase 2: after payment, mint the signatures and assemble the card file.
 *
 * Idempotent on the pending state: NUT-04 permits re-submitting the same quote
 * with the same outputs, so calling this again after a crash or a network
 * failure re-fetches the same signatures rather than double-spending the
 * quote. Returns an error — with the pending state untouched and reusable —
 * on any failure, including an unpaid quote.
 */
const completeFunding = async (pending, { requireDleq = false } = {}) => {
    const state = await (0, mint_1.getMintQuoteState)(pending.mintUrl, pending.quoteId);
    if (state instanceof errors_1.CashuMintError)
        return state;
    if (state.state !== "PAID" && state.state !== "ISSUED") {
        return new errors_1.CashuMintError(`quote ${pending.quoteId} is ${state.state}, not PAID — pay the invoice first ` +
            `(it expires at unix ${pending.expiry})`);
    }
    const keyset = await (0, mint_1.getMintKeyset)(pending.mintUrl, pending.keysetId);
    if (keyset instanceof errors_1.CashuMintError)
        return keyset;
    const signatures = await (0, mint_1.mintProofs)(pending.mintUrl, pending.quoteId, pending.outputs.map(o => ({
        id: pending.keysetId,
        amount: o.amount,
        B_: o.B_,
    })));
    if (signatures instanceof errors_1.CashuMintError)
        return signatures;
    const slots = [];
    let missingDleq = 0;
    for (let i = 0; i < signatures.length; i++) {
        const sig = signatures[i];
        const output = pending.outputs[i];
        const mintKey = keyset.keys[String(output.amount)];
        if (!mintKey) {
            return new errors_1.CashuMintError(`mint keyset ${pending.keysetId} publishes no key for amount ${output.amount}`);
        }
        const r = Buffer.from(output.r, "hex");
        let C;
        try {
            C = (0, crypto_1.unblindSignature)(sig.C_, r, mintKey);
        }
        catch (error) {
            return new errors_1.CashuMintError(`output ${i} (amount ${output.amount}): ${error.message}`);
        }
        // DLEQ: absent is policy, present-but-invalid is always a refusal — a
        // failing proof means the mint signed with a key it did not publish, and a
        // proof like that can be linked to this card at redemption.
        const dleq = (0, dleq_1.proofDLEQFromBlindSignature)(sig, r);
        if (dleq) {
            const proof = {
                id: pending.keysetId,
                amount: output.amount,
                secret: (0, crypto_2.buildP2PKSecret)(output.nonce, pending.cardPubkey),
                C,
                dleq,
            };
            if (!(0, dleq_1.verifyProofDLEQ)(proof, mintKey)) {
                return new errors_1.CashuMintError(`output ${i} (amount ${output.amount}): DLEQ verification failed — ` +
                    `the mint signed with a key it did not publish. Refusing the whole batch.`);
            }
        }
        else {
            missingDleq += 1;
            if (requireDleq) {
                return new errors_1.CashuMintError(`output ${i} (amount ${output.amount}) carries no DLEQ and requireDleq is set`);
            }
        }
        slots.push({
            keysetId: pending.keysetId,
            amount: output.amount,
            nonce: output.nonce,
            C,
            spent: false,
        });
    }
    // serializeCardFile re-validates everything (curve membership, duplicates,
    // powers of two) — the last free place to catch a bad proof before a card
    // burns a slot on it.
    let cardFile;
    try {
        cardFile = (0, cardFile_1.serializeCardFile)({
            mint: pending.mintUrl,
            unit: pending.unit,
            cardPubkey: pending.cardPubkey,
            slots,
            note: `funded via quote ${pending.quoteId}`,
        });
    }
    catch (error) {
        return new errors_1.CashuMintError(`assembled card file failed validation: ${error.message}`);
    }
    return {
        cardFile,
        total: slots.reduce((sum, s) => sum + s.amount, 0),
        amounts: slots.map(s => s.amount),
        missingDleq,
    };
};
exports.completeFunding = completeFunding;
