"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.swapProofs = void 0;
const axios_1 = __importDefault(require("axios"));
const errors_1 = require("./errors");
const http_1 = require("./http");
const witness_1 = require("./witness");
const melt_1 = require("./melt");
/**
 * NUT-03: swapping — exchange proofs for new ones of the same total value.
 *
 * Three things need this. Receiving a token means swapping the sender's proofs
 * for ones locked to you. Making change means swapping one large denomination
 * for several small. And unlocking a card proof means swapping a P2PK-locked
 * proof (with the card's witness) for an unlocked one the terminal controls.
 */
/**
 * NUT-03: submit inputs and blinded outputs, receive blind signatures.
 *
 * Inputs are consumed on success. Like melt this is not idempotent: if the
 * response is lost, check the inputs with NUT-07 rather than resubmitting.
 */
const swapProofs = async (mintUrl, inputs, outputs) => {
    try {
        if (!Array.isArray(inputs) || inputs.length === 0) {
            return new errors_1.CashuMintError("Swap requires at least one input proof");
        }
        if (!Array.isArray(outputs) || outputs.length === 0) {
            return new errors_1.CashuMintError("Swap requires at least one output");
        }
        // The mint enforces this too, but failing here costs nothing while failing
        // there consumes the attempt — and for a card proof the slot is already
        // marked spent by the time we are assembling a swap.
        const inputTotal = (0, melt_1.sumProofs)(inputs);
        const outputTotal = outputs.reduce((total, o) => total + o.amount, 0);
        if (outputTotal > inputTotal) {
            return new errors_1.CashuMintError(`Swap outputs (${outputTotal}) exceed inputs (${inputTotal})`);
        }
        const unsigned = (0, witness_1.findUnsignedProofs)(inputs);
        if (unsigned.length > 0) {
            return new errors_1.CashuMintError(`Inputs at index [${unsigned.join(", ")}] are P2PK-locked with a missing or invalid witness`);
        }
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const { data } = await axios_1.default.post(`${url}/v1/swap`, {
            inputs: inputs.map(p => ({
                id: p.id,
                amount: p.amount,
                secret: p.secret,
                C: p.C,
                ...(p.witness ? { witness: p.witness } : {}),
            })),
            outputs: outputs.map(o => ({ id: o.id, amount: o.amount, B_: o.B_ })),
        }, http_1.axiosConfig);
        if (!Array.isArray(data.signatures)) {
            return new errors_1.CashuMintError("Swap response missing signatures array");
        }
        if (data.signatures.length !== outputs.length) {
            return new errors_1.CashuMintError(`Swap returned ${data.signatures.length} signatures for ${outputs.length} outputs`);
        }
        // Bind each signature to the output it answers. A mint that reordered or
        // relabelled these would hand back proofs worth less than was swapped, or
        // proofs that cannot be unblinded at all.
        const raw = data.signatures;
        const result = [];
        for (let i = 0; i < raw.length; i++) {
            const sig = raw[i];
            const out = outputs[i];
            if (sig.id !== out.id) {
                return new errors_1.CashuMintError(`Swap signature ${i}: keyset ID mismatch (expected ${out.id}, got ${String(sig.id)})`);
            }
            if (sig.amount !== out.amount) {
                return new errors_1.CashuMintError(`Swap signature ${i}: amount mismatch (expected ${out.amount}, got ${String(sig.amount)})`);
            }
            if (!(0, http_1.isCompressedPointHex)(sig.C_)) {
                return new errors_1.CashuMintError(`Swap signature ${i}: malformed C_`);
            }
            const entry = { id: sig.id, amount: sig.amount, C_: sig.C_ };
            const dleq = sig.dleq;
            if (dleq && (0, http_1.isScalarHex)(dleq.e) && (0, http_1.isScalarHex)(dleq.s)) {
                ;
                entry.dleq = {
                    e: dleq.e,
                    s: dleq.s,
                };
            }
            result.push(entry);
        }
        return result;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Swap failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.swapProofs = swapProofs;
