"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.allProofsUnspent = exports.checkProofStates = exports.proofIdentifier = void 0;
const axios_1 = __importDefault(require("axios"));
const errors_1 = require("./errors");
const http_1 = require("./http");
const crypto_1 = require("./crypto");
/**
 * NUT-07: asking the mint whether proofs are still spendable.
 *
 * This is the double-spend check. A card is a bearer instrument and its
 * on-card SPENT flag only stops the *card* from signing again — it says
 * nothing about whether those proofs were already melted at the mint from a
 * copy of the data. An offline terminal genuinely cannot detect that; an
 * online one has no excuse not to check.
 *
 * Also the correct recovery step after a melt or swap whose response was lost:
 * ask what happened rather than resubmitting and risking a second payment.
 */
/**
 * The mint's identifier for a proof: Y = hash_to_curve(secret), compressed hex.
 * Note this is derived from the secret only — it does not reveal the signature.
 */
const proofIdentifier = (proof) => Buffer.from((0, crypto_1.hashToCurve)(Buffer.from(proof.secret, "utf8"))).toString("hex");
exports.proofIdentifier = proofIdentifier;
/**
 * NUT-07: look up the state of each proof.
 *
 * Results are returned in the same order as `proofs`. A mint that returns a
 * different number of states, or reorders them, is rejected rather than
 * silently mapped — pairing a SPENT verdict against the wrong proof is worse
 * than no answer.
 */
const checkProofStates = async (mintUrl, proofs) => {
    try {
        if (!Array.isArray(proofs) || proofs.length === 0) {
            return new errors_1.CashuMintError("checkProofStates requires at least one proof");
        }
        const url = (0, http_1.sanitizeMintUrl)(mintUrl);
        const ys = proofs.map(exports.proofIdentifier);
        const { data } = await axios_1.default.post(`${url}/v1/checkstate`, { Ys: ys }, http_1.axiosConfig);
        if (!Array.isArray(data.states)) {
            return new errors_1.CashuMintError("checkstate response missing states array");
        }
        if (data.states.length !== ys.length) {
            return new errors_1.CashuMintError(`checkstate returned ${data.states.length} states for ${ys.length} proofs`);
        }
        const byY = new Map();
        for (const [i, entry] of data.states.entries()) {
            const y = entry.Y;
            const state = entry.state;
            if (!(0, http_1.isCompressedPointHex)(y)) {
                return new errors_1.CashuMintError(`checkstate entry ${i}: malformed Y`);
            }
            if (state !== "UNSPENT" && state !== "PENDING" && state !== "SPENT") {
                return new errors_1.CashuMintError(`checkstate entry ${i}: unknown state ${String(state)}`);
            }
            byY.set(y.toLowerCase(), {
                Y: y.toLowerCase(),
                state,
                witness: typeof entry.witness === "string" ? entry.witness : null,
            });
        }
        // Re-pair by Y rather than by position, then require every proof to be
        // accounted for. A missing Y means the mint answered a different question
        // than the one asked.
        const ordered = [];
        for (const [i, y] of ys.entries()) {
            const found = byY.get(y.toLowerCase());
            if (!found) {
                return new errors_1.CashuMintError(`checkstate did not return a state for proof ${i}`);
            }
            ordered.push(found);
        }
        return ordered;
    }
    catch (err) {
        return new errors_1.CashuMintError(`Proof state check failed: ${(0, http_1.describeAxiosError)(err)}`);
    }
};
exports.checkProofStates = checkProofStates;
/**
 * Convenience: are all of these proofs still unspent?
 *
 * Treats PENDING as not-spendable. A pending proof is committed to an in-flight
 * operation, and accepting it as payment is how the same value gets counted
 * twice.
 *
 * Callers must compare explicitly and handle the error case:
 *
 * ```ts
 * const verdict = await allProofsUnspent(url, proofs)
 * if (verdict instanceof CashuMintError) return refuse(verdict)
 * if (verdict !== "UNSPENT") return refuse("already spent or pending")
 * ```
 */
const allProofsUnspent = async (mintUrl, proofs) => {
    const states = await (0, exports.checkProofStates)(mintUrl, proofs);
    if (states instanceof errors_1.CashuMintError)
        return states;
    return states.every(s => s.state === "UNSPENT") ? "UNSPENT" : "NOT_UNSPENT";
};
exports.allProofsUnspent = allProofsUnspent;
