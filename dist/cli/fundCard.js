#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_CONSECUTIVE_FAILURES = exports.POLL_INTERVAL_MS = exports.FundCardCliError = void 0;
exports.runFundCard = runFundCard;
/**
 * fund-card — turn money at the mint into a card file.
 *
 *   fund-card --mint https://forge.flashapp.me --amount 500 --unit sat \
 *             --card-pubkey 02… [--out card.json] [--require-dleq]
 *
 * Flow: quote → PERSIST PENDING STATE → show invoice → poll until paid →
 * mint → verify → write card file → delete pending state.
 *
 * The persistence ordering is the whole design. Once the invoice is paid, the
 * pending file's blinding data is the only thing that can turn the mint's
 * signatures into proofs — so it is written before the invoice is ever shown,
 * and a crash at any later point is recovered by re-running the same command:
 * the pending file is detected and funding resumes from it (NUT-04 lets the
 * same quote and outputs be re-submitted).
 *
 * The flow lives in `runFundCard` with an injectable io surface (fs, output,
 * clock, sleep) so the money-safety ordering above is testable; `main` only
 * parses argv and wires the real io.
 */
const nodeFs = __importStar(require("fs"));
const fundCard_1 = require("../fundCard");
const errors_1 = require("../errors");
const USAGE = `usage: fund-card --mint <url> --amount <n> --card-pubkey <hex>
                 [--unit sat] [--out <file>] [--max-slots 32]
                 [--require-dleq] [--force]

Writes a card file of P2PK-locked proofs for the card, ready for
\`cardctl load-file\`. Re-running with the same --out resumes an
interrupted funding from its .pending.json.`;
/** A fatal CLI condition: `runFundCard` throws it, `main` prints it and exits 1. */
class FundCardCliError extends Error {
}
exports.FundCardCliError = FundCardCliError;
function die(message) {
    process.stderr.write(message + "\n");
    process.exit(1);
}
function parseArgs(argv) {
    const flags = new Map();
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (!arg.startsWith("--"))
            die(`unexpected argument ${arg}\n\n${USAGE}`);
        const name = arg.slice(2);
        if (name === "require-dleq" || name === "force" || name === "help") {
            flags.set(name, true);
        }
        else {
            const value = argv[++i];
            if (value === undefined)
                die(`--${name} needs a value\n\n${USAGE}`);
            flags.set(name, value);
        }
    }
    if (flags.has("help")) {
        process.stdout.write(USAGE + "\n");
        process.exit(0);
    }
    for (const required of ["mint", "amount", "card-pubkey"]) {
        if (!flags.has(required))
            die(`--${required} is required\n\n${USAGE}`);
    }
    const amount = Number(flags.get("amount"));
    if (!Number.isInteger(amount) || amount <= 0) {
        die(`--amount must be a positive integer, got ${flags.get("amount")}`);
    }
    const maxSlots = Number(flags.get("max-slots") ?? 32);
    if (!Number.isInteger(maxSlots) || maxSlots <= 0 || maxSlots > 32) {
        die(`--max-slots must be 1..32, got ${flags.get("max-slots")}`);
    }
    const cardPubkey = String(flags.get("card-pubkey")).toLowerCase();
    return {
        mint: String(flags.get("mint")),
        amount,
        cardPubkey,
        unit: String(flags.get("unit") ?? "sat"),
        out: String(flags.get("out") ?? `card-${cardPubkey.slice(0, 10)}.json`),
        maxSlots,
        requireDleq: flags.has("require-dleq"),
        force: flags.has("force"),
    };
}
const defaultIo = () => ({
    fs: nodeFs,
    stdout: text => process.stdout.write(text),
    stderr: text => process.stderr.write(text),
    sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
    now: () => Date.now(),
});
/** Poll interval while waiting for the invoice to be paid. */
exports.POLL_INTERVAL_MS = 5000;
/**
 * Consecutive non-"not paid" failures tolerated while polling before dying.
 * A transient network blip on the quote-state GET must not kill an unattended
 * funding mid-wait; a persistent failure still surfaces after this many tries
 * (the pending file survives either way, so nothing is lost — only unattended).
 */
exports.MAX_CONSECUTIVE_FAILURES = 3;
async function runFundCard(args, io = defaultIo()) {
    const fail = (message) => {
        throw new FundCardCliError(message);
    };
    const pendingPath = args.out + ".pending.json";
    let pending;
    if (io.fs.existsSync(pendingPath)) {
        // A previous run got as far as persisting the quote. That state is the
        // only copy of the blinding data — resume from it, never re-quote.
        pending = JSON.parse(io.fs.readFileSync(pendingPath, "utf-8"));
        if (pending.version !== 1)
            fail(`${pendingPath}: unsupported pending version`);
        if (pending.cardPubkey !== args.cardPubkey) {
            fail(`${pendingPath} is for card ${pending.cardPubkey}, not ${args.cardPubkey}.\n` +
                `Finish or remove it before funding a different card to the same --out.`);
        }
        // A resume ignores --amount and re-uses the persisted quote, so the flags
        // must not silently disagree with it: resuming "5000 sat at mint B" from a
        // pending file for "500 sat at mint A" would fund the wrong thing.
        if (pending.mintUrl !== args.mint) {
            fail(`${pendingPath} is a pending funding at ${pending.mintUrl}, not ${args.mint}.\n` +
                `Finish it (re-run with --mint ${pending.mintUrl}) or remove it to start over.`);
        }
        if (pending.unit !== args.unit) {
            fail(`${pendingPath} is a pending funding in ${pending.unit}, not ${args.unit}.\n` +
                `Finish it (re-run with --unit ${pending.unit}) or remove it to start over.`);
        }
        const pendingAmount = pending.outputs.reduce((sum, o) => sum + o.amount, 0);
        io.stderr(`resuming from ${pendingPath}: ${pendingAmount} ${pending.unit} at ` +
            `${pending.mintUrl} (quote ${pending.quoteId})\n`);
    }
    else {
        if (io.fs.existsSync(args.out) && !args.force) {
            fail(`${args.out} already exists; pass --force to overwrite`);
        }
        const prepared = await (0, fundCard_1.prepareFunding)(args.mint, args.amount, args.unit, args.cardPubkey, { maxSlots: args.maxSlots });
        if (prepared instanceof errors_1.CashuMintError)
            fail(prepared.message);
        pending = prepared;
        // Before the invoice is shown, atomically: write-then-rename so a crash
        // mid-write cannot leave a truncated pending file that resumes wrong.
        io.fs.writeFileSync(pendingPath + ".tmp", JSON.stringify(pending, null, 2));
        io.fs.renameSync(pendingPath + ".tmp", pendingPath);
        io.stdout(`\nPay this invoice (${args.amount} ${args.unit}):\n\n` +
            `${pending.paymentRequest}\n\n` +
            `Blinding state saved to ${pendingPath} — do not delete it until the\n` +
            `card file is written; after payment it is the only way to recover.\n\n`);
    }
    // Poll until paid. completeFunding checks the state itself, so the loop just
    // keeps trying it; a not-paid result is a typed CashuMintQuoteNotPaidError.
    const deadline = pending.expiry * 1000;
    let consecutiveFailures = 0;
    for (;;) {
        const result = await (0, fundCard_1.completeFunding)(pending, { requireDleq: args.requireDleq });
        if (!(result instanceof errors_1.CashuMintError)) {
            // Ordering is money safety: the card file must exist on disk before the
            // pending file — the only recovery artifact — is deleted.
            io.fs.writeFileSync(args.out, result.cardFile + "\n");
            io.fs.unlinkSync(pendingPath);
            io.stdout(`\nwrote ${args.out}: ${result.amounts.length} proof(s), ` +
                `${result.total} ${pending.unit} total` +
                (result.missingDleq > 0
                    ? `\nwarning: ${result.missingDleq} signature(s) carried no DLEQ ` +
                        `(the mint does not emit NUT-12)`
                    : "") +
                `\n\nnext: cardctl load-file ${args.out}\n`);
            return;
        }
        if (result instanceof errors_1.CashuMintQuoteNotPaidError) {
            consecutiveFailures = 0;
            if (io.now() > deadline) {
                fail(`quote expired unpaid. ${pendingPath} is kept for the record; remove it ` +
                    `to start over.`);
            }
            io.stderr("waiting for payment…\n");
        }
        else if (result instanceof errors_1.CashuVerificationError) {
            // Deterministic refusal (DLEQ failure, --require-dleq, keyset missing a
            // key): re-running will fail identically, so don't retry and don't
            // suggest resuming. The pending file is kept as the audit record.
            fail(`${result.message}\n(this is not a transient error — re-running will fail ` +
                `the same way; ${pendingPath} is kept for the record)`);
        }
        else {
            // Anything else may be a transient blip (mint unreachable, timeout).
            // Retry a bounded number of times; the pending file survives regardless.
            consecutiveFailures += 1;
            if (consecutiveFailures >= exports.MAX_CONSECUTIVE_FAILURES) {
                fail(`${result.message}\n(giving up after ${consecutiveFailures} consecutive ` +
                    `failures; ${pendingPath} is kept — re-run to resume)`);
            }
            io.stderr(`mint error (will retry): ${result.message}\n`);
        }
        await io.sleep(exports.POLL_INTERVAL_MS);
    }
}
async function main() {
    await runFundCard(parseArgs(process.argv.slice(2)));
}
/* istanbul ignore next -- entrypoint wiring, exercised only as a binary */
if (require.main === module) {
    main().catch(error => die(error instanceof Error ? error.message : String(error)));
}
