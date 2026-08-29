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
 */
const fs = __importStar(require("fs"));
const fundCard_1 = require("../fundCard");
const errors_1 = require("../errors");
const USAGE = `usage: fund-card --mint <url> --amount <n> --card-pubkey <hex>
                 [--unit sat] [--out <file>] [--max-slots 32]
                 [--require-dleq] [--force]

Writes a card file of P2PK-locked proofs for the card, ready for
\`cardctl load-file\`. Re-running with the same --out resumes an
interrupted funding from its .pending.json.`;
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
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
async function main() {
    const args = parseArgs(process.argv.slice(2));
    const pendingPath = args.out + ".pending.json";
    let pending;
    if (fs.existsSync(pendingPath)) {
        // A previous run got as far as persisting the quote. That state is the
        // only copy of the blinding data — resume from it, never re-quote.
        process.stderr.write(`resuming from ${pendingPath}\n`);
        pending = JSON.parse(fs.readFileSync(pendingPath, "utf-8"));
        if (pending.version !== 1)
            die(`${pendingPath}: unsupported pending version`);
        if (pending.cardPubkey !== args.cardPubkey) {
            die(`${pendingPath} is for card ${pending.cardPubkey}, not ${args.cardPubkey}.\n` +
                `Finish or remove it before funding a different card to the same --out.`);
        }
    }
    else {
        if (fs.existsSync(args.out) && !args.force) {
            die(`${args.out} already exists; pass --force to overwrite`);
        }
        const prepared = await (0, fundCard_1.prepareFunding)(args.mint, args.amount, args.unit, args.cardPubkey, { maxSlots: args.maxSlots });
        if (prepared instanceof errors_1.CashuMintError)
            die(prepared.message);
        pending = prepared;
        // Before the invoice is shown, atomically: write-then-rename so a crash
        // mid-write cannot leave a truncated pending file that resumes wrong.
        fs.writeFileSync(pendingPath + ".tmp", JSON.stringify(pending, null, 2));
        fs.renameSync(pendingPath + ".tmp", pendingPath);
        process.stdout.write(`\nPay this invoice (${args.amount} ${args.unit}):\n\n` +
            `${pending.paymentRequest}\n\n` +
            `Blinding state saved to ${pendingPath} — do not delete it until the\n` +
            `card file is written; after payment it is the only way to recover.\n\n`);
    }
    // Poll until paid. completeFunding checks the state itself, so the loop just
    // keeps trying it; a not-paid result is distinguishable by message.
    const deadline = pending.expiry * 1000;
    for (;;) {
        const result = await (0, fundCard_1.completeFunding)(pending, { requireDleq: args.requireDleq });
        if (!(result instanceof errors_1.CashuMintError)) {
            fs.writeFileSync(args.out, result.cardFile + "\n");
            fs.unlinkSync(pendingPath);
            process.stdout.write(`\nwrote ${args.out}: ${result.amounts.length} proof(s), ` +
                `${result.total} ${pending.unit} total` +
                (result.missingDleq > 0
                    ? `\nwarning: ${result.missingDleq} signature(s) carried no DLEQ ` +
                        `(the mint does not emit NUT-12)`
                    : "") +
                `\n\nnext: cardctl load-file ${args.out}\n`);
            return;
        }
        if (!/not PAID/.test(result.message))
            die(result.message);
        if (Date.now() > deadline) {
            die(`quote expired unpaid. ${pendingPath} is kept for the record; remove it ` +
                `to start over.`);
        }
        process.stderr.write("waiting for payment…\n");
        await sleep(5000);
    }
}
main().catch(error => die(error instanceof Error ? error.message : String(error)));
