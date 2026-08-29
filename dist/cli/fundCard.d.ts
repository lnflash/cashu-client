#!/usr/bin/env node
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
import * as nodeFs from "fs";
export type Args = {
    mint: string;
    amount: number;
    cardPubkey: string;
    unit: string;
    out: string;
    maxSlots: number;
    requireDleq: boolean;
    force: boolean;
};
/** A fatal CLI condition: `runFundCard` throws it, `main` prints it and exits 1. */
export declare class FundCardCliError extends Error {
}
/** The filesystem surface the flow touches — injectable so tests can observe ordering. */
export type FundCardFs = Pick<typeof nodeFs, "existsSync" | "readFileSync" | "writeFileSync" | "renameSync" | "unlinkSync">;
export type FundCardIo = {
    fs: FundCardFs;
    stdout: (text: string) => void;
    stderr: (text: string) => void;
    sleep: (ms: number) => Promise<void>;
    now: () => number;
};
/** Poll interval while waiting for the invoice to be paid. */
export declare const POLL_INTERVAL_MS = 5000;
/**
 * Consecutive non-"not paid" failures tolerated while polling before dying.
 * A transient network blip on the quote-state GET must not kill an unattended
 * funding mid-wait; a persistent failure still surfaces after this many tries
 * (the pending file survives either way, so nothing is lost — only unattended).
 */
export declare const MAX_CONSECUTIVE_FAILURES = 3;
export declare function runFundCard(args: Args, io?: FundCardIo): Promise<void>;
