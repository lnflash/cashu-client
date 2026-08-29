/**
 * fund-card CLI: the pending-file lifecycle, against a real tmp dir and a fake
 * mint. This is the money-safety path — persist-before-invoice, atomic
 * write-then-rename, resume-from-pending, write-card-then-unlink — so each of
 * those orderings gets a test that fails if someone reorders it.
 */
const mockAxios = jest.fn()
jest.mock("axios", () => ({
  ...jest.requireActual("axios"),
  post: (...args: unknown[]) => mockAxios("post", ...args),
  get: (...args: unknown[]) => mockAxios("get", ...args),
  isAxiosError: jest.fn(
    (err: unknown) => Boolean(err && typeof err === "object" && "isAxiosError" in err),
  ),
}))

import * as fs from "fs"
import * as os from "os"
import * as path from "path"

import {
  FundCardCliError,
  MAX_CONSECUTIVE_FAILURES,
  runFundCard,
  type Args,
  type FundCardIo,
} from "../src/cli/fundCard"
import { prepareFunding, type PendingFunding } from "../src/fundCard"
import { CashuMintError } from "../src/errors"
import { blindSignWithDLEQ, cardPubkey, makeMint, type TestMint } from "./helpers/nut12"

const MINT_URL = "https://forge.flashapp.me"
const KEYSET_ID = "0059534ce0bfa19a"
const CARD = cardPubkey()

/** Same fake mint as fundCard.spec.ts: real BDHKE, real NUT-12. */
function installMint({
  emitDleq = true,
  paid = true,
  perAmount = {} as Record<string, TestMint>,
} = {}) {
  const mints = perAmount
  const keyFor = (amount: number): TestMint =>
    (mints[String(amount)] ??= makeMint())

  mockAxios.mockImplementation((method: string, url: string, body?: unknown) => {
    if (method === "get" && url.endsWith("/v1/keysets")) {
      return Promise.resolve({
        data: {keysets: [{id: KEYSET_ID, unit: "sat", active: true}]},
      })
    }
    if (method === "post" && url.endsWith("/v1/mint/quote/bolt11")) {
      return Promise.resolve({
        data: {quote: "q-1", request: "lnbc1...", state: "UNPAID", expiry: 4102444800},
      })
    }
    if (method === "get" && url.includes("/v1/mint/quote/bolt11/")) {
      return Promise.resolve({
        data: {quote: "q-1", request: "lnbc1...", state: paid ? "PAID" : "UNPAID", expiry: 4102444800},
      })
    }
    if (method === "get" && url.includes("/v1/keys/")) {
      const keys: Record<string, string> = {}
      for (const amount of [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]) {
        keys[String(amount)] = keyFor(amount).AHex
      }
      return Promise.resolve({data: {keysets: [{id: KEYSET_ID, unit: "sat", keys}]}})
    }
    if (method === "post" && url.endsWith("/v1/mint/bolt11")) {
      const {outputs} = body as {outputs: Array<{id: string; amount: number; B_: string}>}
      return Promise.resolve({
        data: {
          signatures: outputs.map(o => {
            const {C_hex, dleq} = blindSignWithDLEQ(keyFor(o.amount), o.B_)
            return {id: o.id, amount: o.amount, C_: C_hex, ...(emitDleq ? {dleq} : {})}
          }),
        },
      })
    }
    return Promise.reject(new Error(`unmocked: ${method} ${url}`))
  })
  return mints
}

let dir: string
beforeEach(() => {
  mockAxios.mockReset()
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "fund-card-"))
})
afterEach(() => fs.rmSync(dir, {recursive: true, force: true}))

type Harness = {
  io: FundCardIo
  events: string[]
  stdout: string[]
  stderr: string[]
}

/** Real fs against the tmp dir, with every mutation logged so ordering is assertable. */
function makeHarness(): Harness {
  const events: string[] = []
  const stdout: string[] = []
  const stderr: string[] = []
  const io: FundCardIo = {
    fs: {
      existsSync: p => fs.existsSync(p),
      readFileSync: ((p: fs.PathOrFileDescriptor, o?: never) =>
        fs.readFileSync(p, o)) as typeof fs.readFileSync,
      writeFileSync: (p, data) => {
        events.push(`write:${String(p)}`)
        fs.writeFileSync(p, data as string)
      },
      renameSync: (from, to) => {
        events.push(`rename:${String(from)}→${String(to)}`)
        fs.renameSync(from, to)
      },
      unlinkSync: p => {
        events.push(`unlink:${String(p)}`)
        fs.unlinkSync(p)
      },
    },
    stdout: text => {
      events.push("stdout")
      stdout.push(text)
    },
    stderr: text => stderr.push(text),
    sleep: () => Promise.resolve(),
    now: () => Date.now(),
  }
  return {io, events, stdout, stderr}
}

const argsFor = (overrides: Partial<Args> = {}): Args => ({
  mint: MINT_URL,
  amount: 41,
  cardPubkey: CARD,
  unit: "sat",
  out: path.join(dir, "card.json"),
  maxSlots: 32,
  requireDleq: false,
  force: false,
  ...overrides,
})

const quotePosts = () =>
  mockAxios.mock.calls.filter(
    ([method, url]) => method === "post" && String(url).endsWith("/v1/mint/quote/bolt11"),
  )

describe("fund-card CLI lifecycle", () => {
  it("persists the pending file (via write-then-rename) before the invoice is printed", async () => {
    installMint()
    const h = makeHarness()
    const args = argsFor()
    const pendingPath = args.out + ".pending.json"

    let pendingExistedAtInvoice: boolean | undefined
    const stdoutFn = h.io.stdout
    h.io.stdout = text => {
      if (text.includes("Pay this invoice")) {
        pendingExistedAtInvoice = fs.existsSync(pendingPath)
      }
      stdoutFn(text)
    }

    await runFundCard(args, h.io)
    expect(pendingExistedAtInvoice).toBe(true)

    // Atomic persist: written to .tmp, then renamed into place — never a
    // direct write that could leave a truncated pending file.
    expect(h.events).toContain(`write:${pendingPath}.tmp`)
    expect(h.events).toContain(`rename:${pendingPath}.tmp→${pendingPath}`)
    expect(h.events.indexOf(`rename:${pendingPath}.tmp→${pendingPath}`))
      .toBeLessThan(h.events.indexOf("stdout"))
    expect(h.events).not.toContain(`write:${pendingPath}`)
  })

  it("writes the card file BEFORE unlinking the pending file", async () => {
    installMint()
    const h = makeHarness()
    const args = argsFor()
    await runFundCard(args, h.io)

    const pendingPath = args.out + ".pending.json"
    const writeIdx = h.events.indexOf(`write:${args.out}`)
    const unlinkIdx = h.events.indexOf(`unlink:${pendingPath}`)
    expect(writeIdx).toBeGreaterThanOrEqual(0)
    expect(unlinkIdx).toBeGreaterThanOrEqual(0)
    expect(writeIdx).toBeLessThan(unlinkIdx)

    expect(fs.existsSync(args.out)).toBe(true)
    expect(fs.existsSync(pendingPath)).toBe(false)
  })

  it("resumes from an existing pending file without re-quoting, announcing what it resumes", async () => {
    installMint()
    const args = argsFor()
    const pending = await prepareFunding(MINT_URL, 41, "sat", CARD)
    if (pending instanceof CashuMintError) throw pending
    fs.writeFileSync(args.out + ".pending.json", JSON.stringify(pending))
    mockAxios.mockClear()
    installMint()

    const h = makeHarness()
    await runFundCard(args, h.io)

    // The resume path must never request a new quote — the persisted blinding
    // data is the only thing that can redeem the already-shown invoice.
    expect(quotePosts()).toHaveLength(0)
    expect(fs.existsSync(args.out)).toBe(true)
    // The operator sees what is actually being resumed.
    expect(h.stderr.join("")).toMatch(/resuming .*41 sat at https:\/\/forge\.flashapp\.me/)
  })

  it("dies on resume when the pending file is for a different card pubkey", async () => {
    installMint()
    const args = argsFor()
    const pending = await prepareFunding(MINT_URL, 41, "sat", cardPubkey())
    if (pending instanceof CashuMintError) throw pending
    fs.writeFileSync(args.out + ".pending.json", JSON.stringify(pending))

    const h = makeHarness()
    await expect(runFundCard(args, h.io)).rejects.toThrow(/is for card/)
    // The pending file must survive — it is still the only recovery artifact.
    expect(fs.existsSync(args.out + ".pending.json")).toBe(true)
  })

  it("dies on resume when --mint or --unit disagree with the pending file", async () => {
    installMint()
    const args = argsFor()
    const pending = await prepareFunding(MINT_URL, 41, "sat", CARD)
    if (pending instanceof CashuMintError) throw pending
    fs.writeFileSync(args.out + ".pending.json", JSON.stringify(pending))

    await expect(
      runFundCard(argsFor({mint: "https://other.mint.example"}), makeHarness().io),
    ).rejects.toThrow(FundCardCliError)
    await expect(
      runFundCard(argsFor({unit: "usd"}), makeHarness().io),
    ).rejects.toThrow(/in sat, not usd/)
    // No new quote was requested by either refused resume.
    expect(fs.existsSync(args.out + ".pending.json")).toBe(true)
  })

  it("keeps polling through a transient mint error instead of dying mid-wait", async () => {
    installMint()
    const h = makeHarness()
    const args = argsFor()

    // First quote-state GET after the invoice blips; the next succeeds.
    let blipped = false
    const base = mockAxios.getMockImplementation()!
    mockAxios.mockImplementation((method: string, url: string, body?: unknown) => {
      if (!blipped && method === "get" && String(url).includes("/v1/mint/quote/bolt11/")) {
        blipped = true
        return Promise.reject(Object.assign(new Error("socket hang up"), {isAxiosError: true}))
      }
      return base(method, url, body)
    })

    await runFundCard(args, h.io)
    expect(h.stderr.join("")).toMatch(/mint error \(will retry\)/)
    expect(fs.existsSync(args.out)).toBe(true)
  })

  it("gives up after bounded consecutive failures, keeping the pending file", async () => {
    installMint()
    const h = makeHarness()
    const args = argsFor()

    let prepared = false
    const base = mockAxios.getMockImplementation()!
    mockAxios.mockImplementation((method: string, url: string, body?: unknown) => {
      if (prepared && method === "get" && String(url).includes("/v1/mint/quote/bolt11/")) {
        return Promise.reject(Object.assign(new Error("mint down"), {isAxiosError: true}))
      }
      if (method === "post" && String(url).endsWith("/v1/mint/quote/bolt11")) prepared = true
      return base(method, url, body)
    })

    await expect(runFundCard(args, h.io)).rejects.toThrow(/giving up after/)
    const retries = h.stderr.join("").match(/mint error \(will retry\)/g) ?? []
    expect(retries).toHaveLength(MAX_CONSECUTIVE_FAILURES - 1)
    expect(fs.existsSync(args.out + ".pending.json")).toBe(true)
  })

  it("fails immediately on a deterministic verification refusal instead of retrying", async () => {
    // A mint that emits no DLEQ while --require-dleq is set is a deterministic
    // refusal: re-minting cannot change the outcome, so the CLI must die on
    // the first attempt with no retry and no "re-run to resume" advice.
    installMint({emitDleq: false})
    const h = makeHarness()
    const args = argsFor({requireDleq: true})

    await expect(runFundCard(args, h.io)).rejects.toThrow(/not a transient error/)
    expect(h.stderr.join("")).not.toMatch(/mint error \(will retry\)/)
    const mintPosts = mockAxios.mock.calls.filter(
      ([method, url]) => method === "post" && String(url).endsWith("/v1/mint/bolt11"),
    )
    expect(mintPosts).toHaveLength(1) // one attempt, never re-minted
    expect(fs.existsSync(args.out + ".pending.json")).toBe(true)
    expect(fs.existsSync(args.out)).toBe(false)
  })

  it("refuses to overwrite an existing card file without --force", async () => {
    installMint()
    const args = argsFor()
    fs.writeFileSync(args.out, "{}")
    await expect(runFundCard(args, makeHarness().io)).rejects.toThrow(/--force/)
    expect(quotePosts()).toHaveLength(0)
  })

  it("dies when the quote expires unpaid, keeping the pending file", async () => {
    installMint({paid: false})
    const h = makeHarness()
    h.io.now = () => 4102444801 * 1000 // past the fake quote's expiry
    const args = argsFor()
    await expect(runFundCard(args, h.io)).rejects.toThrow(/expired unpaid/)
    expect(fs.existsSync(args.out + ".pending.json")).toBe(true)
  })
})

describe("resume round trip", () => {
  it("a JSON-round-tripped pending file resumes to the same card file", async () => {
    installMint({paid: false})
    const h = makeHarness()
    const args = argsFor()
    const pendingPath = args.out + ".pending.json"

    // First run: quote persisted, invoice shown, quote never paid → expire it
    // artificially by flipping now() after the first poll.
    let polls = 0
    h.io.sleep = () => {
      polls += 1
      if (polls >= 1) h.io.now = () => 4102444801 * 1000
      return Promise.resolve()
    }
    await expect(runFundCard(args, h.io)).rejects.toThrow(/expired unpaid/)
    const persisted = JSON.parse(fs.readFileSync(pendingPath, "utf-8")) as PendingFunding
    expect(persisted.quoteId).toBe("q-1")

    // Second run against a paid mint resumes and finishes.
    installMint({paid: true})
    await runFundCard(args, makeHarness().io)
    expect(fs.existsSync(args.out)).toBe(true)
    expect(fs.existsSync(pendingPath)).toBe(false)
  })
})
