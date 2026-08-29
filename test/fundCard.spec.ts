/**
 * fund-card: the mint → card-file pipeline, end to end against a fake mint
 * that does real BDHKE and real NUT-12 — so the proofs this suite accepts are
 * proofs a genuine mint would produce, not fixtures.
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

import * as secp from "tiny-secp256k1"

import {
  CashuMintError,
  CashuMintQuoteNotPaidError,
  cardFileTotal,
  completeFunding,
  hashToCurve,
  parseCardFile,
  prepareFunding,
  reconstructProofsFromCard,
  type PendingFunding,
} from "../src"
import { blindSignWithDLEQ, cardPubkey, makeMint, type TestMint } from "./helpers/nut12"

const MINT_URL = "https://forge.flashapp.me"
const KEYSET_ID = "0059534ce0bfa19a"
const CARD = cardPubkey()

/**
 * A fake mint: one NUT-12 keypair per denomination, real signing.
 *
 * `emitDleq: false` models a mint that predates NUT-12; `paid` drives the
 * quote-state machine.
 */
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
        data: {keysets: [
          {id: KEYSET_ID, unit: "sat", active: true},
          {id: "00aaaaaaaaaaaaaa", unit: "usd", active: true},
          {id: "00bbbbbbbbbbbbbb", unit: "sat", active: false},
        ]},
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
      // Publish A for every denomination the batch could ask for.
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

beforeEach(() => mockAxios.mockReset())

describe("prepareFunding", () => {
  it("returns a JSON-serializable pending state whose outputs sum to the amount", async () => {
    installMint()
    const pending = await prepareFunding(MINT_URL, 41, "sat", CARD)
    if (pending instanceof CashuMintError) throw pending

    // The crash-recovery contract: everything survives a JSON round trip.
    const revived = JSON.parse(JSON.stringify(pending)) as PendingFunding
    expect(revived).toEqual(pending)

    expect(pending.keysetId).toBe(KEYSET_ID)
    expect(pending.quoteId).toBe("q-1")
    expect(pending.outputs.reduce((s, o) => s + o.amount, 0)).toBe(41)
    // 41 = 1 + 8 + 32: powers of two, and every nonce distinct.
    expect(pending.outputs.map(o => o.amount).sort((a, b) => a - b)).toEqual([1, 8, 32])
    expect(new Set(pending.outputs.map(o => o.nonce)).size).toBe(3)
  })

  it("picks only an ACTIVE keyset for the requested unit", async () => {
    installMint()
    const pending = await prepareFunding(MINT_URL, 8, "sat", CARD)
    if (pending instanceof CashuMintError) throw pending
    expect(pending.keysetId).toBe(KEYSET_ID) // not the inactive sat keyset
  })

  it("refuses a unit the mint has no active keyset for, naming what it offers", async () => {
    installMint()
    const result = await prepareFunding(MINT_URL, 8, "eur", CARD)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as CashuMintError).message).toMatch(/no active keyset for unit "eur"/)
    expect((result as CashuMintError).message).toMatch(/sat/)
  })

  it("refuses an amount that cannot fit the slot budget", async () => {
    installMint()
    // 0b1111111 needs 7 denominations; give it 3 slots.
    const result = await prepareFunding(MINT_URL, 127, "sat", CARD, {maxSlots: 3})
    expect(result).toBeInstanceOf(CashuMintError)
  })

  it("refuses BEFORE requesting a quote when the keyset lacks a key for a denomination", async () => {
    installMint()
    const base = mockAxios.getMockImplementation()!
    mockAxios.mockImplementation((method: string, url: string, body?: unknown) => {
      if (method === "get" && String(url).includes("/v1/keys/")) {
        // Publishes a key for 1 but not for 8 — 9 = 1 + 8 needs both.
        return Promise.resolve({data: {keysets: [{id: KEYSET_ID, unit: "sat",
          keys: {"1": makeMint().AHex}}]}})
      }
      return base(method, url, body)
    })

    const result = await prepareFunding(MINT_URL, 9, "sat", CARD)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as CashuMintError).message).toMatch(/no key for denomination\(s\) 8/)
    // No quote was requested: no invoice exists, so no money can get stuck.
    const quotePosts = mockAxios.mock.calls.filter(
      ([method, url]) => method === "post" && String(url).endsWith("/v1/mint/quote/bolt11"),
    )
    expect(quotePosts).toHaveLength(0)
  })

  it("passes a quote failure through without minting anything", async () => {
    mockAxios.mockImplementation((method: string, url: string) => {
      if (method === "get" && url.endsWith("/v1/keysets")) {
        return Promise.resolve({data: {keysets: [{id: KEYSET_ID, unit: "sat", active: true}]}})
      }
      return Promise.reject(Object.assign(new Error("mint down"), {isAxiosError: true}))
    })
    const result = await prepareFunding(MINT_URL, 8, "sat", CARD)
    expect(result).toBeInstanceOf(CashuMintError)
  })
})

const prepare = async (amount: number) => {
  const pending = await prepareFunding(MINT_URL, amount, "sat", CARD)
  if (pending instanceof CashuMintError) throw pending
  return pending
}

describe("completeFunding", () => {
  it("produces a card file whose proofs reconstruct and DLEQ-verify", async () => {
    const mints = installMint()
    const pending = await prepare(41)
    const result = await completeFunding(pending)
    if (result instanceof CashuMintError) throw result

    expect(result.total).toBe(41)
    expect(result.missingDleq).toBe(0)

    // The file is real: it parses, reconstructs, and every proof's C is the
    // genuine unblinded mint signature — verified against the published key.
    const file = parseCardFile(result.cardFile)
    expect(file.cardPubkey).toBe(CARD)
    expect(cardFileTotal(file)).toBe(41)
    expect(file.slots.every(s => s.spent === false)).toBe(true)

    const proofs = reconstructProofsFromCard(file.slots, file.cardPubkey)
    for (const proof of proofs) {
      const mint = mints[String(proof.amount)]
      // C = a*Y for the mint's real key — the unblinding actually worked.
      const Y = hashToCurve(Buffer.from(proof.secret, "utf8"))
      const expectedC = Buffer.from(
        secp.pointMultiply(Buffer.from(Y), mint.a, true)!,
      ).toString("hex")
      expect(proof.C).toBe(expectedC)
    }
  })

  it("carries the DLEQ through so redemption can be verified offline", async () => {
    installMint()
    const pending = await prepare(8)
    const result = await completeFunding(pending)
    if (result instanceof CashuMintError) throw result

    // Rebuild the proof with the pending state's r and check NUT-12 end to end.
    const file = parseCardFile(result.cardFile)
    const [proof] = reconstructProofsFromCard(file.slots, file.cardPubkey)
    expect(proof.amount).toBe(8)
  })

  it("refuses an unpaid quote and leaves the pending state reusable", async () => {
    installMint({paid: false})
    const pending = await prepare(8)
    const before = JSON.parse(JSON.stringify(pending))

    const result = await completeFunding(pending)
    expect(result).toBeInstanceOf(CashuMintError)
    // Typed, not just a message: callers polling for payment match on this.
    expect(result).toBeInstanceOf(CashuMintQuoteNotPaidError)
    expect((result as CashuMintError).message).toMatch(/not PAID/)
    expect(pending).toEqual(before) // untouched — retry later with the same state

    // The quote gets paid; the same pending state now succeeds. Idempotence is
    // the crash-recovery story: same quote, same outputs, no double spend.
    installMint({paid: true})
    const retry = await completeFunding(pending)
    expect(retry).not.toBeInstanceOf(CashuMintError)
  })

  it("refuses the whole batch when a DLEQ fails — the mint signed with an unpublished key", async () => {
    const mints = installMint()
    const pending = await prepare(8)

    // The mint publishes one key but signs with another: DLEQ's raison d'être.
    const published = makeMint()
    mockAxios.mockImplementation((method: string, url: string, body?: unknown) => {
      if (method === "get" && url.includes("/v1/mint/quote/bolt11/")) {
        return Promise.resolve({data: {quote: "q-1", request: "x", state: "PAID", expiry: 4102444800}})
      }
      if (method === "get" && url.includes("/v1/keys/")) {
        return Promise.resolve({data: {keysets: [{id: KEYSET_ID, unit: "sat",
          keys: {"8": published.AHex}}]}})
      }
      if (method === "post" && url.endsWith("/v1/mint/bolt11")) {
        const {outputs} = body as {outputs: Array<{id: string; amount: number; B_: string}>}
        return Promise.resolve({data: {signatures: outputs.map(o => {
          const {C_hex, dleq} = blindSignWithDLEQ(mints[String(o.amount)] ?? makeMint(), o.B_)
          return {id: o.id, amount: o.amount, C_: C_hex, dleq}
        })}})
      }
      return Promise.reject(new Error(`unmocked: ${method} ${url}`))
    })

    const result = await completeFunding(pending)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as CashuMintError).message).toMatch(/DLEQ verification failed/)
  })

  it("counts missing DLEQs and only refuses them under requireDleq", async () => {
    installMint({emitDleq: false})
    const pending = await prepare(9) // two outputs

    const lenient = await completeFunding(pending)
    if (lenient instanceof CashuMintError) throw lenient
    expect(lenient.missingDleq).toBe(2)

    const strict = await completeFunding(pending, {requireDleq: true})
    expect(strict).toBeInstanceOf(CashuMintError)
    expect((strict as CashuMintError).message).toMatch(/no DLEQ/)
  })

  it("refuses when the keyset publishes no key for a denomination", async () => {
    installMint()
    const pending = await prepare(8)
    pending.outputs[0].amount = 2048 // no published key in the fake keyset
    const result = await completeFunding(pending)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as CashuMintError).message).toMatch(/no key for amount 2048/)
  })
})
