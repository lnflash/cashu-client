/**
 * Tests for NUT-05 melting — the money-relevant path. Uses the mocked-axios
 * harness so no request leaves the process.
 */

const mockAxios = jest.fn()
jest.mock("axios", () => ({
  ...jest.requireActual("axios"),
  post: (...args: unknown[]) => mockAxios("post", ...args),
  get: (...args: unknown[]) => mockAxios("get", ...args),
  isAxiosError: jest.fn(
    (err: unknown) => err && typeof err === "object" && "isAxiosError" in err,
  ),
}))

import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  attachP2PKWitness,
  buildP2PKSecret,
  CashuMeltResponseError,
  CashuMintError,
  getMeltQuoteState,
  inputFee,
  meltAmountRequired,
  meltProofs,
  p2pkMessageToSign,
  requestMeltQuote,
  selectProofsForMelt,
  sumProofs,
} from "../src"
import type { CashuMeltQuote, CashuProof } from "../src"

const MINT = "https://mint.example.com"
const C_ = "02" + "11".repeat(32)
const SCALAR = "ab".repeat(32)

const plainProof = (amount: number): CashuProof => ({
  id: "0059534ce0bfa19a",
  amount,
  secret: `plain-secret-${amount}-${crypto.randomBytes(4).toString("hex")}`,
  C: "02" + "22".repeat(32),
})

const quote = (amount: number, feeReserve: number): CashuMeltQuote => ({
  quoteId: "q",
  amount,
  feeReserve,
  state: "UNPAID",
  expiry: 0,
})

beforeEach(() => mockAxios.mockReset())

describe("melt quote parsing", () => {
  it("normalises a legacy `paid: true` quote with no state field to PAID", () => {
    mockAxios.mockResolvedValueOnce({
      data: {quote: "q1", amount: 100, fee_reserve: 2, paid: true, expiry: 999},
    })

    return requestMeltQuote(MINT, "lnbc1...", "sat").then(result => {
      expect(result).not.toBeInstanceOf(Error)
      expect(result).toMatchObject({quoteId: "q1", state: "PAID", amount: 100, feeReserve: 2})
    })
  })

  it("normalises a legacy `paid: false` quote to UNPAID", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {quote: "q1", amount: 100, fee_reserve: 2, paid: false},
    })
    const result = await requestMeltQuote(MINT, "lnbc1...", "sat")
    expect(result).toMatchObject({state: "UNPAID"})
  })

  it("prefers an explicit state over the legacy paid flag", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {quote: "q1", amount: 100, fee_reserve: 2, state: "PENDING", paid: false},
    })
    const result = await requestMeltQuote(MINT, "lnbc1...", "sat")
    expect(result).toMatchObject({state: "PENDING"})
  })

  it("rejects an unknown state", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {quote: "q1", amount: 100, fee_reserve: 2, state: "SETTLED_MAYBE"},
    })
    const result = await requestMeltQuote(MINT, "lnbc1...", "sat")
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/unknown state/)
  })

  it("requires amount and fee_reserve on the quote endpoint", async () => {
    // The caller cannot select proofs without these, so a quote lacking them
    // is an error rather than a zero-valued quote.
    mockAxios.mockResolvedValueOnce({data: {quote: "q1", state: "UNPAID"}})
    const result = await requestMeltQuote(MINT, "lnbc1...", "sat")
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/amount/)
  })

  it("rejects a present-but-malformed amount on the quote endpoint", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {quote: "q1", amount: 1.5, fee_reserve: 0, state: "UNPAID"},
    })
    expect(await getMeltQuoteState(MINT, "q1")).toBeInstanceOf(CashuMintError)
  })

  it("surfaces the mint's detail body rather than the axios status text", async () => {
    mockAxios.mockRejectedValueOnce({
      isAxiosError: true,
      message: "Request failed with status code 400",
      response: {data: {detail: "quote already paid"}},
    })
    const result = await requestMeltQuote(MINT, "lnbc1...", "sat")
    expect((result as Error).message).toContain("quote already paid")
  })

  it("rejects a path-unsafe quote id without making a request", async () => {
    const result = await getMeltQuoteState(MINT, "../../admin")
    expect(result).toBeInstanceOf(CashuMintError)
    expect(mockAxios).not.toHaveBeenCalled()
  })
})

describe("meltProofs", () => {
  it("refuses an unsigned P2PK input without issuing a request", async () => {
    const card = crypto.randomBytes(32)
    const pub = Buffer.from(secp.pointFromScalar(card, true)!).toString("hex")
    const locked: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: buildP2PKSecret("aa".repeat(32), pub),
      C: "02" + "22".repeat(32),
    }

    const result = await meltProofs(MINT, "q1", [locked])
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/missing or invalid witness/)
    // The important half: nothing was submitted, so the proof is still intact.
    expect(mockAxios).not.toHaveBeenCalled()
  })

  it("submits a correctly witnessed P2PK input", async () => {
    const d = (() => {
      let k: Buffer
      do {
        k = crypto.randomBytes(32)
      } while (!secp.isPrivate(k))
      return k
    })()
    const pub = Buffer.from(secp.pointFromScalar(d, true)!).toString("hex")
    const base: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: buildP2PKSecret("aa".repeat(32), pub),
      C: "02" + "22".repeat(32),
    }
    const sig = Buffer.from(secp.signSchnorr(p2pkMessageToSign(base), d)).toString("hex")
    const signed = attachP2PKWitness(base, [sig])

    mockAxios.mockResolvedValueOnce({data: {state: "PAID", payment_preimage: "deadbeef"}})
    const result = await meltProofs(MINT, "q1", [signed])

    expect(result).not.toBeInstanceOf(Error)
    expect(result).toMatchObject({state: "PAID", paymentPreimage: "deadbeef"})
    const body = mockAxios.mock.calls[0][2] as {inputs: Array<{witness?: string}>}
    expect(body.inputs[0].witness).toBe(signed.witness)
  })

  it("accepts a legacy execute response carrying only {paid, change}", async () => {
    // Legacy mints answer POST /v1/melt/bolt11 without amount/fee_reserve.
    // Reporting a settled invoice as an error is the worst possible outcome.
    mockAxios.mockResolvedValueOnce({
      data: {paid: true, change: [{id: "ks", amount: 2, C_}]},
    })
    const result = await meltProofs(MINT, "q1", [plainProof(8)])

    expect(result).not.toBeInstanceOf(Error)
    expect(result).toMatchObject({quoteId: "q1", state: "PAID"})
    expect((result as CashuMeltQuote).change).toHaveLength(1)
  })

  it("carries DLEQ through on change signatures", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {state: "PAID", change: [{id: "ks", amount: 2, C_, dleq: {e: SCALAR, s: SCALAR}}]},
    })
    const result = await meltProofs(MINT, "q1", [plainProof(8)])
    expect((result as CashuMeltQuote).change![0].dleq).toEqual({e: SCALAR, s: SCALAR})
  })

  it("rejects a present-but-malformed DLEQ on change rather than dropping it", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {state: "PAID", change: [{id: "ks", amount: 2, C_, dleq: {e: "nope", s: SCALAR}}]},
    })
    const result = (await meltProofs(MINT, "q1", [plainProof(8)])) as CashuMeltQuote
    expect(result.change).toHaveLength(0)
    expect(result.changeErrors!.join()).toMatch(/malformed DLEQ/)
  })

  it("keeps the valid change when one entry is malformed", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {
        state: "PAID",
        change: [
          {id: "ks", amount: 2, C_},
          {id: "ks", amount: 1, C_: "not-a-point"},
          {id: "ks", amount: 4, C_},
        ],
      },
    })
    const result = (await meltProofs(MINT, "q1", [plainProof(8)])) as CashuMeltQuote

    expect(result).not.toBeInstanceOf(Error)
    // The inputs are gone and these signatures cannot be re-fetched: aborting on
    // entry 1 would destroy the 2 and the 4 as well.
    expect(result.change!.map(c => c.amount)).toEqual([2, 4])
    expect(result.changeErrors).toHaveLength(1)
  })

  it("still returns the change when the quote portion is unparseable", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {state: "NONSENSE", change: [{id: "ks", amount: 2, C_}]},
    })
    const result = await meltProofs(MINT, "q1", [plainProof(8)])

    expect(result).toBeInstanceOf(CashuMeltResponseError)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as CashuMeltResponseError).change.map(c => c.amount)).toEqual([2])
  })

  it("rejects an empty proof set and a bad quote id before submitting", async () => {
    expect(await meltProofs(MINT, "q1", [])).toBeInstanceOf(CashuMintError)
    expect(await meltProofs(MINT, "../x", [plainProof(1)])).toBeInstanceOf(CashuMintError)
    expect(mockAxios).not.toHaveBeenCalled()
  })
})

describe("input fees", () => {
  it("is ceil(nInputs * ppk / 1000)", () => {
    expect(inputFee(3, 0)).toBe(0)
    expect(inputFee(1, 100)).toBe(1)
    expect(inputFee(10, 100)).toBe(1)
    expect(inputFee(11, 100)).toBe(2)
  })

  it("is added to the melt requirement", () => {
    expect(meltAmountRequired(quote(100, 7))).toBe(107)
    expect(meltAmountRequired(quote(100, 7), 3, 1000)).toBe(110)
  })

  it("makes the selection cover the fee too", () => {
    // 8 one-sat proofs, invoice 4, half a sat of fee per input. Selecting 4
    // proofs covers the invoice but not the 2 sats of fee they owe; a
    // fee-blind selection stops there and the mint rejects the melt.
    const proofs = [1, 1, 1, 1, 1, 1, 1, 1].map(plainProof)
    expect(selectProofsForMelt(proofs, quote(4, 0), 0)).toHaveLength(4)

    const chosen = selectProofsForMelt(proofs, quote(4, 0), 500)
    expect(chosen).not.toBeNull()
    expect(chosen!.length).toBeGreaterThan(4)
    expect(sumProofs(chosen!)).toBeGreaterThanOrEqual(4 + inputFee(chosen!.length, 500))
  })

  it("returns null when the fee pushes the requirement out of reach", () => {
    const proofs = [1, 1, 1, 1].map(plainProof)
    expect(selectProofsForMelt(proofs, quote(4, 0), 1000)).toBeNull()
  })
})

describe("selectProofsForMelt overpay", () => {
  it("does not melt 64 to pay 4 when [4, 1] covers it exactly", () => {
    const proofs = [64, 4, 1].map(plainProof)
    const chosen = selectProofsForMelt(proofs, quote(4, 1))!

    expect(chosen).not.toBeNull()
    // Largest-first would pick the 64 alone and hand the mint 60 sats, because
    // change outputs are optional and a slot-constrained terminal may omit them.
    expect(sumProofs(chosen)).toBe(5)
    expect(chosen.map(p => p.amount).sort()).toEqual([1, 4])
  })

  it("still covers the requirement when no exact combination exists", () => {
    const proofs = [64, 8].map(plainProof)
    const chosen = selectProofsForMelt(proofs, quote(4, 1))!
    expect(sumProofs(chosen)).toBe(8)
  })

  it("prefers fewer proofs on an exact tie", () => {
    const proofs = [8, 4, 4].map(plainProof)
    const chosen = selectProofsForMelt(proofs, quote(8, 0))!
    expect(sumProofs(chosen)).toBe(8)
    expect(chosen).toHaveLength(1)
  })

  it("keeps the documented largest-first behaviour when it is also cheapest", () => {
    const proofs = [1, 2, 4, 8, 64].map(plainProof)
    const chosen = selectProofsForMelt(proofs, quote(60, 5))!
    expect(sumProofs(chosen)).toBe(65)
    expect(chosen[0].amount).toBe(64)
  })

  it("returns null rather than a short selection", () => {
    expect(selectProofsForMelt([1, 2].map(plainProof), quote(3, 1))).toBeNull()
    expect(selectProofsForMelt([], quote(1, 0))).toBeNull()
  })
})
