/**
 * Tests for NUT-03 swapping: the balance check, the signature/output binding,
 * and DLEQ carry-through.
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

import { CashuMintError, swapProofs } from "../src"
import type { CashuBlindSignature, CashuBlindedMessage, CashuProof } from "../src"

const MINT = "https://mint.example.com"
const KS = "0059534ce0bfa19a"
const C_ = "02" + "11".repeat(32)
const SCALAR = "ab".repeat(32)

const proof = (amount: number): CashuProof => ({
  id: KS,
  amount,
  secret: `plain-${amount}-${crypto.randomBytes(4).toString("hex")}`,
  C: "02" + "22".repeat(32),
})

const output = (amount: number): CashuBlindedMessage => ({
  id: KS,
  amount,
  B_: "03" + crypto.randomBytes(32).toString("hex"),
})

const sigsFor = (outputs: CashuBlindedMessage[]) =>
  outputs.map(o => ({id: o.id, amount: o.amount, C_}))

beforeEach(() => mockAxios.mockReset())

describe("swap balance", () => {
  it("rejects outputs exceeding inputs", async () => {
    const result = await swapProofs(MINT, [proof(8)], [output(16)])
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/exceed/)
    expect(mockAxios).not.toHaveBeenCalled()
  })

  it("rejects outputs short of inputs instead of donating the difference", async () => {
    // The mint accepts a short output set happily and keeps the remainder, with
    // no signal to the caller — an off-by-one in a denomination split would
    // otherwise burn value silently.
    const result = await swapProofs(MINT, [proof(8), proof(4)], [output(8), output(2)])
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/short of inputs .* by 2/)
    expect(mockAxios).not.toHaveBeenCalled()
  })

  it("accepts an exact balance", async () => {
    const outputs = [output(8), output(4)]
    mockAxios.mockResolvedValueOnce({data: {signatures: sigsFor(outputs)}})

    const result = await swapProofs(MINT, [proof(8), proof(4)], outputs)
    expect(result).not.toBeInstanceOf(Error)
    expect(result).toHaveLength(2)
  })

  it("expects outputs to be short by exactly the NUT-02 input fee", async () => {
    const inputs = [proof(8), proof(4)]
    // 2 inputs at 1000 ppk = 2 sats of fee, so 12 in means 10 out.
    expect(await swapProofs(MINT, inputs, [output(12)], 1000)).toBeInstanceOf(
      CashuMintError,
    )

    const outputs = [output(8), output(2)]
    mockAxios.mockResolvedValueOnce({data: {signatures: sigsFor(outputs)}})
    expect(await swapProofs(MINT, inputs, outputs, 1000)).toHaveLength(2)
  })

  it("rejects empty input or output sets", async () => {
    expect(await swapProofs(MINT, [], [output(1)])).toBeInstanceOf(CashuMintError)
    expect(await swapProofs(MINT, [proof(1)], [])).toBeInstanceOf(CashuMintError)
  })
})

describe("swap signature binding", () => {
  it("rejects a reordered signature array", async () => {
    const outputs = [output(8), output(4)]
    mockAxios.mockResolvedValueOnce({data: {signatures: sigsFor(outputs).reverse()}})

    const result = await swapProofs(MINT, [proof(8), proof(4)], outputs)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/amount mismatch/)
  })

  it("rejects a relabelled keyset id", async () => {
    const outputs = [output(8)]
    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: "deadbeefdeadbeef", amount: 8, C_}]},
    })

    const result = await swapProofs(MINT, [proof(8)], outputs)
    expect((result as Error).message).toMatch(/keyset ID mismatch/)
  })

  it("rejects a wrong signature count", async () => {
    const outputs = [output(8), output(4)]
    mockAxios.mockResolvedValueOnce({data: {signatures: [sigsFor(outputs)[0]]}})

    const result = await swapProofs(MINT, [proof(8), proof(4)], outputs)
    expect((result as Error).message).toMatch(/1 signatures for 2 outputs/)
  })

  it("rejects a missing signatures array", async () => {
    const outputs = [output(8)]
    mockAxios.mockResolvedValueOnce({data: {}})
    expect(await swapProofs(MINT, [proof(8)], outputs)).toBeInstanceOf(CashuMintError)
  })

  it("rejects a malformed C_", async () => {
    const outputs = [output(8)]
    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount: 8, C_: "04" + "11".repeat(32)}]},
    })
    expect((await swapProofs(MINT, [proof(8)], outputs) as Error).message).toMatch(
      /malformed C_/,
    )
  })
})

describe("swap DLEQ", () => {
  it("carries a well-formed DLEQ through", async () => {
    const outputs = [output(8)]
    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount: 8, C_, dleq: {e: SCALAR, s: SCALAR}}]},
    })

    const result = (await swapProofs(MINT, [proof(8)], outputs)) as CashuBlindSignature[]
    expect(result[0].dleq).toEqual({e: SCALAR, s: SCALAR})
  })

  it("rejects a present-but-malformed DLEQ rather than dropping it", async () => {
    // Dropping it makes a misbehaving mint indistinguishable from one that
    // emits no DLEQ — i.e. it lets a hostile mint opt out of verification.
    const outputs = [output(8)]
    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount: 8, C_, dleq: {e: "short", s: SCALAR}}]},
    })

    const result = await swapProofs(MINT, [proof(8)], outputs)
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/malformed DLEQ/)
  })

  it("accepts an absent DLEQ", async () => {
    const outputs = [output(8)]
    mockAxios.mockResolvedValueOnce({data: {signatures: sigsFor(outputs)}})

    const result = (await swapProofs(MINT, [proof(8)], outputs)) as CashuBlindSignature[]
    expect(result[0].dleq).toBeUndefined()
  })
})
