/**
 * Tests for NUT-07 proof state — the double-spend check. The important
 * property here is that it fails *closed*: a mint error must never read as
 * "safe to accept".
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

import { allProofsUnspent, CashuMintError, checkProofStates, proofIdentifier } from "../src"
import type { CashuProof, CashuProofState } from "../src"

const MINT = "https://mint.example.com"

const proof = (secret: string): CashuProof => ({
  id: "0059534ce0bfa19a",
  amount: 8,
  secret,
  C: "02" + "22".repeat(32),
})

const stateFor = (p: CashuProof, state: CashuProofState["state"]) => ({
  Y: proofIdentifier(p),
  state,
})

beforeEach(() => mockAxios.mockReset())

describe("checkProofStates", () => {
  it("returns states in the caller's order, re-paired by Y", async () => {
    const a = proof("secret-a")
    const b = proof("secret-b")
    // Answered out of order — must be re-paired by Y, not by position.
    mockAxios.mockResolvedValueOnce({
      data: {states: [stateFor(b, "SPENT"), stateFor(a, "UNSPENT")]},
    })

    const result = (await checkProofStates(MINT, [a, b])) as CashuProofState[]
    expect(result.map(s => s.state)).toEqual(["UNSPENT", "SPENT"])
  })

  it("rejects a response missing one Y", async () => {
    const a = proof("secret-a")
    const b = proof("secret-b")
    const c = proof("secret-c")
    // Right count, wrong question: c's state answered instead of b's.
    mockAxios.mockResolvedValueOnce({
      data: {states: [stateFor(a, "UNSPENT"), stateFor(c, "UNSPENT")]},
    })

    const result = await checkProofStates(MINT, [a, b])
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/did not return a state for proof 1/)
  })

  it("rejects a wrong number of states", async () => {
    const a = proof("secret-a")
    const b = proof("secret-b")
    mockAxios.mockResolvedValueOnce({data: {states: [stateFor(a, "UNSPENT")]}})

    const result = await checkProofStates(MINT, [a, b])
    expect((result as Error).message).toMatch(/1 states for 2 proofs/)
  })

  it("rejects a malformed Y and an unknown state", async () => {
    const a = proof("secret-a")
    mockAxios.mockResolvedValueOnce({data: {states: [{Y: "nope", state: "UNSPENT"}]}})
    expect((await checkProofStates(MINT, [a]) as Error).message).toMatch(/malformed Y/)

    mockAxios.mockResolvedValueOnce({
      data: {states: [{...stateFor(a, "UNSPENT"), state: "PROBABLY_FINE"}]},
    })
    expect((await checkProofStates(MINT, [a]) as Error).message).toMatch(/unknown state/)
  })

  it("rejects a missing states array and an empty proof set", async () => {
    mockAxios.mockResolvedValueOnce({data: {}})
    expect(await checkProofStates(MINT, [proof("s")])).toBeInstanceOf(CashuMintError)

    expect(await checkProofStates(MINT, [])).toBeInstanceOf(CashuMintError)
  })
})

describe("allProofsUnspent fails closed", () => {
  it("returns UNSPENT only when every proof is unspent", async () => {
    const a = proof("secret-a")
    const b = proof("secret-b")
    mockAxios.mockResolvedValueOnce({
      data: {states: [stateFor(a, "UNSPENT"), stateFor(b, "UNSPENT")]},
    })
    expect(await allProofsUnspent(MINT, [a, b])).toBe("UNSPENT")
  })

  it("treats PENDING as not unspent", async () => {
    const a = proof("secret-a")
    mockAxios.mockResolvedValueOnce({data: {states: [stateFor(a, "PENDING")]}})
    expect(await allProofsUnspent(MINT, [a])).toBe("NOT_UNSPENT")
  })

  it("treats SPENT as not unspent", async () => {
    const a = proof("secret-a")
    mockAxios.mockResolvedValueOnce({data: {states: [stateFor(a, "SPENT")]}})
    expect(await allProofsUnspent(MINT, [a])).toBe("NOT_UNSPENT")
  })

  it("does not let a mint error read as unspent", async () => {
    // The regression this guards: a `boolean | CashuMintError` return type
    // compiles fine, and `if (await allProofsUnspent(...))` then accepts a
    // timeout as "all proofs unspent" because an Error is a truthy object.
    const a = proof("secret-a")
    mockAxios.mockRejectedValueOnce({
      isAxiosError: true,
      message: "timeout of 5000ms exceeded",
    })

    const verdict = await allProofsUnspent(MINT, [a])
    expect(verdict).toBeInstanceOf(CashuMintError)
    expect(verdict).not.toBe("UNSPENT")
    // A caller that forgot the instanceof check still cannot mistake this for
    // a verdict, because the success values are strings.
    expect(typeof verdict).not.toBe("string")
  })

  it("does not let a malformed response read as unspent", async () => {
    const a = proof("secret-a")
    mockAxios.mockResolvedValueOnce({data: {states: "not-an-array"}})

    const verdict = await allProofsUnspent(MINT, [a])
    expect(verdict).toBeInstanceOf(CashuMintError)
    expect(verdict).not.toBe("UNSPENT")
  })
})
