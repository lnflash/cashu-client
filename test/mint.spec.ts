/**
 * Tests for mint client URL sanitization and response validation.
 * Uses mocked axios to avoid real network calls.
 */

const mockAxios = jest.fn()
jest.mock("axios", () => ({
  ...jest.requireActual("axios"),
  post: (...args: unknown[]) => mockAxios("post", ...args),
  get: (...args: unknown[]) => mockAxios("get", ...args),
  isAxiosError: jest.fn((err: unknown) => err && typeof err === "object" && "isAxiosError" in err),
}))

import {requestMintQuote, getMintKeysets, getMintKeyset, CashuMintError} from "../src"
import type {CashuKeyset} from "../src"

describe("Mint client URL sanitization", () => {
  beforeEach(() => {
    mockAxios.mockReset()
  })

  it("rejects non-HTTPS mint URLs", async () => {
    const result = await requestMintQuote("http://evil.example.com", 100, "sat")
    expect(result).toBeInstanceOf(Error)
    expect((result as Error).message).toContain("HTTPS")
  })

  it("allows localhost HTTP for dev", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {quote: "q1", request: "lnbc1...", state: "UNPAID", expiry: 9999999999},
    })

    const result = await requestMintQuote("http://localhost:3338", 100, "sat")
    expect(result).toHaveProperty("quoteId", "q1")
  })

  it("strips trailing slashes from mint URL", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {keysets: [{id: "abc", unit: "sat", active: true}]},
    })

    await getMintKeysets("https://forge.flashapp.me///")

    const url = mockAxios.mock.calls[0][1] as string
    expect(url).not.toContain("///")
    expect(url).toBe("https://forge.flashapp.me/v1/keysets")
  })

  it("rejects empty mint URL", async () => {
    const result = await getMintKeysets("")
    expect(result).toBeInstanceOf(Error)
  })
})

describe("keyset parsing", () => {
  beforeEach(() => mockAxios.mockReset())

  it("carries NUT-02 input_fee_ppk through instead of discarding it", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {keysets: [{id: "abc", unit: "sat", active: true, input_fee_ppk: 100}]},
    })

    const result = (await getMintKeysets("https://mint.example.com")) as CashuKeyset[]
    expect(result[0].input_fee_ppk).toBe(100)
  })

  it("leaves input_fee_ppk undefined when the mint advertises none", async () => {
    mockAxios.mockResolvedValueOnce({
      data: {keysets: [{id: "abc", unit: "sat", active: true}]},
    })

    const result = (await getMintKeysets("https://mint.example.com")) as CashuKeyset[]
    expect(result[0]).toEqual({id: "abc", unit: "sat", active: true})
    expect(result[0].input_fee_ppk).toBeUndefined()
  })

  it("rejects a malformed keyset entry", async () => {
    mockAxios.mockResolvedValueOnce({data: {keysets: [{id: 42, unit: "sat"}]}})
    expect(await getMintKeysets("https://mint.example.com")).toBeInstanceOf(CashuMintError)

    mockAxios.mockResolvedValueOnce({
      data: {keysets: [{id: "abc", unit: "sat", active: true, input_fee_ppk: -1}]},
    })
    expect(await getMintKeysets("https://mint.example.com")).toBeInstanceOf(CashuMintError)
  })

  it("explains a keyset fetch failure with the mint's detail body", async () => {
    // Not `(err as Error).message` — "Request failed with status code 404"
    // tells an operator nothing about why the keyset fetch was refused.
    mockAxios.mockRejectedValueOnce({
      isAxiosError: true,
      message: "Request failed with status code 404",
      response: {data: {detail: "keyset not found"}},
    })

    const result = await getMintKeyset("https://mint.example.com", "00abcdef")
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toContain("keyset not found")
  })
})
