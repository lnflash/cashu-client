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

import {requestMintQuote, getMintKeysets} from "../src"

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
