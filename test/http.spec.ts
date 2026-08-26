/**
 * Tests for the shared HTTP surface: the SSRF URL controls and the response
 * field validators every mint call routes through.
 */

import {
  isCompressedPointHex,
  isSafeKeysetId,
  isSafePathId,
  isScalarHex,
  normalizeHostname,
  parseResponseDLEQ,
  sanitizeMintUrl,
} from "../src/http"

const POINT = "02" + "11".repeat(32)
const SCALAR = "ab".repeat(32)

describe("sanitizeMintUrl — scheme and credentials", () => {
  it("rejects embedded credentials", () => {
    expect(() => sanitizeMintUrl("https://user:pass@mint.example.com")).toThrow(
      /credentials/,
    )
    expect(() => sanitizeMintUrl("https://user@mint.example.com")).toThrow(/credentials/)
  })

  it("rejects non-HTTPS remote URLs", () => {
    expect(() => sanitizeMintUrl("http://mint.example.com")).toThrow(/HTTPS/)
  })

  it("rejects non-HTTP(S) schemes", () => {
    expect(() => sanitizeMintUrl("file:///etc/passwd")).toThrow(/https:\/\//)
    expect(() => sanitizeMintUrl("ftp://mint.example.com")).toThrow(/https:\/\//)
  })

  it("rejects an empty or malformed URL", () => {
    expect(() => sanitizeMintUrl("")).toThrow(/empty or malformed/)
    expect(() => sanitizeMintUrl("not a url")).toThrow(/empty or malformed/)
  })

  it("keeps a base path and strips trailing slashes", () => {
    expect(sanitizeMintUrl("https://mint.example.com/cashu///")).toBe(
      "https://mint.example.com/cashu",
    )
    expect(sanitizeMintUrl("https://mint.example.com/")).toBe("https://mint.example.com")
  })
})

describe("sanitizeMintUrl — SSRF host controls", () => {
  it("blocks the cloud metadata address", () => {
    expect(() => sanitizeMintUrl("https://169.254.169.254/")).toThrow(/not allowed/)
  })

  it("blocks the metadata address wearing an IPv4-mapped IPv6 hat", () => {
    // Node normalises this hostname to "[::ffff:a9fe:a9fe]", which a
    // string-prefix check for "169.254." misses entirely.
    expect(() => sanitizeMintUrl("https://[::ffff:169.254.169.254]/")).toThrow(
      /not allowed/,
    )
    expect(() => sanitizeMintUrl("https://[::ffff:a9fe:a9fe]/")).toThrow(/not allowed/)
  })

  it("blocks metadata.google.internal with a trailing root dot", () => {
    expect(() => sanitizeMintUrl("https://metadata.google.internal/")).toThrow(
      /not allowed/,
    )
    expect(() => sanitizeMintUrl("https://metadata.google.internal./")).toThrow(
      /not allowed/,
    )
  })

  it("blocks RFC1918 private ranges", () => {
    expect(() => sanitizeMintUrl("https://10.0.0.1/")).toThrow(/not allowed/)
    expect(() => sanitizeMintUrl("https://172.16.0.1/")).toThrow(/not allowed/)
    expect(() => sanitizeMintUrl("https://172.31.255.254/")).toThrow(/not allowed/)
    expect(() => sanitizeMintUrl("https://192.168.1.1/")).toThrow(/not allowed/)
  })

  it("does not over-block ranges adjacent to the private ones", () => {
    expect(sanitizeMintUrl("https://172.15.0.1/")).toBe("https://172.15.0.1")
    expect(sanitizeMintUrl("https://172.32.0.1/")).toBe("https://172.32.0.1")
    expect(sanitizeMintUrl("https://11.0.0.1/")).toBe("https://11.0.0.1")
    expect(sanitizeMintUrl("https://192.169.1.1/")).toBe("https://192.169.1.1")
  })

  it("blocks IPv6 link-local and unique-local", () => {
    expect(() => sanitizeMintUrl("https://[fe80::1]/")).toThrow(/not allowed/)
    expect(() => sanitizeMintUrl("https://[febf::1]/")).toThrow(/not allowed/)
    expect(() => sanitizeMintUrl("https://[fd00::1]/")).toThrow(/not allowed/)
  })

  it("blocks the unspecified address", () => {
    expect(() => sanitizeMintUrl("https://0.0.0.0/")).toThrow(/not allowed/)
  })

  it("still allows loopback for local development", () => {
    expect(sanitizeMintUrl("http://localhost:3338")).toBe("http://localhost:3338")
    expect(sanitizeMintUrl("http://127.0.0.1:3338")).toBe("http://127.0.0.1:3338")
    expect(sanitizeMintUrl("http://[::1]:3338")).toBe("http://[::1]:3338")
  })

  it("allows an ordinary public mint", () => {
    expect(sanitizeMintUrl("https://forge.flashapp.me")).toBe("https://forge.flashapp.me")
  })
})

describe("normalizeHostname", () => {
  it("unwraps brackets, drops trailing dots, and canonicalises mapped v4", () => {
    expect(normalizeHostname("EXAMPLE.COM.")).toBe("example.com")
    expect(normalizeHostname("[::1]")).toBe("::1")
    expect(normalizeHostname("[::ffff:a9fe:a9fe]")).toBe("169.254.169.254")
    expect(normalizeHostname("[::ffff:192.168.0.1]")).toBe("192.168.0.1")
  })
})

describe("response field validators", () => {
  it("accepts only compressed points", () => {
    expect(isCompressedPointHex(POINT)).toBe(true)
    expect(isCompressedPointHex("03" + "11".repeat(32))).toBe(true)
    expect(isCompressedPointHex("04" + "11".repeat(32))).toBe(false)
    expect(isCompressedPointHex("02" + "11".repeat(31))).toBe(false)
    expect(isCompressedPointHex(42)).toBe(false)
  })

  it("accepts only 32-byte scalars", () => {
    expect(isScalarHex(SCALAR)).toBe(true)
    expect(isScalarHex("ab".repeat(31))).toBe(false)
    expect(isScalarHex(null)).toBe(false)
  })

  it("rejects path ids that could escape the URL path", () => {
    expect(isSafePathId("quote-123_A")).toBe(true)
    expect(isSafePathId("../../admin")).toBe(false)
    expect(isSafePathId("")).toBe(false)
    expect(isSafePathId("a".repeat(257))).toBe(false)
  })

  it("bounds keyset ids to hex of a plausible length", () => {
    expect(isSafeKeysetId("0059534ce0bfa19a")).toBe(true)
    expect(isSafeKeysetId("00ABCDEF")).toBe(true)
    expect(isSafeKeysetId("../../admin")).toBe(false)
    expect(isSafeKeysetId("zz")).toBe(false)
    expect(isSafeKeysetId("")).toBe(false)
    expect(isSafeKeysetId("0".repeat(129))).toBe(false)
  })
})

describe("parseResponseDLEQ", () => {
  it("distinguishes absent from malformed", () => {
    expect(parseResponseDLEQ(undefined)).toBeUndefined()
    expect(parseResponseDLEQ(null)).toBeUndefined()
    // Present but garbage — a hostile mint must not be able to opt out of DLEQ
    // by making its proof indistinguishable from "no DLEQ".
    expect(parseResponseDLEQ({e: "nope", s: SCALAR})).toBeNull()
    expect(parseResponseDLEQ({e: SCALAR})).toBeNull()
    expect(parseResponseDLEQ("garbage")).toBeNull()
  })

  it("lowercases a well-formed pair", () => {
    expect(parseResponseDLEQ({e: "AB".repeat(32), s: SCALAR})).toEqual({
      e: SCALAR,
      s: SCALAR,
    })
  })
})
