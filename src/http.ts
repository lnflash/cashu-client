import axios from "axios"

import type { CashuDLEQ } from "./types"

/**
 * Shared HTTP surface for every mint call.
 *
 * This lives in one place deliberately: the URL sanitiser is an SSRF control
 * and the size caps are a memory-exhaustion control, and both are worth
 * exactly nothing if a newly added endpoint quietly forgets to apply them.
 */

// HTTP timeout for all mint requests (5 seconds)
export const HTTP_TIMEOUT = 5000

/**
 * Validate a mint URL is well-formed and uses HTTPS (or localhost for dev).
 * Parses with the URL API rather than string-prefix matching so that
 * credential-embedded and internal/metadata hosts cannot slip through.
 */
/**
 * Canonicalise a URL hostname before any range check.
 *
 * String-prefix matching on `parsed.hostname` is not enough — several spellings
 * of the same address survive it:
 *   - `https://metadata.google.internal./` keeps the trailing root dot, so an
 *     equality test against the bare name misses it;
 *   - `https://[::ffff:169.254.169.254]/` is normalised by the URL parser to
 *     `[::ffff:a9fe:a9fe]`, which does not start with "169.254.".
 * Both resolve and connect. So: unwrap brackets, drop trailing dots, and
 * rewrite an IPv4-mapped IPv6 address back to dotted-quad, then compare.
 */
export const normalizeHostname = (hostname: string): string => {
  let host = hostname.toLowerCase()
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1)
  host = host.replace(/\.+$/, "")

  // ::ffff:169.254.169.254 and its normalised form ::ffff:a9fe:a9fe are the
  // same v4 address wearing a v6 hat.
  const mapped = /^(?:0*:)*:ffff:(.+)$/.exec(host)
  if (mapped) {
    const rest = mapped[1]
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(rest)) return rest
    const hexPair = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(rest)
    if (hexPair) {
      const hi = parseInt(hexPair[1], 16)
      const lo = parseInt(hexPair[2], 16)
      return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`
    }
  }
  return host
}

/** Loopback, which stays reachable deliberately so a dev mint can run locally. */
const isLoopbackHost = (host: string): boolean => {
  if (host === "localhost" || host === "::1") return true
  const v4 = parseIPv4(host)
  return v4 !== null && v4[0] === 127
}

const parseIPv4 = (host: string): number[] | null => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (!m) return null
  const octets = m.slice(1).map(Number)
  return octets.every(o => o <= 255) ? octets : null
}

/**
 * Hosts a mint is never legitimately served from: cloud metadata endpoints and
 * every address range that only exists inside the caller's own network.
 * Checked against the canonical form, by range rather than by string prefix.
 */
const isBlockedHost = (host: string): boolean => {
  if (host === "metadata" || host === "metadata.google.internal" || host === "metadata.goog") {
    return true
  }

  const v4 = parseIPv4(host)
  if (v4) {
    const [a, b] = v4
    if (a === 0) return true                      // 0.0.0.0/8 "this host"
    if (a === 10) return true                     // RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true // RFC6598 CGNAT
    if (a === 169 && b === 254) return true       // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true  // RFC1918
    if (a === 192 && b === 168) return true       // RFC1918
    return false
  }

  if (host.includes(":")) {
    if (host === "::") return true                // unspecified
    const group = host.split(":")[0]
    if (/^fe[89ab][0-9a-f]{0,2}$/.test(group)) return true // fe80::/10 link-local
    if (/^f[cd][0-9a-f]{0,2}$/.test(group)) return true    // fc00::/7 unique-local
    return false
  }

  return false
}

export const sanitizeMintUrl = (mintUrl: string): string => {
  let parsed: URL
  try {
    parsed = new URL(mintUrl)
  } catch {
    throw new Error("Mint URL is empty or malformed")
  }

  // Reject embedded credentials (https://user:pass@host) — an SSRF/obfuscation vector
  if (parsed.username || parsed.password) {
    throw new Error("Mint URL must not contain credentials")
  }

  const host = normalizeHostname(parsed.hostname)
  const isLoopback = isLoopbackHost(host)

  if (parsed.protocol === "http:") {
    if (!isLoopback) {
      throw new Error("Mint URL must use HTTPS")
    }
  } else if (parsed.protocol !== "https:") {
    throw new Error("Mint URL must start with https:// (or http:// for localhost)")
  }

  // Block cloud-metadata / link-local / private endpoints — never a legitimate
  // mint. Loopback is exempt: a dev mint on 127.0.0.1 is the supported path.
  if (!isLoopback && isBlockedHost(host)) {
    throw new Error("Mint URL host is not allowed")
  }

  // Rebuild without trailing slashes, preserving any base path the mint uses.
  const path = parsed.pathname.replace(/\/+$/, "")
  return `${parsed.origin}${path}`
}

export const axiosConfig = {
  timeout: HTTP_TIMEOUT,
  maxRedirects: 0,
  // Cap response size so a hostile mint can't exhaust client memory.
  maxContentLength: 1_000_000,
  maxBodyLength: 1_000_000,
  headers: {"Content-Type": "application/json"},
  validateStatus: (status: number) => status >= 200 && status < 300,
} as const

/**
 * Mints report failures as `{"detail": "..."}`; surface that rather than the
 * generic "Request failed with status code 400", which tells an operator
 * nothing about why a melt was refused.
 */
export const describeAxiosError = (err: unknown): string => {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail
    if (typeof detail === "string" && detail.length > 0) return detail
  }
  return (err as Error).message
}

/** A quote/keyset identifier safe to interpolate into a URL path. */
export const isSafePathId = (id: string): boolean =>
  typeof id === "string" && id.length > 0 && id.length <= 256 && /^[a-zA-Z0-9_-]+$/.test(id)

/**
 * A NUT-02 keyset identifier safe to interpolate into a URL path.
 *
 * Narrower than {@link isSafePathId} — keyset ids are hex — and bounded, so a
 * caller cannot hand the mint a megabyte-long path segment.
 */
export const isSafeKeysetId = (id: string): boolean =>
  typeof id === "string" && /^[0-9a-fA-F]{1,128}$/.test(id)

/** A compressed secp256k1 point in hex. */
export const isCompressedPointHex = (v: unknown): v is string =>
  typeof v === "string" && /^0[23][0-9a-fA-F]{64}$/.test(v)

/** A 32-byte scalar in hex. */
export const isScalarHex = (v: unknown): v is string =>
  typeof v === "string" && /^[0-9a-fA-F]{64}$/.test(v)

/**
 * Parse the NUT-12 `dleq` field off a blind signature in a mint response.
 *
 * Returns `undefined` when the mint sent none, and `null` when it sent one that
 * is malformed. Callers must keep those apart and reject the second: not every
 * mint emits DLEQ, so absent is a policy decision for the caller, but a mint
 * that could opt out of verification by sending garbage has defeated the point
 * of the check.
 */
export const parseResponseDLEQ = (raw: unknown): CashuDLEQ | undefined | null => {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw !== "object") return null
  const d = raw as Record<string, unknown>
  if (!isScalarHex(d.e) || !isScalarHex(d.s)) return null
  return {e: d.e.toLowerCase(), s: d.s.toLowerCase()}
}
