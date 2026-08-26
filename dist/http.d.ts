import type { CashuDLEQ } from "./types";
/**
 * Shared HTTP surface for every mint call.
 *
 * This lives in one place deliberately: the URL sanitiser is an SSRF control
 * and the size caps are a memory-exhaustion control, and both are worth
 * exactly nothing if a newly added endpoint quietly forgets to apply them.
 */
export declare const HTTP_TIMEOUT = 5000;
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
export declare const normalizeHostname: (hostname: string) => string;
export declare const sanitizeMintUrl: (mintUrl: string) => string;
export declare const axiosConfig: {
    readonly timeout: 5000;
    readonly maxRedirects: 0;
    readonly maxContentLength: 1000000;
    readonly maxBodyLength: 1000000;
    readonly headers: {
        readonly "Content-Type": "application/json";
    };
    readonly validateStatus: (status: number) => boolean;
};
/**
 * Mints report failures as `{"detail": "..."}`; surface that rather than the
 * generic "Request failed with status code 400", which tells an operator
 * nothing about why a melt was refused.
 */
export declare const describeAxiosError: (err: unknown) => string;
/** A quote/keyset identifier safe to interpolate into a URL path. */
export declare const isSafePathId: (id: string) => boolean;
/**
 * A NUT-02 keyset identifier safe to interpolate into a URL path.
 *
 * Narrower than {@link isSafePathId} — keyset ids are hex — and bounded, so a
 * caller cannot hand the mint a megabyte-long path segment.
 */
export declare const isSafeKeysetId: (id: string) => boolean;
/** A compressed secp256k1 point in hex. */
export declare const isCompressedPointHex: (v: unknown) => v is string;
/** A 32-byte scalar in hex. */
export declare const isScalarHex: (v: unknown) => v is string;
/**
 * Parse the NUT-12 `dleq` field off a blind signature in a mint response.
 *
 * Returns `undefined` when the mint sent none, and `null` when it sent one that
 * is malformed. Callers must keep those apart and reject the second: not every
 * mint emits DLEQ, so absent is a policy decision for the caller, but a mint
 * that could opt out of verification by sending garbage has defeated the point
 * of the check.
 */
export declare const parseResponseDLEQ: (raw: unknown) => CashuDLEQ | undefined | null;
