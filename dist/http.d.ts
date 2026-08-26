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
/** A compressed secp256k1 point in hex. */
export declare const isCompressedPointHex: (v: unknown) => v is string;
/** A 32-byte scalar in hex. */
export declare const isScalarHex: (v: unknown) => v is string;
