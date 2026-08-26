"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isScalarHex = exports.isCompressedPointHex = exports.isSafePathId = exports.describeAxiosError = exports.axiosConfig = exports.sanitizeMintUrl = exports.HTTP_TIMEOUT = void 0;
const axios_1 = __importDefault(require("axios"));
/**
 * Shared HTTP surface for every mint call.
 *
 * This lives in one place deliberately: the URL sanitiser is an SSRF control
 * and the size caps are a memory-exhaustion control, and both are worth
 * exactly nothing if a newly added endpoint quietly forgets to apply them.
 */
// HTTP timeout for all mint requests (5 seconds)
exports.HTTP_TIMEOUT = 5000;
/**
 * Validate a mint URL is well-formed and uses HTTPS (or localhost for dev).
 * Parses with the URL API rather than string-prefix matching so that
 * credential-embedded and internal/metadata hosts cannot slip through.
 */
const sanitizeMintUrl = (mintUrl) => {
    let parsed;
    try {
        parsed = new URL(mintUrl);
    }
    catch {
        throw new Error("Mint URL is empty or malformed");
    }
    // Reject embedded credentials (https://user:pass@host) — an SSRF/obfuscation vector
    if (parsed.username || parsed.password) {
        throw new Error("Mint URL must not contain credentials");
    }
    const host = parsed.hostname.toLowerCase();
    const isLoopback = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
    if (parsed.protocol === "http:") {
        if (!isLoopback) {
            throw new Error("Mint URL must use HTTPS");
        }
    }
    else if (parsed.protocol !== "https:") {
        throw new Error("Mint URL must start with https:// (or http:// for localhost)");
    }
    // Block cloud-metadata / link-local endpoints — never a legitimate mint.
    if (host === "metadata.google.internal" || host.startsWith("169.254.") || host.startsWith("fe80:")) {
        throw new Error("Mint URL host is not allowed");
    }
    // Rebuild without trailing slashes, preserving any base path the mint uses.
    const path = parsed.pathname.replace(/\/+$/, "");
    return `${parsed.origin}${path}`;
};
exports.sanitizeMintUrl = sanitizeMintUrl;
exports.axiosConfig = {
    timeout: exports.HTTP_TIMEOUT,
    maxRedirects: 0,
    // Cap response size so a hostile mint can't exhaust client memory.
    maxContentLength: 1000000,
    maxBodyLength: 1000000,
    headers: { "Content-Type": "application/json" },
    validateStatus: (status) => status >= 200 && status < 300,
};
/**
 * Mints report failures as `{"detail": "..."}`; surface that rather than the
 * generic "Request failed with status code 400", which tells an operator
 * nothing about why a melt was refused.
 */
const describeAxiosError = (err) => {
    if (axios_1.default.isAxiosError(err)) {
        const detail = err.response?.data?.detail;
        if (typeof detail === "string" && detail.length > 0)
            return detail;
    }
    return err.message;
};
exports.describeAxiosError = describeAxiosError;
/** A quote/keyset identifier safe to interpolate into a URL path. */
const isSafePathId = (id) => typeof id === "string" && id.length > 0 && id.length <= 256 && /^[a-zA-Z0-9_-]+$/.test(id);
exports.isSafePathId = isSafePathId;
/** A compressed secp256k1 point in hex. */
const isCompressedPointHex = (v) => typeof v === "string" && /^0[23][0-9a-fA-F]{64}$/.test(v);
exports.isCompressedPointHex = isCompressedPointHex;
/** A 32-byte scalar in hex. */
const isScalarHex = (v) => typeof v === "string" && /^[0-9a-fA-F]{64}$/.test(v);
exports.isScalarHex = isScalarHex;
