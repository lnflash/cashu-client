# cashu-client — Audit Report

**Package:** `@lnflash/cashu-client` v0.2.0 — TypeScript Cashu (ecash) BDHKE crypto + Nutshell mint HTTP client
**Date:** 2026-06-22
**Reviewed:** `main` after the `fix/protocol-hardening` merge
**Method:** Four parallel deep-dives — crypto correctness, mint-client security, API/quality, deps/build/tests. `hash_to_curve` independently verified against NUT-00 vectors; build + tests run.

> The highest-value, well-contained findings were **fixed in this PR** (see below). The deeper items — DLEQ verification and the `@noble/curves` migration — are left as documented follow-ups because each warrants its own focused review.

## Overall verdict

**The cryptographic primitives are sound; the trust model was the gap.** The BDHKE math is correct and the recent `hash_to_curve` endianness fix is genuine (now pinned by spec test vectors). The core weakness was that the client **trusted the mint blindly** — no binding between requests and responses, no DLEQ. This PR closes the contained fund-safety gaps and hardens inputs; DLEQ remains a follow-up.

## ✅ Verified correct (no change needed)

- **`hash_to_curve` is NUT-00 spec-correct** — domain separator, SHA256 loop, `0x02` prefix, **little-endian** counter; matches the published vectors (now asserted in `test/crypto.spec.ts`). The endianness fix was real.
- **Blinding/unblinding math** (`B'=Y+rG`, `C=C'−rK`) and **point negation** are exact.
- **Randomness**: blinding scalar `r` and nonce use CSPRNG with `0<r<n` rejection, fresh per output.
- **NUT-10 secret via `JSON.stringify`** (no injection); axios timeout + `maxRedirects:0`; path params sanitized; no logging / no secret leakage.
- **Tooling**: `strict` on; zero `any`/`@ts-ignore`/`console`/TODO; **0 production-dependency vulnerabilities**; clean supply chain (WASM crypto dep, not native; no install scripts).

## 🔧 Fixed in this PR

| Finding | Severity | Fix |
|---------|----------|-----|
| `splitIntoDenominations` dropped every bit above 2¹⁵ (`1<<bit` is 32-bit; loop was 0–15) → wrong split / **fund loss** for amounts ≥ 65536 | **High** | Decompose with `2**bit` over the full safe-integer range (`crypto.ts`). |
| `mintProofs` trusted mint responses positionally — no check that returned `amount`/keyset `id` matched the requested output → proofs worth less than paid or unspendable | **High** | Bind each signature to its output: assert `id` + `amount` match and `C_` is a valid compressed point; reject the batch otherwise (`mint.ts`). |
| `getMintKeyset` returned keys without verifying the keyset `id` matched the request → wrong `K` during unblinding → unspendable proofs | **High** | Assert `ks.id === keysetId` and `keys` is a non-empty object (`mint.ts`). |
| `sanitizeMintUrl` used string-prefix matching → `https://…@internal`, cloud-metadata, link-local hosts passed (**SSRF**) | **High** | Parse with the `URL` API; enforce `https:` (loopback may use `http:`); reject embedded credentials; block metadata/link-local hosts (`mint.ts`). |
| `requestMintQuote` sent `amount`/`unit` unvalidated (negative/0/NaN/fractional) | High | Validate `amount` is a positive integer and `unit` matches `^[a-z]{3,4}$` (`mint.ts`). |
| `unblindSignature` didn't range-check `r` (exported; zero `r` → `C=C_`, silent no-op) | Medium | Validate `secp.isPrivate(r)` after the point checks (`crypto.ts`). |
| No response-size cap → hostile mint could exhaust memory | Medium | `maxContentLength`/`maxBodyLength` = 1 MB on axios (`mint.ts`). |
| No NUT-00 known-answer tests (suite proved self-consistency, not interop) | Low | Added the official `0x00*32` and `0x00..01` `hash_to_curve` vectors (`test/crypto.spec.ts`). |
| `dist/` committed with nothing keeping it in sync | Low | CI step `git diff --exit-code dist` fails PRs where the committed build drifts. |
| No `engines`/`.nvmrc` | Low | Added `engines: node>=18` + `.nvmrc`. |

All verified: `npm run build` clean, **31/31 tests pass** (29 + 2 new spec vectors), committed `dist/` rebuilt and in sync.

## 📋 Remaining follow-ups (documented, not in this PR)

- **NUT-12 DLEQ verification** *(High)* — the client still doesn't prove the mint signed with its advertised key. Without it, a malicious mint can run a per-user-key **tagging/deanonymization oracle**. This is the most important remaining item; it needs `e,s` proof handling and is substantial enough to warrant its own PR. The amount/keyset binding added here mitigates the fund-loss half but not the privacy half.
- **Migrate `tiny-secp256k1` → `@noble/curves`** *(Medium)* — audited (Cure53/ToB), constant-time, pure-JS, no WASM loader; the ecosystem standard. Its own PR + re-verification against the new spec-vector tests.
- **Error-handling convention** *(Medium)* — `mint.ts` returns `T | CashuMintError` unions while `crypto.ts` throws; the README examples skip the narrowing. Unify (idiomatic: throw typed errors), and map the mint's NUT error `code` into the (currently never-thrown) error subclasses.
- **Runtime response validation** *(Medium)* — replace the remaining blind `as` casts of mint JSON (quote shape, `getMintKeysets` elements) with a validator (e.g. `zod`); enable `noUncheckedIndexedAccess`.
- **Packaging** *(Low)* — add an `exports` map, consider a dual ESM/CJS build, `sideEffects:false`; fix the README install pin (`#v0.1.0` → current).
- **Scope** — `swap`/`melt`/`info` endpoints are not implemented yet, so the library cannot spend/receive ecash on its own.

## Bottom line

The hard part — the BDHKE primitives — is correct and now pinned by spec vectors. This PR closes the contained fund-safety and input-hardening gaps (denomination overflow, request/response binding, keyset-ID binding, SSRF, amount validation). The one major item left is **DLEQ verification**, tracked as a dedicated follow-up; until it lands, treat tokens from this client as integrity-checked on amount/keyset but **not** privacy-verified against a hostile mint.

---

*Audit generated with Claude Code.*
