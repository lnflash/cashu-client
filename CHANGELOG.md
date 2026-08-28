# Changelog

## 0.5.0

### Added

- **`cardFile` module — the interchange format between the mint side and the
  card side.** The mint protocol is TypeScript (this library) and the card
  driver is dependency-free Python (`tools/cardctl` in lnflash/cashu-javacard),
  so proofs cross the boundary as a file. The schema is defined here, once, and
  both sides validate against it — a field that drifts fails at the boundary
  instead of at the mint, where the card may already have burned the slot.

  ```jsonc
  {
    "version": 1,
    "mint": "https://forge.flashapp.me",  // canonicalised on read
    "unit": "sat",                        // trimmed + lower-cased on read
    "cardPubkey": "03…",                  // 33 bytes, on-curve
    "slots": [
      {
        "keysetId": "0059534ce0bfa19a",   // NUT-02 v0, 8 bytes
        "amount": 8,                      // positive power of two, below 2^32
        "nonce": "916c…",                 // 32 bytes — NOT the secret; unique per slot
        "C": "02c6…",                     // 33 bytes, on-curve, unique per slot
        "spent": false                    // required; card → mint only
      }
    ],
    "note": "loaded at till 2"            // optional, ≤ 512 chars, never trusted
  }
  ```

  Two entry points:

  - `serializeCardFile(file, {pretty})` — **mint → card.** Round-trips the file
    through `parseCardFile` and then through the redeem path
    (`reconstructProofsFromCard`, result discarded) before writing. This is the
    only gate in that direction: cardctl does no curve math, so whatever this
    writes is what reaches the card. It also refuses a `spent: true` slot — see
    the `spent` row below.
  - `parseCardFile(stringOrObject)` — **card → mint.** Returns a `CardFile`
    whose `slots` feed `reconstructProofsFromCard` directly, with no field
    renaming in between. Throws on anything malformed; a card file is an
    instruction to move money on or off a bearer instrument, so there is no
    useful partial success.

  Also exported: `parseCardSlot`, `cardFileTotal`, `CARD_FILE_VERSION` and the
  `CardFile` and `CardFileSlot` types. `cardFileTotal` sums the **unspent**
  slots only: a spent proof is money already gone, and this number is what a
  terminal shows a holder as the card's worth.

  The wire shape carries the *card's* vocabulary — `nonce`, not `secret`, and
  `keysetId` as 16 hex chars — because that is what the card stores. A file that
  said `secret` would invite ~150 bytes of P2PK JSON into a 32-byte field, so
  that spelling is rejected by name rather than as an unknown field.

  What the reader refuses, and why each one would otherwise burn a slot:

  | Refused | Because |
  |---|---|
  | An unknown field | A future cardctl added it and forgot to bump `version`; dropping it silently is the drift `version` exists to announce |
  | A `note` that is not a string, or is over 512 characters | Same drift, on a known field — and `note` is the file's only provenance record, third-party data a terminal renders back to a human |
  | An off-curve or bad-prefix `C` / `cardPubkey` | Produces a proof that was never spendable; cardctl cannot catch it |
  | A non-v0 or half-length `keysetId` | Matches no keyset at the mint |
  | An amount that is not a positive power of two | A mint keyset has no key for 3 |
  | An amount of `2^32` or more | `LOAD_PROOF` carries the amount as a 4-byte unsigned integer, so a larger one cannot be written to a card even though it is a valid denomination elsewhere |
  | A missing or non-boolean `spent` | Required, never defaulted: defaulting to `false` silently resurrects a spent proof as spendable on the next load |
  | **The same `C` in two slots** | Every per-slot check passes and both copies load; slot 0 redeems, slot 1 burns on `SPEND_PROOF` and the mint refuses it as already spent, while `cardFileTotal` claimed the card held double |
  | **The same `nonce` in two slots** | The secret is `buildP2PKSecret(nonce, cardPubkey)` and nothing else, so two slots sharing a nonce reconstruct to one proof — same `Y` at the mint — even with different amounts and therefore different `C`. Same burn as the row above, one field over |
  | A mint URL the HTTP sanitiser refuses | A bearer instrument's file is third-party data — it can carry a link-local or metadata URL |
  | A `spent: true` slot, **in the writer only** | `parseCardFile` keeps the bit because a card dump is where it comes from, but `LOAD_PROOF` has no spent bit: re-serializing a dump (the "top up an existing card" flow) would write spent proofs back and the card would return them as spendable. Filter them out before serializing |

### Changed

- `mint` and `unit` are stored canonical (`mint` through the same
  `sanitizeMintUrl` every network path uses; `unit` trimmed and lower-cased).
  Both exist to be compared — `file.mint === expected`, `file.unit ===
  keyset.unit` — and an untrimmed value makes those comparisons return false
  against the right mint or the right keyset, silently.
- The package barrel exports `card`'s public surface by name rather than with
  `export *`. `requireHex`, `requirePoint`, `requireKeysetV0`, `requireAmount`
  and the `CardField` type are exported from the module so `cardFile.ts` can
  reuse the checks instead of keeping a second copy that drifts; they were never
  meant as package API, and `export *` had made four validators carrying an
  internal `where` parameter into a semver commitment.
  `reconstructProofFromCard`, `reconstructProofsFromCard`, `CardProofSlot`,
  `CardSlotFailure`, `CardReconstructionResult`, `ReconstructCardOptions` and
  `ReconstructCardBatchOptions` are unchanged.

## 0.4.0

### Breaking

- **`buildP2PKSecret` now lower-cases the nonce and the card pubkey.** The
  serialization has one canonical form, so a proof cannot be minted under one
  hex case and reconstructed under another. The secret is committed to at mint
  time as UTF-8 bytes — `Y = hash_to_curve(secret)` — which makes the two cases
  two different proofs.

  **Proofs minted by <= 0.3.0 with an upper-case `cardPubkey` are not
  reconstructable by this version.** The canonical secret hashes to a `Y` the
  mint has never signed, and because `SPEND_PROOF` marks a slot spent *before*
  returning its signature, the card burns the slot and the mint then rejects the
  proof — the exact failure this release exists to prevent.

  Cards funded that way remain redeemable:

  ```typescript
  reconstructProofFromCard(slot, cardPubkey, {legacyHexCase: true})
  ```

  which reproduces the pre-0.4.0 serialization byte-for-byte: the card key is
  serialized in the case supplied, and the nonce is still lower-cased. Pre-0.4.0
  `createBlindedMessage` generated the nonce itself as lower-case hex and never
  read one off a card, so `cardPubkey` is the only field whose case could ever
  have reached a minted secret; freezing the nonce's case too would emit a secret
  no released version has minted. Try the default first and fall back only when
  the mint rejects the proof as unknown. Never mint with it.

### Added

- `card` module: `reconstructProofFromCard` / `reconstructProofsFromCard` turn
  what `GET_PROOF` returns into a spendable `CashuProof`. Previously a card's
  contents were inert — a terminal could read every slot and still have no proof
  to hand the mint.
- `reconstructProofsFromCard(slots, cardPubkey, {skipInvalid: true})` returns
  `{proofs, failures}` so one corrupt slot no longer makes the rest of the card
  unreadable through this API. The default stays throw-on-first-failure.
- `ReconstructCardOptions`, `ReconstructCardBatchOptions`, `CardSlotFailure` and
  `CardReconstructionResult` types.

### Changed

- Point rejections name the actual fault: a bad prefix byte and an on-prefix,
  off-curve value now produce different messages, instead of both blaming the
  prefix.
- `amount` rejections quote the value (`got "8"`) and report a non-number input
  by type, so a string from an untyped reader bridge is not rendered as though
  it were a valid number.
- `reconstructProofsFromCard` accepts a non-literal `skipInvalid` and returns
  `CashuProof[] | CardReconstructionResult` for it. Recovery mode is routinely
  driven from config or from a retry after the strict pass threw, and the two
  literal overloads alone rejected a runtime `boolean` (TS2769), pushing that
  caller into an `as any`. A literal `true`/`false` still resolves to its precise
  return type.
