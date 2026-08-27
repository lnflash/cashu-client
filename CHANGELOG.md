# Changelog

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
