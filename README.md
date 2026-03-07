# @lnflash/cashu-client

Cashu NFC card client library — crypto primitives and [Nutshell](https://github.com/cashubtc/nutshell) mint HTTP client.

Part of the [Cashu-First Flash Cards](https://github.com/lnflash/cashu-javacard) project.

## What's in here

| Module | Description |
|--------|-------------|
| `crypto` | NUT-00 `hash_to_curve`, NUT-03 BDHKE blinding/unblinding, NUT-10 P2PK secret serialization, denomination splitting |
| `mint` | Nutshell HTTP client — NUT-01 keysets, NUT-04 mint quotes + proof issuance |
| `types` | Shared TypeScript types (`CashuProof`, `CashuBlindingData`, `CashuMintQuote`, etc.) |
| `errors` | Typed error classes with numeric codes |

## Install

```bash
# yarn v1 (git dep, no npm publish needed)
yarn add github:lnflash/cashu-client#v0.1.0

# or via npm
npm install @lnflash/cashu-client
```

## Usage

```typescript
import {
  splitIntoDenominations,
  createBlindedMessage,
  unblindSignature,
  requestMintQuote,
  getMintKeysets,
  getMintKeyset,
  mintProofs,
} from "@lnflash/cashu-client"

const MINT_URL = "https://forge.flashapp.me"

// 1. Request a mint quote
const quote = await requestMintQuote(MINT_URL, 100, "usd") // 100 cents
if (quote instanceof Error) throw quote

// 2. Pay quote.paymentRequest (bolt11 invoice) externally

// 3. Fetch keyset keys
const keysets = await getMintKeysets(MINT_URL)
const usdKeyset = keysets.find(ks => ks.unit === "usd" && ks.active)
const keysetDetail = await getMintKeyset(MINT_URL, usdKeyset.id)

// 4. Build P2PK-locked blind messages for the card
const denominations = splitIntoDenominations(100)
const blindingData = denominations.map(amount =>
  createBlindedMessage(usdKeyset.id, amount, cardPubkeyHex)
)
const blindedMessages = blindingData.map((bd, i) => ({
  id: usdKeyset.id, amount: denominations[i], B_: bd.B_
}))

// 5. Mint proofs (with optional retry logic on "quote not paid")
const sigs = await mintProofs(MINT_URL, quote.quoteId, blindedMessages)

// 6. Unblind signatures → final proofs
const proofs = sigs.map((sig, i) => ({
  id: sig.id,
  amount: sig.amount,
  secret: blindingData[i].secretStr,
  C: unblindSignature(sig.C_, blindingData[i].r, keysetDetail.keys[String(sig.amount)])
}))
```

## Spec

- [NUT-XX: Cashu NFC Card Protocol](https://github.com/lnflash/cashu-javacard/blob/main/spec/NUT-XX.md)
- [JavaCard applet](https://github.com/lnflash/cashu-javacard)

## License

MIT
