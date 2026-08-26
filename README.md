# @lnflash/cashu-client

Cashu NFC card client library — crypto primitives and [Nutshell](https://github.com/cashubtc/nutshell) mint HTTP client.

Part of the [Cashu-First Flash Cards](https://github.com/lnflash/cashu-javacard) project.

## What's in here

| Module | Description |
|--------|-------------|
| `crypto` | NUT-00 `hash_to_curve`, NUT-03 BDHKE blinding/unblinding, NUT-10 P2PK secret serialization, denomination splitting |
| `mint` | Nutshell HTTP client — NUT-01 keysets, NUT-04 mint quotes + proof issuance |
| `witness` | NUT-11 P2PK witnesses — the message a card must sign, attaching its signature, verifying the result |
| `melt` | NUT-05 melting — quote, execute, and proof selection. **This is how a card gets redeemed.** |
| `swap` | NUT-03 swapping — change, receiving, and unlocking card-locked proofs |
| `state` | NUT-07 proof state — the double-spend check |
| `dleq` | NUT-12 discrete-log equality — verify a mint signed with its published key, offline |
| `http` | Shared URL sanitising and response limits for every mint call |
| `types` | Shared TypeScript types (`CashuProof`, `CashuMeltQuote`, `CashuProofState`, …) |
| `errors` | Typed error classes with numeric codes |

### The card lifecycle

The library previously wrote the P2PK *lock* and had no way to produce the
*unlock*, so a card could be funded and never spent. The full round trip is now
covered:

| Stage | Calls |
|---|---|
| **Load** a card | `requestMintQuote` → pay → `mintProofs` → `unblindSignature` |
| **Verify** what's on it | `verifyProofDLEQ` (offline) or `checkProofStates` (online) |
| **Spend** at a terminal | `requestMeltQuote` → `selectProofsForMelt` → card signs `p2pkMessageToSign` → `attachP2PKWitness` → `meltProofs` |
| **Make change** | `swapProofs` |

Two things worth knowing before wiring this up. **Melt and swap are not
idempotent** — the inputs are consumed when the mint accepts them, so after a
lost response the correct move is `getMeltQuoteState` or `checkProofStates`,
never a retry. And **`meltProofs` refuses to submit a proof whose P2PK witness
is missing or invalid**, because by the time a terminal is assembling a melt the
card has already marked its slots spent; failing locally leaves the proof
intact, whereas failing at the mint does not.

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
