# @lnflash/cashu-client

Cashu NFC card client library — crypto primitives and [Nutshell](https://github.com/cashubtc/nutshell) mint HTTP client.

Part of the [Cashu-First Flash Cards](https://github.com/lnflash/cashu-javacard)
project — a physical card holding Bitcoin-denominated ecash on its own chip,
spendable by tap with no phone, no account and no internet at the point of sale.

This library is the **host half**: the card itself does no blinding, no mint
communication and no verification. It stores proofs and signs. Everything else
happens here.

| To understand… | Read |
|---|---|
| Why the project exists | [VISION](https://github.com/lnflash/cashu-javacard/blob/main/docs/VISION.md) |
| How the pieces fit | [ARCHITECTURE](https://github.com/lnflash/cashu-javacard/blob/main/docs/ARCHITECTURE.md) |
| Why the API refuses things | [DECISIONS](https://github.com/lnflash/cashu-javacard/blob/main/docs/DECISIONS.md) |
| What an attacker can do | [SECURITY-MODEL](https://github.com/lnflash/cashu-javacard/blob/main/docs/SECURITY-MODEL.md) |
| A term you don't know | [GLOSSARY](https://github.com/lnflash/cashu-javacard/blob/main/docs/GLOSSARY.md) |

## What's in here

| Module | Description |
|--------|-------------|
| `crypto` | NUT-00 `hash_to_curve`, NUT-03 BDHKE blinding/unblinding, NUT-10 P2PK secret serialization, denomination splitting |
| `card` | Reconstructing a spendable proof from a card's 78-byte slot layout — NUT-10 P2PK secret recovery |
| `cardFile` | The interchange format between this library and the Python card driver — one schema both sides validate against |
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
| **Load** a card | `requestMintQuote` → pay → `mintProofs` → `unblindSignature` + `proofDLEQFromBlindSignature` → `serializeCardFile` → cardctl `LOAD_PROOF` |
| **Verify** what's on it | `verifyProofDLEQ` (offline) or `checkProofStates` (online) |
| **Spend** at a terminal | `GET_PROOF` → `parseCardFile` → `reconstructProofsFromCard` → `requestMeltQuote` → `selectProofsForMelt` → card signs `p2pkMessageToSign` → `attachP2PKWitness` → `meltProofs` |
| **Make change** | `swapProofs` |

#### Crossing to the card: the card file

The card driver ([`tools/cardctl`](https://github.com/lnflash/cashu-javacard))
is dependency-free Python so it runs anywhere a reader does; this library is
TypeScript. Neither can call the other, so proofs cross as a file — and the
schema for it lives here, in `cardFile`, rather than in either CLI. Both sides
validate against the same definition, so a field that drifts fails at the
boundary instead of at the mint, where the card may already have burned the
slot on `SPEND_PROOF`.

```jsonc
{
  "version": 1,
  "mint": "https://forge.flashapp.me",
  "unit": "sat",
  "cardPubkey": "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da",
  "slots": [
    {
      "keysetId": "0059534ce0bfa19a",
      "amount": 8,
      "nonce": "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e",
      "C": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    }
  ],
  "note": "loaded at till 2"
}
```

```typescript
import {
  serializeCardFile,
  parseCardFile,
  cardFileTotal,
  reconstructProofsFromCard,
} from "@lnflash/cashu-client"

// mint → card: hand this to cardctl to load. `blindingData` is what
// createBlindedMessage returned — it carries the 32-byte nonce the card
// stores, which is not recoverable from anything else in the proof.
const json = serializeCardFile({
  mint: MINT_URL,
  unit: "sat",
  cardPubkey,
  slots: proofs.map((p, i) => ({
    keysetId: p.id,
    amount: p.amount,
    nonce: blindingData[i].nonce, // the 32-byte nonce, not the ~150-byte secret
    C: p.C,
  })),
  note: "loaded at till 2",
})

// card → mint: what cardctl dumped, ready to spend.
const card = parseCardFile(await fs.readFile("card.json", "utf8"))
if (card.mint !== MINT_URL) throw new Error("card is from a different mint")
const spendable = reconstructProofsFromCard(card.slots, card.cardPubkey)
console.log(`${cardFileTotal(card)} ${card.unit} across ${card.slots.length} slots`)
```

**The wire shape is the card's vocabulary, not `CashuProof`'s.** `nonce`, not
`secret`, and `keysetId` as 16 hex chars — because that is what the card
actually stores. A file that said `secret` would invite ~150 bytes of P2PK JSON
into a field that holds 32 bytes, so that spelling is rejected by name.

**`serializeCardFile` is the only gate in the mint → card direction.** cardctl
does no curve math, so whatever this writes reaches the card. It therefore
round-trips the file through `parseCardFile` *and* through the redeem path
(`reconstructProofsFromCard`, result discarded) before returning: what it
writes is, by construction, what the spend path reads back. An on-prefix but
off-curve `C` would otherwise load fine, burn the slot on `SPEND_PROOF`, and be
rejected by the mint as a proof that was never spendable.

**Both directions refuse rather than repair.** Unknown fields (bump `version`
instead of adding one silently), a `note` that is not a string, a non-v0 or
half-length `keysetId`, an amount that is not a positive power of two, a mint
URL the HTTP sanitiser refuses, and — the one shape every per-slot check
otherwise waves through — **the same `C` in two slots**. Duplicate slots both
load; the first redeems, the second burns on `SPEND_PROOF` and comes back
already-spent, while `cardFileTotal` told the holder the card was worth double.
`mint` and `unit` come back canonicalised, so the `card.mint !== MINT_URL`
comparison above is not defeated by a trailing slash.

Five things worth knowing before wiring this up.

**A card slot is not a proof.** A NUT-10 P2PK secret is ~150 bytes of JSON and a
slot is 78 bytes total, so the card stores the 32-byte *nonce* and nothing else;
`reconstructProofsFromCard` rebuilds the secret from the nonce, the card's public
key and the fixed tag set. Without that step `GET_PROOF` gives you bytes and no
`CashuProof` to hand `selectProofsForMelt`. It throws on a malformed slot rather
than returning a proof the mint will reject — by then the card may already have
burned the slot on `SPEND_PROOF`. Pass `{skipInvalid: true}` to get
`{proofs, failures}` back instead and read the rest of a card around one corrupt
slot; check each failure's class first, since a bad *card key* fails every slot
and means abort the card, not skip a slot.

**Melt and swap are not idempotent** — the inputs are consumed when the mint
accepts them, so after a lost response the correct move is `getMeltQuoteState`
or `checkProofStates`, never a retry.

**`meltProofs` refuses to submit a proof whose P2PK witness is missing or
invalid**, because by the time a terminal is assembling a melt the card has
already marked its slots spent; failing locally leaves the proof intact, whereas
failing at the mint does not. The local check honours the secret's `sigflag` and
`n_sigs` tags, and refuses outright on a tag it does not implement — or on a tag
it cannot parse, since a dropped tag is indistinguishable from an absent one. A
check looser than the mint's would pass locally and still burn the slots. Same
reasoning for a NUT-10 secret of a kind this library cannot verify (an HTLC, or
a P2PK secret with a malformed body): it is reported by `findUnsignedProofs`
rather than treated as an unlocked, witness-free proof.

**Overpay is silent.** `changeOutputs` on `meltProofs` is optional and anything
overpaid without them is kept by the mint, so `selectProofsForMelt` minimises
the overpay rather than taking the largest proof that fits. If the mint charges
a NUT-02 `input_fee_ppk`, pass it to `selectProofsForMelt` and `swapProofs` —
otherwise every request is short by exactly the fee and gets rejected. The rate
is declared *per keyset*, so once a rotation leaves a card holding proofs from
two of them, pass a `{[keysetId]: input_fee_ppk}` map instead of one number; a
single rate applied to a mixed set is refused rather than mispriced.

**The error-returning calls return errors, not falsy values.** These functions
return `T | CashuMintError` rather than throwing, so check before use.
`allProofsUnspent` in particular returns `"UNSPENT" | "NOT_UNSPENT" |
CashuMintError` and never a bare boolean: an error is a truthy object, so a
boolean union would make `if (await allProofsUnspent(...))` read a mint timeout
as "safe to accept" — the inverse of the double-spend check's purpose.

## Install

```bash
# yarn v1 (git dep, no npm publish needed)
yarn add github:lnflash/cashu-client#v0.5.0

# or via npm
npm install @lnflash/cashu-client
```

## Usage

```typescript
import {
  splitIntoDenominations,
  createBlindedMessage,
  unblindSignature,
  proofDLEQFromBlindSignature,
  verifyProofDLEQ,
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

// 6. Unblind signatures → final proofs, carrying the mint's DLEQ across
//    (proofDLEQFromBlindSignature pairs the mint's e/s with the blinding
//    factor r, which is what makes the offline check in step 7 possible)
const proofs = sigs.map((sig, i) => ({
  id: sig.id,
  amount: sig.amount,
  secret: blindingData[i].secretStr,
  C: unblindSignature(sig.C_, blindingData[i].r, keysetDetail.keys[String(sig.amount)]),
  dleq: proofDLEQFromBlindSignature(sig, blindingData[i].r),
}))

// 7. Verify offline — no mint contact, no trust in whoever handed these over.
//    Undefined dleq means the mint emits none; that is a policy call for you.
const mintKey = amount => keysetDetail.keys[String(amount)]
const verified = proofs.every(p => !p.dleq || verifyProofDLEQ(p, mintKey(p.amount)))
```

## Compatibility

**0.4.0 changes `buildP2PKSecret` output for upper-case hex input.** It now
lower-cases the nonce and the card pubkey, so the serialization has one canonical
form. Proofs minted by **0.3.0 or earlier with an upper-case `cardPubkey` are not
reconstructable by this version**: the secret is committed to at mint time as
UTF-8 bytes — `Y = hash_to_curve(secret)` — so the canonical secret is a
different proof, one the mint has never signed.

Cards funded that way stay redeemable via the escape hatch:

```typescript
// Try canonical first; fall back only if the mint rejects the proof as unknown.
const legacy = reconstructProofFromCard(slot, cardPubkey, {legacyHexCase: true})
```

The hatch freezes the case of `data` only. Pre-0.4.0 `createBlindedMessage`
generated the nonce here as lower-case hex and never read one off a card, so the
card key is the only field whose case could ever have reached a minted secret —
freezing the nonce's too would build a secret no released version ever minted,
and you would find out at the mint, after `SPEND_PROOF` burned the slot.

Never mint with `legacyHexCase`. It exists to spend what the old code already
locked, not to produce more of it. See [CHANGELOG.md](CHANGELOG.md).

## Spec

- [NUT-XX: Cashu NFC Card Protocol](https://github.com/lnflash/cashu-javacard/blob/main/spec/NUT-XX.md)
- [JavaCard applet](https://github.com/lnflash/cashu-javacard)

## License

MIT
