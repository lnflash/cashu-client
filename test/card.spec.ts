import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  attachP2PKWitness,
  buildP2PKSecret,
  CashuInvalidCardPubkeyError,
  CashuInvalidProofError,
  createBlindedMessage,
  parseP2PKSecret,
  p2pkMessageToSign,
  reconstructProofFromCard,
  reconstructProofsFromCard,
  verifyP2PKWitness,
} from "../src"
import type { CardProofSlot } from "../src"

const makeCardKey = () => {
  let d: Buffer
  do {
    d = crypto.randomBytes(32)
  } while (!secp.isPrivate(d))
  const pub = Buffer.from(secp.pointFromScalar(d, true)!).toString("hex")
  return { d, pub }
}

const card = makeCardKey()

const slot = (over: Partial<CardProofSlot> = {}): CardProofSlot => ({
  keysetId: "0059534ce0bfa19a",
  amount: 8,
  nonce: "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e",
  C: "02" + "ab".repeat(32),
  ...over,
})

describe("reconstructProofFromCard", () => {
  it("rebuilds a proof whose secret matches the canonical P2PK serialization", () => {
    const s = slot()
    const proof = reconstructProofFromCard(s, card.pub)

    expect(proof.id).toBe(s.keysetId)
    expect(proof.amount).toBe(8)
    expect(proof.C).toBe(s.C)
    expect(proof.secret).toBe(buildP2PKSecret(s.nonce, card.pub))
  })

  it("produces a secret the P2PK parser accepts and that locks to the card", () => {
    const proof = reconstructProofFromCard(slot(), card.pub)
    const parsed = parseP2PKSecret(proof.secret)

    expect(parsed).not.toBeNull()
    expect(parsed!.data).toBe(card.pub)
    expect(parsed!.nonce).toBe(slot().nonce)
  })

  it("round-trips: a card signature over the rebuilt proof verifies", () => {
    // This is the whole point — a reconstructed proof must be spendable with a
    // signature the card produced over it.
    const proof = reconstructProofFromCard(slot(), card.pub)
    const msg = p2pkMessageToSign(proof)
    const sig = Buffer.from(secp.signSchnorr(msg, card.d)).toString("hex")

    expect(verifyP2PKWitness(attachP2PKWitness(proof, [sig]))).toBe(true)
  })

  it("rejects a signature from a different key", () => {
    const other = makeCardKey()
    const proof = reconstructProofFromCard(slot(), card.pub)
    const sig = Buffer.from(
      secp.signSchnorr(p2pkMessageToSign(proof), other.d),
    ).toString("hex")

    expect(verifyP2PKWitness(attachP2PKWitness(proof, [sig]))).toBe(false)
  })

  it("returns no witness — the proof is not yet spendable", () => {
    expect(reconstructProofFromCard(slot(), card.pub).witness).toBeUndefined()
  })

  it("normalises the keyset id to lower case", () => {
    const upper = reconstructProofFromCard(
      slot({ keysetId: "0059534CE0BFA19A" }),
      card.pub,
    )
    expect(upper.id).toBe("0059534ce0bfa19a")
  })

  // The only agreement that matters is with the secret committed to at *mint*
  // time — comparing reconstruction against reconstruction proves nothing,
  // because both sides normalise. `Y = hash_to_curve(secret)` is over the
  // secret's UTF-8 bytes, so a case difference between the two paths is a proof
  // the mint never signed: verifyP2PKWitness hex-decodes the pubkey and so says
  // `true` regardless, the card burns the slot, and only the mint objects.
  describe.each([
    ["lower-case reader output", (h: string) => h.toLowerCase()],
    // `String.format("%02X")` is the idiomatic Java bytes-to-hex, and the
    // counterparty here is a Javacard reader.
    ["upper-case reader output", (h: string) => h.toUpperCase()],
  ])("mint-time and reconstructed secrets agree — %s", (_label, cased) => {
    it("produces the byte-identical secret createBlindedMessage committed to", () => {
      const pubkey = cased(card.pub)
      const bd = createBlindedMessage("0059534ce0bfa19a", 8, pubkey)
      const proof = reconstructProofFromCard(slot({ nonce: cased(bd.nonce) }), pubkey)

      expect(proof.secret).toBe(bd.secretStr)
    })
  })

  it("a card signature over a proof rebuilt from upper-case reader output verifies", () => {
    const pubkey = card.pub.toUpperCase()
    const bd = createBlindedMessage("0059534ce0bfa19a", 8, pubkey)
    const proof = reconstructProofFromCard(slot({ nonce: bd.nonce.toUpperCase() }), pubkey)
    const sig = Buffer.from(
      secp.signSchnorr(p2pkMessageToSign(proof), card.d),
    ).toString("hex")

    expect(proof.secret).toBe(bd.secretStr)
    expect(verifyP2PKWitness(attachP2PKWitness(proof, [sig]))).toBe(true)
  })

  // Every rejection asserts its error *class* as well as its message. A caller
  // has to decide between "this card's key is bad, abort the card" and "this
  // slot is corrupt, skip it", and it cannot make that call by regex-matching
  // messages — so the class is part of the contract, not decoration.
  describe("rejects malformed input rather than producing an unspendable proof", () => {
    it("half-length keyset id — the ASCII-truncation bug", () => {
      // 8 hex chars is what ASCII-encoding a keyset id into 8 bytes produces.
      expect(() => reconstructProofFromCard(slot({ keysetId: "0059534c" }), card.pub))
        .toThrow(/keysetId must be 8 bytes/)
      expect(() => reconstructProofFromCard(slot({ keysetId: "0059534c" }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("non-hex keyset id", () => {
      expect(() => reconstructProofFromCard(slot({ keysetId: "zzzz534ce0bfa19a" }), card.pub))
        .toThrow(/keysetId must be hex/)
      expect(() => reconstructProofFromCard(slot({ keysetId: "zzzz534ce0bfa19a" }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("short nonce", () => {
      expect(() => reconstructProofFromCard(slot({ nonce: "ab".repeat(16) }), card.pub))
        .toThrow(/nonce must be 32 bytes/)
      expect(() => reconstructProofFromCard(slot({ nonce: "ab".repeat(16) }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    // A reader bridge that omits a field is the one input shape that used to
    // escape as `Cannot read properties of undefined (reading 'trim')` — a stack
    // trace from inside a module whose whole job is turning reader garbage into
    // a diagnosis.
    it.each(["nonce", "keysetId", "C"] as const)("missing %s", field => {
      const bad = { ...slot(), [field]: undefined } as unknown as CardProofSlot
      expect(() => reconstructProofFromCard(bad, card.pub))
        .toThrow(`${field} must be a hex string, got undefined`)
      expect(() => reconstructProofFromCard(bad, card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("missing card pubkey", () => {
      const missing = undefined as unknown as string
      expect(() => reconstructProofFromCard(slot(), missing))
        .toThrow("cardPubkey must be a hex string, got undefined")
      expect(() => reconstructProofFromCard(slot(), missing))
        .toThrow(CashuInvalidCardPubkeyError)
    })

    it("non-string nonce — a reader bridge handing over raw bytes", () => {
      const bad = { ...slot(), nonce: Buffer.alloc(32) } as unknown as CardProofSlot
      expect(() => reconstructProofFromCard(bad, card.pub))
        .toThrow(/nonce must be a hex string, got object/)
    })

    it("keyset id with a non-zero version byte", () => {
      // 8 bytes is the only NUT-02 id version that fits the card's field, so a
      // first byte other than 00 is corruption, not a newer id format.
      expect(() => reconstructProofFromCard(slot({ keysetId: "ff59534ce0bfa19a" }), card.pub))
        .toThrow(/keysetId must be a NUT-02 v0 id/)
      expect(() => reconstructProofFromCard(slot({ keysetId: "ff59534ce0bfa19a" }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("uncompressed C point", () => {
      expect(() => reconstructProofFromCard(slot({ C: "04" + "ab".repeat(32) }), card.pub))
        .toThrow(/C must be a compressed/)
      expect(() => reconstructProofFromCard(slot({ C: "04" + "ab".repeat(32) }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("uncompressed card pubkey", () => {
      expect(() => reconstructProofFromCard(slot(), "04" + "cd".repeat(32)))
        .toThrow(/cardPubkey must be a compressed/)
      expect(() => reconstructProofFromCard(slot(), "04" + "cd".repeat(32)))
        .toThrow(CashuInvalidCardPubkeyError)
    })

    // A prefix-character test (`v[1] === "2" || v[1] === "3"`) accepts every one
    // of these; only a curve check rejects them.
    it("C whose low nibble is 2 but whose prefix byte is not 02/03", () => {
      const bad = "12" + "ab".repeat(32)
      expect(secp.isPoint(Buffer.from(bad, "hex"))).toBe(false)
      expect(() => reconstructProofFromCard(slot({ C: bad }), card.pub))
        .toThrow(/C must be a compressed/)
      expect(() => reconstructProofFromCard(slot({ C: bad }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("card pubkey whose low nibble is 2 but whose prefix byte is not 02/03", () => {
      const bad = "12" + "ab".repeat(32)
      expect(secp.isPoint(Buffer.from(bad, "hex"))).toBe(false)
      expect(() => reconstructProofFromCard(slot(), bad))
        .toThrow(/cardPubkey must be a compressed/)
      expect(() => reconstructProofFromCard(slot(), bad))
        .toThrow(CashuInvalidCardPubkeyError)
    })

    it("off-curve C with a valid 02 prefix", () => {
      const offCurve = "02" + "00".repeat(32)
      // Asserted so the fixture cannot silently become a valid point.
      expect(secp.isPoint(Buffer.from(offCurve, "hex"))).toBe(false)
      expect(() => reconstructProofFromCard(slot({ C: offCurve }), card.pub))
        .toThrow(/C must be a compressed/)
      expect(() => reconstructProofFromCard(slot({ C: offCurve }), card.pub))
        .toThrow(CashuInvalidProofError)
    })

    it("off-curve card pubkey with a valid 02 prefix", () => {
      const offCurve = "02" + "00".repeat(32)
      expect(secp.isPoint(Buffer.from(offCurve, "hex"))).toBe(false)
      expect(() => reconstructProofFromCard(slot(), offCurve))
        .toThrow(/cardPubkey must be a compressed/)
      expect(() => reconstructProofFromCard(slot(), offCurve))
        .toThrow(CashuInvalidCardPubkeyError)
    })

    it("wrong-length pubkey", () => {
      expect(() => reconstructProofFromCard(slot(), "02" + "cd".repeat(20)))
        .toThrow(/cardPubkey must be 33 bytes/)
      expect(() => reconstructProofFromCard(slot(), "02" + "cd".repeat(20)))
        .toThrow(CashuInvalidCardPubkeyError)
    })

    it.each([0, -1, 1.5, 3])("non-positive, fractional or non-power-of-two amount: %p", amount => {
      expect(() => reconstructProofFromCard(slot({ amount }), card.pub))
        .toThrow(/amount must be a positive power of two/)
      expect(() => reconstructProofFromCard(slot({ amount }), card.pub))
        .toThrow(CashuInvalidProofError)
    })
  })
})

describe("reconstructProofsFromCard", () => {
  it("preserves order and reconstructs each slot", () => {
    const slots = [
      slot({ amount: 1, nonce: "11".repeat(32) }),
      slot({ amount: 2, nonce: "22".repeat(32) }),
      slot({ amount: 4, nonce: "33".repeat(32) }),
    ]
    const proofs = reconstructProofsFromCard(slots, card.pub)

    expect(proofs.map(p => p.amount)).toEqual([1, 2, 4])
    expect(new Set(proofs.map(p => p.secret)).size).toBe(3)
  })

  it("fails the batch if any slot is malformed, naming the slot index", () => {
    expect(() =>
      reconstructProofsFromCard([slot(), slot({ nonce: "00" })], card.pub),
    ).toThrow(/slot 1: nonce must be 32 bytes/)
  })

  it("names the slot index for a missing field instead of a TypeError", () => {
    const bad = { ...slot(), nonce: undefined } as unknown as CardProofSlot
    expect(() => reconstructProofsFromCard([slot(), bad], card.pub))
      .toThrow("slot 1: nonce must be a hex string, got undefined")
  })

  // Re-labelling with the index must not flatten the error: a caller still has
  // to tell a bad card key from a corrupt slot, and the original is still the
  // only thing carrying the stack of the check that actually failed.
  it("preserves the error class and the original as `cause`", () => {
    const run = () => reconstructProofsFromCard([slot(), slot({ nonce: "00" })], card.pub)
    expect(run).toThrow(CashuInvalidProofError)

    let thrown: unknown
    try {
      run()
    } catch (e) {
      thrown = e
    }
    expect((thrown as { cause?: unknown }).cause).toBeInstanceOf(CashuInvalidProofError)
    expect(((thrown as { cause?: Error }).cause as Error).message)
      .toBe("nonce must be 32 bytes (64 hex chars), got 2")
  })

  it("a bad card key stays distinguishable from a bad slot on the batch path", () => {
    expect(() => reconstructProofsFromCard([slot()], "04" + "cd".repeat(32)))
      .toThrow(CashuInvalidCardPubkeyError)
    expect(() => reconstructProofsFromCard([slot()], "04" + "cd".repeat(32)))
      .toThrow(/slot 0: cardPubkey must be a compressed/)
  })

  it("handles an empty card", () => {
    expect(reconstructProofsFromCard([], card.pub)).toEqual([])
  })
})
