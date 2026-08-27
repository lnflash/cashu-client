import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  attachP2PKWitness,
  buildP2PKSecret,
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

  it("normalises hex case without changing the secret's meaning", () => {
    const upper = reconstructProofFromCard(
      slot({ keysetId: "0059534CE0BFA19A" }),
      card.pub.toUpperCase(),
    )
    expect(upper.id).toBe("0059534ce0bfa19a")
    expect(upper.secret).toBe(reconstructProofFromCard(slot(), card.pub).secret)
  })

  describe("rejects malformed input rather than producing an unspendable proof", () => {
    it("half-length keyset id — the ASCII-truncation bug", () => {
      // 8 hex chars is what ASCII-encoding a keyset id into 8 bytes produces.
      expect(() => reconstructProofFromCard(slot({ keysetId: "0059534c" }), card.pub))
        .toThrow(/keysetId must be 8 bytes/)
    })

    it("non-hex keyset id", () => {
      expect(() => reconstructProofFromCard(slot({ keysetId: "zzzz534ce0bfa19a" }), card.pub))
        .toThrow(/keysetId must be hex/)
    })

    it("short nonce", () => {
      expect(() => reconstructProofFromCard(slot({ nonce: "ab".repeat(16) }), card.pub))
        .toThrow(/nonce must be 32 bytes/)
    })

    it("uncompressed C point", () => {
      expect(() => reconstructProofFromCard(slot({ C: "04" + "ab".repeat(32) }), card.pub))
        .toThrow(/C must be a compressed/)
    })

    it("uncompressed card pubkey", () => {
      expect(() => reconstructProofFromCard(slot(), "04" + "cd".repeat(32)))
        .toThrow(/cardPubkey must be a compressed/)
    })

    it("wrong-length pubkey", () => {
      expect(() => reconstructProofFromCard(slot(), "02" + "cd".repeat(20)))
        .toThrow(/cardPubkey must be 33 bytes/)
    })

    it.each([0, -1, 1.5])("non-positive or fractional amount: %p", amount => {
      expect(() => reconstructProofFromCard(slot({ amount }), card.pub))
        .toThrow(/amount must be a positive integer/)
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

  it("fails the batch if any slot is malformed", () => {
    expect(() =>
      reconstructProofsFromCard([slot(), slot({ nonce: "00" })], card.pub),
    ).toThrow(/nonce must be 32 bytes/)
  })

  it("handles an empty card", () => {
    expect(reconstructProofsFromCard([], card.pub)).toEqual([])
  })
})
