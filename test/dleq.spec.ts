import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  createBlindedMessage,
  hashE,
  hasDLEQ,
  hashToCurve,
  unblindSignature,
  verifyBlindSignatureDLEQ,
  verifyProofDLEQ,
} from "../src"
import type { CashuBlindSignature, CashuDLEQ, CashuProof } from "../src"
import {
  blindSignWithDLEQ,
  cardPubkey,
  makeMint,
  randomScalar,
} from "./helpers/nut12"

/**
 * These tests use the *mint* side of NUT-12 (see ./helpers/nut12) so the
 * verifier is checked against a genuinely valid proof rather than a fixture
 * someone transcribed. A verifier that always returns true passes any
 * positive-only test; the tampering cases below are what force it to actually
 * do the arithmetic.
 */

describe("NUT-12 DLEQ on blind signatures", () => {
  it("accepts a correctly constructed proof", () => {
    const mint = makeMint()
    const blinding = createBlindedMessage("0059534ce0bfa19a", 8, cardPubkey())
    const {C_hex, dleq} = blindSignWithDLEQ(mint, blinding.B_)

    const sig: CashuBlindSignature & {dleq: CashuDLEQ} = {
      id: "0059534ce0bfa19a", amount: 8, C_: C_hex, dleq,
    }
    expect(verifyBlindSignatureDLEQ(sig, mint.AHex, blinding.B_)).toBe(true)
  })

  it("rejects a proof made with a different key — the tagging attack", () => {
    const honest = makeMint()
    const sneaky = makeMint()
    const blinding = createBlindedMessage("0059534ce0bfa19a", 8, cardPubkey())

    // The mint signs with a per-user key but publishes the honest one. This is
    // precisely what DLEQ exists to catch.
    const {C_hex, dleq} = blindSignWithDLEQ(sneaky, blinding.B_)
    const sig: CashuBlindSignature & {dleq: CashuDLEQ} = {
      id: "0059534ce0bfa19a", amount: 8, C_: C_hex, dleq,
    }
    expect(verifyBlindSignatureDLEQ(sig, honest.AHex, blinding.B_)).toBe(false)
  })

  it("rejects tampered scalars and a tampered C_", () => {
    const mint = makeMint()
    const blinding = createBlindedMessage("0059534ce0bfa19a", 8, cardPubkey())
    const {C_hex, dleq} = blindSignWithDLEQ(mint, blinding.B_)
    const base = {id: "0059534ce0bfa19a", amount: 8, C_: C_hex}

    const bumpHex = (hex: string) => {
      const b = Buffer.from(hex, "hex")
      b[31] ^= 0x01
      return b.toString("hex")
    }

    expect(verifyBlindSignatureDLEQ({...base, dleq: {...dleq, s: bumpHex(dleq.s)}}, mint.AHex, blinding.B_)).toBe(false)
    expect(verifyBlindSignatureDLEQ({...base, dleq: {...dleq, e: bumpHex(dleq.e)}}, mint.AHex, blinding.B_)).toBe(false)
    expect(verifyBlindSignatureDLEQ({...base, C_: bumpHex(C_hex)}, mint.AHex, blinding.B_)).toBe(false)
  })

  it("rejects a signature with no DLEQ at all", () => {
    const mint = makeMint()
    const blinding = createBlindedMessage("0059534ce0bfa19a", 8, cardPubkey())
    const {C_hex} = blindSignWithDLEQ(mint, blinding.B_)
    expect(verifyBlindSignatureDLEQ({id: "x", amount: 8, C_: C_hex}, mint.AHex, blinding.B_)).toBe(false)
  })

  it("rejects malformed scalar lengths without throwing", () => {
    const mint = makeMint()
    const blinding = createBlindedMessage("0059534ce0bfa19a", 8, cardPubkey())
    const {C_hex} = blindSignWithDLEQ(mint, blinding.B_)
    const sig = {id: "x", amount: 8, C_: C_hex, dleq: {e: "aa", s: "bb"}}
    expect(verifyBlindSignatureDLEQ(sig, mint.AHex, blinding.B_)).toBe(false)
  })
})

describe("NUT-12 DLEQ on unblinded proofs", () => {
  /** Full issuance: blind, mint-sign with DLEQ, unblind, carry r onto the proof. */
  const issue = (mint: ReturnType<typeof makeMint>) => {
    const blinding = createBlindedMessage("0059534ce0bfa19a", 8, cardPubkey())
    const {C_hex, dleq} = blindSignWithDLEQ(mint, blinding.B_)
    const C = unblindSignature(C_hex, blinding.r, mint.AHex)
    const proof: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: blinding.secretStr,
      C,
      dleq: {...dleq, r: Buffer.from(blinding.r).toString("hex")},
    }
    return proof
  }

  it("verifies offline, with no mint contact", () => {
    const mint = makeMint()
    expect(verifyProofDLEQ(issue(mint), mint.AHex)).toBe(true)
  })

  it("rejects the proof under a different mint key", () => {
    const mint = makeMint()
    expect(verifyProofDLEQ(issue(mint), makeMint().AHex)).toBe(false)
  })

  it("rejects a proof whose C has been swapped", () => {
    const mint = makeMint()
    const a = issue(mint)
    const b = issue(mint)
    expect(verifyProofDLEQ({...a, C: b.C}, mint.AHex)).toBe(false)
  })

  it("rejects a proof whose secret has been altered", () => {
    const mint = makeMint()
    const proof = issue(mint)
    expect(verifyProofDLEQ({...proof, secret: proof.secret + " "}, mint.AHex)).toBe(false)
  })

  it("needs the blinding factor r", () => {
    const mint = makeMint()
    const proof = issue(mint)
    expect(hasDLEQ(proof)).toBe(true)
    const withoutR = {...proof, dleq: {e: proof.dleq!.e, s: proof.dleq!.s}}
    expect(hasDLEQ(withoutR)).toBe(false)
    expect(verifyProofDLEQ(withoutR, mint.AHex)).toBe(false)
  })
})

describe("hash_e", () => {
  it("hashes the uncompressed form — the compressed form gives a different digest", () => {
    const point = Buffer.from(secp.pointFromScalar(randomScalar(), true)!)
    const overUncompressed = hashE([point])
    const overCompressed = crypto
      .createHash("sha256")
      .update(Buffer.from(point.toString("hex"), "utf8"))
      .digest()
    expect(overUncompressed.equals(overCompressed)).toBe(false)
    expect(overUncompressed).toHaveLength(32)
  })

  it("is order-sensitive", () => {
    const p1 = Buffer.from(secp.pointFromScalar(randomScalar(), true)!)
    const p2 = Buffer.from(secp.pointFromScalar(randomScalar(), true)!)
    expect(hashE([p1, p2]).equals(hashE([p2, p1]))).toBe(false)
  })
})

describe("hash_to_curve reuse", () => {
  it("still yields a valid point for a P2PK secret", () => {
    const y = hashToCurve(Buffer.from("test-secret", "utf8"))
    expect(secp.isPoint(Buffer.from(y))).toBe(true)
  })
})
