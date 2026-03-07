import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  hashToCurve,
  splitIntoDenominations,
  buildP2PKSecret,
  createBlindedMessage,
  unblindSignature,
} from "../src"

// ---------------------------------------------------------------------------
// hashToCurve
// ---------------------------------------------------------------------------

describe("hashToCurve", () => {
  it("returns a valid compressed secp256k1 point for a known input", () => {
    const secret = Buffer.alloc(32, 0x00)
    const point = hashToCurve(secret)
    expect(point).toHaveLength(33)
    expect(secp.isPoint(point)).toBe(true)
    expect(point[0] === 0x02 || point[0] === 0x03).toBe(true)
  })

  it("returns a valid point for a random input", () => {
    const secret = crypto.randomBytes(32)
    const point = hashToCurve(secret)
    expect(point).toHaveLength(33)
    expect(secp.isPoint(point)).toBe(true)
  })

  it("is deterministic — same input produces same output", () => {
    const secret = Buffer.from("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "hex")
    const p1 = hashToCurve(secret)
    const p2 = hashToCurve(secret)
    expect(Buffer.from(p1).toString("hex")).toBe(Buffer.from(p2).toString("hex"))
  })

  it("produces different points for different inputs", () => {
    const a = hashToCurve(Buffer.alloc(32, 0x01))
    const b = hashToCurve(Buffer.alloc(32, 0x02))
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"))
  })
})

// ---------------------------------------------------------------------------
// splitIntoDenominations
// ---------------------------------------------------------------------------

describe("splitIntoDenominations", () => {
  it("splits 1 cent correctly", () => {
    expect(splitIntoDenominations(1)).toEqual([1])
  })

  it("splits 3 cents into [2, 1]", () => {
    expect(splitIntoDenominations(3)).toEqual([2, 1])
  })

  it("splits 100 cents into [64, 32, 4]", () => {
    expect(splitIntoDenominations(100)).toEqual([64, 32, 4])
  })

  it("splits 500 cents into correct denominations", () => {
    const denoms = splitIntoDenominations(500)
    expect(denoms.reduce((a, b) => a + b, 0)).toBe(500)
    denoms.forEach((d) => expect(Math.log2(d) % 1).toBe(0))
  })

  it("sum of denominations always equals the input", () => {
    for (const amount of [1, 7, 50, 99, 128, 255, 1000, 32767]) {
      const denoms = splitIntoDenominations(amount)
      expect(denoms.reduce((a, b) => a + b, 0)).toBe(amount)
    }
  })

  it("returns empty array for 0", () => {
    expect(splitIntoDenominations(0)).toEqual([])
  })

  it("throws CashuInsufficientSlotsError when maxSlots is exceeded", () => {
    // 100 = [64, 32, 4] = 3 denominations; maxSlots=2 should throw
    const { CashuInsufficientSlotsError } = require("../src")
    expect(() => splitIntoDenominations(100, 2)).toThrow(CashuInsufficientSlotsError)
  })

  it("does not throw when denominations fit within maxSlots", () => {
    // 100 = [64, 32, 4] = 3 denominations; maxSlots=3 is exactly enough
    expect(() => splitIntoDenominations(100, 3)).not.toThrow()
    expect(() => splitIntoDenominations(100, 32)).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// buildP2PKSecret
// ---------------------------------------------------------------------------

describe("buildP2PKSecret", () => {
  it("produces canonical NUT-10 P2PK JSON with no spaces", () => {
    const nonce = "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e"
    const pubkey = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    const secret = buildP2PKSecret(nonce, pubkey)

    const parsed = JSON.parse(secret)
    expect(parsed[0]).toBe("P2PK")
    expect(parsed[1].nonce).toBe(nonce)
    expect(parsed[1].data).toBe(pubkey)
    expect(parsed[1].tags).toEqual([["sigflag", "SIG_INPUTS"]])
    expect(secret).not.toContain(" ")

    const keys = Object.keys(parsed[1])
    expect(keys).toEqual(["nonce", "data", "tags"])
  })

  it("matches NUT-XX worked example exactly", () => {
    const nonce = "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e"
    const pubkey = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"
    const expected =
      `["P2PK",{"nonce":"${nonce}","data":"${pubkey}","tags":[["sigflag","SIG_INPUTS"]]}]`
    expect(buildP2PKSecret(nonce, pubkey)).toBe(expected)
  })
})

// ---------------------------------------------------------------------------
// createBlindedMessage + unblindSignature (round-trip)
// ---------------------------------------------------------------------------

describe("createBlindedMessage + unblindSignature", () => {
  it("B_ is a valid secp256k1 point", () => {
    let cardPriv: Uint8Array
    do { cardPriv = crypto.randomBytes(32) } while (!secp.isPrivate(cardPriv))
    const cardPub = secp.pointFromScalar(cardPriv, true)!
    const cardPubHex = Buffer.from(cardPub).toString("hex")

    const bd = createBlindedMessage("0059534ce0bfa19a", 4, cardPubHex)
    const B_bytes = Buffer.from(bd.B_, "hex")
    expect(secp.isPoint(B_bytes)).toBe(true)
    expect(B_bytes).toHaveLength(33)
  })

  it("round-trip: unblind(mint_sign(B_)) == hash_to_curve(secret)", () => {
    let mintPriv: Uint8Array
    do { mintPriv = crypto.randomBytes(32) } while (!secp.isPrivate(mintPriv))
    const mintPub = secp.pointFromScalar(mintPriv, true)!
    const mintPubHex = Buffer.from(mintPub).toString("hex")

    let cardPriv: Uint8Array
    do { cardPriv = crypto.randomBytes(32) } while (!secp.isPrivate(cardPriv))
    const cardPub = secp.pointFromScalar(cardPriv, true)!
    const cardPubHex = Buffer.from(cardPub).toString("hex")

    const bd = createBlindedMessage("0059534ce0bfa19a", 8, cardPubHex)
    const B_bytes = Buffer.from(bd.B_, "hex")

    const C_ = secp.pointMultiply(B_bytes, mintPriv, true)
    expect(C_).not.toBeNull()
    const C_hex = Buffer.from(C_!).toString("hex")

    const C_unblinded = unblindSignature(C_hex, bd.r, mintPubHex)

    const secretStr = buildP2PKSecret(bd.nonce, cardPubHex)
    const secretBytes = Buffer.from(secretStr, "utf8")
    const Y = hashToCurve(secretBytes)
    const C_expected = secp.pointMultiply(Y, mintPriv, true)!
    const C_expected_hex = Buffer.from(C_expected).toString("hex")

    expect(C_unblinded).toBe(C_expected_hex)
  })

  it("different nonces produce different blinded messages", () => {
    let cardPriv: Uint8Array
    do { cardPriv = crypto.randomBytes(32) } while (!secp.isPrivate(cardPriv))
    const cardPub = secp.pointFromScalar(cardPriv, true)!
    const cardPubHex = Buffer.from(cardPub).toString("hex")

    const bd1 = createBlindedMessage("0059534ce0bfa19a", 1, cardPubHex)
    const bd2 = createBlindedMessage("0059534ce0bfa19a", 1, cardPubHex)

    expect(bd1.nonce).not.toBe(bd2.nonce)
    expect(bd1.B_).not.toBe(bd2.B_)
  })
})
