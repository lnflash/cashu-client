import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  attachP2PKWitness,
  buildP2PKSecret,
  findUnsignedProofs,
  meltAmountRequired,
  p2pkMessageToSign,
  parseP2PKSecret,
  parseWitnessSignatures,
  proofIdentifier,
  requiresWitness,
  selectProofsForMelt,
  sumProofs,
  verifyP2PKWitness,
} from "../src"
import type { CashuMeltQuote, CashuProof } from "../src"

/** A keypair standing in for the card. */
const makeCardKey = () => {
  let d: Buffer
  do {
    d = crypto.randomBytes(32)
  } while (!secp.isPrivate(d))
  const pub = Buffer.from(secp.pointFromScalar(d, true)!)
  return {d, pubHex: pub.toString("hex"), xOnly: pub.subarray(1)}
}

/** What the card does inside SPEND_PROOF: BIP-340 over sha256(secret). */
const cardSign = (d: Buffer, proof: Pick<CashuProof, "secret">): string =>
  Buffer.from(secp.signSchnorr(p2pkMessageToSign(proof), d)).toString("hex")

const makeProof = (cardPubkey: string, amount = 8): CashuProof => ({
  id: "0059534ce0bfa19a",
  amount,
  secret: buildP2PKSecret(crypto.randomBytes(32).toString("hex"), cardPubkey),
  C: "02" + crypto.randomBytes(32).toString("hex"),
})

describe("NUT-10 secret parsing", () => {
  it("parses a P2PK secret and recovers the locked key", () => {
    const card = makeCardKey()
    const secret = buildP2PKSecret("aa".repeat(32), card.pubHex)
    const parsed = parseP2PKSecret(secret)
    expect(parsed).not.toBeNull()
    expect(parsed!.kind).toBe("P2PK")
    expect(parsed!.data).toBe(card.pubHex)
    expect(parsed!.tags).toContainEqual(["sigflag", "SIG_INPUTS"])
  })

  it("returns null for a plain secret rather than throwing", () => {
    expect(parseP2PKSecret("just-a-random-string")).toBeNull()
    expect(parseP2PKSecret('["HTLC",{"nonce":"x","data":"y"}]')).toBeNull()
    expect(parseP2PKSecret("")).toBeNull()
  })

  it("treats a plain-secret proof as needing no witness", () => {
    const proof: CashuProof = {id: "a", amount: 1, secret: "plain", C: "02" + "11".repeat(32)}
    expect(requiresWitness(proof)).toBe(false)
    expect(findUnsignedProofs([proof])).toEqual([])
  })
})

describe("P2PK witness", () => {
  it("round-trips: card signs the message, witness verifies", () => {
    const card = makeCardKey()
    const proof = makeProof(card.pubHex)
    const signed = attachP2PKWitness(proof, [cardSign(card.d, proof)])

    expect(parseWitnessSignatures(signed.witness)).toHaveLength(1)
    expect(verifyP2PKWitness(signed)).toBe(true)
    expect(findUnsignedProofs([signed])).toEqual([])
  })

  it("signs the sha256 of the secret, not the raw secret", () => {
    const proof = makeProof(makeCardKey().pubHex)
    const expected = crypto.createHash("sha256").update(Buffer.from(proof.secret, "utf8")).digest()
    expect(p2pkMessageToSign(proof).equals(expected)).toBe(true)
    expect(p2pkMessageToSign(proof)).toHaveLength(32)
  })

  it("rejects a signature from the wrong key", () => {
    const card = makeCardKey()
    const attacker = makeCardKey()
    const proof = makeProof(card.pubHex)
    const signed = attachP2PKWitness(proof, [cardSign(attacker.d, proof)])
    expect(verifyP2PKWitness(signed)).toBe(false)
    expect(findUnsignedProofs([signed])).toEqual([0])
  })

  it("rejects a signature over a different proof", () => {
    const card = makeCardKey()
    const proofA = makeProof(card.pubHex)
    const proofB = makeProof(card.pubHex)
    // Valid signature, wrong message — the classic replay attempt.
    const signed = {...proofA, ...attachP2PKWitness(proofA, [cardSign(card.d, proofB)])}
    expect(verifyP2PKWitness(signed)).toBe(false)
  })

  it("rejects a corrupted signature", () => {
    const card = makeCardKey()
    const proof = makeProof(card.pubHex)
    const sig = Buffer.from(cardSign(card.d, proof), "hex")
    sig[0] ^= 0x01
    expect(verifyP2PKWitness(attachP2PKWitness(proof, [sig.toString("hex")]))).toBe(false)
  })

  it("treats a missing or malformed witness as unsigned", () => {
    const proof = makeProof(makeCardKey().pubHex)
    expect(verifyP2PKWitness(proof)).toBe(false)
    expect(verifyP2PKWitness({...proof, witness: "not json"})).toBe(false)
    expect(verifyP2PKWitness({...proof, witness: '{"signatures":[]}'})).toBe(false)
    expect(parseWitnessSignatures(undefined)).toEqual([])
  })

  it("refuses to build a witness from a wrong-length signature", () => {
    const proof = makeProof(makeCardKey().pubHex)
    expect(() => attachP2PKWitness(proof, ["abcd"])).toThrow(/64 bytes/)
    expect(() => attachP2PKWitness(proof, [])).toThrow(/no signatures/)
  })

  it("does not mutate the input proof", () => {
    const card = makeCardKey()
    const proof = makeProof(card.pubHex)
    attachP2PKWitness(proof, [cardSign(card.d, proof)])
    expect(proof.witness).toBeUndefined()
  })

  it("reports every unsigned proof in a batch, not just the first", () => {
    const card = makeCardKey()
    const p0 = makeProof(card.pubHex)
    const p1 = makeProof(card.pubHex)
    const p2 = makeProof(card.pubHex)
    const batch = [
      attachP2PKWitness(p0, [cardSign(card.d, p0)]),
      p1, // unsigned
      p2, // unsigned
    ]
    expect(findUnsignedProofs(batch)).toEqual([1, 2])
  })
})

describe("melt helpers", () => {
  const quote = (amount: number, feeReserve: number): CashuMeltQuote => ({
    quoteId: "q",
    amount,
    feeReserve,
    state: "UNPAID",
    expiry: 0,
  })

  it("requires the invoice amount plus the fee reserve", () => {
    expect(meltAmountRequired(quote(100, 7))).toBe(107)
  })

  it("selects largest-first and covers amount + fee", () => {
    const proofs: CashuProof[] = [1, 2, 4, 8, 64].map(a => ({
      id: "x", amount: a, secret: `s${a}`, C: "02" + "11".repeat(32),
    }))
    const chosen = selectProofsForMelt(proofs, quote(60, 5))!
    expect(chosen).not.toBeNull()
    expect(sumProofs(chosen)).toBeGreaterThanOrEqual(65)
    expect(chosen[0].amount).toBe(64)
  })

  it("returns null rather than a short selection", () => {
    const proofs: CashuProof[] = [1, 2].map(a => ({
      id: "x", amount: a, secret: `s${a}`, C: "02" + "11".repeat(32),
    }))
    // Short by one because of the fee reserve — the mint would reject this
    // after the card had already burned the slots.
    expect(selectProofsForMelt(proofs, quote(3, 1))).toBeNull()
  })
})

describe("NUT-07 proof identifier", () => {
  it("is hash_to_curve(secret) as a compressed point", () => {
    const proof = makeProof(makeCardKey().pubHex)
    const y = proofIdentifier(proof)
    expect(y).toMatch(/^0[23][0-9a-f]{64}$/)
  })

  it("is stable for the same secret and differs across secrets", () => {
    const a = makeProof(makeCardKey().pubHex)
    const b = makeProof(makeCardKey().pubHex)
    expect(proofIdentifier(a)).toBe(proofIdentifier(a))
    expect(proofIdentifier(a)).not.toBe(proofIdentifier(b))
  })

  it("does not depend on the signature C", () => {
    const proof = makeProof(makeCardKey().pubHex)
    const other = {...proof, C: "03" + "22".repeat(32)}
    expect(proofIdentifier(other)).toBe(proofIdentifier(proof))
  })
})
