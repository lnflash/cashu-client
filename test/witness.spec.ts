import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import {
  attachP2PKWitness,
  buildP2PKSecret,
  findUnsignedProofs,
  isWellKnownSecret,
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
    expect(isWellKnownSecret("plain")).toBe(false)
    expect(isWellKnownSecret('["P2PK"]')).toBe(false)
    expect(isWellKnownSecret('["P2PK","not-an-object"]')).toBe(false)
  })

  /**
   * `parseP2PKSecret` returns null for three different things — a plain secret,
   * a well-known secret of another kind, and a malformed P2PK secret — and only
   * the first means "unlocked". Keying `requiresWitness` off the null meant the
   * other two were submitted unwitnessed, refused by the mint, and the card had
   * already burned its slots.
   */
  it("flags a well-known secret of another kind as needing a witness", () => {
    const secret = JSON.stringify([
      "HTLC",
      {nonce: "aa".repeat(32), data: "ff".repeat(32), tags: [["pubkeys", "02" + "11".repeat(32)]]},
    ])
    const proof: CashuProof = {id: "a", amount: 1, secret, C: "02" + "11".repeat(32)}

    // Not a P2PK secret, so this verifier cannot vouch for it …
    expect(parseP2PKSecret(secret)).toBeNull()
    // … which is exactly why it must not be waved through as unlocked.
    expect(isWellKnownSecret(secret)).toBe(true)
    expect(requiresWitness(proof)).toBe(true)
    expect(verifyP2PKWitness(proof)).toBe(false)
    expect(findUnsignedProofs([proof])).toEqual([0])
  })

  it("flags a malformed P2PK secret as needing a witness rather than as plain", () => {
    // `data` is a JSON number, so the P2PK parser bails — but the secret is
    // still a NUT-10 spending condition and the mint will still demand one.
    const secret = JSON.stringify(["P2PK", {nonce: "aa".repeat(32), data: 42}])
    const proof: CashuProof = {id: "a", amount: 1, secret, C: "02" + "11".repeat(32)}

    expect(parseP2PKSecret(secret)).toBeNull()
    expect(requiresWitness(proof)).toBe(true)
    expect(findUnsignedProofs([proof])).toEqual([0])
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

describe("NUT-11 spending-condition tags", () => {
  /**
   * `swapProofs` exists to receive a sender's proofs — secrets this library did
   * not construct — so these tags are reachable. Accepting on one valid
   * signature regardless of what the tags say means the local check passes and
   * the mint still refuses, after the card has burned its slots.
   */
  const lockedSecret = (pubkey: string, tags: string[][]): string =>
    JSON.stringify(["P2PK", {nonce: crypto.randomBytes(32).toString("hex"), data: pubkey, tags}])

  const proofWithTags = (card: ReturnType<typeof makeCardKey>, tags: string[][]) => {
    const base: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: lockedSecret(card.pubHex, tags),
      C: "02" + crypto.randomBytes(32).toString("hex"),
    }
    return attachP2PKWitness(base, [cardSign(card.d, base)])
  }

  it("accepts an explicit SIG_INPUTS", () => {
    const card = makeCardKey()
    expect(verifyP2PKWitness(proofWithTags(card, [["sigflag", "SIG_INPUTS"]]))).toBe(true)
  })

  it("accepts a secret with no tags at all", () => {
    const card = makeCardKey()
    expect(verifyP2PKWitness(proofWithTags(card, []))).toBe(true)
  })

  it("rejects SIG_ALL — that signature is over a different message", () => {
    // SIG_ALL signs over every input and output of the request, so a
    // SIG_INPUTS-shaped signature verifies here and is refused at the mint.
    const card = makeCardKey()
    const proof = proofWithTags(card, [["sigflag", "SIG_ALL"]])
    expect(verifyP2PKWitness(proof)).toBe(false)
    expect(findUnsignedProofs([proof])).toEqual([0])
  })

  it("rejects an unrecognised sigflag value", () => {
    const card = makeCardKey()
    expect(verifyP2PKWitness(proofWithTags(card, [["sigflag", "SIG_FUTURE"]]))).toBe(false)
    expect(verifyP2PKWitness(proofWithTags(card, [["sigflag"]]))).toBe(false)
  })

  it("rejects a single signature against n_sigs 2", () => {
    const card = makeCardKey()
    const proof = proofWithTags(card, [["n_sigs", "2"]])
    expect(parseWitnessSignatures(proof.witness)).toHaveLength(1)
    expect(verifyP2PKWitness(proof)).toBe(false)
  })

  it("does not let a repeated signature satisfy n_sigs", () => {
    const card = makeCardKey()
    const base: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: lockedSecret(card.pubHex, [["n_sigs", "2"]]),
      C: "02" + crypto.randomBytes(32).toString("hex"),
    }
    const sig = cardSign(card.d, base)
    const proof = attachP2PKWitness(base, [sig, sig])
    expect(verifyP2PKWitness(proof)).toBe(false)
  })

  it("accepts n_sigs 2 with two distinct valid signatures", () => {
    const card = makeCardKey()
    const base: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: lockedSecret(card.pubHex, [["n_sigs", "2"]]),
      C: "02" + crypto.randomBytes(32).toString("hex"),
    }
    // BIP-340 admits distinct valid signatures for the same key and message
    // when the auxiliary randomness differs.
    const msg = p2pkMessageToSign(base)
    const a = Buffer.from(secp.signSchnorr(msg, card.d, Buffer.alloc(32, 1))).toString("hex")
    const b = Buffer.from(secp.signSchnorr(msg, card.d, Buffer.alloc(32, 2))).toString("hex")
    expect(a).not.toBe(b)
    expect(verifyP2PKWitness(attachP2PKWitness(base, [a, b]))).toBe(true)
  })

  it("rejects a malformed n_sigs", () => {
    const card = makeCardKey()
    expect(verifyP2PKWitness(proofWithTags(card, [["n_sigs", "many"]]))).toBe(false)
    expect(verifyP2PKWitness(proofWithTags(card, [["n_sigs", "0"]]))).toBe(false)
  })

  /**
   * Filtering malformed tag entries out before the strict-tag check made a
   * dropped tag indistinguishable from an absent one — so the whole policy was
   * bypassable by making a tag *malformed* rather than unknown. Nutshell reads
   * `["n_sigs", 2]` (a JSON number) as 2 and enforces it; a client that dropped
   * the tag would submit one signature and be refused at the mint.
   */
  const rawTaggedProof = (card: ReturnType<typeof makeCardKey>, tags: unknown) => {
    const base: CashuProof = {
      id: "0059534ce0bfa19a",
      amount: 8,
      secret: JSON.stringify([
        "P2PK",
        {nonce: crypto.randomBytes(32).toString("hex"), data: card.pubHex, tags},
      ]),
      C: "02" + crypto.randomBytes(32).toString("hex"),
    }
    return attachP2PKWitness(base, [cardSign(card.d, base)])
  }

  it("rejects a malformed tag instead of dropping it", () => {
    const card = makeCardKey()
    for (const tags of [
      [["n_sigs", 2]], // number, not string — the mint still enforces it
      [["sigflag", ["SIG_ALL"]]], // nested array
      [["n_sigs", null]],
      ["n_sigs"], // tag is not an array at all
      "tags-should-be-an-array",
      {},
      null,
    ]) {
      const proof = rawTaggedProof(card, tags)
      expect(parseP2PKSecret(proof.secret)).toBeNull()
      expect(verifyP2PKWitness(proof)).toBe(false)
      // Still a NUT-10 secret, so it must be reported rather than submitted.
      expect(requiresWitness(proof)).toBe(true)
      expect(findUnsignedProofs([proof])).toEqual([0])
    }
  })

  it("still accepts an absent tags field", () => {
    const card = makeCardKey()
    expect(verifyP2PKWitness(rawTaggedProof(card, undefined))).toBe(true)
  })

  it("rejects tags this verifier does not implement rather than ignoring them", () => {
    const card = makeCardKey()
    for (const tag of [
      ["locktime", "1700000000"],
      ["refund", "02" + "11".repeat(32)],
      ["pubkeys", "02" + "11".repeat(32)],
      [],
    ]) {
      expect(verifyP2PKWitness(proofWithTags(card, [tag]))).toBe(false)
    }
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
