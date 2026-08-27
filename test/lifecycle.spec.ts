/**
 * The card lifecycle the README advertises, executed end to end against a
 * mocked mint:
 *
 *   requestMintQuote → mintProofs → unblindSignature → verifyProofDLEQ
 *
 * This is the test that would have caught the DLEQ gap. `mintProofs` used to
 * strip `sig.dleq` and `CashuBlindSignature` had no field to hold it, so no
 * proof this library produced could ever carry `dleq.e/s/r` — making
 * `verifyProofDLEQ` and `hasDLEQ` unreachable from the only flow that loads a
 * card, and the documented sequence impossible to run.
 */

const mockAxios = jest.fn()
jest.mock("axios", () => ({
  ...jest.requireActual("axios"),
  post: (...args: unknown[]) => mockAxios("post", ...args),
  get: (...args: unknown[]) => mockAxios("get", ...args),
  isAxiosError: jest.fn(
    (err: unknown) => err && typeof err === "object" && "isAxiosError" in err,
  ),
}))

import * as secp from "tiny-secp256k1"

import {
  attachP2PKWitness,
  CashuMintError,
  createBlindedMessage,
  hasDLEQ,
  mintProofs,
  p2pkMessageToSign,
  proofDLEQFromBlindSignature,
  reconstructProofFromCard,
  reconstructProofsFromCard,
  unblindSignature,
  verifyP2PKWitness,
  verifyProofDLEQ,
} from "../src"
import type { CashuBlindSignature, CashuProof } from "../src"

import { blindSignWithDLEQ, cardKeypair, cardPubkey, makeMint } from "./helpers/nut12"

const MINT = "https://mint.example.com"
const KS = "0059534ce0bfa19a"

beforeEach(() => mockAxios.mockReset())

describe("load a card, then verify it offline", () => {
  it("carries the mint's DLEQ all the way onto a verifiable proof", async () => {
    const mint = makeMint()
    const card = cardPubkey()

    // Build the blinded outputs a terminal would send.
    const amounts = [4, 8]
    const blinding = amounts.map(amount => createBlindedMessage(KS, amount, card))
    const outputs = blinding.map((bd, i) => ({id: KS, amount: amounts[i], B_: bd.B_}))

    // The mint signs each one and attaches a NUT-12 DLEQ.
    const signed = blinding.map(bd => blindSignWithDLEQ(mint, bd.B_))
    mockAxios.mockResolvedValueOnce({
      data: {
        signatures: signed.map((s, i) => ({
          id: KS,
          amount: amounts[i],
          C_: s.C_hex,
          dleq: s.dleq,
        })),
      },
    })

    const sigs = (await mintProofs(MINT, "quote-1", outputs)) as CashuBlindSignature[]
    expect(sigs).not.toBeInstanceOf(Error)
    expect(sigs[0].dleq).toEqual(signed[0].dleq)

    // Unblind, pairing the mint's e/s with the client's blinding factor r.
    const proofs: CashuProof[] = sigs.map((sig, i) => ({
      id: sig.id,
      amount: sig.amount,
      secret: blinding[i].secretStr,
      C: unblindSignature(sig.C_, blinding[i].r, mint.AHex),
      dleq: proofDLEQFromBlindSignature(sig, blinding[i].r),
    }))

    for (const proof of proofs) {
      expect(hasDLEQ(proof)).toBe(true)
      // Offline, no mint contact — the check a receiving terminal runs.
      expect(verifyProofDLEQ(proof, mint.AHex)).toBe(true)
      expect(verifyProofDLEQ(proof, makeMint().AHex)).toBe(false)
    }
  })

  it("leaves the proof DLEQ-less when the mint emits none", async () => {
    const mint = makeMint()
    const blinding = createBlindedMessage(KS, 4, cardPubkey())
    const {C_hex} = blindSignWithDLEQ(mint, blinding.B_)

    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount: 4, C_: C_hex}]},
    })

    const sigs = (await mintProofs(MINT, "quote-1", [
      {id: KS, amount: 4, B_: blinding.B_},
    ])) as CashuBlindSignature[]

    expect(sigs[0].dleq).toBeUndefined()
    // Absent is a caller policy decision, not an error.
    expect(proofDLEQFromBlindSignature(sigs[0], blinding.r)).toBeUndefined()
  })

  it("rejects a present-but-malformed DLEQ from the mint", async () => {
    const mint = makeMint()
    const blinding = createBlindedMessage(KS, 4, cardPubkey())
    const {C_hex} = blindSignWithDLEQ(mint, blinding.B_)

    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount: 4, C_: C_hex, dleq: {e: "zz", s: "zz"}}]},
    })

    const result = await mintProofs(MINT, "quote-1", [
      {id: KS, amount: 4, B_: blinding.B_},
    ])
    expect(result).toBeInstanceOf(CashuMintError)
    expect((result as Error).message).toMatch(/malformed DLEQ/)
  })

  it("catches a mint that signed with a key it does not publish", async () => {
    // The tagging attack, caught offline at the proof level rather than only on
    // the blind signature — which is the whole reason r has to be carried.
    const honest = makeMint()
    const sneaky = makeMint()
    const blinding = createBlindedMessage(KS, 4, cardPubkey())
    const {C_hex, dleq} = blindSignWithDLEQ(sneaky, blinding.B_)

    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount: 4, C_: C_hex, dleq}]},
    })

    const sigs = (await mintProofs(MINT, "quote-1", [
      {id: KS, amount: 4, B_: blinding.B_},
    ])) as CashuBlindSignature[]

    const proof: CashuProof = {
      id: KS,
      amount: 4,
      secret: blinding.secretStr,
      C: unblindSignature(sigs[0].C_, blinding.r, honest.AHex),
      dleq: proofDLEQFromBlindSignature(sigs[0], blinding.r),
    }
    expect(verifyProofDLEQ(proof, honest.AHex)).toBe(false)
  })
})

/**
 * The other half of the lifecycle, executed against the same mocked mint:
 *
 *   mintProofs → unblindSignature → (card stores 78 bytes) → reconstruct → spend
 *
 * `card.spec.ts` covers the reconstruction seam in isolation, but every fixture
 * there uses `C = "02" + "ab".repeat(32)` — a point no mint ever signed. Nothing
 * asserted that a proof `mintProofs` *actually issued* survives a round trip
 * through the card's slot layout, which is the only claim this module makes.
 */
describe("load a card, then spend what is actually on it", () => {
  /** Mint one proof end to end, exactly as the README's Usage section does. */
  const mintOne = async (mint: ReturnType<typeof makeMint>, cardPub: string, amount: number) => {
    const bd = createBlindedMessage(KS, amount, cardPub)
    const signed = blindSignWithDLEQ(mint, bd.B_)
    mockAxios.mockResolvedValueOnce({
      data: {signatures: [{id: KS, amount, C_: signed.C_hex, dleq: signed.dleq}]},
    })

    const sigs = (await mintProofs(MINT, "quote-1", [
      {id: KS, amount, B_: bd.B_},
    ])) as CashuBlindSignature[]
    expect(sigs).not.toBeInstanceOf(Error)

    const proof: CashuProof = {
      id: sigs[0].id,
      amount: sigs[0].amount,
      secret: bd.secretStr,
      C: unblindSignature(sigs[0].C_, bd.r, mint.AHex),
      dleq: proofDLEQFromBlindSignature(sigs[0], bd.r),
    }
    return {bd, proof}
  }

  it("rebuilds a proof the mint actually signed, from the card's four fields", async () => {
    const mint = makeMint()
    const card = cardKeypair()
    const {bd, proof} = await mintOne(mint, card.pub, 8)

    // Sanity: this is a genuine, mint-signed proof, not a fixture.
    expect(verifyProofDLEQ(proof, mint.AHex)).toBe(true)

    // Everything the card keeps: keyset id, amount, nonce, C. No secret — it
    // does not fit in 78 bytes, which is the entire reason this module exists.
    const rebuilt = reconstructProofFromCard(
      {keysetId: KS, amount: proof.amount, nonce: bd.nonce, C: proof.C},
      card.pub,
    )

    const {dleq, ...withoutDLEQ} = proof
    expect(dleq).toBeDefined()
    expect(rebuilt).toEqual(withoutDLEQ)
    // Stated separately because it is the load-bearing field: `Y =
    // hash_to_curve(secret)` is what the mint's signature is over, so one byte
    // of drift here is a proof the mint has never seen.
    expect(rebuilt.secret).toBe(bd.secretStr)
  })

  it("the rebuilt proof is spendable once the card signs it", async () => {
    const mint = makeMint()
    const card = cardKeypair()
    const {bd, proof} = await mintOne(mint, card.pub, 4)

    const rebuilt = reconstructProofFromCard(
      {keysetId: KS, amount: proof.amount, nonce: bd.nonce, C: proof.C},
      card.pub,
    )
    expect(rebuilt.witness).toBeUndefined()

    // SPEND_PROOF: the card signs the message derived from the rebuilt proof.
    const sig = Buffer.from(
      secp.signSchnorr(p2pkMessageToSign(rebuilt), card.d),
    ).toString("hex")
    const spendable = attachP2PKWitness(rebuilt, [sig])

    expect(verifyP2PKWitness(spendable)).toBe(true)
    // The DLEQ still checks out against the reconstructed secret, so the proof
    // handed to the mint is the same one it signed.
    expect(verifyProofDLEQ({...spendable, dleq: proof.dleq}, mint.AHex)).toBe(true)
  })

  it("reconstructs a whole card of minted proofs in order", async () => {
    const mint = makeMint()
    const card = cardKeypair()
    const minted = []
    for (const amount of [1, 2, 4]) {
      minted.push(await mintOne(mint, card.pub, amount))
    }

    const proofs = reconstructProofsFromCard(
      minted.map(({bd, proof}) => ({
        keysetId: KS,
        amount: proof.amount,
        nonce: bd.nonce,
        C: proof.C,
      })),
      card.pub,
    )

    expect(proofs.map(p => p.amount)).toEqual([1, 2, 4])
    expect(proofs.map(p => p.secret)).toEqual(minted.map(m => m.bd.secretStr))
  })
})
