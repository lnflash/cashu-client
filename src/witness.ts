import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import type { CashuProof } from "./types"

/**
 * NUT-11 P2PK witnesses.
 *
 * A card proof is locked to the card's public key, so the mint will not accept
 * it without a signature from that key. The card produces the signature
 * (SPEND_PROOF returns 64 bytes of BIP-340); this module is the other half —
 * it computes the exact message the card must sign, attaches the resulting
 * signature to the proof in the shape the mint expects, and can verify the
 * pair locally before anything is submitted.
 *
 * The library previously wrote the P2PK *lock* and had no way to produce the
 * *unlock*, which meant a card could be funded and never redeemed.
 */

/** The parsed form of a NUT-10 well-known secret. */
export type ParsedP2PKSecret = {
  kind: string                      // "P2PK"
  nonce: string
  /** The public key the proof is locked to — for a card proof, the card's key. */
  data: string
  tags: string[][]
}

/**
 * Parse a NUT-10 secret string: `["P2PK", {"nonce":..., "data":..., "tags":[...]}]`.
 * Returns null for a plain (non-P2PK) secret, which is not an error — an
 * unlocked proof simply needs no witness.
 */
export const parseP2PKSecret = (secret: string): ParsedP2PKSecret | null => {
  let parsed: unknown
  try {
    parsed = JSON.parse(secret)
  } catch {
    return null // a plain string secret, not a well-known secret
  }
  if (!Array.isArray(parsed) || parsed.length < 2) return null
  const [kind, body] = parsed as [unknown, unknown]
  if (kind !== "P2PK" || typeof body !== "object" || body === null) return null

  const b = body as Record<string, unknown>
  if (typeof b.nonce !== "string" || typeof b.data !== "string") return null

  const tags = Array.isArray(b.tags)
    ? (b.tags.filter(
        t => Array.isArray(t) && t.every(x => typeof x === "string"),
      ) as string[][])
    : []

  return {kind, nonce: b.nonce, data: b.data, tags}
}

/**
 * The 32-byte message a P2PK proof must be signed over: SHA-256 of the secret
 * string's UTF-8 bytes.
 *
 * Hand this to the card as the SPEND_PROOF payload. Getting it wrong produces a
 * signature that is valid BIP-340 and still rejected by every mint, which is a
 * confusing failure to debug from the card side — so it is computed here, once.
 */
export const p2pkMessageToSign = (proof: Pick<CashuProof, "secret">): Buffer =>
  crypto.createHash("sha256").update(Buffer.from(proof.secret, "utf8")).digest()

/**
 * Attach one or more signatures to a proof as a NUT-11 witness.
 * Returns a new proof; the input is not mutated.
 */
export const attachP2PKWitness = (proof: CashuProof, signatures: string[]): CashuProof => {
  if (signatures.length === 0) {
    throw new Error("attachP2PKWitness: no signatures supplied")
  }
  for (const sig of signatures) {
    if (!/^[0-9a-fA-F]{128}$/.test(sig)) {
      throw new Error(
        `attachP2PKWitness: signature must be 64 bytes of hex, got ${sig.length / 2} bytes`,
      )
    }
  }
  return {...proof, witness: JSON.stringify({signatures: signatures.map(s => s.toLowerCase())})}
}

/** Read the signatures back out of a proof's witness field. */
export const parseWitnessSignatures = (witness: string | undefined): string[] => {
  if (!witness) return []
  try {
    const parsed = JSON.parse(witness) as unknown
    if (typeof parsed !== "object" || parsed === null) return []
    const sigs = (parsed as {signatures?: unknown}).signatures
    if (!Array.isArray(sigs)) return []
    return sigs.filter((s): s is string => typeof s === "string")
  } catch {
    return []
  }
}

/**
 * Verify a proof's witness against the key its secret is locked to.
 *
 * Worth doing before submitting: a mint rejects a bad witness with a generic
 * error *after* the card has already marked the proof spent, so the failure is
 * unrecoverable at exactly the point it is least recoverable. Checking here
 * turns that into a local error with the proof still intact.
 */
export const verifyP2PKWitness = (proof: CashuProof): boolean => {
  const parsedSecret = parseP2PKSecret(proof.secret)
  if (!parsedSecret) return false

  const sigs = parseWitnessSignatures(proof.witness)
  if (sigs.length === 0) return false

  let lockedKey: Buffer
  try {
    lockedKey = Buffer.from(parsedSecret.data, "hex")
  } catch {
    return false
  }
  // NUT-11 keys are compressed (33 bytes); BIP-340 verifies against x-only.
  if (lockedKey.length !== 33 || !secp.isPoint(lockedKey)) return false
  const xOnly = lockedKey.subarray(1)

  const msg = p2pkMessageToSign(proof)

  return sigs.some(sig => {
    try {
      return secp.verifySchnorr(msg, xOnly, Buffer.from(sig, "hex"))
    } catch {
      return false
    }
  })
}

/**
 * True when this proof needs a witness before the mint will accept it.
 * A plain-secret proof does not.
 */
export const requiresWitness = (proof: CashuProof): boolean =>
  parseP2PKSecret(proof.secret) !== null

/**
 * Check every proof in a set carries a valid witness, returning the indices
 * that do not. Callers should treat a non-empty result as "do not submit":
 * the mint fails the whole request atomically, so one bad witness wastes the
 * spend attempt for all of them.
 */
export const findUnsignedProofs = (proofs: CashuProof[]): number[] =>
  proofs.reduce<number[]>((bad, proof, i) => {
    if (requiresWitness(proof) && !verifyP2PKWitness(proof)) bad.push(i)
    return bad
  }, [])
