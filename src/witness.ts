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

/** The NUT-10 envelope a well-known secret is carried in. */
export type WellKnownSecret = {
  kind: string
  body: Record<string, unknown>
}

/**
 * Parse the NUT-10 envelope only: `[kind, {...}]`.
 *
 * Deliberately separate from {@link parseP2PKSecret}. "Is this a well-known
 * secret at all?" and "is this a P2PK secret this module can verify?" are
 * different questions, and collapsing them is how an HTLC — or a P2PK secret
 * whose body is malformed — gets waved through as a plain, unlocked secret that
 * needs no witness. Returns null only when the secret is not a `[kind, {...}]`
 * pair, i.e. when it really is a plain string secret.
 */
export const parseWellKnownSecret = (secret: string): WellKnownSecret | null => {
  let parsed: unknown
  try {
    parsed = JSON.parse(secret)
  } catch {
    return null // a plain string secret, not a well-known secret
  }
  if (!Array.isArray(parsed) || parsed.length < 2) return null
  const [kind, body] = parsed as [unknown, unknown]
  if (typeof kind !== "string" || kind.length === 0) return null
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null
  return {kind, body: body as Record<string, unknown>}
}

/**
 * True when `secret` is a NUT-10 well-known secret of any kind — P2PK, HTLC, or
 * something this library has never heard of. Anything that is one carries a
 * spending condition, so it needs a witness the mint will accept.
 */
export const isWellKnownSecret = (secret: string): boolean =>
  parseWellKnownSecret(secret) !== null

/**
 * Parse a NUT-10 secret string: `["P2PK", {"nonce":..., "data":..., "tags":[...]}]`.
 *
 * Returns null for a plain (non-P2PK) secret, for a well-known secret of
 * another kind, and for a P2PK secret whose body is malformed. Callers deciding
 * whether a witness is needed must use {@link isWellKnownSecret} instead — a
 * null here means "this verifier cannot vouch for it", not "it is unlocked".
 *
 * Malformed `tags` are rejected outright rather than filtered out. A dropped
 * tag is indistinguishable from an absent one, so filtering would let anyone
 * bypass the strict-tag policy in {@link verifyP2PKWitness} by making a tag
 * malformed (`[["n_sigs", 2]]` — a JSON number, which the mint reads as 2)
 * instead of unknown.
 */
export const parseP2PKSecret = (secret: string): ParsedP2PKSecret | null => {
  const envelope = parseWellKnownSecret(secret)
  if (!envelope || envelope.kind !== "P2PK") return null

  const b = envelope.body
  if (typeof b.nonce !== "string" || typeof b.data !== "string") return null

  if (b.tags !== undefined) {
    if (
      !Array.isArray(b.tags) ||
      !b.tags.every(t => Array.isArray(t) && t.every(x => typeof x === "string"))
    ) {
      return null
    }
  }
  const tags = (b.tags ?? []) as string[][]

  return {kind: envelope.kind, nonce: b.nonce, data: b.data, tags}
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
 * NUT-11 spending-condition tags this verifier actually implements.
 *
 * Anything else — `locktime`, `refund`, `pubkeys` — changes what makes a
 * witness valid in a way the check below does not model, so a secret carrying
 * one is rejected rather than accepted on the strength of the parts we do
 * understand. `swapProofs` exists to receive a *sender's* proofs, i.e. secrets
 * this library did not construct, so these are reachable in practice.
 */
const SUPPORTED_TAGS = new Set(["sigflag", "n_sigs"])

/** The spending conditions read off a P2PK secret, or null if unsupported. */
const readSpendingConditions = (
  parsedSecret: ParsedP2PKSecret,
): {requiredSigs: number} | null => {
  let requiredSigs = 1
  for (const tag of parsedSecret.tags) {
    const key = tag[0]
    if (key === undefined || !SUPPORTED_TAGS.has(key)) return null

    if (key === "sigflag") {
      // SIG_ALL signs over every input and output of the request, so a
      // SIG_INPUTS-shaped signature verifies here and is still refused by the
      // mint. Absent means SIG_INPUTS by default.
      if (tag[1] !== "SIG_INPUTS") return null
    }

    if (key === "n_sigs") {
      const n = Number(tag[1])
      if (!Number.isInteger(n) || n < 1) return null
      requiredSigs = Math.max(requiredSigs, n)
    }
  }
  return {requiredSigs}
}

/**
 * Verify a proof's witness against the key its secret is locked to, and against
 * the spending conditions its secret declares.
 *
 * Worth doing before submitting: a mint rejects a bad witness with a generic
 * error *after* the card has already marked the proof spent, so the failure is
 * unrecoverable at exactly the point it is least recoverable. Checking here
 * turns that into a local error with the proof still intact — but only if the
 * check is the same one the mint runs, which means honouring `sigflag` and
 * `n_sigs` rather than accepting on any one valid signature.
 */
export const verifyP2PKWitness = (proof: CashuProof): boolean => {
  const parsedSecret = parseP2PKSecret(proof.secret)
  if (!parsedSecret) return false

  const conditions = readSpendingConditions(parsedSecret)
  if (!conditions) return false

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

  // Count *distinct* valid signatures: repeating one signature n times must not
  // satisfy an n_sigs requirement.
  const valid = new Set<string>()
  for (const sig of sigs) {
    const normalised = sig.toLowerCase()
    if (valid.has(normalised)) continue
    try {
      if (secp.verifySchnorr(msg, xOnly, Buffer.from(sig, "hex"))) valid.add(normalised)
    } catch {
      // Malformed signature — not a match, keep checking the rest.
    }
  }
  return valid.size >= conditions.requiredSigs
}

/**
 * True when this proof needs a witness before the mint will accept it.
 * A plain-secret proof does not.
 *
 * Keyed on "is this a well-known secret" rather than "did the P2PK parser
 * succeed". Those differ for an HTLC secret and for a malformed P2PK one, and
 * reading either as "plain, needs no witness" submits a proof the mint will
 * refuse — after the card has already burned the slot. Anything carrying a
 * NUT-10 spending condition this module cannot verify is reported by
 * {@link findUnsignedProofs} instead of waved through.
 */
export const requiresWitness = (proof: CashuProof): boolean =>
  isWellKnownSecret(proof.secret)

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
