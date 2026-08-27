import crypto from "crypto"
import * as secp from "tiny-secp256k1"

import { hashE } from "../../src"
import type { CashuDLEQ } from "../../src"

/**
 * The *mint* side of NUT-12, implemented here so the verifier is checked
 * against a genuinely valid proof rather than a fixture someone transcribed.
 * A verifier that always returns true passes any positive-only test; the
 * tampering cases in the specs are what force it to actually do the arithmetic.
 */

export const N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
)

export const toScalar = (v: bigint): Buffer =>
  Buffer.from(v.toString(16).padStart(64, "0"), "hex")

export const randomScalar = (): Buffer => {
  let s: Buffer
  do {
    s = crypto.randomBytes(32)
  } while (!secp.isPrivate(s))
  return s
}

/** The mint: holds `a`, publishes `A = a*G`. */
export const makeMint = () => {
  const a = randomScalar()
  const A = Buffer.from(secp.pointFromScalar(a, true)!)
  return {a, A, AHex: A.toString("hex")}
}

export type TestMint = ReturnType<typeof makeMint>

/**
 * Mint-side blind-sign with a DLEQ proof, exactly as NUT-12 specifies:
 *   C_ = a*B_
 *   k random;  R1 = k*G;  R2 = k*B_
 *   e = hash_e(R1, R2, A, C_)
 *   s = k + e*a  (mod n)
 */
export const blindSignWithDLEQ = (
  mint: TestMint,
  B_hex: string,
): {C_hex: string; dleq: CashuDLEQ} => {
  const B_ = Buffer.from(B_hex, "hex")
  const C_ = Buffer.from(secp.pointMultiply(B_, mint.a, true)!)

  const k = randomScalar()
  const R1 = Buffer.from(secp.pointFromScalar(k, true)!)
  const R2 = Buffer.from(secp.pointMultiply(B_, k, true)!)

  const e = hashE([R1, R2, mint.A, C_])
  const eBig = BigInt("0x" + e.toString("hex"))
  const aBig = BigInt("0x" + mint.a.toString("hex"))
  const kBig = BigInt("0x" + k.toString("hex"))
  const s = toScalar((kBig + eBig * aBig) % N)

  return {C_hex: C_.toString("hex"), dleq: {e: e.toString("hex"), s: s.toString("hex")}}
}

/** A card: holds `d`, publishes `P = d*G` and signs with Schnorr. */
export const cardKeypair = (): {d: Buffer; pub: string} => {
  const d = randomScalar()
  return {d, pub: Buffer.from(secp.pointFromScalar(d, true)!).toString("hex")}
}

export const cardPubkey = (): string => cardKeypair().pub
