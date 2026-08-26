import axios from "axios"

import type { CashuProof, CashuProofState } from "./types"
import { CashuMintError } from "./errors"
import {
  axiosConfig,
  describeAxiosError,
  isCompressedPointHex,
  sanitizeMintUrl,
} from "./http"
import { hashToCurve } from "./crypto"

/**
 * NUT-07: asking the mint whether proofs are still spendable.
 *
 * This is the double-spend check. A card is a bearer instrument and its
 * on-card SPENT flag only stops the *card* from signing again — it says
 * nothing about whether those proofs were already melted at the mint from a
 * copy of the data. An offline terminal genuinely cannot detect that; an
 * online one has no excuse not to check.
 *
 * Also the correct recovery step after a melt or swap whose response was lost:
 * ask what happened rather than resubmitting and risking a second payment.
 */

/**
 * The mint's identifier for a proof: Y = hash_to_curve(secret), compressed hex.
 * Note this is derived from the secret only — it does not reveal the signature.
 */
export const proofIdentifier = (proof: Pick<CashuProof, "secret">): string =>
  Buffer.from(hashToCurve(Buffer.from(proof.secret, "utf8"))).toString("hex")

/**
 * NUT-07: look up the state of each proof.
 *
 * Results are returned in the same order as `proofs`. A mint that returns a
 * different number of states, or reorders them, is rejected rather than
 * silently mapped — pairing a SPENT verdict against the wrong proof is worse
 * than no answer.
 */
export const checkProofStates = async (
  mintUrl: string,
  proofs: CashuProof[],
): Promise<CashuProofState[] | CashuMintError> => {
  try {
    if (!Array.isArray(proofs) || proofs.length === 0) {
      return new CashuMintError("checkProofStates requires at least one proof")
    }

    const url = sanitizeMintUrl(mintUrl)
    const ys = proofs.map(proofIdentifier)

    const {data} = await axios.post(`${url}/v1/checkstate`, {Ys: ys}, axiosConfig)

    if (!Array.isArray(data.states)) {
      return new CashuMintError("checkstate response missing states array")
    }
    if (data.states.length !== ys.length) {
      return new CashuMintError(
        `checkstate returned ${data.states.length} states for ${ys.length} proofs`,
      )
    }

    const byY = new Map<string, CashuProofState>()
    for (const [i, entry] of (data.states as Array<Record<string, unknown>>).entries()) {
      const y = entry.Y
      const state = entry.state
      if (!isCompressedPointHex(y)) {
        return new CashuMintError(`checkstate entry ${i}: malformed Y`)
      }
      if (state !== "UNSPENT" && state !== "PENDING" && state !== "SPENT") {
        return new CashuMintError(`checkstate entry ${i}: unknown state ${String(state)}`)
      }
      byY.set(y.toLowerCase(), {
        Y: y.toLowerCase(),
        state,
        witness: typeof entry.witness === "string" ? entry.witness : null,
      })
    }

    // Re-pair by Y rather than by position, then require every proof to be
    // accounted for. A missing Y means the mint answered a different question
    // than the one asked.
    const ordered: CashuProofState[] = []
    for (const [i, y] of ys.entries()) {
      const found = byY.get(y.toLowerCase())
      if (!found) {
        return new CashuMintError(`checkstate did not return a state for proof ${i}`)
      }
      ordered.push(found)
    }
    return ordered
  } catch (err) {
    return new CashuMintError(`Proof state check failed: ${describeAxiosError(err)}`)
  }
}

/**
 * The verdict of {@link allProofsUnspent}.
 *
 * Deliberately not a boolean. `boolean | CashuMintError` type-checks but fails
 * open at runtime: a CashuMintError is a truthy object, so
 * `if (await allProofsUnspent(...)) acceptPayment()` reads a mint timeout, a
 * 5xx, or a malformed checkstate response as "all proofs unspent" — the exact
 * inverse of what this module is for. A string verdict has no truthy shortcut.
 */
export type CashuUnspentVerdict = "UNSPENT" | "NOT_UNSPENT"

/**
 * Convenience: are all of these proofs still unspent?
 *
 * Treats PENDING as not-spendable. A pending proof is committed to an in-flight
 * operation, and accepting it as payment is how the same value gets counted
 * twice.
 *
 * Callers must compare explicitly and handle the error case:
 *
 * ```ts
 * const verdict = await allProofsUnspent(url, proofs)
 * if (verdict instanceof CashuMintError) return refuse(verdict)
 * if (verdict !== "UNSPENT") return refuse("already spent or pending")
 * ```
 */
export const allProofsUnspent = async (
  mintUrl: string,
  proofs: CashuProof[],
): Promise<CashuUnspentVerdict | CashuMintError> => {
  const states = await checkProofStates(mintUrl, proofs)
  if (states instanceof CashuMintError) return states
  return states.every(s => s.state === "UNSPENT") ? "UNSPENT" : "NOT_UNSPENT"
}
