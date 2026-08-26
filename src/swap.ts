import axios from "axios"

import type { CashuBlindSignature, CashuBlindedMessage, CashuProof } from "./types"
import { CashuMintError } from "./errors"
import {
  axiosConfig,
  describeAxiosError,
  isCompressedPointHex,
  parseResponseDLEQ,
  sanitizeMintUrl,
} from "./http"
import { findUnsignedProofs } from "./witness"
import { inputFee, sumProofs } from "./melt"

/**
 * NUT-03: swapping — exchange proofs for new ones of the same total value.
 *
 * Three things need this. Receiving a token means swapping the sender's proofs
 * for ones locked to you. Making change means swapping one large denomination
 * for several small. And unlocking a card proof means swapping a P2PK-locked
 * proof (with the card's witness) for an unlocked one the terminal controls.
 */

/**
 * NUT-03: submit inputs and blinded outputs, receive blind signatures.
 *
 * Inputs are consumed on success. Like melt this is not idempotent: if the
 * response is lost, check the inputs with NUT-07 rather than resubmitting.
 */
export const swapProofs = async (
  mintUrl: string,
  inputs: CashuProof[],
  outputs: CashuBlindedMessage[],
  inputFeePpk = 0,
): Promise<CashuBlindSignature[] | CashuMintError> => {
  try {
    if (!Array.isArray(inputs) || inputs.length === 0) {
      return new CashuMintError("Swap requires at least one input proof")
    }
    if (!Array.isArray(outputs) || outputs.length === 0) {
      return new CashuMintError("Swap requires at least one output")
    }

    // Outputs must balance the inputs exactly, less the NUT-02 input fee. The
    // mint enforces the upper bound, but nothing enforces the lower one: an
    // output set summing to less than the inputs is accepted and the mint keeps
    // the difference with no signal at all. Since making change is this
    // module's job, an off-by-one in the caller's denomination split would
    // otherwise burn value silently. Failing here also costs nothing, while
    // failing at the mint consumes the attempt — and for a card proof the slot
    // is already marked spent by the time we are assembling a swap.
    const inputTotal = sumProofs(inputs)
    const outputTotal = outputs.reduce((total, o) => total + o.amount, 0)
    const fee = inputFee(inputs.length, inputFeePpk)
    const expected = inputTotal - fee
    if (outputTotal !== expected) {
      const feeNote = fee > 0 ? ` minus the ${fee} input fee` : ""
      const delta = expected - outputTotal
      return outputTotal > expected
        ? new CashuMintError(
            `Swap outputs (${outputTotal}) exceed inputs (${inputTotal})${feeNote} by ${-delta}`,
          )
        : new CashuMintError(
            `Swap outputs (${outputTotal}) are short of inputs (${inputTotal})${feeNote} by ${delta} — the mint would keep the difference`,
          )
    }

    const unsigned = findUnsignedProofs(inputs)
    if (unsigned.length > 0) {
      return new CashuMintError(
        `Inputs at index [${unsigned.join(", ")}] are P2PK-locked with a missing or invalid witness`,
      )
    }

    const url = sanitizeMintUrl(mintUrl)
    const {data} = await axios.post(
      `${url}/v1/swap`,
      {
        inputs: inputs.map(p => ({
          id: p.id,
          amount: p.amount,
          secret: p.secret,
          C: p.C,
          ...(p.witness ? {witness: p.witness} : {}),
        })),
        outputs: outputs.map(o => ({id: o.id, amount: o.amount, B_: o.B_})),
      },
      axiosConfig,
    )

    if (!Array.isArray(data.signatures)) {
      return new CashuMintError("Swap response missing signatures array")
    }
    if (data.signatures.length !== outputs.length) {
      return new CashuMintError(
        `Swap returned ${data.signatures.length} signatures for ${outputs.length} outputs`,
      )
    }

    // Bind each signature to the output it answers. A mint that reordered or
    // relabelled these would hand back proofs worth less than was swapped, or
    // proofs that cannot be unblinded at all.
    const raw = data.signatures as Array<Record<string, unknown>>
    const result: CashuBlindSignature[] = []
    for (let i = 0; i < raw.length; i++) {
      const sig = raw[i]
      const out = outputs[i]
      if (sig.id !== out.id) {
        return new CashuMintError(
          `Swap signature ${i}: keyset ID mismatch (expected ${out.id}, got ${String(sig.id)})`,
        )
      }
      if (sig.amount !== out.amount) {
        return new CashuMintError(
          `Swap signature ${i}: amount mismatch (expected ${out.amount}, got ${String(sig.amount)})`,
        )
      }
      if (!isCompressedPointHex(sig.C_)) {
        return new CashuMintError(`Swap signature ${i}: malformed C_`)
      }

      // A present-but-malformed DLEQ is rejected rather than dropped. Dropping
      // it makes a misbehaving mint indistinguishable from one that emits no
      // DLEQ at all, which is exactly how a hostile mint would opt out of
      // verification: send garbage and be treated as absent.
      const dleq = parseResponseDLEQ(sig.dleq)
      if (dleq === null) {
        return new CashuMintError(`Swap signature ${i}: malformed DLEQ`)
      }
      result.push({
        id: sig.id as string,
        amount: sig.amount as number,
        C_: sig.C_,
        ...(dleq ? {dleq} : {}),
      })
    }
    return result
  } catch (err) {
    return new CashuMintError(`Swap failed: ${describeAxiosError(err)}`)
  }
}
