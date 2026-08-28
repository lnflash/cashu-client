/**
 * The card file — the interchange format between the mint side and the card side.
 *
 * This project is deliberately split across two toolchains: the mint protocol
 * is TypeScript (this library), and the card driver is Python
 * (`tools/cardctl` in lnflash/cashu-javacard, which stays dependency-free so it
 * can run anywhere a reader does). They cannot call each other, so proofs cross
 * the boundary as a file.
 *
 * Defining that file here rather than in either CLI is the point. Both sides
 * validate against this one schema, so a field that drifts fails at the
 * boundary instead of at the mint — where the card may already have burned the
 * slot.
 *
 * Two directions:
 *
 *   mint → card   `serializeCardFile` writes proofs to be loaded onto a card
 *   card → mint   `parseCardFile` reads slots dumped from a card, ready for
 *                 `reconstructProofsFromCard`
 *
 * Nothing here restates a rule `card.ts` already owns: the hex, point, keyset-id
 * and denomination checks are imported from it, and `serializeCardFile` runs the
 * redeem path itself and discards the result. Do not reintroduce local copies
 * "to keep this module structural". A second copy of the prefix test that reads
 * the wrong nibble, or of the amount check that lets 3 through, does not fail
 * loudly — it writes a file that loads onto a card and is rejected by the mint
 * only after SPEND_PROOF has burned the slot, which is the single failure this
 * format exists to prevent.
 *
 * That bites hardest on the mint → card direction, where `serializeCardFile` is
 * the only gate: cardctl is dependency-free Python and will not do curve math,
 * so whatever is written here is what reaches the card.
 *
 * The wire shape carries the *card's* vocabulary — `nonce`, not `secret`, and
 * `keysetId` as 16 hex chars — because that is what the card actually stores. A
 * file that said `secret` would invite someone to put ~150 bytes of P2PK JSON
 * in a field that holds 32 bytes.
 */
import {
  reconstructProofsFromCard,
  requireAmount,
  requireHex,
  requireKeysetV0,
  requirePoint,
} from "./card"
import type { CardProofSlot } from "./card"
import { CashuInvalidProofError } from "./errors"
import { sanitizeMintUrl } from "./http"

/** Bumped only for a breaking change to the shape below. */
export const CARD_FILE_VERSION = 1

export type CardFile = {
  version: number
  /** Mint the proofs belong to. Loading a card from the wrong mint is silent. */
  mint: string
  /**
   * Keyset unit, e.g. `sat` or `usd`. Carried so amounts are unambiguous.
   *
   * Canonicalised on read — trimmed and lower-cased — for the same reason
   * `mint` is: its only use is a `file.unit === keyset.unit` comparison.
   */
  unit: string
  /** Compressed secp256k1 pubkey of the card these proofs are locked to. */
  cardPubkey: string
  slots: CardProofSlot[]
  /** Free-form; ignored on read. Provenance for a human, never trusted. */
  note?: string
}

const SLOT_FIELDS = ["keysetId", "amount", "nonce", "C"]
const FILE_FIELDS = ["version", "mint", "unit", "cardPubkey", "slots", "note"]

/**
 * Refuse a field this version does not know about.
 *
 * The format's whole claim is that "a field that drifts fails at the boundary".
 * Silently dropping an unrecognised field is that drift: a future cardctl adds
 * one, forgets to bump `version`, and this side discards it without a word —
 * the failure then surfaces at the mint, or as money that quietly went nowhere.
 * `version` exists precisely so an additive change announces itself.
 */
const rejectUnknownFields = (
  raw: Record<string, unknown>,
  known: string[],
  where: string,
): void => {
  const extra = Object.keys(raw).filter(k => !known.includes(k))
  if (extra.length > 0) {
    throw new CashuInvalidProofError(
      `${where}unknown field(s): ${extra.join(", ")} — bump the card file ` +
        `version rather than adding fields silently`,
    )
  }
}

/**
 * Validate one slot from a file.
 *
 * Strict on purpose, and it throws the same classes `reconstructProofFromCard`
 * does — because it runs the same checks — so a caller can tell "this card's
 * key is wrong" from "slot 3 is corrupt" without matching on message text.
 */
export const parseCardSlot = (value: unknown, index: number): CardProofSlot => {
  const where = `slot ${index}: `
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CashuInvalidProofError(`${where}expected an object, got ${typeof value}`)
  }
  const raw = value as Record<string, unknown>

  // A file that spells this `secret` was written against the wrong mental
  // model: a NUT-10 P2PK secret is ~150 bytes of JSON and cannot be a slot
  // field. Say so, rather than reporting it as an unknown field.
  if (raw.nonce === undefined && raw.secret !== undefined) {
    throw new CashuInvalidProofError(
      `${where}has "secret" but no "nonce" — the card stores the 32-byte P2PK ` +
        `nonce, not the secret string (which is ~150 bytes of JSON). See NUT-XX.`,
    )
  }
  rejectUnknownFields(raw, SLOT_FIELDS, where)

  const keysetId = requireHex(raw.keysetId, 8, "keysetId", where)
  requireKeysetV0(keysetId, where)

  const C = requireHex(raw.C, 33, "C", where)
  requirePoint(C, "C", where)

  return {
    keysetId,
    amount: requireAmount(raw.amount, where),
    nonce: requireHex(raw.nonce, 32, "nonce", where),
    C,
  }
}

/**
 * Parse and validate a card file.
 *
 * Accepts a JSON string or an already-parsed object. Throws on anything
 * malformed — a card file is an instruction to move money onto or off a bearer
 * card, so there is no useful partial success here.
 */
export const parseCardFile = (input: string | unknown): CardFile => {
  let doc: unknown = input
  if (typeof input === "string") {
    try {
      doc = JSON.parse(input)
    } catch (error) {
      throw new CashuInvalidProofError(
        `card file is not valid JSON: ${(error as Error).message}`,
      )
    }
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new CashuInvalidProofError("card file must be a JSON object")
  }
  const raw = doc as Record<string, unknown>

  if (raw.version !== CARD_FILE_VERSION) {
    throw new CashuInvalidProofError(
      `unsupported card file version ${JSON.stringify(raw.version)}, expected ${CARD_FILE_VERSION}`,
    )
  }
  rejectUnknownFields(raw, FILE_FIELDS, "")
  for (const field of ["mint", "unit"] as const) {
    if (typeof raw[field] !== "string" || raw[field] === "") {
      throw new CashuInvalidProofError(`card file ${field} must be a non-empty string`)
    }
  }
  // Stored canonical, through the same sanitiser every network path uses. A
  // file is third-party data off a bearer instrument: unsanitised it can carry
  // a link-local or metadata URL, and even a benign trailing slash breaks the
  // `mint === expected` comparison that is the only guard against loading a
  // card from the wrong mint.
  let mint: string
  try {
    mint = sanitizeMintUrl(raw.mint as string)
  } catch (error) {
    throw new CashuInvalidProofError(`card file mint: ${(error as Error).message}`)
  }
  // `unit` gets the same treatment, because it has the same job. A caller's
  // only use for it is `file.unit === keyset.unit`, and a mint declares its
  // keyset units trimmed and lower case — so `"SAT "` stored verbatim makes
  // that comparison return false against a keyset that is in fact the right
  // one, silently, exactly the way an untrimmed mint URL did.
  const unit = (raw.unit as string).trim().toLowerCase()
  if (unit === "") {
    throw new CashuInvalidProofError("card file unit must be a non-empty string")
  }
  // A known field with the wrong type is checked, not dropped. Discarding it
  // silently is the drift `rejectUnknownFields` refuses two fields up — and
  // `note` is the file's only provenance record, so losing it without a word
  // is how "loaded at till 2" becomes an unattributable card.
  if (raw.note !== undefined && typeof raw.note !== "string") {
    throw new CashuInvalidProofError("card file note must be a string when present")
  }
  if (!Array.isArray(raw.slots)) {
    throw new CashuInvalidProofError("card file slots must be an array")
  }

  // The card's key is checked before any slot, and completely: if it is bad
  // every slot is unusable and the answer is "reject the card", not "slot 0 is
  // corrupt". Same ordering, and the same reason, as reconstructProofFromCard.
  const cardPubkey = requireHex(raw.cardPubkey, 33, "cardPubkey", "card file ")
  requirePoint(cardPubkey, "cardPubkey", "card file ")

  const slots = (raw.slots as unknown[]).map(parseCardSlot)

  // The same proof twice. Every per-slot check passes — both copies are
  // well-formed, on-curve and reconstruct fine — which makes this the one
  // malformed file the writer would otherwise hand to a card, and the failure
  // it produces is the one this format exists to prevent: slot 0 burns and
  // redeems, slot 1 burns on SPEND_PROOF and the mint refuses it as already
  // spent, while `cardFileTotal` told the holder the card was worth double.
  //
  // `C` is the mint's unblinded signature over a per-proof secret, so it is
  // unique per proof and a repeat is never a coincidence. Checked here rather
  // than in `serializeCardFile` so a card *dumped* with a duplicated slot is
  // caught on the read direction too, before anything is redeemed.
  const seen = new Set<string>()
  slots.forEach((s, i) => {
    if (seen.has(s.C)) {
      throw new CashuInvalidProofError(
        `slot ${i}: duplicates an earlier slot's C — the same proof twice burns a ` +
          `slot the mint will reject as already spent`,
      )
    }
    seen.add(s.C)
  })

  return {
    version: CARD_FILE_VERSION,
    mint,
    unit,
    cardPubkey,
    slots,
    ...(raw.note !== undefined ? { note: raw.note as string } : {}),
  }
}

/**
 * Serialize a card file.
 *
 * Round-trips through `parseCardFile` and then through the *redeem* path —
 * `reconstructProofsFromCard`, whose result is discarded — before writing. This
 * is the only place the mint → card direction is checked at all, and the
 * checks it adds over parsing (curve membership above all) are exactly the ones
 * that cannot be caught later: cardctl does no curve math, so an on-prefix,
 * off-curve `C` reaches the card, burns the slot on SPEND_PROOF, and only then
 * is rejected by the mint as a proof that was never spendable.
 *
 * Reusing the redeem path rather than restating its rules is the point: what
 * this writes is, by construction, what that reads.
 */
export const serializeCardFile = (
  file: Omit<CardFile, "version">,
  { pretty = true }: { pretty?: boolean } = {},
): string => {
  const validated = parseCardFile({ ...file, version: CARD_FILE_VERSION })
  reconstructProofsFromCard(validated.slots, validated.cardPubkey)
  return JSON.stringify(validated, null, pretty ? 2 : undefined)
}

/** Total value in a card file, in the file's `unit`. */
export const cardFileTotal = (file: CardFile): number =>
  file.slots.reduce((sum, s) => sum + s.amount, 0)
