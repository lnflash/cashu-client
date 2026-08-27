import {
  CARD_FILE_VERSION,
  CashuInvalidCardPubkeyError,
  CashuInvalidProofError,
  cardFileTotal,
  parseCardFile,
  parseCardSlot,
  reconstructProofsFromCard,
  serializeCardFile,
} from "../src"
import type { CardFile } from "../src"

// Real secp256k1 points: reconstructProofFromCard checks curve membership,
// so placeholder hex would fail there rather than in the parser under test.
const CARD_PUBKEY = "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da"
const REAL_C = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

const slot = (over: Record<string, unknown> = {}) => ({
  keysetId: "0059534ce0bfa19a",
  amount: 8,
  nonce: "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e",
  C: REAL_C,
  ...over,
})

const file = (over: Record<string, unknown> = {}) => ({
  version: CARD_FILE_VERSION,
  mint: "https://forge.flashapp.me",
  unit: "sat",
  cardPubkey: CARD_PUBKEY,
  slots: [slot()],
  ...over,
})

describe("parseCardFile", () => {
  it("accepts a well-formed file and normalises hex case", () => {
    const parsed = parseCardFile(
      file({ cardPubkey: CARD_PUBKEY.toUpperCase(), slots: [slot({ keysetId: "0059534CE0BFA19A" })] }),
    )
    expect(parsed.cardPubkey).toBe(CARD_PUBKEY)
    expect(parsed.slots[0].keysetId).toBe("0059534ce0bfa19a")
  })

  it("accepts a JSON string as well as an object", () => {
    expect(parseCardFile(JSON.stringify(file())).slots).toHaveLength(1)
  })

  it("keeps an optional note but never trusts it structurally", () => {
    expect(parseCardFile(file({ note: "loaded at till 2" })).note).toBe("loaded at till 2")
    expect(parseCardFile(file()).note).toBeUndefined()
  })

  it("accepts an empty card", () => {
    const parsed = parseCardFile(file({ slots: [] }))
    expect(parsed.slots).toEqual([])
    expect(cardFileTotal(parsed)).toBe(0)
  })

  describe("rejects malformed files", () => {
    it("invalid JSON", () => {
      expect(() => parseCardFile("{ not json")).toThrow(/not valid JSON/)
    })

    it("a non-object document", () => {
      expect(() => parseCardFile("[]")).toThrow(/must be a JSON object/)
      expect(() => parseCardFile('"nope"')).toThrow(/must be a JSON object/)
    })

    it("a version it does not understand", () => {
      expect(() => parseCardFile(file({ version: 2 }))).toThrow(/unsupported card file version 2/)
      expect(() => parseCardFile(file({ version: undefined }))).toThrow(/unsupported card file version/)
    })

    it.each(["mint", "unit"])("a missing or empty %s", field => {
      expect(() => parseCardFile(file({ [field]: "" }))).toThrow(
        new RegExp(`${field} must be a non-empty string`),
      )
      expect(() => parseCardFile(file({ [field]: undefined }))).toThrow(
        new RegExp(`${field} must be a non-empty string`),
      )
    })

    it("slots that are not an array", () => {
      expect(() => parseCardFile(file({ slots: {} }))).toThrow(/slots must be an array/)
    })

    // The card's key belongs to the card; a slot field belongs to one slot.
    // A caller has to tell "abort this card" from "skip this slot".
    it("a bad card pubkey, with the card-level error class", () => {
      expect(() => parseCardFile(file({ cardPubkey: "04" + "ab".repeat(32) }))).toThrow(
        CashuInvalidCardPubkeyError,
      )
      expect(() => parseCardFile(file({ cardPubkey: "02ab" }))).toThrow(/33 bytes/)
    })

    it("a bad slot, with the slot-level error class and its index", () => {
      expect(() => parseCardFile(file({ slots: [slot(), slot({ nonce: "ab" })] }))).toThrow(
        CashuInvalidProofError,
      )
      expect(() => parseCardFile(file({ slots: [slot(), slot({ nonce: "ab" })] }))).toThrow(
        /slot 1: nonce must be 32 bytes/,
      )
    })
  })
})

describe("parseCardSlot", () => {
  it("rejects a half-length keyset id — the ASCII-truncation shape", () => {
    expect(() => parseCardSlot(slot({ keysetId: "0059534c" }), 0)).toThrow(
      /keysetId must be 8 bytes/,
    )
  })

  it("names the mistake when a file says secret instead of nonce", () => {
    // The single most likely way for a hand-written or third-party file to be
    // wrong, and the failure it would otherwise produce ("nonce must be a hex
    // string, got undefined") points at the wrong thing entirely.
    const { nonce, ...rest } = slot()
    expect(() => parseCardSlot({ ...rest, secret: nonce }, 3)).toThrow(
      /slot 3: has "secret" but no "nonce"/,
    )
    expect(() => parseCardSlot({ ...rest, secret: nonce }, 3)).toThrow(/~150 bytes of JSON/)
  })

  it.each([0, -1, 1.5, "8", null])("rejects a bad amount: %p", amount => {
    expect(() => parseCardSlot(slot({ amount }), 0)).toThrow(/amount must be a positive integer/)
  })

  it("rejects an uncompressed C point", () => {
    expect(() => parseCardSlot(slot({ C: "04" + "cd".repeat(32) }), 0)).toThrow(
      /C must be a compressed/,
    )
  })

  it.each(["object", "array", "null"])("rejects a %s in place of a slot", kind => {
    const value = kind === "array" ? [] : kind === "null" ? null : "nope"
    expect(() => parseCardSlot(value, 2)).toThrow(/slot 2: expected an object/)
  })
})

describe("serializeCardFile", () => {
  it("round-trips through parse unchanged", () => {
    const original = file()
    const parsed = parseCardFile(serializeCardFile(original as Omit<CardFile, "version">))
    expect(parsed).toEqual(parseCardFile(original))
  })

  it("stamps the current version so the reader can refuse a future shape", () => {
    const written = JSON.parse(serializeCardFile(file() as Omit<CardFile, "version">))
    expect(written.version).toBe(CARD_FILE_VERSION)
  })

  it("refuses to write a file that could not be read back", () => {
    // Catching this here means a card is never handed a malformed file.
    expect(() =>
      serializeCardFile({
        mint: "https://forge.flashapp.me",
        unit: "sat",
        cardPubkey: CARD_PUBKEY,
        slots: [slot({ keysetId: "0059534c" })],
      } as unknown as Omit<CardFile, "version">),
    ).toThrow(/keysetId must be 8 bytes/)
  })

  it("emits compact output when asked", () => {
    const compact = serializeCardFile(file() as Omit<CardFile, "version">, { pretty: false })
    expect(compact).not.toContain("\n")
    expect(parseCardFile(compact).slots).toHaveLength(1)
  })
})

describe("the card → mint direction", () => {
  it("a parsed file feeds reconstructProofsFromCard directly", () => {
    // This is the whole point of the format: what cardctl dumps is what the
    // mint side reconstructs, with no field renaming in between.
    const parsed = parseCardFile(
      file({ slots: [slot(), slot({ amount: 16, nonce: "cd".repeat(32) })] }),
    )
    const proofs = reconstructProofsFromCard(parsed.slots, parsed.cardPubkey)

    expect(proofs).toHaveLength(2)
    expect(proofs.map(p => p.amount)).toEqual([8, 16])
    expect(proofs[0].id).toBe("0059534ce0bfa19a")
    expect(proofs[0].secret).toContain(parsed.cardPubkey)
    expect(cardFileTotal(parsed)).toBe(24)
  })
})
