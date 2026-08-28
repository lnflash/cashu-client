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
import type { CardFile, CardFileSlot } from "../src"

// Real secp256k1 points: reconstructProofFromCard checks curve membership,
// so placeholder hex would fail there rather than in the parser under test.
const CARD_PUBKEY = "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da"
const REAL_C = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
// Further on-curve signatures. Two slots on one card are two different proofs,
// so multi-slot fixtures must carry different `C` values — a card whose slots
// share one is the duplicate-proof file parseCardFile now refuses.
const REAL_C2 = "02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af"
const REAL_C3 = "03d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9"
// On-prefix, off-curve: the shape a prefix-only check waves through.
const OFF_CURVE = "02" + "ff".repeat(32)

const slot = (over: Partial<CardFileSlot> = {}): CardFileSlot => ({
  keysetId: "0059534ce0bfa19a",
  amount: 8,
  nonce: "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e",
  C: REAL_C,
  spent: false,
  ...over,
})

const file = (over: Partial<CardFile> = {}): CardFile => ({
  version: CARD_FILE_VERSION,
  mint: "https://forge.flashapp.me",
  unit: "sat",
  cardPubkey: CARD_PUBKEY,
  slots: [slot()],
  ...over,
})

// The rejection paths need shapes the types forbid, which is the point of them.
// Both casts live here so the helpers above stay honestly typed: a signature
// change to serializeCardFile has to fail this suite, not be absorbed by an
// `as unknown as` at every call site.
const invalidSlot = (over: Record<string, unknown>): CardFileSlot =>
  ({ ...slot(), ...over }) as unknown as CardFileSlot

const invalidFile = (over: Record<string, unknown>): CardFile =>
  ({ ...file(), ...over }) as unknown as CardFile

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

  // A trailing slash would otherwise survive into the file and fail the
  // `file.mint === expected` comparison that is the only guard against loading
  // a card from the wrong mint — silently, since both spellings are the mint.
  it("canonicalises the mint URL the way every network path does", () => {
    expect(parseCardFile(file({ mint: "https://forge.flashapp.me/" })).mint).toBe(
      "https://forge.flashapp.me",
    )
    expect(parseCardFile(file({ mint: "https://forge.flashapp.me/cashu/" })).mint).toBe(
      "https://forge.flashapp.me/cashu",
    )
  })

  // `unit` has the same job and therefore the same failure: the only thing a
  // caller does with it is compare it against a keyset's unit, and a mint
  // declares those trimmed and lower case.
  it.each([
    ["SAT", "sat"],
    ["sat ", "sat"],
    [" Sat\t", "sat"],
    ["USD", "usd"],
  ])("canonicalises the unit %p to %p", (raw, expected) => {
    expect(parseCardFile(file({ unit: raw })).unit).toBe(expected)
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
      expect(() => parseCardFile(invalidFile({ version: undefined }))).toThrow(
        /unsupported card file version/,
      )
    })

    it.each(["mint", "unit"])("a missing or empty %s", field => {
      expect(() => parseCardFile(invalidFile({ [field]: "" }))).toThrow(
        new RegExp(`${field} must be a non-empty string`),
      )
      expect(() => parseCardFile(invalidFile({ [field]: undefined }))).toThrow(
        new RegExp(`${field} must be a non-empty string`),
      )
    })

    // A card file is third-party data off a bearer instrument. The SSRF
    // controls the HTTP layer applies apply here too, at the boundary, rather
    // than relying on every consumer to remember to sanitise before dialling.
    it.each([
      "http://169.254.169.254/latest/meta-data/",
      "http://10.0.0.1",
      "https://user:pass@forge.flashapp.me",
      "ftp://forge.flashapp.me",
      "not a url",
    ])("a mint URL the sanitiser refuses: %s", mint => {
      expect(() => parseCardFile(file({ mint }))).toThrow(/card file mint:/)
      expect(() => parseCardFile(file({ mint }))).toThrow(CashuInvalidProofError)
    })

    it("slots that are not an array", () => {
      expect(() => parseCardFile(invalidFile({ slots: {} }))).toThrow(/slots must be an array/)
    })

    // Silently dropping a field a future cardctl added — without bumping
    // `version` — is exactly the drift `version` exists to catch.
    it("a field this version does not know about", () => {
      expect(() => parseCardFile(invalidFile({ counter: 7 }))).toThrow(
        /unknown field\(s\): counter/,
      )
      expect(() => parseCardFile(invalidFile({ counter: 7 }))).toThrow(CashuInvalidProofError)
    })

    // The card's key belongs to the card; a slot field belongs to one slot.
    // A caller has to tell "abort this card" from "skip this slot".
    it("a bad card pubkey, with the card-level error class", () => {
      expect(() => parseCardFile(file({ cardPubkey: "04" + "ab".repeat(32) }))).toThrow(
        CashuInvalidCardPubkeyError,
      )
      expect(() => parseCardFile(file({ cardPubkey: "02ab" }))).toThrow(/33 bytes/)
    })

    it("an on-prefix but off-curve card pubkey", () => {
      expect(() => parseCardFile(file({ cardPubkey: OFF_CURVE }))).toThrow(
        /cardPubkey is not on the secp256k1 curve/,
      )
      expect(() => parseCardFile(file({ cardPubkey: OFF_CURVE }))).toThrow(
        CashuInvalidCardPubkeyError,
      )
    })

    it("a bad slot, with the slot-level error class and its index", () => {
      expect(() => parseCardFile(file({ slots: [slot(), slot({ nonce: "ab" })] }))).toThrow(
        CashuInvalidProofError,
      )
      expect(() => parseCardFile(file({ slots: [slot(), slot({ nonce: "ab" })] }))).toThrow(
        /slot 1: nonce must be 32 bytes/,
      )
    })

    // The one shape where every per-slot check passes and the card still
    // burns a slot the mint refuses: slot 0 redeems, slot 1 burns on
    // SPEND_PROOF and comes back already-spent, while cardFileTotal claimed
    // both were spendable.
    it("the same proof twice", () => {
      expect(() => parseCardFile(file({ slots: [slot(), slot()] }))).toThrow(
        /slot 1: duplicates an earlier slot's C/,
      )
      expect(() => parseCardFile(file({ slots: [slot(), slot()] }))).toThrow(
        CashuInvalidProofError,
      )
    })

    // Differing amount or nonce is not a different proof: `C` is the mint's
    // signature over one secret, so a repeat is the same proof relabelled.
    it("a duplicate C even when the other slot fields differ", () => {
      expect(() =>
        parseCardFile(
          file({
            slots: [slot(), slot({ amount: 16, nonce: "cd".repeat(32) })],
          }),
        ),
      ).toThrow(/slot 1: duplicates an earlier slot's C/)
    })

    it("a duplicate that is not adjacent, naming the later index", () => {
      expect(() =>
        parseCardFile(file({ slots: [slot(), slot({ C: REAL_C2 }), slot({ C: REAL_C })] })),
      ).toThrow(/slot 2: duplicates an earlier slot's C/)
    })

    it("a note that is not a string", () => {
      expect(() => parseCardFile(invalidFile({ note: 42 }))).toThrow(
        /note must be a string when present/,
      )
      expect(() => parseCardFile(invalidFile({ note: 42 }))).toThrow(CashuInvalidProofError)
      expect(() => parseCardFile(invalidFile({ note: { at: "till 2" } }))).toThrow(
        /note must be a string when present/,
      )
    })

    it("a unit that is only whitespace", () => {
      expect(() => parseCardFile(file({ unit: "   " }))).toThrow(
        /unit must be a non-empty string/,
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

  // 8 bytes is the only NUT-02 id version that fits the card's field, so a
  // first byte other than 00 is a corrupted id that matches no keyset — and
  // one the mint only rejects after the slot is burned.
  it("rejects a keyset id that is not NUT-02 v0", () => {
    expect(() => parseCardSlot(slot({ keysetId: "0159534ce0bfa19a" }), 0)).toThrow(
      /keysetId must be a NUT-02 v0 id/,
    )
    expect(() => parseCardSlot(slot({ keysetId: "0159534ce0bfa19a" }), 0)).toThrow(
      CashuInvalidProofError,
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

  it("rejects a slot field this version does not know about", () => {
    expect(() => parseCardSlot(invalidSlot({ counter: 7 }), 1)).toThrow(
      /slot 1: unknown field\(s\): counter/,
    )
  })

  it.each(["8", null, undefined, {}])("rejects a non-numeric amount: %p", amount => {
    expect(() => parseCardSlot(invalidSlot({ amount }), 0)).toThrow(/amount must be a number/)
  })

  // Cashu denominations are powers of two; a mint keyset has no key for 3, so
  // a corrupted amount byte must not survive to the card.
  it.each([0, -1, 1.5, 3, 9, 2 ** 60])("rejects a non-denomination amount: %p", amount => {
    expect(() => parseCardSlot(invalidSlot({ amount }), 0)).toThrow(
      /amount must be a positive power of two/,
    )
  })

  it("rejects an uncompressed C point", () => {
    expect(() => parseCardSlot(slot({ C: "04" + "cd".repeat(32) }), 0)).toThrow(
      /C must be a compressed/,
    )
  })

  // The check this replaced tested the low nibble of the first byte, so it
  // accepted 32 of the 256 possible prefixes and passed its own test by luck:
  // 0x04's nibble happens to be 4. These are the prefixes that slipped through.
  it.each(["12", "f3", "22", "33", "ff"])("rejects the bogus C prefix 0x%s", prefix => {
    expect(() => parseCardSlot(slot({ C: prefix + "cd".repeat(32) }), 0)).toThrow(
      new RegExp(`C must be a compressed secp256k1 point, got prefix 0x${prefix}`),
    )
  })

  it("rejects an on-prefix but off-curve C", () => {
    expect(() => parseCardSlot(slot({ C: OFF_CURVE }), 0)).toThrow(
      /C is not on the secp256k1 curve/,
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
    const parsed = parseCardFile(serializeCardFile(original))
    expect(parsed).toEqual(parseCardFile(original))
  })

  it("stamps the current version so the reader can refuse a future shape", () => {
    const written = JSON.parse(serializeCardFile(file()))
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
      }),
    ).toThrow(/keysetId must be 8 bytes/)
  })

  // This is the whole contract of the write direction: cardctl does no curve
  // math, so anything serializeCardFile accepts is loaded onto a card. A file
  // the redeem path would reject is money burned at SPEND_PROOF.
  describe("refuses anything the redeem path would reject", () => {
    const cases: Array<[string, Record<string, unknown>, RegExp]> = [
      ["an on-prefix, off-curve C", { C: OFF_CURVE }, /C is not on the secp256k1 curve/],
      ["a non-v0 keyset id", { keysetId: "0159534ce0bfa19a" }, /keysetId must be a NUT-02 v0 id/],
      ["a non-power-of-two amount", { amount: 3 }, /amount must be a positive power of two/],
      ["an unsafe-integer amount", { amount: 2 ** 60 }, /amount must be a positive power of two/],
    ]

    it.each(cases)("%s", (_name, over, message) => {
      expect(() => serializeCardFile(file({ slots: [invalidSlot(over)] }))).toThrow(message)
    })

    it("an off-curve card pubkey", () => {
      expect(() => serializeCardFile(file({ cardPubkey: OFF_CURVE }))).toThrow(
        CashuInvalidCardPubkeyError,
      )
    })

    // The property behind the cases above: acceptance by the writer implies
    // acceptance by the reader, for every shape either of them sees.
    //
    // Split into accept rows and reject rows deliberately. A single table with
    // a `catch { return }` makes the accept rows unfalsifiable — the row named
    // "what the writer accepts, the reader accepts" would pass on a writer that
    // threw on a well-formed card, asserting nothing about the half of the
    // property it is named for. Each half now asserts its own direction.
    describe("what the writer accepts, the reader accepts", () => {
      it.each([
        ["a well-formed card", file()],
        ["an empty card", file({ slots: [] })],
        [
          "several denominations",
          file({
            slots: [slot(), slot({ amount: 16, C: REAL_C2 }), slot({ amount: 1, C: REAL_C3 })],
          }),
        ],
        ["upper-case hex", file({ cardPubkey: CARD_PUBKEY.toUpperCase() })],
        ["an unsanitised mint URL", file({ mint: "https://forge.flashapp.me/" })],
        ["an uncanonical unit", file({ unit: "SAT " })],
        ["a note", file({ note: "till 2" })],
      ])("%s", (_name, candidate) => {
        expect(() => serializeCardFile(candidate)).not.toThrow()
        const parsed = parseCardFile(serializeCardFile(candidate))
        expect(() => reconstructProofsFromCard(parsed.slots, parsed.cardPubkey)).not.toThrow()
      })
    })

    // The other half: what the reader would reject never gets written, so it
    // never reaches a card. These assert the throw rather than tolerating it.
    describe("what the reader would reject, the writer refuses to write", () => {
      it.each([
        [
          "a bad C prefix",
          invalidFile({ slots: [invalidSlot({ C: "12" + "cd".repeat(32) })] }),
          /C must be a compressed secp256k1 point/,
        ],
        [
          "an off-curve C",
          invalidFile({ slots: [invalidSlot({ C: OFF_CURVE })] }),
          /C is not on the secp256k1 curve/,
        ],
        [
          "a non-v0 keyset id",
          invalidFile({ slots: [invalidSlot({ keysetId: "01".repeat(8) })] }),
          /keysetId must be a NUT-02 v0 id/,
        ],
        [
          "amount 3",
          invalidFile({ slots: [invalidSlot({ amount: 3 })] }),
          /amount must be a positive power of two/,
        ],
        [
          "a corrupted amount byte",
          invalidFile({ slots: [invalidSlot({ amount: 9 })] }),
          /amount must be a positive power of two/,
        ],
        [
          "an unknown slot field",
          invalidFile({ slots: [invalidSlot({ counter: 7 })] }),
          /unknown field\(s\): counter/,
        ],
        [
          "the same proof in two slots",
          file({ slots: [slot(), slot()] }),
          /slot 1: duplicates an earlier slot's C/,
        ],
        [
          "a note that is not a string",
          invalidFile({ note: 42 }),
          /note must be a string when present/,
        ],
      ])("%s", (_name, candidate, message) => {
        expect(() => serializeCardFile(candidate)).toThrow(message)
      })
    })
  })

  it("emits compact output when asked", () => {
    const compact = serializeCardFile(file(), { pretty: false })
    expect(compact).not.toContain("\n")
    expect(parseCardFile(compact).slots).toHaveLength(1)
  })
})

describe("the card → mint direction", () => {
  it("a parsed file feeds reconstructProofsFromCard directly", () => {
    // This is the whole point of the format: what cardctl dumps is what the
    // mint side reconstructs, with no field renaming in between.
    const parsed = parseCardFile(
      file({ slots: [slot(), slot({ amount: 16, nonce: "cd".repeat(32), C: REAL_C2 })] }),
    )
    const proofs = reconstructProofsFromCard(parsed.slots, parsed.cardPubkey)

    expect(proofs).toHaveLength(2)
    expect(proofs.map(p => p.amount)).toEqual([8, 16])
    expect(proofs[0].id).toBe("0059534ce0bfa19a")
    expect(proofs[0].secret).toContain(parsed.cardPubkey)
    expect(cardFileTotal(parsed)).toBe(24)
  })
})

describe("the spent bit", () => {
  // A card cannot carry this: LOAD_PROOF has no spent field. So a spent proof
  // written back onto a card returns as unspent and inflates the balance with
  // money that is already gone. The file is the only place it can live, which
  // is why it is required rather than defaulted.
  it("round-trips both values", () => {
    const parsed = parseCardFile(
      file({ slots: [slot({ spent: false }), slot({ spent: true, C: REAL_C2 })] }),
    )
    expect(parsed.slots.map(s => s.spent)).toEqual([false, true])
  })

  it("is required — a missing bit is refused, never defaulted to false", () => {
    const { spent, ...withoutSpent } = slot()
    expect(() => parseCardFile(file({ slots: [withoutSpent as never] }))).toThrow(
      /slot 0: spent must be a boolean, got undefined/,
    )
  })

  it.each([["string", "false"], ["number", 0], ["null", null]])(
    "rejects a %s in place of the boolean",
    (_label, value) => {
      expect(() => parseCardFile(file({ slots: [slot({ spent: value as never })] }))).toThrow(
        /spent must be a boolean/,
      )
    },
  )

  it("survives serialization", () => {
    const written = serializeCardFile(
      file({ slots: [slot({ spent: true })] }) as Omit<CardFile, "version">,
    )
    expect(parseCardFile(written).slots[0].spent).toBe(true)
  })
})

describe("the card's 4-byte amount field", () => {
  // requireAmount allows any safe power of two, which is right for a proof in
  // general. LOAD_PROOF carries the amount as a 4-byte unsigned integer, so the
  // file — written before anything reaches a card — is where that bound belongs.
  it("accepts the largest amount a card can hold", () => {
    expect(parseCardFile(file({ slots: [slot({ amount: 2 ** 31 })] })).slots[0].amount).toBe(
      2 ** 31,
    )
  })

  it("rejects an amount the card could not store", () => {
    expect(() => parseCardFile(file({ slots: [slot({ amount: 2 ** 32 })] }))).toThrow(
      /below 2\^32/,
    )
    expect(() => parseCardFile(file({ slots: [slot({ amount: 2 ** 40 })] }))).toThrow(
      /4-byte unsigned integer/,
    )
  })
})

describe("cross-repo contract", () => {
  /**
   * What this side can and cannot check.
   *
   * These assertions pin the field names *this* implementation reads and
   * writes. They cannot catch a rename in cardctl — that repo holds the
   * published schema (`spec/CARD-FILE.md`) and a fixture generated by
   * `serializeCardFile`, and its CI checks both halves against the spec.
   *
   * Stating the limit rather than implying coverage we do not have: an earlier
   * revision of this work claimed a fixture made renames fail "on either side",
   * which was true in one direction only.
   */
  it("reads and writes exactly the published slot fields", () => {
    const written = JSON.parse(serializeCardFile(file() as Omit<CardFile, "version">))
    expect(Object.keys(written.slots[0]).sort()).toEqual(
      ["C", "amount", "keysetId", "nonce", "spent"].sort(),
    )
    expect(Object.keys(written).sort()).toEqual(
      ["cardPubkey", "mint", "slots", "unit", "version"].sort(),
    )
  })

  it("refuses a field the schema does not publish", () => {
    expect(() => parseCardFile(file({ slots: [{ ...slot(), extra: 1 } as never] }))).toThrow(
      /unknown field\(s\): extra/,
    )
  })
})
