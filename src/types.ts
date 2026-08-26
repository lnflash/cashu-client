export type CashuProof = {
  id: string        // keyset ID (hex, e.g. "0059534ce0bfa19a")
  amount: number    // denomination in keyset base unit (cents for USD)
  secret: string    // NUT-10 P2PK secret JSON string
  C: string         // mint signature (compressed secp256k1 point, hex)
  /**
   * NUT-11 witness: JSON string of {"signatures": ["<64-byte schnorr hex>"]}.
   * A P2PK-locked proof is only spendable with this attached — for a card
   * proof the signature comes from the card's SPEND_PROOF response.
   */
  witness?: string
  /** NUT-12 DLEQ proof, carried through from the blind signature. */
  dleq?: CashuDLEQ
}

/**
 * NUT-12 discrete-log equality proof. On a blind signature it proves the mint
 * used the advertised key `K`; carried onto a proof (with the blinding factor
 * `r`) it lets a receiver verify the same offline, without asking the mint.
 */
export type CashuDLEQ = {
  e: string  // challenge scalar, 32-byte hex
  s: string  // response scalar, 32-byte hex
  r?: string // blinding factor, 32-byte hex — present on proofs, not on blind sigs
}

/** NUT-05: a quote to pay a bolt11 invoice by melting proofs. */
export type CashuMeltQuote = {
  quoteId: string
  amount: number      // invoice amount in the keyset base unit
  feeReserve: number  // maximum routing fee the mint may keep
  state: "UNPAID" | "PENDING" | "PAID"
  expiry: number
  /** Present once state is PAID — proof the Lightning payment settled. */
  paymentPreimage?: string | null
  /** Overpaid fee returned as blind signatures when change outputs were supplied. */
  change?: CashuBlindSignature[]
}

/** NUT-07: the mint's view of a single proof. */
export type CashuProofState = {
  Y: string  // hash_to_curve(secret), the proof's identifier
  state: "UNSPENT" | "PENDING" | "SPENT"
  witness?: string | null
}

export type CashuMintQuote = {
  quoteId: string
  paymentRequest: string // bolt11 invoice
  state: "UNPAID" | "PAID" | "ISSUED" | "EXPIRED"
  expiry: number // unix timestamp
}

export type CashuBlindedMessage = {
  id: string     // keyset ID
  amount: number
  B_: string     // blinded point hex (compressed)
}

export type CashuBlindSignature = {
  id: string
  amount: number
  C_: string     // blind signature hex (compressed)
}

export type CashuBlindingData = {
  nonce: string     // raw 32-byte nonce (hex) — stored on card
  secretStr: string // full NUT-10 P2PK secret JSON string — becomes Proof.secret
  r: Uint8Array     // blinding factor scalar
  B_: string        // blinded point hex
  amount: number
}

export type CashuKeyset = {
  id: string
  unit: string
  active: boolean
}

export type CashuKeysetDetail = {
  id: string
  unit: string
  keys: Record<string, string> // denomination -> mint pubkey hex
}
