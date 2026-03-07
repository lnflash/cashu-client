export type CashuProof = {
  id: string        // keyset ID (hex, e.g. "0059534ce0bfa19a")
  amount: number    // denomination in keyset base unit (cents for USD)
  secret: string    // NUT-10 P2PK secret JSON string
  C: string         // mint signature (compressed secp256k1 point, hex)
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
