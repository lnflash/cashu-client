import type { CashuBlindSignature, CashuBlindedMessage, CashuProof } from "./types";
import { CashuMintError } from "./errors";
import type { InputFeeRates } from "./melt";
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
export declare const swapProofs: (mintUrl: string, inputs: CashuProof[], outputs: CashuBlindedMessage[], inputFeePpk?: number | InputFeeRates) => Promise<CashuBlindSignature[] | CashuMintError>;
