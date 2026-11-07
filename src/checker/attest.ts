import { KeyPair, type KeyPairString } from "near-api-js";

/** Must match `attestation_message` in contracts/pay-guard/src/lib.rs. */
export const MESSAGE_PREFIX = "pay-guard:v1";

export interface Attestation {
  receiver_id: string;
  amount: string; // yoctoNEAR
  verdict: "allow" | "warn";
  nonce: string; // u64
  expires_at: string; // ns
  signature: string; // base64 ed25519
}

export function attestationMessage(contractId: string, agentId: string, a: Omit<Attestation, "signature">): string {
  return [MESSAGE_PREFIX, contractId, agentId, a.receiver_id, a.amount, a.verdict, a.nonce, a.expires_at].join("|");
}

export class AttestationSigner {
  private lastNonce = 0n;
  readonly keyPair: KeyPair;
  constructor(secretKey: string, readonly contractId: string, readonly ttlSec = 120) {
    this.keyPair = KeyPair.fromString(secretKey as KeyPairString);
  }
  publicKey(): string {
    return this.keyPair.getPublicKey().toString();
  }
  /** Nonces are microsecond timestamps, strictly increasing per process. */
  private nextNonce(nowMs: number): bigint {
    let n = BigInt(nowMs) * 1000n;
    if (n <= this.lastNonce) n = this.lastNonce + 1n;
    this.lastNonce = n;
    return n;
  }
  sign(agentId: string, receiverId: string, amount: bigint, verdict: "allow" | "warn", nowMs = Date.now()): Attestation {
    const body = {
      receiver_id: receiverId,
      amount: amount.toString(),
      verdict,
      nonce: this.nextNonce(nowMs).toString(),
      expires_at: ((BigInt(nowMs) + BigInt(this.ttlSec * 1000)) * 1_000_000n).toString(),
    };
    const msg = new TextEncoder().encode(attestationMessage(this.contractId, agentId, body));
    const { signature } = this.keyPair.sign(msg);
    return { ...body, signature: Buffer.from(signature).toString("base64") };
  }
}
