/**
 * Agent-side guard. The only way the agent's code should spend money.
 *   1. Refuses to start unless its key is a function-call key scoped to the guard
 *      contract with method_names ["pay"]. A full-access key is rejected outright.
 *   2. Asks the checker about every receiver before signing.
 *   3. block  -> refuses, never signs.
 *      warn   -> asks a human; signs only on an explicit yes.
 *      allow  -> signs the pay call with the checker's attestation.
 * The contract enforces the same attestation again, so skipping this wrapper does not
 * let a compromised agent pay an unchecked receiver.
 */
import type { Chain } from "../chain.ts";
import type { Attestation } from "../checker/attest.ts";
import type { CheckRequest, Decision } from "../checker/service.ts";
import { fmtNear } from "../config.ts";
import { log } from "../log.ts";

export interface CheckerClient {
  check(req: CheckRequest): Promise<Decision>;
}

export class HttpCheckerClient implements CheckerClient {
  constructor(readonly url: string) {}
  async check(req: CheckRequest): Promise<Decision> {
    const res = await fetch(`${this.url}/check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) throw new Error(`checker answered ${res.status}: ${await res.text()}`);
    return (await res.json()) as Decision;
  }
}

export interface Approver {
  approve(req: { receiverId: string; amount: bigint; purpose: string; decision: Decision }): Promise<boolean>;
}

/** Asks in the terminal. Anything but "y" or "yes" is a no. */
export class TerminalApprover implements Approver {
  async approve({ receiverId, amount, purpose, decision }: Parameters<Approver["approve"]>[0]): Promise<boolean> {
    const { createInterface } = await import("node:readline/promises");
    console.log(`\n  The checker says WARN for ${receiverId} (${fmtNear(amount)}), purpose: ${purpose}`);
    for (const r of decision.reasons.filter((x) => x.level === "warn")) console.log(`    * ${r.code}: ${r.detail}`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const ans = (await rl.question("  Approve this payment? [y/N] ")).trim().toLowerCase();
    rl.close();
    return ans === "y" || ans === "yes";
  }
}

/** Non-interactive approver for the recorded demo: approves only the payee the human actually asked to pay. */
export class ExpectedPayeeApprover implements Approver {
  constructor(readonly expected: Set<string>) {}
  async approve({ receiverId }: Parameters<Approver["approve"]>[0]): Promise<boolean> {
    const ok = this.expected.has(receiverId);
    log("HUMAN", ok ? "APPROVED" : "DENIED", { receiver: receiverId, why: ok ? "this is the invoice I asked the agent to pay" : "I never asked to pay this account" });
    return ok;
  }
}

export interface PayResult {
  ok: boolean;
  txHash?: string;
  error?: string;
}

/** Sends the `pay` function call to the guard contract. */
export interface PaySubmitter {
  submitPay(att: Attestation): Promise<PayResult>;
}

export type Outcome =
  | { status: "paid"; decision: Decision; txHash?: string }
  | { status: "refused"; decision: Decision }
  | { status: "declined"; decision: Decision }
  | { status: "failed"; decision: Decision; error: string };

export interface WalletOptions {
  agentId: string;
  agentPublicKey: string;
  guardContractId: string;
  chain: Chain;
  checker: CheckerClient;
  approver: Approver;
  submitter: PaySubmitter;
}

export class KeyScopeError extends Error {}

export class GuardedWallet {
  private verified = false;
  constructor(readonly o: WalletOptions) {}

  /** Refuse to operate with anything broader than a ["pay"]-only key on the guard. */
  async verifyKeyScope(): Promise<void> {
    const p = await this.o.chain.accessKey(this.o.agentId, this.o.agentPublicKey);
    if (p.kind === "full") throw new KeyScopeError("agent key is a FULL-ACCESS key. Refusing to run. Use a function-call key scoped to the guard contract.");
    if (p.kind === "missing") throw new KeyScopeError(`key ${this.o.agentPublicKey} is not on ${this.o.agentId}`);
    if (p.receiverId !== this.o.guardContractId) throw new KeyScopeError(`agent key is scoped to ${p.receiverId}, expected ${this.o.guardContractId}`);
    if (p.methodNames.length !== 1 || p.methodNames[0] !== "pay") {
      throw new KeyScopeError(`agent key allows methods [${p.methodNames.join(",") || "ANY"}], expected exactly ["pay"]`);
    }
    const others = (await this.o.chain.accessKeys(this.o.agentId)).filter((k) => k.permission.kind === "full");
    log("WRAPPER", "KEY_OK", {
      key: "function-call",
      receiver: p.receiverId,
      methods: p.methodNames,
      allowance: p.allowance ? fmtNear(BigInt(p.allowance)) : "unlimited",
      fullAccessKeysOnAccount: others.length,
    });
    if (others.length) log("WRAPPER", "WARNING", { detail: `agent account still has ${others.length} full-access key(s); keep them off this host` });
    this.verified = true;
  }

  async pay(receiverId: string, amount: bigint, purpose: string): Promise<Outcome> {
    if (!this.verified) await this.verifyKeyScope();
    log("WRAPPER", "CHECK", { receiver: receiverId, amount: fmtNear(amount), purpose });
    const decision = await this.o.checker.check({ agentId: this.o.agentId, receiverId, amount: amount.toString() });
    const shown = decision.reasons.filter((r) => r.level !== "info");
    log("CHECKER", decision.verdict.toUpperCase(), { receiver: receiverId, reasons: shown.length ? shown.map((r) => `${r.code}: ${r.detail}`) : ["no risk signals"] });

    if (decision.verdict === "block") {
      log("WRAPPER", "REFUSED", { receiver: receiverId, detail: "checker said block; nothing was signed" });
      return { status: "refused", decision };
    }
    if (decision.verdict === "warn") {
      const ok = await this.o.approver.approve({ receiverId, amount, purpose, decision });
      if (!ok) {
        log("WRAPPER", "DECLINED", { receiver: receiverId, detail: "human did not approve; nothing was signed" });
        return { status: "declined", decision };
      }
    }
    if (!decision.attestation) return { status: "failed", decision, error: "checker returned no attestation" };
    const att = decision.attestation;
    if (att.receiver_id !== receiverId || att.amount !== amount.toString()) {
      return { status: "failed", decision, error: "attestation does not match the requested payment" };
    }
    log("WRAPPER", "SIGNING", { method: "pay", contract: this.o.guardContractId, nonce: att.nonce });
    const r = await this.o.submitter.submitPay(att);
    if (!r.ok) {
      log("CONTRACT", "REJECTED", { error: r.error });
      return { status: "failed", decision, error: r.error ?? "unknown error" };
    }
    log("CONTRACT", "PAID", { receiver: receiverId, amount: fmtNear(amount), tx: r.txHash ?? "(offline)" });
    return { status: "paid", decision, txHash: r.txHash };
  }
}
