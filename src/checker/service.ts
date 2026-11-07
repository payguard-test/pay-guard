import type { Chain } from "../chain.ts";
import type { Policy } from "../config.ts";
import type { History } from "../history.ts";
import { AttestationSigner, type Attestation } from "./attest.ts";
import { CodeHashCache } from "./code-cache.ts";
import { classifyAccountId, findLookalike, score, type Reason, type RegistryStatus, type Signals, type Verdict } from "./score.ts";

export interface CheckRequest {
  agentId: string;
  receiverId: string;
  amount: string; // yoctoNEAR
}

export interface Decision {
  verdict: Verdict;
  reasons: Reason[];
  signals: Record<string, unknown>;
  /** Present only for allow and warn. The checker never signs block. */
  attestation?: Attestation;
  checkedAt: string;
}

export interface CheckerDeps {
  chain: Chain;
  history: History;
  policy: Policy;
  signer: AttestationSigner;
  guardContractId: string;
  registryContractId: string;
  codeCache?: CodeHashCache;
  now?: () => number;
}

const DAY_MS = 86_400_000;

async function safe<T>(f: () => Promise<T>): Promise<T | null> {
  try {
    return await f();
  } catch {
    return null;
  }
}

export class Checker {
  private codeCache: CodeHashCache;
  private now: () => number;
  constructor(readonly d: CheckerDeps) {
    this.codeCache = d.codeCache ?? new CodeHashCache();
    this.now = d.now ?? Date.now;
  }

  async gather(req: CheckRequest): Promise<Signals> {
    const { chain, history, policy } = this.d;
    const id = req.receiverId;
    const idKind = classifyAccountId(id);
    const base: Signals = {
      receiverId: id,
      amountYocto: BigInt(req.amount),
      idKind,
      exists: null,
      isContract: null,
      codeChangedRecently: null,
      ageDays: null,
      ageIsLowerBound: false,
      txCount: null,
      txCountCapped: false,
      lastDeployDays: null,
      priorPayments: null,
      registry: null,
      attestation: null,
      lookalikeOf: null,
      isProtected: id === this.d.guardContractId || id === req.agentId,
      isKnown: policy.knownReceivers.includes(id),
    };
    if (idKind === "invalid") return base;

    const [acct, activity, prior, status, reports, att] = await Promise.all([
      safe(() => chain.account(id)),
      safe(() => history.activity(id)),
      safe(() => chain.view<{ count: string }>(this.d.guardContractId, "get_interaction", { agent_id: req.agentId, receiver_id: id })),
      safe(() => chain.view<any>(this.d.registryContractId, "get_status", { subject: id })),
      safe(() => chain.view<any[]>(this.d.registryContractId, "get_reports", { subject: id, limit: 5 })),
      safe(() => chain.view<any>(this.d.registryContractId, "get_attestation", { subject: id, attribute: policy.trustedAttribute })),
    ]);

    const now = this.now();
    if (acct) {
      base.exists = acct.exists;
      base.isContract = acct.exists ? !!acct.isContract : false;
      if (acct.isContract && acct.codeHash) {
        const changedAt = this.codeCache.observe(id, acct.codeHash, now);
        base.codeChangedRecently = changedAt !== undefined && now - changedAt < policy.recentDeployDays * DAY_MS;
      } else base.codeChangedRecently = false;
    }
    if (activity) {
      base.txCount = activity.txCount;
      base.txCountCapped = activity.capped;
      if (activity.oldestSeenMs !== undefined) {
        base.ageDays = (now - activity.oldestSeenMs) / DAY_MS;
        base.ageIsLowerBound = activity.capped; // oldest of a capped page is only a lower bound on age
      }
      if (activity.lastDeployMs !== undefined) base.lastDeployDays = (now - activity.lastDeployMs) / DAY_MS;
    }
    if (prior) base.priorPayments = Number(prior.count);
    if (status) {
      const r: RegistryStatus = {
        reportCount: status.report_count,
        trustedReportCount: status.trusted_report_count,
        categories: status.categories ?? [],
        curated: status.curated ?? null,
        evidence: (reports ?? []).map((x) => (x.evidence_tx ? `tx ${x.evidence_tx}: ${x.evidence_text}` : x.evidence_text)),
      };
      base.registry = r;
    }
    if (att) base.attestation = { attribute: policy.trustedAttribute, issuer: att.issuer, valid: !!att.valid };
    base.lookalikeOf = findLookalike(id, policy.knownReceivers);
    return base;
  }

  async check(req: CheckRequest): Promise<Decision> {
    if (!/^\d+$/.test(req.amount) || BigInt(req.amount) <= 0n) throw new Error("amount must be a positive integer in yoctoNEAR");
    const signals = await this.gather(req);
    const { verdict, reasons } = score(signals, this.d.policy);
    const decision: Decision = {
      verdict,
      reasons,
      signals: { ...signals, amountYocto: signals.amountYocto.toString() },
      checkedAt: new Date(this.now()).toISOString(),
    };
    if (verdict !== "block") {
      decision.attestation = this.d.signer.sign(req.agentId, req.receiverId, BigInt(req.amount), verdict, this.now());
    }
    return decision;
  }
}
