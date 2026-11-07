import type { Policy } from "../config.ts";

export type Verdict = "allow" | "warn" | "block";
export type Level = "info" | "warn" | "block";

export interface Reason {
  code: string;
  level: Level;
  detail: string;
}

export type IdKind = "named" | "implicit" | "eth-implicit" | "deterministic" | "invalid";

export interface RegistryStatus {
  reportCount: number;
  trustedReportCount: number;
  categories: string[];
  curated: { blocked: boolean; reason: string } | null;
  /** Evidence from the reports (tx hash or text), for the reasons list. */
  evidence: string[];
}

export interface Signals {
  receiverId: string;
  amountYocto: bigint;
  idKind: IdKind;
  /** null means the chain could not be read. */
  exists: boolean | null;
  isContract: boolean | null;
  codeChangedRecently: boolean | null;
  ageDays: number | null;
  ageIsLowerBound: boolean;
  txCount: number | null;
  txCountCapped: boolean;
  lastDeployDays: number | null;
  priorPayments: number | null;
  registry: RegistryStatus | null;
  attestation: { attribute: string; issuer: string; valid: boolean } | null;
  lookalikeOf: string | null;
  isProtected: boolean;
  isKnown: boolean;
}

const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

/** Account ID rules from https://docs.near.org/protocol/account-id */
export function classifyAccountId(id: string): IdKind {
  if (id.length < 2 || id.length > 64 || !ACCOUNT_RE.test(id)) return "invalid";
  if (/^[0-9a-f]{64}$/.test(id)) return "implicit";
  if (/^0x[0-9a-f]{40}$/.test(id)) return "eth-implicit";
  if (/^0s[0-9a-f]{40}$/.test(id)) return "deterministic";
  return "named";
}

export function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length];
}

/** Map characters attackers swap in lookalike names to one canonical form. */
export function skeleton(id: string): string {
  return id
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[0]/g, "o")
    .replace(/[1l|i]/g, "l")
    .replace(/[5]/g, "s")
    .replace(/[-_]/g, "");
}

/** Returns the known account this one imitates, if any. */
export function findLookalike(id: string, known: string[]): string | null {
  for (const k of known) {
    if (k === id) return null; // exact match is the real thing
  }
  for (const k of known) {
    if (skeleton(k) === skeleton(id)) return k;
    const dist = levenshtein(id, k);
    if (dist > 0 && dist <= 2 && Math.min(id.length, k.length) >= 6) return k;
  }
  return null;
}

/** Turn signals into a verdict. Pure function: no I/O, easy to test and audit. */
export function score(s: Signals, p: Policy): { verdict: Verdict; reasons: Reason[] } {
  const r: Reason[] = [];
  const add = (code: string, level: Level, detail: string) => r.push({ code, level, detail });

  // Hard failures
  if (s.idKind === "invalid") {
    add("INVALID_ACCOUNT_ID", "block", `${s.receiverId} is not a valid NEAR account ID`);
    return finish(r);
  }
  if (s.isProtected) add("PROTECTED_ACCOUNT", "block", "receiver is the guard contract or the paying agent itself");

  // Shared blocklist
  const reg = s.registry;
  if (!reg) {
    add("REGISTRY_UNAVAILABLE", "warn", "could not read the shared blocklist");
  } else {
    const ev = reg.evidence.length ? ` Evidence: ${reg.evidence.slice(0, 3).join("; ")}` : "";
    if (reg.curated?.blocked) {
      add("CURATED_BLOCK", "block", `blocklist curator marked this account: ${reg.curated.reason}`);
    }
    const cleared = reg.curated && !reg.curated.blocked;
    if (reg.trustedReportCount > 0) {
      add("TRUSTED_REPORT", cleared ? "warn" : "block", `reported by ${reg.trustedReportCount} trusted reporter(s) (${reg.categories.join(", ")}).${ev}`);
    } else if (reg.reportCount >= p.blockReportCount) {
      add("REPORTED_MULTI", cleared ? "warn" : "block", `reported by ${reg.reportCount} independent accounts (${reg.categories.join(", ")}).${ev}`);
    } else if (reg.reportCount > 0) {
      add("REPORTED_ONCE", "warn", `reported by ${reg.reportCount} account (${reg.categories.join(", ")}); one report alone is not enough to block.${ev}`);
    }
    if (cleared) add("CURATED_CLEARED", "info", `curator reviewed and cleared: ${reg.curated!.reason}`);
  }

  if (s.lookalikeOf) add("LOOKALIKE", "block", `name imitates known receiver ${s.lookalikeOf}`);

  // Existence
  if (s.exists === null) add("CHAIN_UNAVAILABLE", "warn", "could not read the account from RPC");
  else if (!s.exists) {
    if (s.idKind === "named") add("ACCOUNT_NOT_FOUND", "block", "named account does not exist; the transfer would fail or go to a squatted name later");
    else add("UNFUNDED_IMPLICIT", "warn", "implicit account has never been funded");
  }

  // Contract code
  if (s.isContract) {
    add("IS_CONTRACT", "info", "receiver is a smart contract");
    if (s.codeChangedRecently) add("CODE_CHANGED", "warn", `contract code changed within the last ${p.recentDeployDays} days`);
    if (s.lastDeployDays !== null && s.lastDeployDays < p.recentDeployDays) {
      add("RECENT_DEPLOY", "warn", `contract deployed ${s.lastDeployDays.toFixed(1)} days ago`);
    }
  }

  // Age and activity (weak evidence, softened by an attestation or a known receiver)
  const vetted = s.attestation?.valid || s.isKnown;
  const soft = (code: string, detail: string) => add(code, vetted ? "info" : "warn", detail);
  if (s.exists) {
    if (s.ageDays === null || s.txCount === null) {
      soft("HISTORY_UNKNOWN", "account age and activity could not be read");
    } else {
      if (s.ageDays < p.minAgeDays && !s.ageIsLowerBound) soft("NEW_ACCOUNT", `first activity ${s.ageDays.toFixed(1)} days ago`);
      if (s.txCount < p.minTxCount && !s.txCountCapped) soft("LOW_ACTIVITY", `only ${s.txCount} transactions`);
    }
  }

  // Prior relationship
  if (s.priorPayments === null) add("PRIOR_UNKNOWN", "info", "could not read payment history from the guard");
  else if (s.priorPayments === 0) soft("FIRST_PAYMENT", "this agent has never paid this receiver");
  else add("PRIOR_PAYMENTS", "info", `${s.priorPayments} earlier payment(s) to this receiver`);

  // Attestation
  if (s.attestation?.valid) add("ATTESTED", "info", `holds ${s.attestation.attribute} from ${s.attestation.issuer}`);
  else if (s.attestation && !s.attestation.valid) add("ATTESTATION_INVALID", "warn", `${s.attestation.attribute} attestation is expired or revoked`);

  return finish(r);
}

function finish(r: Reason[]): { verdict: Verdict; reasons: Reason[] } {
  const verdict: Verdict = r.some((x) => x.level === "block") ? "block" : r.some((x) => x.level === "warn") ? "warn" : "allow";
  const order = { block: 0, warn: 1, info: 2 } as const;
  return { verdict, reasons: [...r].sort((a, b) => order[a.level] - order[b.level]) };
}
