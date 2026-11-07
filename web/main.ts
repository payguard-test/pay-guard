/**
 * Browser build of the pay-guard checker for the project website (docs/index.html).
 * Read-only: it gathers the same signals as src/checker/service.ts straight from
 * NEAR testnet RPC and NearBlocks, then runs the exact same score() function.
 * It never signs anything; attestations come only from the checker service.
 */
import { classifyAccountId, findLookalike, score, type Signals } from "../src/checker/score.ts";

const RPC = "https://test.rpc.fastnear.com";
const NEARBLOCKS = "https://api-testnet.nearblocks.io";
const EMPTY_CODE_HASH = "11111111111111111111111111111111";
export const LIVE = {
  guard: "pgd4yk-guard.payguard-bay.testnet",
  registry: "pgd4yk-registry.payguard-bay.testnet",
  agent: "pgd4yk-agent.payguard-bay.testnet",
  shop: "pgd4yk-shop.payguard-bay.testnet",
};
const POLICY = {
  minAgeDays: 7,
  minTxCount: 5,
  blockReportCount: 2,
  recentDeployDays: 7,
  knownReceivers: [LIVE.shop],
  trustedAttribute: "verified_merchant",
  attestationTtlSec: 120,
};
const DAY = 86_400_000;

async function rpc(params: Record<string, unknown>): Promise<any> {
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query", params: { finality: "final", ...params } }),
  });
  const j = await r.json();
  if (j.error) throw Object.assign(new Error(JSON.stringify(j.error)), { rpc: j.error });
  return j.result;
}

async function view<T>(contract: string, method: string, args: Record<string, unknown>): Promise<T> {
  const res = await rpc({ request_type: "call_function", account_id: contract, method_name: method, args_base64: btoa(JSON.stringify(args)) });
  return JSON.parse(new TextDecoder().decode(new Uint8Array(res.result)));
}

async function account(id: string): Promise<{ exists: boolean; codeHash?: string }> {
  try {
    const a = await rpc({ request_type: "view_account", account_id: id });
    return { exists: true, codeHash: a.code_hash };
  } catch (e: any) {
    if (/UNKNOWN_ACCOUNT|does not exist/i.test(JSON.stringify(e.rpc ?? e.message))) return { exists: false };
    throw e;
  }
}

function ts(item: any): number | undefined {
  const raw = item?.block?.block_timestamp ?? item?.block_timestamp ?? item?.receipt_block?.block_timestamp;
  const n = Number(raw);
  if (!Number.isFinite(n) || raw === undefined) return undefined;
  return n > 1e15 ? Math.floor(n / 1e6) : n;
}

async function activity(id: string) {
  const r = await fetch(`${NEARBLOCKS}/v3/accounts/${encodeURIComponent(id)}/txns?limit=100`);
  if (!r.ok) throw new Error(`NearBlocks ${r.status}`);
  const list: any[] = (await r.json())?.data ?? [];
  const times = list.map(ts).filter((t): t is number => t !== undefined);
  return { txCount: list.length, capped: list.length >= 100, oldest: times.length ? Math.min(...times) : undefined };
}

const safe = async <T,>(f: () => Promise<T>): Promise<T | null> => {
  try {
    return await f();
  } catch {
    return null;
  }
};

export async function check(receiverId: string, amountNear: number) {
  const id = receiverId.trim().toLowerCase();
  const kind = classifyAccountId(id);
  const s: Signals = {
    receiverId: id,
    amountYocto: BigInt(Math.round(amountNear * 1e6)) * 10n ** 18n,
    idKind: kind,
    exists: null,
    isContract: null,
    codeChangedRecently: false,
    ageDays: null,
    ageIsLowerBound: false,
    txCount: null,
    txCountCapped: false,
    lastDeployDays: null,
    priorPayments: null,
    registry: null,
    attestation: null,
    lookalikeOf: null,
    isProtected: id === LIVE.guard || id === LIVE.agent,
    isKnown: POLICY.knownReceivers.includes(id),
  };
  const sources: Record<string, string> = {};
  if (kind !== "invalid") {
    const [acct, act, prior, status, reports, att] = await Promise.all([
      safe(() => account(id)),
      safe(() => activity(id)),
      safe(() => view<{ count: string }>(LIVE.guard, "get_interaction", { agent_id: LIVE.agent, receiver_id: id })),
      safe(() => view<any>(LIVE.registry, "get_status", { subject: id })),
      safe(() => view<any[]>(LIVE.registry, "get_reports", { subject: id, limit: 5 })),
      safe(() => view<any>(LIVE.registry, "get_attestation", { subject: id, attribute: POLICY.trustedAttribute })),
    ]);
    if (acct) {
      s.exists = acct.exists;
      s.isContract = acct.exists ? acct.codeHash !== EMPTY_CODE_HASH : false;
    }
    sources.rpc = acct ? "ok" : "unavailable";
    if (act) {
      s.txCount = act.txCount;
      s.txCountCapped = act.capped;
      if (act.oldest !== undefined) {
        s.ageDays = (Date.now() - act.oldest) / DAY;
        s.ageIsLowerBound = act.capped;
      }
    }
    sources.nearblocks = act ? "ok" : "unavailable";
    if (prior) s.priorPayments = Number(prior.count);
    if (status) {
      s.registry = {
        reportCount: status.report_count,
        trustedReportCount: status.trusted_report_count,
        categories: status.categories ?? [],
        curated: status.curated ?? null,
        evidence: (reports ?? []).map((x: any) => (x.evidence_tx ? `tx ${x.evidence_tx}: ${x.evidence_text}` : x.evidence_text)),
      };
    }
    sources.registry = status ? "ok" : "unavailable";
    if (att) s.attestation = { attribute: POLICY.trustedAttribute, issuer: att.issuer, valid: !!att.valid };
    s.lookalikeOf = findLookalike(id, POLICY.knownReceivers);
  }
  return { ...score(s, POLICY), signals: s, sources };
}

(globalThis as any).payGuard = { check, LIVE };
