/**
 * Account age and activity from the NearBlocks API (v3).
 * Docs: https://docs.near.org/tools/ecosystem-apis/nearblocks-api and
 * https://api.nearblocks.io/api-docs/migration (v1/v2 are retired on testnet).
 * The free tier is rate limited (about 6 calls per minute), so results are cached.
 * Parsing is defensive: if a field is missing the signal is reported as unknown,
 * never as safe.
 */

export interface Activity {
  /** Transactions seen (capped at the page size). */
  txCount: number;
  /** True when txCount hit the page size, so the real count is higher. */
  capped: boolean;
  /** Oldest transaction seen, ms since epoch. Only a true first-seen time when not capped. */
  oldestSeenMs?: number;
  /** Most recent contract deployment, ms since epoch. */
  lastDeployMs?: number;
}

export interface History {
  activity(accountId: string): Promise<Activity | null>;
}

const PAGE = 100;

function tsMs(item: any): number | undefined {
  const raw = item?.block?.block_timestamp ?? item?.block_timestamp ?? item?.receipt_block?.block_timestamp ?? item?.timestamp;
  if (raw === undefined || raw === null) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n)) return undefined;
  // nanoseconds (19 digits) or milliseconds (13 digits)
  return n > 1e15 ? Math.floor(n / 1e6) : n;
}

export class NearBlocksHistory implements History {
  private cache = new Map<string, { at: number; value: Activity | null }>();
  constructor(readonly baseUrl: string, readonly apiKey?: string, readonly timeoutMs = 8000) {}

  private async get(path: string): Promise<any> {
    const res = await fetch(this.baseUrl + path, {
      headers: this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {},
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new Error(`NearBlocks ${path} answered ${res.status}`);
    return res.json();
  }

  async activity(accountId: string): Promise<Activity | null> {
    const hit = this.cache.get(accountId);
    if (hit && Date.now() - hit.at < 10 * 60_000) return hit.value;
    let value: Activity | null = null;
    try {
      const txns = await this.get(`/v3/accounts/${encodeURIComponent(accountId)}/txns?limit=${PAGE}`);
      const list: any[] = Array.isArray(txns?.data) ? txns.data : [];
      const times = list.map(tsMs).filter((t): t is number => t !== undefined);
      value = {
        txCount: list.length,
        capped: list.length >= PAGE,
        oldestSeenMs: times.length ? Math.min(...times) : undefined,
      };
      try {
        const dep = await this.get(`/v3/accounts/${encodeURIComponent(accountId)}/contract/deployments`);
        const dlist: any[] = Array.isArray(dep?.data) ? dep.data : [];
        const dtimes = dlist.map(tsMs).filter((t): t is number => t !== undefined);
        if (dtimes.length) value.lastDeployMs = Math.max(...dtimes);
      } catch {
        /* deployments are optional */
      }
    } catch {
      value = null;
    }
    this.cache.set(accountId, { at: Date.now(), value });
    return value;
  }
}

/** Fixed answers for the offline demo, tests and the local sandbox (which has no indexer). */
export class FixtureHistory implements History {
  constructor(readonly data: Record<string, Activity | null>) {}
  async activity(accountId: string) {
    return accountId in this.data ? this.data[accountId] : null;
  }
}
