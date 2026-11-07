import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

interface Entry {
  hash: string;
  firstSeenMs: number;
  changedAtMs?: number;
}

/**
 * Remembers each receiver's contract code_hash. RPC only shows the current code, and
 * scanning history needs an archival node, so the checker keeps its own record and
 * flags a change since it last looked.
 */
export class CodeHashCache {
  private data: Record<string, Entry> = {};
  constructor(readonly path?: string) {
    if (path && existsSync(path)) this.data = JSON.parse(readFileSync(path, "utf8"));
  }
  /** Records the hash and returns when it last changed (undefined if never seen changing). */
  observe(accountId: string, hash: string, nowMs = Date.now()): number | undefined {
    const e = this.data[accountId];
    if (!e) {
      this.data[accountId] = { hash, firstSeenMs: nowMs };
    } else if (e.hash !== hash) {
      e.hash = hash;
      e.changedAtMs = nowMs;
    }
    this.save();
    return this.data[accountId].changedAtMs;
  }
  private save() {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.data, null, 2));
  }
}
