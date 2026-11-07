import { JsonRpcProvider } from "near-api-js";
import { AccountDoesNotExistError, AccessKeyDoesNotExistError } from "near-api-js/rpc-errors";

/** code_hash of an account with no contract: base58 of 32 zero bytes. */
export const EMPTY_CODE_HASH = "11111111111111111111111111111111";

export interface AccountInfo {
  exists: boolean;
  codeHash?: string;
  isContract?: boolean;
  balance?: bigint;
}

export type KeyPermission =
  | { kind: "full" }
  | { kind: "function_call"; receiverId: string; methodNames: string[]; allowance: string | null }
  | { kind: "missing" };

/** Read-only chain access used by the checker and the wrapper. */
export interface Chain {
  account(accountId: string): Promise<AccountInfo>;
  view<T>(contractId: string, method: string, args: Record<string, unknown>): Promise<T>;
  accessKey(accountId: string, publicKey: string): Promise<KeyPermission>;
  accessKeys(accountId: string): Promise<{ publicKey: string; permission: KeyPermission }[]>;
}

function toPermission(p: unknown): KeyPermission {
  if (p === "FullAccess") return { kind: "full" };
  const fc = (p as { FunctionCall?: { receiver_id: string; method_names: string[]; allowance?: string | null } }).FunctionCall;
  if (fc) {
    return { kind: "function_call", receiverId: fc.receiver_id, methodNames: fc.method_names, allowance: fc.allowance ?? null };
  }
  return { kind: "full" }; // unknown shapes are treated as the most dangerous case
}

function isMissingAccount(e: unknown): boolean {
  if (e instanceof AccountDoesNotExistError) return true;
  const m = String((e as Error)?.message ?? e);
  return /does not exist|UNKNOWN_ACCOUNT|AccountDoesNotExist/i.test(m);
}

export class RpcChain implements Chain {
  readonly provider: JsonRpcProvider;
  constructor(readonly url: string) {
    this.provider = new JsonRpcProvider({ url });
  }

  async account(accountId: string): Promise<AccountInfo> {
    try {
      const v = await this.provider.viewAccount({ accountId });
      return { exists: true, codeHash: v.code_hash, isContract: v.code_hash !== EMPTY_CODE_HASH, balance: v.amount };
    } catch (e) {
      if (isMissingAccount(e)) return { exists: false };
      throw e;
    }
  }

  async view<T>(contractId: string, method: string, args: Record<string, unknown>): Promise<T> {
    return (await this.provider.callFunction<any>({ contractId, method, args })) as T;
  }

  async accessKey(accountId: string, publicKey: string): Promise<KeyPermission> {
    try {
      const k = await this.provider.viewAccessKey({ accountId, publicKey });
      return toPermission(k.permission);
    } catch (e) {
      if (e instanceof AccessKeyDoesNotExistError || /does not exist|UNKNOWN_ACCESS_KEY/i.test(String((e as Error)?.message))) {
        return { kind: "missing" };
      }
      throw e;
    }
  }

  async accessKeys(accountId: string) {
    const list = await this.provider.viewAccessKeyList({ accountId });
    return list.keys.map((k) => ({ publicKey: k.public_key, permission: toPermission(k.access_key.permission) }));
  }
}

/** In-memory chain for the offline demo and tests. */
export interface FixtureData {
  accounts: Record<string, { codeHash?: string; balance?: string }>;
  views?: Record<string, (args: Record<string, unknown>) => unknown>;
  keys?: Record<string, Record<string, KeyPermission>>;
}

export class FixtureChain implements Chain {
  constructor(readonly data: FixtureData) {}
  async account(accountId: string): Promise<AccountInfo> {
    const a = this.data.accounts[accountId];
    if (!a) return { exists: false };
    const codeHash = a.codeHash ?? EMPTY_CODE_HASH;
    return { exists: true, codeHash, isContract: codeHash !== EMPTY_CODE_HASH, balance: BigInt(a.balance ?? "0") };
  }
  async view<T>(contractId: string, method: string, args: Record<string, unknown>): Promise<T> {
    const fn = this.data.views?.[`${contractId}.${method}`];
    if (!fn) throw new Error(`no fixture for view ${contractId}.${method}`);
    return fn(args) as T;
  }
  async accessKey(accountId: string, publicKey: string): Promise<KeyPermission> {
    return this.data.keys?.[accountId]?.[publicKey] ?? { kind: "missing" };
  }
  async accessKeys(accountId: string) {
    return Object.entries(this.data.keys?.[accountId] ?? {}).map(([publicKey, permission]) => ({ publicKey, permission }));
  }
}
