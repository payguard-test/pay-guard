import { existsSync, readFileSync } from "node:fs";

if (existsSync(".env")) process.loadEnvFile(".env");

export function env(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v !== undefined && v !== "") return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`missing environment variable ${name} (see .env.example)`);
}

export function envOpt(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === "" ? undefined : v;
}

/** Public RPC defaults from https://docs.near.org/api/rpc/providers */
export const DEFAULT_RPC: Record<string, string> = {
  testnet: "https://test.rpc.fastnear.com",
  mainnet: "https://free.rpc.fastnear.com",
};

/** NearBlocks API bases from https://docs.near.org/tools/ecosystem-apis/nearblocks-api */
export const DEFAULT_NEARBLOCKS: Record<string, string> = {
  testnet: "https://api-testnet.nearblocks.io",
  mainnet: "https://api.nearblocks.io",
};

export interface Policy {
  /** Accounts younger than this many days get a warning. */
  minAgeDays: number;
  /** Fewer transactions than this gets a warning. */
  minTxCount: number;
  /** This many independent untrusted reports produce a block. One report is a warning. */
  blockReportCount: number;
  /** A contract (re)deployed within this many days gets a warning. */
  recentDeployDays: number;
  /** Receivers the operator already knows. Used for lookalike detection and skip first-payment warnings. */
  knownReceivers: string[];
  /** Attribute in the registry that marks a vetted counterparty. */
  trustedAttribute: string;
  /** Attestation lifetime in seconds (contract max is 300). */
  attestationTtlSec: number;
}

export const DEFAULT_POLICY: Policy = {
  minAgeDays: 7,
  minTxCount: 5,
  blockReportCount: 2,
  recentDeployDays: 7,
  knownReceivers: [],
  trustedAttribute: "verified_merchant",
  attestationTtlSec: 120,
};

export function loadPolicy(path = "checker.policy.json"): Policy {
  if (!existsSync(path)) return { ...DEFAULT_POLICY };
  return { ...DEFAULT_POLICY, ...JSON.parse(readFileSync(path, "utf8")) };
}

export const NEAR = 10n ** 24n;
export function near(n: string | number): bigint {
  const [whole, frac = ""] = String(n).split(".");
  return BigInt(whole) * NEAR + BigInt((frac + "0".repeat(24)).slice(0, 24));
}
export function fmtNear(yocto: bigint): string {
  const whole = yocto / NEAR;
  const frac = (yocto % NEAR).toString().padStart(24, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac.slice(0, 4)} NEAR` : `${whole} NEAR`;
}
