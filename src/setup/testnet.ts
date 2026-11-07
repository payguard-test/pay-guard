/**
 * One-time testnet setup. Needs one funded testnet account (about 8 NEAR from the faucet).
 * Signs real testnet transactions with OWNER_PRIVATE_KEY. Run it yourself:
 *   npm run build:contracts && npm run setup:testnet
 * Writes the created accounts and their keys to .pay-guard/testnet.json (git-ignored).
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { DEFAULT_RPC, env } from "../config.ts";
import { logToFile } from "../log.ts";
import { deployWorld, GUARD_WASM, REGISTRY_WASM } from "./deploy.ts";

const OUT = ".pay-guard/testnet.json";
for (const w of [GUARD_WASM, REGISTRY_WASM]) {
  if (!existsSync(w)) throw new Error(`${w} not found. Run: npm run build:contracts`);
}
if (existsSync(OUT) && !process.argv.includes("--force")) {
  throw new Error(`${OUT} already exists. Pass --force to create a fresh set of accounts.`);
}
const owner = env("OWNER_ACCOUNT_ID");
if (!owner.endsWith(".testnet")) throw new Error("OWNER_ACCOUNT_ID must be a .testnet account. This script never touches mainnet.");
const prefix = `pg${Date.now().toString(36).slice(-4)}-`;
logToFile("logs/setup-testnet.jsonl");
const world = await deployWorld(owner, env("OWNER_PRIVATE_KEY"), env("NEAR_RPC_URL", DEFAULT_RPC.testnet), "testnet", prefix);
mkdirSync(".pay-guard", { recursive: true });
writeFileSync(OUT, JSON.stringify(world, null, 2));
console.log(`\nSaved ${OUT}. Next: npm run demo:testnet`);
