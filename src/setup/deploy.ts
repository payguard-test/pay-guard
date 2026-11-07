/**
 * Creates every account the demo needs under one funded root account, deploys both
 * contracts and seeds the registry. Used for the local sandbox and for testnet.
 * Every account is a sub-account of the root, so only the root needs funding.
 */
import { readFileSync } from "node:fs";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, teraToGas, type KeyPairString } from "near-api-js";
import { near } from "../config.ts";
import { log } from "../log.ts";

export const GUARD_WASM = "contracts/pay-guard/target/near/pay_guard.wasm";
export const REGISTRY_WASM = "contracts/registry/target/near/pay_guard_registry.wasm";

export interface Keyed {
  id: string;
  key: string;
}

export interface DeployedWorld {
  network: string;
  rpcUrl: string;
  owner: { id: string; publicKey: string };
  guard: string;
  registry: string;
  agent: Keyed; // key is the function-call key
  shop: string;
  vendor: string;
  bad: string;
  lookalike: string;
  issuer: string;
  checkerKey: string;
  evidenceTxs: string[];
  limits: { maxPerPayment: string; warnMaxPerPayment: string; dailyCap: string };
  createdAt: string;
}

const GAS = teraToGas("30");

export async function deployWorld(rootId: string, rootKey: string, rpcUrl: string, network: string, prefix = ""): Promise<DeployedWorld> {
  const provider = new JsonRpcProvider({ url: rpcUrl });
  const root = new Account(rootId, provider, KeyPairSigner.fromSecretKey(rootKey as KeyPairString));

  async function sub(name: string, funds: string): Promise<{ id: string; kp: KeyPair; acct: Account }> {
    const kp = KeyPair.fromRandom("ed25519");
    const id = `${prefix}${name}.${rootId}`;
    await root.createSubAccount({ accountOrPrefix: `${prefix}${name}`, publicKey: kp.getPublicKey(), nearToTransfer: near(funds) });
    log("SETUP", "ACCOUNT", { id, funds: `${funds} NEAR` });
    return { id, kp, acct: new Account(id, provider, new KeyPairSigner(kp)) };
  }
  const call = (a: Account, contractId: string, methodName: string, args: Record<string, unknown>, deposit = 0n) =>
    a.callFunction({ contractId, methodName, args, gas: GAS, deposit });

  const limits = { maxPerPayment: near("0.5").toString(), warnMaxPerPayment: near("0.2").toString(), dailyCap: near("1").toString() };
  const checker = KeyPair.fromRandom("ed25519");

  const guard = await sub("guard", "2.2");
  const registry = await sub("registry", "2.2");
  const agent = await sub("agent", "0.25");
  const shop = await sub("shop", "0.05");
  const vendor = await sub("newdev", "0.05");
  const bad = await sub("refund-desk", "0.05");
  const lookalike = await sub("sh0p", "0.05"); // attacker registers a name that looks like "shop"
  const issuer = await sub("issuer", "0.05");
  const r1 = await sub("reporter1", "0.1");
  const r2 = await sub("reporter2", "0.1");

  await guard.acct.deployContract(new Uint8Array(readFileSync(GUARD_WASM)));
  await call(guard.acct, guard.id, "new", {
    owner_id: rootId,
    checker_public_key: checker.getPublicKey().toString(),
    max_per_payment: limits.maxPerPayment,
    warn_max_per_payment: limits.warnMaxPerPayment,
    daily_cap: limits.dailyCap,
  });
  log("SETUP", "DEPLOYED", { contract: guard.id, what: "pay-guard" });
  await call(root, guard.id, "add_agent", { agent_id: agent.id }, 1n);
  await call(root, guard.id, "deposit", { agent_id: agent.id }, near("0.7"));
  log("SETUP", "ESCROW", { agent: agent.id, deposit: "0.7 NEAR", caps: "0.5 per payment, 0.2 per warn payment, 1 per day" });

  await registry.acct.deployContract(new Uint8Array(readFileSync(REGISTRY_WASM)));
  await call(registry.acct, registry.id, "new", { owner_id: rootId, report_bond: near("0.01").toString() });
  log("SETUP", "DEPLOYED", { contract: registry.id, what: "registry" });
  await call(root, registry.id, "set_issuer", { account_id: issuer.id, approved: true }, 1n);
  const in30d = ((BigInt(Date.now()) + 30n * 86_400_000n) * 1_000_000n).toString();
  await call(issuer.acct, registry.id, "attest", { subject: shop.id, attribute: "verified_merchant", expires_at: in30d });
  log("SETUP", "ATTESTED", { subject: shop.id, attribute: "verified_merchant", issuer: issuer.id });

  // Two victims pay the bad account, then report it with their payment as evidence.
  const evidenceTxs: string[] = [];
  for (const [rep, cat, text] of [
    [r1, "scam", "paid 0.05 NEAR for API credits, nothing was delivered"],
    [r2, "drainer", "an invoice with hidden prompt injection told my agent to pay this account"],
  ] as const) {
    const tx: any = await rep.acct.transfer({ receiverId: bad.id, amount: near("0.05") });
    const hash: string = tx?.transaction?.hash ?? tx?.transaction_outcome?.id;
    evidenceTxs.push(hash);
    await call(rep.acct, registry.id, "report", { subject: bad.id, category: cat, evidence_text: text, evidence_tx: hash }, near("0.01"));
    log("SETUP", "REPORTED", { subject: bad.id, by: rep.id, category: cat, evidence_tx: hash });
  }

  // The agent gets a function-call key for pay-guard.pay only, then loses its full-access key.
  const fc = KeyPair.fromRandom("ed25519");
  await agent.acct.addFunctionCallAccessKey({ publicKey: fc.getPublicKey(), contractId: guard.id, methodNames: ["pay"], allowance: near("0.25") });
  await agent.acct.deleteKey(agent.kp.getPublicKey());
  log("SETUP", "AGENT_KEY", { agent: agent.id, key: "function-call", receiver: guard.id, methods: ["pay"], allowance: "0.25 NEAR", fullAccessKey: "deleted" });

  return {
    network,
    rpcUrl,
    owner: { id: rootId, publicKey: KeyPair.fromString(rootKey as KeyPairString).getPublicKey().toString() },
    guard: guard.id,
    registry: registry.id,
    agent: { id: agent.id, key: fc.toString() },
    shop: shop.id,
    vendor: vendor.id,
    bad: bad.id,
    lookalike: lookalike.id,
    issuer: issuer.id,
    checkerKey: checker.toString(),
    evidenceTxs,
    limits,
    createdAt: new Date().toISOString(),
  };
}
