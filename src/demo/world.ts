import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, readFileSync } from "node:fs";
import { KeyPair } from "near-api-js";
import { FixtureChain, RpcChain, type Chain } from "../chain.ts";
import { AttestationSigner } from "../checker/attest.ts";
import { CodeHashCache } from "../checker/code-cache.ts";
import { handler } from "../checker/server.ts";
import { Checker } from "../checker/service.ts";
import { DEFAULT_NEARBLOCKS, DEFAULT_POLICY, envOpt, near, type Policy } from "../config.ts";
import { FixtureHistory, NearBlocksHistory, type History } from "../history.ts";
import { log } from "../log.ts";
import type { PaySubmitter } from "../wrapper/guarded-wallet.ts";
import { NearSubmitter, SimulatedGuard, SimulatedSubmitter } from "../wrapper/submitters.ts";
import { deployWorld, type DeployedWorld } from "../setup/deploy.ts";

export interface World {
  mode: "offline" | "sandbox" | "testnet";
  agentId: string;
  agentPublicKey: string;
  ownerId: string;
  ownerPublicKey: string;
  guardId: string;
  shop: string;
  vendor: string;
  bad: string;
  lookalike: string;
  chain: Chain;
  checkerUrl: string;
  /** Sends `pay` signed with the agent's function-call key, with no wrapper in between. */
  submitter: PaySubmitter;
  balance(id: string): Promise<bigint>;
  close(): Promise<void>;
}

async function startChecker(d: ConstructorParameters<typeof Checker>[0]): Promise<{ url: string; server: Server }> {
  const checker = new Checker(d);
  const server = createServer(handler(checker, d.signer.publicKey(), true));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  log("CHECKER", "LISTENING", { url, publicKey: d.signer.publicKey() });
  return { url, server };
}

const SIM_BIN = "contracts/pay-guard/target/debug/examples/simulate";

/** Fully offline: chain data from fixtures, the real pay-guard code runs in near-sdk's test VM. */
export async function offlineWorld(): Promise<World> {
  if (!existsSync(SIM_BIN)) throw new Error(`${SIM_BIN} missing. Run: npm run build:sim`);
  const ids = {
    owner: "owner.demo.testnet",
    guard: "guard.demo.testnet",
    registry: "registry.demo.testnet",
    agent: "agent.demo.testnet",
    shop: "shop.demo.testnet",
    vendor: "newdev.demo.testnet",
    bad: "refund-desk.demo.testnet",
    lookalike: "sh0p.demo.testnet",
    issuer: "issuer.demo.testnet",
  };
  const checkerKey = KeyPair.fromRandom("ed25519");
  const agentKey = KeyPair.fromRandom("ed25519").getPublicKey().toString();
  const ownerKey = KeyPair.fromRandom("ed25519").getPublicKey().toString();
  const sim = new SimulatedGuard(SIM_BIN);
  const nowNs = () => BigInt(Date.now()) * 1_000_000n;
  await sim.send({
    cmd: "init",
    guard: ids.guard,
    owner: ids.owner,
    now_ns: nowNs().toString(),
    checker_public_key: checkerKey.getPublicKey().toString(),
    max_per_payment: near("0.5").toString(),
    warn_max_per_payment: near("0.2").toString(),
    daily_cap: near("1").toString(),
    agents: [{ id: ids.agent, deposit: near("1").toString() }],
  });
  const balances: Record<string, bigint> = { [ids.shop]: near("5"), [ids.vendor]: near("0.1"), [ids.bad]: near("0.2"), [ids.lookalike]: near("0.1") };
  const day = 86_400_000;
  const fx = new FixtureChain({
    accounts: Object.fromEntries(
      [ids.owner, ids.guard, ids.registry, ids.agent, ids.shop, ids.vendor, ids.bad, ids.lookalike, ids.issuer].map((id) => [
        id,
        { codeHash: id === ids.guard || id === ids.registry ? "5uhCkm3cNchzmVNJE4dCBwQjjTmJZk2DzJLMgGcVjv8K" : undefined },
      ]),
    ),
    keys: {
      [ids.agent]: { [agentKey]: { kind: "function_call", receiverId: ids.guard, methodNames: ["pay"], allowance: near("0.25").toString() } },
      [ids.owner]: { [ownerKey]: { kind: "full" } },
    },
    views: {
      [`${ids.guard}.get_interaction`]: async (a) => (await sim.send({ cmd: "view_interaction", agent_id: a.agent_id, receiver_id: a.receiver_id })).result,
      [`${ids.registry}.get_status`]: (a) =>
        a.subject === ids.bad
          ? { report_count: 2, trusted_report_count: 0, categories: ["drainer", "scam"], curated: null }
          : { report_count: 0, trusted_report_count: 0, categories: [], curated: null },
      [`${ids.registry}.get_reports`]: (a) =>
        a.subject === ids.bad
          ? [
              { reporter: "reporter1.demo.testnet", category: "scam", evidence_tx: "9fJ2kVq4offlineFixtureTx1", evidence_text: "paid 0.05 NEAR for API credits, nothing was delivered" },
              { reporter: "reporter2.demo.testnet", category: "drainer", evidence_tx: "3hQx7Lm8offlineFixtureTx2", evidence_text: "an invoice with hidden prompt injection told my agent to pay this account" },
            ]
          : [],
      [`${ids.registry}.get_attestation`]: (a) =>
        a.subject === ids.shop ? { issuer: ids.issuer, expires_at: "0", revoked: false, valid: true } : null,
    },
  });
  const history = new FixtureHistory({
    [ids.shop]: { txCount: 100, capped: true, oldestSeenMs: Date.now() - 400 * day },
    [ids.vendor]: { txCount: 2, capped: false, oldestSeenMs: Date.now() - 1 * day },
    [ids.bad]: { txCount: 3, capped: false, oldestSeenMs: Date.now() - 2 * day },
    [ids.lookalike]: { txCount: 1, capped: false, oldestSeenMs: Date.now() - 0.5 * day },
  });
  const policy: Policy = { ...DEFAULT_POLICY, knownReceivers: [ids.shop] };
  const { url, server } = await startChecker({
    chain: fx,
    history,
    policy,
    signer: new AttestationSigner(checkerKey.toString(), ids.guard),
    guardContractId: ids.guard,
    registryContractId: ids.registry,
  });
  const simSubmit = new SimulatedSubmitter(sim, ids.agent, nowNs);
  const submitter: PaySubmitter = {
    async submitPay(att) {
      const r = await simSubmit.submitPay(att);
      if (r.ok) balances[att.receiver_id] = (balances[att.receiver_id] ?? 0n) + BigInt(att.amount);
      return r;
    },
  };
  return {
    mode: "offline",
    agentId: ids.agent,
    agentPublicKey: agentKey,
    ownerId: ids.owner,
    ownerPublicKey: ownerKey,
    guardId: ids.guard,
    shop: ids.shop,
    vendor: ids.vendor,
    bad: ids.bad,
    lookalike: ids.lookalike,
    chain: fx,
    checkerUrl: url,
    submitter,
    balance: async (id) => balances[id] ?? 0n,
    close: async () => {
      sim.close();
      server.close();
    },
  };
}

async function liveWorld(mode: "sandbox" | "testnet", w: DeployedWorld, history: History, onClose: () => Promise<void>): Promise<World> {
  const chain = new RpcChain(w.rpcUrl);
  const policy: Policy = { ...DEFAULT_POLICY, knownReceivers: [w.shop] };
  const { url, server } = await startChecker({
    chain,
    history,
    policy,
    signer: new AttestationSigner(w.checkerKey, w.guard),
    guardContractId: w.guard,
    registryContractId: w.registry,
    codeCache: new CodeHashCache(`.pay-guard/code-hashes-${mode}.json`),
  });
  return {
    mode,
    agentId: w.agent.id,
    agentPublicKey: KeyPair.fromString(w.agent.key as any).getPublicKey().toString(),
    ownerId: w.owner.id,
    ownerPublicKey: w.owner.publicKey,
    guardId: w.guard,
    shop: w.shop,
    vendor: w.vendor,
    bad: w.bad,
    lookalike: w.lookalike,
    chain,
    checkerUrl: url,
    submitter: new NearSubmitter(w.agent.id, w.agent.key, w.guard, w.rpcUrl),
    balance: async (id) => (await chain.account(id)).balance ?? 0n,
    close: async () => {
      server.close();
      await onClose();
    },
  };
}

/** Local NEAR node via near-sandbox: real contracts, real transactions, no accounts or tokens needed. */
export async function sandboxWorld(): Promise<World> {
  const { Sandbox, DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY } = await import("near-sandbox");
  log("SETUP", "SANDBOX", { detail: "starting a local NEAR node (first run downloads the binary)" });
  const sandbox = await Sandbox.start({});
  const w = await deployWorld(DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY, sandbox.rpcUrl, "sandbox");
  // The sandbox has no indexer, so age and activity are reported as unknown (never as safe).
  return liveWorld("sandbox", w, new FixtureHistory({}), () => sandbox.tearDown());
}

export async function testnetWorld(): Promise<World> {
  const path = ".pay-guard/testnet.json";
  if (!existsSync(path)) throw new Error(`${path} missing. Run: npm run setup:testnet`);
  const w: DeployedWorld = JSON.parse(readFileSync(path, "utf8"));
  const history = new NearBlocksHistory(envOpt("NEARBLOCKS_URL") ?? DEFAULT_NEARBLOCKS.testnet, envOpt("NEARBLOCKS_API_KEY"));
  return liveWorld("testnet", w, history, async () => {});
}
