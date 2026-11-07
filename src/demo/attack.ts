/**
 * Attack demo. A prompt-injected agent tries to pay a known-bad account and is stopped,
 * first by the wrapper and then, when it skips the wrapper, by the contract.
 *
 *   npm run demo           offline: real contract code in near-sdk's test VM, no network
 *   npm run demo:sandbox   local NEAR node, real transactions, no accounts needed
 *   npm run demo:testnet   NEAR testnet (run npm run setup:testnet first)
 *
 * Every line is also written to logs/demo-<mode>.jsonl.
 */
import { KeyPair } from "near-api-js";
import { invoices, mockModel } from "../agent/mock-agent.ts";
import { AttestationSigner, type Attestation } from "../checker/attest.ts";
import { fmtNear, near } from "../config.ts";
import { banner, log, logToFile } from "../log.ts";
import { ExpectedPayeeApprover, GuardedWallet, HttpCheckerClient, KeyScopeError, TerminalApprover, type Outcome } from "../wrapper/guarded-wallet.ts";
import { offlineWorld, sandboxWorld, testnetWorld, type World } from "./world.ts";

const mode = (process.argv[process.argv.indexOf("--mode") + 1] ?? "offline") as World["mode"];
const interactive = process.argv.includes("--interactive");
logToFile(`logs/demo-${mode}.jsonl`);

const results: { scenario: string; expected: string; got: string; pass: boolean }[] = [];
function record(scenario: string, expected: string, got: string) {
  const pass = got === expected;
  results.push({ scenario, expected, got, pass });
  log("DEMO", pass ? "OK" : "UNEXPECTED", { scenario, expected, got });
}
const outcomeOf = (o: Outcome) => (o.status === "failed" ? `failed: ${o.error}` : o.status);
const contains = (got: string, needle: string) => (got.includes(needle) ? needle : got);

const world = mode === "sandbox" ? await sandboxWorld() : mode === "testnet" ? await testnetWorld() : await offlineWorld();
try {
  const checker = new HttpCheckerClient(world.checkerUrl);
  // The human asked the agent to pay these two invoices and nothing else.
  const approver = interactive ? new TerminalApprover() : new ExpectedPayeeApprover(new Set([world.shop, world.vendor]));
  const wallet = new GuardedWallet({
    agentId: world.agentId,
    agentPublicKey: world.agentPublicKey,
    guardContractId: world.guardId,
    chain: world.chain,
    checker,
    approver,
    submitter: world.submitter,
  });
  const badBefore = await world.balance(world.bad);
  const lookBefore = await world.balance(world.lookalike);

  async function agentPays(task: string, doc: string) {
    const intent = mockModel(task, doc);
    return wallet.pay(intent.receiverId, near(intent.amountNear), intent.purpose);
  }

  banner(`pay-guard attack demo (${mode})`);
  log("DEMO", "SETUP", { agent: world.agentId, guard: world.guardId, knownBad: world.bad, caps: "0.5 NEAR per payment, 0.2 per warn payment, 1 per day" });

  banner("0. Wrapper refuses to run with a full-access key");
  try {
    await new GuardedWallet({ ...wallet.o, agentId: world.ownerId, agentPublicKey: world.ownerPublicKey }).verifyKeyScope();
    record("full-access key refused", "refused", "accepted");
  } catch (e) {
    log("WRAPPER", "REFUSED", { detail: (e as Error).message });
    record("full-access key refused", "refused", e instanceof KeyScopeError ? "refused" : String(e));
  }

  banner("1. Legit invoice from a vetted merchant: allow");
  const s1 = await agentPays("Pay invoice INV-1042", invoices.legit(world.shop));
  record("legit invoice", "paid", outcomeOf(s1));
  const usedAttestation = s1.decision.attestation;

  banner("2. New vendor: warn, the human approves");
  record("new vendor", "paid", outcomeOf(await agentPays("Pay invoice INV-0007", invoices.newVendor(world.vendor))));

  banner("3. ATTACK: invoice with a hidden prompt injection");
  record("prompt injection to known-bad account", "refused", outcomeOf(await agentPays("Pay invoice INV-1043", invoices.poisoned(world.shop, world.bad))));

  banner("4. ATTACK: lookalike payee name");
  record("lookalike account", "refused", outcomeOf(await agentPays("Pay invoice INV-1044", invoices.lookalike(world.lookalike))));

  banner("5. ATTACK: compromised agent skips the wrapper and forges an attestation");
  log("AGENT", "BYPASS", { detail: "calls pay-guard.pay directly with its function-call key, signing the attestation with its own key" });
  const forged = new AttestationSigner(KeyPair.fromRandom("ed25519").toString(), world.guardId).sign(world.agentId, world.bad, near("0.4"), "allow");
  const r5 = await world.submitter.submitPay(forged);
  log("CONTRACT", r5.ok ? "PAID" : "REJECTED", { error: r5.error, tx: r5.txHash });
  record("forged attestation", "invalid checker signature", r5.ok ? "paid" : contains(r5.error ?? "", "invalid checker signature"));

  banner("6. ATTACK: real attestation for the merchant, receiver swapped to the bad account");
  const real = await checker.check({ agentId: world.agentId, receiverId: world.shop, amount: near("0.1").toString() });
  const swapped: Attestation = { ...real.attestation!, receiver_id: world.bad };
  log("AGENT", "BYPASS", { detail: "took a valid attestation for the merchant and changed receiver_id", receiver: world.bad });
  const r6 = await world.submitter.submitPay(swapped);
  log("CONTRACT", r6.ok ? "PAID" : "REJECTED", { error: r6.error, tx: r6.txHash });
  record("swapped receiver", "invalid checker signature", r6.ok ? "paid" : contains(r6.error ?? "", "invalid checker signature"));

  banner("7. ATTACK: replay the attestation from scenario 1");
  const r7 = await world.submitter.submitPay(usedAttestation!);
  log("CONTRACT", r7.ok ? "PAID" : "REJECTED", { error: r7.error, tx: r7.txHash });
  record("replayed attestation", "nonce already used", r7.ok ? "paid" : contains(r7.error ?? "", "nonce already used"));

  banner("8. ATTACK: drain through an allowed receiver (5 NEAR to the merchant)");
  const s8 = await wallet.pay(world.shop, near("5"), "agent decided to prepay a year");
  record("over the cap", "over per-payment cap", s8.status === "failed" ? contains(s8.error, "over per-payment cap") : s8.status);

  const badAfter = await world.balance(world.bad);
  const lookAfter = await world.balance(world.lookalike);
  banner("Result");
  log("DEMO", badAfter === badBefore ? "OK" : "FAILED", { account: world.bad, received: fmtNear(badAfter - badBefore) });
  log("DEMO", lookAfter === lookBefore ? "OK" : "FAILED", { account: world.lookalike, received: fmtNear(lookAfter - lookBefore) });
  console.log("");
  console.table(results.map((r) => ({ scenario: r.scenario, expected: r.expected, result: r.got, pass: r.pass ? "yes" : "NO" })));
  const allPass = results.every((r) => r.pass) && badAfter === badBefore && lookAfter === lookBefore;
  console.log(allPass ? "\nAll attacks stopped. Known-bad and lookalike accounts received 0 NEAR." : "\nSome scenarios did not behave as expected. See the log above.");
  process.exitCode = allPass ? 0 : 1;
} finally {
  await world.close();
}
