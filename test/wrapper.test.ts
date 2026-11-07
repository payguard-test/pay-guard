import { test } from "node:test";
import assert from "node:assert/strict";
import { KeyPair } from "near-api-js";
import { FixtureChain } from "../src/chain.ts";
import { AttestationSigner, attestationMessage } from "../src/checker/attest.ts";
import { Checker } from "../src/checker/service.ts";
import { DEFAULT_POLICY, near } from "../src/config.ts";
import { FixtureHistory } from "../src/history.ts";
import { GuardedWallet, KeyScopeError, type Approver, type PaySubmitter } from "../src/wrapper/guarded-wallet.ts";
import type { Attestation } from "../src/checker/attest.ts";

const GUARD = "guard.testnet";
const AGENT = "agent.testnet";
const FC = "ed25519:FcKey";
const FULL = "ed25519:FullKey";
const WRONG = "ed25519:WrongScope";

function setup(approve: boolean) {
  const checkerKey = KeyPair.fromRandom("ed25519");
  const chain = new FixtureChain({
    accounts: { [AGENT]: {}, "shop.testnet": {}, "bad.testnet": {}, "new.testnet": {} },
    keys: {
      [AGENT]: {
        [FC]: { kind: "function_call", receiverId: GUARD, methodNames: ["pay"], allowance: null },
        [FULL]: { kind: "full" },
        [WRONG]: { kind: "function_call", receiverId: GUARD, methodNames: [], allowance: null },
      },
    },
    views: {
      [`${GUARD}.get_interaction`]: (a) => ({ count: a.receiver_id === "shop.testnet" ? "2" : "0" }),
      ["registry.testnet.get_status"]: (a) => ({ report_count: a.subject === "bad.testnet" ? 2 : 0, trusted_report_count: 0, categories: ["scam"], curated: null }),
      ["registry.testnet.get_reports"]: () => [],
      ["registry.testnet.get_attestation"]: () => null,
    },
  });
  const history = new FixtureHistory({
    "shop.testnet": { txCount: 100, capped: true, oldestSeenMs: 0 },
    "new.testnet": { txCount: 1, capped: false, oldestSeenMs: Date.now() - 3_600_000 },
    "bad.testnet": { txCount: 1, capped: false, oldestSeenMs: Date.now() - 3_600_000 },
  });
  const checker = new Checker({
    chain,
    history,
    policy: { ...DEFAULT_POLICY, knownReceivers: ["shop.testnet"] },
    signer: new AttestationSigner(checkerKey.toString(), GUARD),
    guardContractId: GUARD,
    registryContractId: "registry.testnet",
  });
  const sent: Attestation[] = [];
  const submitter: PaySubmitter = { submitPay: async (a) => (sent.push(a), { ok: true }) };
  const asked: string[] = [];
  const approver: Approver = { approve: async ({ receiverId }) => (asked.push(receiverId), approve) };
  const mk = (key: string) => new GuardedWallet({ agentId: AGENT, agentPublicKey: key, guardContractId: GUARD, chain, checker, approver, submitter });
  return { mk, sent, asked, checkerKey, checker };
}

test("wrapper refuses a full-access key", async () => {
  const { mk } = setup(true);
  await assert.rejects(mk(FULL).verifyKeyScope(), KeyScopeError);
});

test("wrapper refuses a function-call key that allows any method", async () => {
  const { mk } = setup(true);
  await assert.rejects(mk(WRONG).verifyKeyScope(), /expected exactly \["pay"\]/);
});

test("block: nothing is signed or sent, no human is asked", async () => {
  const { mk, sent, asked } = setup(true);
  const o = await mk(FC).pay("bad.testnet", near("0.1"), "test");
  assert.equal(o.status, "refused");
  assert.equal(o.decision.attestation, undefined);
  assert.equal(sent.length, 0);
  assert.equal(asked.length, 0);
});

test("warn: human says no, nothing is sent", async () => {
  const { mk, sent, asked } = setup(false);
  const o = await mk(FC).pay("new.testnet", near("0.05"), "test");
  assert.equal(o.status, "declined");
  assert.deepEqual(asked, ["new.testnet"]);
  assert.equal(sent.length, 0);
});

test("warn: human says yes, the warn attestation is sent", async () => {
  const { mk, sent } = setup(true);
  const o = await mk(FC).pay("new.testnet", near("0.05"), "test");
  assert.equal(o.status, "paid");
  assert.equal(sent[0].verdict, "warn");
});

test("allow: attestation is bound to receiver and amount and verifies with the checker key", async () => {
  const { mk, sent, checkerKey } = setup(true);
  const o = await mk(FC).pay("shop.testnet", near("0.1"), "test");
  assert.equal(o.status, "paid");
  const a = sent[0];
  assert.equal(a.receiver_id, "shop.testnet");
  assert.equal(a.amount, near("0.1").toString());
  const msg = new TextEncoder().encode(attestationMessage(GUARD, AGENT, a));
  assert.ok(checkerKey.verify(msg, Buffer.from(a.signature, "base64")));
});

test("attestation message matches the contract's format", () => {
  // Same string as contracts/pay-guard/src/tests.rs view_message_matches_signing_format
  assert.equal(
    attestationMessage("guard.testnet", "agent.testnet", { receiver_id: "shop.testnet", amount: "5", verdict: "allow", nonce: "3", expires_at: "99" }),
    "pay-guard:v1|guard.testnet|agent.testnet|shop.testnet|5|allow|3|99",
  );
});

test("nonces strictly increase even within one millisecond", () => {
  const s = new AttestationSigner(KeyPair.fromRandom("ed25519").toString(), GUARD);
  const a = s.sign(AGENT, "shop.testnet", 1n, "allow", 1000);
  const b = s.sign(AGENT, "shop.testnet", 1n, "allow", 1000);
  assert.ok(BigInt(b.nonce) > BigInt(a.nonce));
});
