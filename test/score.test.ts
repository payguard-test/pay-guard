import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_POLICY } from "../src/config.ts";
import { classifyAccountId, findLookalike, score, type Signals } from "../src/checker/score.ts";

const P = { ...DEFAULT_POLICY, knownReceivers: ["shop.testnet"] };
const clean = (over: Partial<Signals> = {}): Signals => ({
  receiverId: "merchant.testnet",
  amountYocto: 1n,
  idKind: "named",
  exists: true,
  isContract: false,
  codeChangedRecently: false,
  ageDays: 400,
  ageIsLowerBound: true,
  txCount: 100,
  txCountCapped: true,
  lastDeployDays: null,
  priorPayments: 3,
  registry: { reportCount: 0, trustedReportCount: 0, categories: [], curated: null, evidence: [] },
  attestation: null,
  lookalikeOf: null,
  isProtected: false,
  isKnown: false,
  ...over,
});
const codes = (s: Signals) => score(s, P).reasons.filter((r) => r.level !== "info").map((r) => r.code);

test("old active account with prior payments is allowed", () => {
  assert.equal(score(clean(), P).verdict, "allow");
});

test("invalid account id is blocked", () => {
  assert.equal(score(clean({ idKind: "invalid" }), P).verdict, "block");
  assert.equal(classifyAccountId("Bad..Name"), "invalid");
  assert.equal(classifyAccountId("a".repeat(65)), "invalid");
});

test("account id kinds", () => {
  assert.equal(classifyAccountId("alice.testnet"), "named");
  assert.equal(classifyAccountId("a".repeat(64).replace(/a/g, "f")), "implicit");
  assert.equal(classifyAccountId("0x" + "1".repeat(40)), "eth-implicit");
});

test("one untrusted report warns, two block, a trusted reporter blocks", () => {
  const reg = (n: number, t = 0) => ({ reportCount: n, trustedReportCount: t, categories: ["scam"], curated: null, evidence: ["tx abc: scam"] });
  assert.equal(score(clean({ registry: reg(1) }), P).verdict, "warn");
  assert.equal(score(clean({ registry: reg(2) }), P).verdict, "block");
  assert.equal(score(clean({ registry: reg(1, 1) }), P).verdict, "block");
  assert.match(score(clean({ registry: reg(2) }), P).reasons[0].detail, /tx abc/);
});

test("curator block wins; curator clearance downgrades reports to warn", () => {
  assert.equal(score(clean({ registry: { reportCount: 0, trustedReportCount: 0, categories: [], curated: { blocked: true, reason: "drainer" }, evidence: [] } }), P).verdict, "block");
  assert.equal(score(clean({ registry: { reportCount: 3, trustedReportCount: 0, categories: ["scam"], curated: { blocked: false, reason: "false reports" }, evidence: [] } }), P).verdict, "warn");
});

test("missing named account blocks, unfunded implicit warns", () => {
  assert.equal(score(clean({ exists: false }), P).verdict, "block");
  assert.equal(score(clean({ exists: false, idKind: "implicit" }), P).verdict, "warn");
});

test("unknown data never counts as safe", () => {
  assert.equal(score(clean({ exists: null }), P).verdict, "warn");
  assert.equal(score(clean({ registry: null }), P).verdict, "warn");
  assert.ok(codes(clean({ ageDays: null, txCount: null })).includes("HISTORY_UNKNOWN"));
});

test("contract code change and recent deploy warn", () => {
  assert.ok(codes(clean({ isContract: true, codeChangedRecently: true })).includes("CODE_CHANGED"));
  assert.ok(codes(clean({ isContract: true, lastDeployDays: 1 })).includes("RECENT_DEPLOY"));
});

test("new account, low activity and first payment warn; an attestation softens them", () => {
  const fresh = clean({ ageDays: 1, ageIsLowerBound: false, txCount: 2, txCountCapped: false, priorPayments: 0 });
  assert.deepEqual(codes(fresh).sort(), ["FIRST_PAYMENT", "LOW_ACTIVITY", "NEW_ACCOUNT"]);
  assert.equal(score({ ...fresh, attestation: { attribute: "verified_merchant", issuer: "kyc.testnet", valid: true } }, P).verdict, "allow");
});

test("an attestation never overrides a block", () => {
  const s = clean({
    registry: { reportCount: 2, trustedReportCount: 0, categories: ["scam"], curated: null, evidence: [] },
    attestation: { attribute: "verified_merchant", issuer: "kyc.testnet", valid: true },
  });
  assert.equal(score(s, P).verdict, "block");
});

test("lookalike detection", () => {
  assert.equal(findLookalike("sh0p.testnet", P.knownReceivers), "shop.testnet");
  assert.equal(findLookalike("shopp.testnet", P.knownReceivers), "shop.testnet");
  assert.equal(findLookalike("shop.testnet", P.knownReceivers), null);
  assert.equal(findLookalike("totally-different.testnet", P.knownReceivers), null);
  assert.equal(score(clean({ lookalikeOf: "shop.testnet" }), P).verdict, "block");
});

test("paying the guard or yourself is blocked", () => {
  assert.equal(score(clean({ isProtected: true }), P).verdict, "block");
});
