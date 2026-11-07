import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

// End to end: runs the offline attack demo (real contract code in the near-sdk test VM).
test("offline attack demo: every scenario behaves as expected", { skip: !existsSync("contracts/pay-guard/target/debug/examples/simulate") && "run npm run build:sim first" }, () => {
  const out = execFileSync("npx", ["tsx", "src/demo/attack.ts", "--mode", "offline"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  assert.match(out, /All attacks stopped/);
  assert.doesNotMatch(out, /UNEXPECTED/);
});
