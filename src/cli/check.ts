/**
 * Ask a running checker about a receiver.
 *   npm run checker            (in one terminal)
 *   npm run check -- <receiver> <amount NEAR> [agent]
 */
import { env, near } from "../config.ts";
import { HttpCheckerClient } from "../wrapper/guarded-wallet.ts";

const [receiverId, amount, agent] = process.argv.slice(2);
if (!receiverId || !amount) {
  console.error("usage: npm run check -- <receiver> <amount NEAR> [agent]");
  process.exit(2);
}
const d = await new HttpCheckerClient(env("CHECKER_URL", "http://127.0.0.1:8787")).check({
  agentId: agent ?? env("AGENT_ACCOUNT_ID"),
  receiverId,
  amount: near(amount).toString(),
});
console.log(`verdict: ${d.verdict.toUpperCase()}`);
for (const r of d.reasons) console.log(`  [${r.level}] ${r.code}: ${r.detail}`);
console.log(d.attestation ? "\nattestation signed (valid for a short time)" : "\nno attestation: the checker never signs block");
