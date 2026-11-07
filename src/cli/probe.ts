/**
 * Prints what NearBlocks returns for one account, so you can confirm the age and
 * activity signal parses correctly on your network.
 *   npm run probe -- <account>
 */
import { DEFAULT_NEARBLOCKS, env, envOpt } from "../config.ts";
import { NearBlocksHistory } from "../history.ts";

const id = process.argv[2];
if (!id) {
  console.error("usage: npm run probe -- <account>");
  process.exit(2);
}
const base = envOpt("NEARBLOCKS_URL") ?? DEFAULT_NEARBLOCKS[env("NEAR_NETWORK", "testnet")];
const res = await fetch(`${base}/v3/accounts/${id}/txns?limit=2`);
console.log(`GET ${base}/v3/accounts/${id}/txns?limit=2 -> ${res.status}`);
console.log(JSON.stringify(await res.json().catch(() => null), null, 2)?.slice(0, 2000));
console.log("\nparsed:", await new NearBlocksHistory(base, envOpt("NEARBLOCKS_API_KEY")).activity(id));
