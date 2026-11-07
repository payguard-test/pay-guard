/**
 * Testnet account without the CLI faucet.
 *   npm run claim-name                         prints the address your OWNER_PRIVATE_KEY controls (fund it at a web faucet)
 *   npm run claim-name -- payguard-bay.testnet registers that name for the same key and moves the funds into it
 * Testnet only. Signs one transaction with OWNER_PRIVATE_KEY.
 */
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, keyToImplicitAddress, type KeyPairString } from "near-api-js";
import { DEFAULT_RPC, env, fmtNear, near } from "../config.ts";

const key = KeyPair.fromString(env("OWNER_PRIVATE_KEY") as KeyPairString);
const implicit = keyToImplicitAddress(key.getPublicKey());
const provider = new JsonRpcProvider({ url: env("NEAR_RPC_URL", DEFAULT_RPC.testnet) });

async function balance(id: string): Promise<bigint | null> {
  try {
    return (await provider.viewAccount({ accountId: id })).amount;
  } catch {
    return null;
  }
}

const name = process.argv[2];
const bal = await balance(implicit);
console.log(`Address controlled by your key: ${implicit}`);
console.log(`Balance: ${bal === null ? "not funded yet" : fmtNear(bal)}`);

if (!name) {
  console.log("\nFund that address at a testnet faucet, then run: npm run claim-name -- <name>.testnet");
  process.exit(0);
}
if (!/^[a-z0-9_-]+\.testnet$/.test(name)) throw new Error("name must look like something.testnet");
if (await balance(name) !== null) throw new Error(`${name} already exists. Pick another name.`);
if (bal === null || bal < near("1")) throw new Error("fund the address above with at least 1 NEAR first");

const keep = near("0.2"); // NEAR reserves the prepaid gas up front, so leave room for it
const acct = new Account(implicit, provider, new KeyPairSigner(key));
await acct.createAccount({ newAccountId: name, publicKey: key.getPublicKey(), nearToTransfer: bal - keep });
console.log(`\nCreated ${name} with the same key, balance ${fmtNear((await balance(name)) ?? 0n)}.`);
console.log(`Set OWNER_ACCOUNT_ID=${name} in .env, then run: npm run setup:testnet`);
