/** Prints a fresh ed25519 key pair for the checker. Put the secret in .env as CHECKER_PRIVATE_KEY. */
import { KeyPair } from "near-api-js";

const kp = KeyPair.fromRandom("ed25519");
console.log(`CHECKER_PUBLIC_KEY=${kp.getPublicKey().toString()}`);
console.log(`CHECKER_PRIVATE_KEY=${kp.toString()}`);
console.log("\nRegister the public key on the guard with `new` or `set_checker_key`. Never commit the private key.");
