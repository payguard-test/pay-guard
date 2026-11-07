/**
 * HTTP checker service.
 *   POST /check  {"agentId","receiverId","amount"}  ->  Decision
 *   GET  /pubkey                                     ->  {"publicKey"}
 *   GET  /health
 * Run: npm run checker   (reads .env; see .env.example)
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { RpcChain } from "../chain.ts";
import { DEFAULT_NEARBLOCKS, DEFAULT_RPC, env, envOpt, loadPolicy } from "../config.ts";
import { NearBlocksHistory } from "../history.ts";
import { log } from "../log.ts";
import { AttestationSigner } from "./attest.ts";
import { CodeHashCache } from "./code-cache.ts";
import { Checker, type CheckRequest } from "./service.ts";

export function handler(checker: Checker, publicKey: string, quiet = false) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const send = (code: number, body: unknown) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.method === "GET" && req.url === "/health") return send(200, { ok: true });
      if (req.method === "GET" && req.url === "/pubkey") return send(200, { publicKey });
      if (req.method === "POST" && req.url === "/check") {
        let raw = "";
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 4096) return send(413, { error: "body too large" });
        }
        const body = JSON.parse(raw) as CheckRequest;
        if (typeof body.agentId !== "string" || typeof body.receiverId !== "string" || typeof body.amount !== "string") {
          return send(400, { error: "agentId, receiverId and amount (yoctoNEAR string) are required" });
        }
        const d = await checker.check(body);
        if (!quiet) log("CHECKER", d.verdict.toUpperCase(), { receiver: body.receiverId, reasons: d.reasons.filter((r) => r.level !== "info").map((r) => r.code) });
        return send(200, d);
      }
      send(404, { error: "not found" });
    } catch (e) {
      send(400, { error: String((e as Error).message) });
    }
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const network = env("NEAR_NETWORK", "testnet");
  const guard = env("PAYGUARD_CONTRACT_ID");
  const signer = new AttestationSigner(env("CHECKER_PRIVATE_KEY"), guard);
  const checker = new Checker({
    chain: new RpcChain(env("NEAR_RPC_URL", DEFAULT_RPC[network])),
    history: new NearBlocksHistory(env("NEARBLOCKS_URL", DEFAULT_NEARBLOCKS[network]), envOpt("NEARBLOCKS_API_KEY")),
    policy: loadPolicy(),
    signer,
    guardContractId: guard,
    registryContractId: env("REGISTRY_CONTRACT_ID"),
    codeCache: new CodeHashCache(".pay-guard/code-hashes.json"),
  });
  const port = Number(env("CHECKER_PORT", "8787"));
  createServer(handler(checker, signer.publicKey())).listen(port, "127.0.0.1", () => {
    log("CHECKER", "LISTENING", { url: `http://127.0.0.1:${port}`, publicKey: signer.publicKey(), network });
  });
}
