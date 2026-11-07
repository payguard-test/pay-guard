import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { Account, JsonRpcProvider, KeyPairSigner, actions, teraToGas, type KeyPairString } from "near-api-js";
import type { Attestation } from "../checker/attest.ts";
import type { PayResult, PaySubmitter } from "./guarded-wallet.ts";

const PAY_GAS = teraToGas("50");

function failureText(f: unknown): string {
  const s = JSON.stringify(f);
  const m = s.match(/"ExecutionError":"((?:[^"\\]|\\.)*)"/);
  return m ? m[1].replace(/\\"/g, '"') : s;
}

/** Signs `pay` with the agent's function-call key and sends it to a real node (sandbox or testnet). */
export class NearSubmitter implements PaySubmitter {
  readonly account: Account;
  constructor(readonly agentId: string, agentSecretKey: string, readonly guardContractId: string, rpcUrl: string) {
    this.account = new Account(agentId, new JsonRpcProvider({ url: rpcUrl }), KeyPairSigner.fromSecretKey(agentSecretKey as KeyPairString));
  }
  async submitPay(att: Attestation): Promise<PayResult> {
    try {
      const res: any = await this.account.signAndSendTransaction({
        receiverId: this.guardContractId,
        actions: [actions.functionCall("pay", att, PAY_GAS, 0n)],
        throwOnFailure: false,
      });
      const txHash: string | undefined = res?.transaction?.hash ?? res?.transaction_outcome?.id;
      const st = res?.status;
      if (st && typeof st === "object" && "Failure" in st) return { ok: false, txHash, error: failureText(st.Failure) };
      if (st && typeof st === "object" && "SuccessValue" in st) {
        // pay() returns the callback's bool: false means the transfer failed and escrow was refunded.
        const v = Buffer.from(st.SuccessValue ?? "", "base64").toString();
        if (v === "false") return { ok: false, txHash, error: "transfer failed; escrow refunded by the contract" };
      }
      return { ok: true, txHash };
    } catch (e) {
      return { ok: false, error: String((e as Error).message ?? e) };
    }
  }
}

/**
 * Runs the real pay-guard contract code in near-sdk's test VM (contracts/pay-guard/examples/simulate.rs).
 * Used by the offline demo so the on-chain layer is the actual contract, not a re-implementation.
 */
export class SimulatedGuard {
  private proc: ChildProcessWithoutNullStreams;
  private pending: ((v: any) => void)[] = [];
  constructor(binPath: string) {
    this.proc = spawn(binPath, [], { stdio: ["pipe", "pipe", "pipe"] });
    const rl = createInterface({ input: this.proc.stdout });
    rl.on("line", (line) => {
      if (!line.startsWith("{")) return; // contract log lines (EVENT_JSON) are not responses
      this.pending.shift()?.(JSON.parse(line));
    });
  }
  send(cmd: Record<string, unknown>): Promise<any> {
    return new Promise((resolve) => {
      this.pending.push(resolve);
      this.proc.stdin.write(JSON.stringify(cmd) + "\n");
    });
  }
  close() {
    this.proc.stdin.end();
  }
}

export class SimulatedSubmitter implements PaySubmitter {
  constructor(readonly sim: SimulatedGuard, readonly agentId: string, readonly nowNs: () => bigint) {}
  async submitPay(att: Attestation): Promise<PayResult> {
    const r = await this.sim.send({ cmd: "pay", caller: this.agentId, now_ns: this.nowNs().toString(), args: att });
    return r.ok ? { ok: true } : { ok: false, error: r.error };
  }
}
