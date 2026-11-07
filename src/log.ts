import { appendFileSync, mkdirSync } from "node:fs";

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const C = { red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m", cyan: "\x1b[36m", dim: "\x1b[2m", bold: "\x1b[1m", reset: "\x1b[0m" };
const paint = (c: keyof typeof C, s: string) => (color ? C[c] + s + C.reset : s);

let file: string | undefined;
export function logToFile(path: string) {
  mkdirSync(path.replace(/\/[^/]*$/, "") || ".", { recursive: true });
  file = path;
}

const LAYER_COLOR: Record<string, keyof typeof C> = { AGENT: "cyan", CHECKER: "yellow", WRAPPER: "bold", CONTRACT: "green", HUMAN: "cyan", SETUP: "dim", DEMO: "bold" };

/** One log line: time, layer, event, details. Also appended as JSON to the log file. */
export function log(layer: string, event: string, data: Record<string, unknown> = {}) {
  const t = new Date().toISOString().slice(11, 23);
  const ev = /REFUSED|REJECTED|BLOCK|DENIED|FAILED/.test(event) ? paint("red", event) : /PAID|ALLOW|APPROVED|OK/.test(event) ? paint("green", event) : event;
  const details = Object.entries(data)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x))}`)
    .join(" ");
  console.log(`${paint("dim", t)} ${paint(LAYER_COLOR[layer] ?? "reset", layer.padEnd(8))} ${ev} ${details}`);
  if (file) appendFileSync(file, JSON.stringify({ t: new Date().toISOString(), layer, event, ...data }, (_, x) => (typeof x === "bigint" ? x.toString() : x)) + "\n");
}

export function banner(title: string) {
  const line = "=".repeat(Math.max(60, title.length + 4));
  console.log("\n" + paint("bold", line) + "\n" + paint("bold", "  " + title) + "\n" + paint("bold", line));
  if (file) appendFileSync(file, JSON.stringify({ t: new Date().toISOString(), layer: "DEMO", event: "SCENARIO", title }) + "\n");
}
