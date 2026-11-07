# pay-guard

A counterparty check for AI agents that pay on NEAR. Before an agent sends funds, a checker service scores the receiver and returns `allow`, `warn` or `block` with reasons. A payment only goes through if the checker signed it, and a NEAR smart contract enforces that rule, so a prompt-injected agent that skips its own safety code still cannot pay an unchecked receiver.

Built at NEAR HACKATHON. Track: AI Security & Defense (`security`).

## The problem

An agent that can pay can be talked into paying the wrong party: an instruction hidden in an invoice or webpage, a lookalike account name, a "we moved accounts" message. On-chain payments cannot be reversed. Today an agent usually either holds a key that can drain its account, or follows a static allowlist that someone keeps up by hand. Neither one judges the counterparty at payment time, and neither limits the damage once the agent is compromised.

## What it does

1. **Escrow on chain.** The agent's spending money sits in the `pay-guard` contract, not in the agent's account.
2. **A scoped key.** The agent signs with a function-call access key that can only call `pay` on `pay-guard`. It cannot transfer NEAR, call other contracts or change settings.
3. **A counterparty check.** The checker service scores the receiver from on-chain and indexer data and a shared blocklist, then returns a verdict with reasons.
4. **Signed verdicts, enforced on chain.** For `allow` and `warn`, the checker signs an ed25519 attestation over the contract, agent, receiver, exact amount, verdict, a nonce and an expiry of at most 5 minutes. `pay` releases funds only with a valid attestation. The checker never signs `block`, and the contract refuses `block` even if it were signed.
5. **An agent-side wrapper.** It refuses to run with a full-access key, refuses to sign on `block`, and asks a human on `warn`.
6. **Caps.** A per-payment cap, a lower cap for `warn` payments and a daily cap, all on chain. Losses stay bounded even if the agent and the checker flow are both abused.
7. **A shared blocklist.** A `registry` contract that any agent can report to, with a bond and evidence (a transaction hash plus text). Approved issuers can also attest that an account holds an attribute such as `verified_merchant`, with expiry and revocation.

## Live on NEAR testnet

| What | Account |
|---|---|
| pay-guard contract | [`pgd4yk-guard.payguard-bay.testnet`](https://testnet.nearblocks.io/address/pgd4yk-guard.payguard-bay.testnet) |
| registry contract | [`pgd4yk-registry.payguard-bay.testnet`](https://testnet.nearblocks.io/address/pgd4yk-registry.payguard-bay.testnet) |
| agent (function-call key only) | [`pgd4yk-agent.payguard-bay.testnet`](https://testnet.nearblocks.io/address/pgd4yk-agent.payguard-bay.testnet) |
| known-bad account (received 0 NEAR) | [`pgd4yk-refund-desk.payguard-bay.testnet`](https://testnet.nearblocks.io/address/pgd4yk-refund-desk.payguard-bay.testnet) |

Transactions from the recorded run ([`docs/demo-testnet.log`](docs/demo-testnet.log)):

* Legit payment: [AkkfZ7a2...](https://testnet.nearblocks.io/txns/AkkfZ7a2VraLpGtpgRZheU1pWWuWLTuW5H4dCAW7X7RZ)
* Bypass with a forged attestation, rejected on chain: [Ho6K6pUT...](https://testnet.nearblocks.io/txns/Ho6K6pUTkkAdj1D6hbv8PruLm7LEc4WPBeSyWPSiJAt7)
* Real attestation with the receiver swapped, rejected: [94ng2pa4...](https://testnet.nearblocks.io/txns/94ng2pa4f4GcERRicNGzybLfXaTXB5hMSnFzFhYKD45Q)
* Replayed attestation, rejected: [9FaycpVh...](https://testnet.nearblocks.io/txns/9FaycpVh9v1Rd8fghKRTemmCTnzQtkQSmfkrtNRSdEhL)
* Evidence transactions behind the blocklist reports: [AA1H2AyL...](https://testnet.nearblocks.io/txns/AA1H2AyL71SCA38xGyW1pzWuxnigqhaMoFYWuzrms3y1), [BzwRn7gw...](https://testnet.nearblocks.io/txns/BzwRn7gww7LngrmPsoUAVXSEJjmiFTJ8oSwipiMqLcm1)

## Try it

### Option A: offline attack demo (about 2 minutes, no NEAR account, no network)

Needs Node 20.12+ and Rust (`rustup`).

1. `npm install`
2. `npm run demo`
3. You see 9 scenarios, each ending in `DEMO OK`, then a table with `pass = yes` on every row and the line `All attacks stopped. Known-bad and lookalike accounts received 0 NEAR.`

Chain data comes from fixtures, but the on-chain layer is the real `pay-guard` contract code running in near-sdk's test VM (`contracts/pay-guard/examples/simulate.rs`), not a re-implementation. A saved run is in [`docs/demo-offline.log`](docs/demo-offline.log), and a testnet run in [`docs/demo-testnet.log`](docs/demo-testnet.log).

### Option B: local NEAR node (real transactions, no account or tokens needed)

Needs Node, Rust and cargo-near (https://github.com/near/cargo-near).

1. `npm install`
2. `npm run demo:sandbox`
3. This builds both contracts, starts a local node with `near-sandbox`, creates every account, deploys and seeds the contracts, gives the agent a function-call key and deletes its full-access key, then runs the same 9 scenarios with real transactions. You see the same `DEMO OK` lines, plus transaction hashes for paid and rejected calls.

### Option C: NEAR testnet

1. Create a testnet account and fund it with about 7 testnet NEAR (https://near-faucet.io or the near-cli faucet).
2. `cp .env.example .env` and set `OWNER_ACCOUNT_ID` and `OWNER_PRIVATE_KEY`.
3. `npm run build:contracts && npm run setup:testnet`. You see one `SETUP` line per created account, both deployments, the attestation, two reports with evidence transaction hashes, and the agent key line ending in `fullAccessKey=deleted`.
4. `npm run demo:testnet`. You see the 9 scenarios with testnet transaction hashes you can open on https://testnet.nearblocks.io.
5. Optional: `npm run demo:testnet -- --interactive` asks you in the terminal on every `warn`.

### Run the tests

1. `cd contracts/pay-guard && cargo test`. You see `21 passed`. The test names list every attack the contract refuses.
2. `cd contracts/registry && cargo test`. You see `11 passed`.
3. `npm run build:sim && npm test`. You see `pass 21` (scoring rules, wrapper behaviour, signature format shared with the contract, and the full offline demo).

### Run the checker as a service

1. `npm run keygen` and put `CHECKER_PRIVATE_KEY` in `.env`, with `PAYGUARD_CONTRACT_ID` and `REGISTRY_CONTRACT_ID` (for example from `.pay-guard/testnet.json`).
2. `npm run checker`. You see `CHECKER LISTENING url=http://127.0.0.1:8787`.
3. In another terminal: `npm run check -- some-account.testnet 0.1 your-agent.testnet`. You see the verdict and every reason.

## The attack demo

| # | What the agent does | Stopped by | Log line |
|---|---|---|---|
| 0 | Starts with a full-access key | wrapper | `WRAPPER REFUSED ... FULL-ACCESS key` |
| 1 | Pays a legit invoice from a vetted merchant | (allowed) | `CHECKER ALLOW`, `CONTRACT PAID` |
| 2 | Pays a brand-new vendor | human approves the `warn` | `CHECKER WARN`, `HUMAN APPROVED` |
| 3 | Reads an invoice with a hidden prompt injection and tries to pay a reported account | wrapper, on `block` | `AGENT INJECTED`, `CHECKER BLOCK ... REPORTED_MULTI ... Evidence: tx ...`, `WRAPPER REFUSED` |
| 4 | Pays a lookalike name (`sh0p` for `shop`) | wrapper, on `block` | `CHECKER BLOCK ... LOOKALIKE` |
| 5 | Skips the wrapper, calls `pay` with an attestation it signed itself | contract | `CONTRACT REJECTED error=... invalid checker signature` |
| 6 | Takes a real attestation for the merchant and swaps the receiver | contract | `CONTRACT REJECTED ... invalid checker signature` |
| 7 | Replays the attestation from scenario 1 | contract | `CONTRACT REJECTED ... nonce already used` |
| 8 | Tries to send 5 NEAR to an allowed receiver | contract cap | `CONTRACT REJECTED ... over per-payment cap` |

The agent is a deterministic mock model (`src/agent/mock-agent.ts`) that obeys any instruction it finds in a document. That makes the injection succeed every time, so the demo shows the defenses, not luck, and needs no API key.

## Signals and where they come from

| Signal | Source | Effect |
|---|---|---|
| Valid account ID and kind (named, implicit, eth-implicit) | local check against the NEAR account ID rules | invalid: block |
| Account exists | RPC `view_account` | missing named account: block; unfunded implicit: warn |
| Is a contract | RPC `view_account` `code_hash` (all ones means no code) | info |
| Contract code changed recently | `code_hash` cached by the checker; NearBlocks `/v3/accounts/{id}/contract/deployments` | warn |
| Account age and activity | NearBlocks `/v3/accounts/{id}/txns` | new or quiet account: warn |
| Prior payments from this agent | `pay-guard.get_interaction` (recorded on chain after each successful payment) | first payment: warn |
| Shared blocklist | `registry.get_status` and `get_reports` | curated block, a trusted reporter, or 2+ independent reports: block; 1 report: warn |
| Attestation (`verified_merchant`) | `registry.get_attestation` (issuer approved, not expired, not revoked) | softens new-account and first-payment warnings; never overrides a block |
| Lookalike name | edit distance and confusable characters against the operator's known receivers | block |
| Receiver is the guard or the agent itself | local | block |

Any signal that cannot be read is reported as unknown and produces a warning. Missing data never counts as safe. The scoring is one pure function, `src/checker/score.ts`, with its own tests.

## The agent's key and its limits

The agent account holds one key: a function-call access key with `receiver_id = <pay-guard contract>`, `method_names = ["pay"]` and an allowance of 0.25 NEAR for gas. The setup deletes the agent's full-access key.

What the key cannot do:

* Transfer NEAR or tokens directly. Function-call keys cannot attach a deposit, so a plain transfer or `ft_transfer` (which needs 1 yoctoNEAR) is impossible.
* Call any other contract, or any other method on `pay-guard`.
* Withdraw escrow, change limits, change the checker key, or unfreeze itself. Those methods require 1 yoctoNEAR, which only a full-access key can attach.
* Add or delete keys on its own account.

What it can still do, and what we accept:

* Spend escrow up to the caps, to receivers the checker signed. A compromised agent combined with a receiver that passes every check still gets paid, up to the caps.
* Pay a `warn` receiver without a human if it skips the wrapper. Human approval is enforced by the wrapper only. The contract limits such payments with the lower `warn` cap.
* Burn its gas allowance with failed calls. The allowance only falls. When it runs out the key stops working, and because the account has no full-access key it is locked out for good. That is acceptable here because the agent account holds almost nothing: the money is in escrow and the owner can `withdraw` it and register a new agent. An allowance on an existing key cannot be raised; add a new key instead.
* The owner's full-access key controls escrow, limits and the kill switch (`set_agent_active`). It must stay off the agent host. If it leaks, none of this holds.

## Contracts

`contracts/pay-guard` (near-sdk 5.30.1):

| Method | Caller | Notes |
|---|---|---|
| `new(owner_id, checker_public_key, max_per_payment, warn_max_per_payment, daily_cap)` | deployer | init once |
| `add_agent`, `set_agent_active`, `set_limits`, `set_checker_key`, `withdraw` | owner, 1 yocto | `set_agent_active(false)` is the kill switch |
| `deposit(agent_id)` | anyone, attach NEAR | |
| `pay(receiver_id, amount, verdict, nonce, expires_at, signature)` | agent | the agent key's only method |
| `get_agent`, `get_limits`, `get_interaction`, `get_attestation_message`, `get_owner` | view | |

The checker signs this UTF-8 string; `get_attestation_message` returns it so clients can check their encoding:

```
pay-guard:v1|<contract_id>|<agent_id>|<receiver_id>|<amount_yocto>|<verdict>|<nonce>|<expires_at_ns>
```

State changes before the transfer; if the transfer fails, the callback refunds the escrow and the day's spend. Events follow NEP-297 (`EVENT_JSON:` logs).

`contracts/registry`:

| Method | Caller | Notes |
|---|---|---|
| `report(subject, category, evidence_text, evidence_tx?, evidence_hash?)` | anyone, attach the bond (0.01 NEAR in the demo) | one report per reporter per subject |
| `dismiss_report`, `set_curated`, `clear_curated`, `set_trusted_reporter`, `set_issuer` | owner, 1 yocto | a dismissed report's bond is kept |
| `attest(subject, attribute, expires_at)`, `revoke(subject, attribute)` | approved issuer (revoke: issuer or owner) | |
| `get_status`, `get_reports`, `get_attestation`, `is_issuer`, `is_trusted_reporter`, `get_report_bond` | view | |

## Repository layout

```
contracts/pay-guard    escrow and attestation check (Rust), plus examples/simulate.rs for the offline demo
contracts/registry     shared blocklist and attestations (Rust)
src/checker            signals, scoring, attestation signing, HTTP service
src/wrapper            agent-side guard and the code that submits pay
src/agent              deterministic mock agent and the demo invoices
src/demo               attack demo (offline, sandbox, testnet)
src/setup              account creation and deployment for sandbox and testnet
test                   TypeScript tests
docs/demo-offline.log  saved demo output
```

## Known weaknesses

* Account age and activity are weak evidence. An attacker can age an account.
* The blocklist only knows reported accounts. Reports can be Sybil attacked, which is why each report costs a bond, one reporter counts once, and a single untrusted report only warns.
* The checker is a trusted signer. If its key leaks, the caps and the kill switch are the remaining defense. Running the checker in a TEE with remote attestation (a track hint) would harden this; it is not built here.
* Payments are NEAR only. Fungible tokens would need an `ft_transfer` path in the contract.
* The sandbox has no indexer, so age and activity show as unknown there. On testnet they come from NearBlocks API v3 (confirmed in `docs/demo-testnet.log`); `npm run probe -- <account>` prints the raw response.
* Testnet history is thin, so most demo accounts look new.

## Built with

near-sdk 5.30.1 (Rust), cargo-near 0.23, near-api-js 7.4.0, near-sandbox 0.3.5, tsx and TypeScript, NearBlocks API v3, FastNEAR public RPC. Contract scaffolding follows the `cargo near new` template. All code in this repository was written during the hackathon window (from Nov 7, 2026) with help from Claude, an AI assistant. There is no pre-hackathon code.

## License

MIT, see `LICENSE`.
