//! Offline simulator: runs the real pay-guard contract code inside near-sdk's
//! unit-testing VM so the attack demo can show the on-chain layer without a node.
//!
//! Protocol: one JSON command per line on stdin, one JSON response per line on stdout.
//!   {"cmd":"init", "guard", "owner", "checker_public_key", "max_per_payment",
//!    "warn_max_per_payment", "daily_cap", "agents":[{"id","deposit"}]}
//!   {"cmd":"pay", "caller", "now_ns", "args":{receiver_id, amount, verdict, nonce, expires_at, signature}}
//!   {"cmd":"view_agent", "agent_id", "now_ns"}
//!   {"cmd":"view_interaction", "agent_id", "receiver_id"}
//! A successful `pay` is followed by the success callback, as a real transfer to an
//! existing account would be.

use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::serde_json::{self, json, Value};
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::{testing_env, AccountId, NearToken};
use pay_guard::PayGuard;
use std::io::{BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

fn acc(v: &Value) -> AccountId {
    v.as_str().expect("account id string").parse().expect("valid account id")
}
fn num(v: &Value) -> u128 {
    v.as_str().map(|s| s.parse().expect("number string")).or_else(|| v.as_u64().map(|n| n as u128)).expect("number")
}

fn ctx(guard: &AccountId, pred: &AccountId, deposit: u128, now: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(guard.clone())
        .predecessor_account_id(pred.clone())
        .signer_account_id(pred.clone())
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .block_timestamp(now);
    testing_env!(b.build());
}

fn panic_text(e: Box<dyn std::any::Any + Send>) -> String {
    let raw = if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = e.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "contract panicked".into()
    };
    // Unwrap "HostError(GuestPanic { panic_msg: \"...\" })" to the contract's message.
    match raw.split("panic_msg: \"").nth(1).and_then(|r| r.split("\" })").next()) {
        Some(msg) => format!("Smart contract panicked: {msg}"),
        None => raw,
    }
}

fn main() {
    panic::set_hook(Box::new(|_| {})); // errors are reported as JSON instead
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut state: Option<(PayGuard, AccountId)> = None;

    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        if line.trim().is_empty() {
            continue;
        }
        let cmd: Value = serde_json::from_str(&line).expect("json command");
        let res = panic::catch_unwind(AssertUnwindSafe(|| -> Value {
            match cmd["cmd"].as_str().unwrap_or("") {
                "init" => {
                    let guard = acc(&cmd["guard"]);
                    let owner = acc(&cmd["owner"]);
                    let now = num(&cmd["now_ns"]) as u64;
                    ctx(&guard, &owner, 0, now);
                    let mut c = PayGuard::new(
                        owner.clone(),
                        cmd["checker_public_key"].as_str().unwrap().parse().unwrap(),
                        U128(num(&cmd["max_per_payment"])),
                        U128(num(&cmd["warn_max_per_payment"])),
                        U128(num(&cmd["daily_cap"])),
                    );
                    for a in cmd["agents"].as_array().cloned().unwrap_or_default() {
                        ctx(&guard, &owner, 1, now);
                        c.add_agent(acc(&a["id"]));
                        ctx(&guard, &owner, num(&a["deposit"]), now);
                        c.deposit(acc(&a["id"]));
                    }
                    state = Some((c, guard));
                    json!({"ok": true})
                }
                "pay" => {
                    let (c, guard) = state.as_mut().expect("init first");
                    let caller = acc(&cmd["caller"]);
                    let now = num(&cmd["now_ns"]) as u64;
                    let a = &cmd["args"];
                    ctx(guard, &caller, 0, now);
                    let receiver = acc(&a["receiver_id"]);
                    let amount = num(&a["amount"]);
                    let sig = near_sdk::base64::Engine::decode(
                        &near_sdk::base64::engine::general_purpose::STANDARD,
                        a["signature"].as_str().unwrap_or(""),
                    )
                    .unwrap_or_default();
                    let _ = c.pay(
                        receiver.clone(),
                        U128(amount),
                        a["verdict"].as_str().unwrap_or("").to_string(),
                        U64(num(&a["nonce"]) as u64),
                        U64(num(&a["expires_at"]) as u64),
                        Base64VecU8(sig),
                    );
                    let mut logs = get_logs();
                    // Callback after the (simulated) successful transfer.
                    ctx(guard, &guard.clone(), 0, now);
                    let day = U64(now / pay_guard::DAY_NS);
                    c.on_pay_complete(caller, receiver.clone(), U128(amount), day, Ok(()));
                    logs.extend(get_logs());
                    json!({"ok": true, "transfer": {"to": receiver, "amount": U128(amount)}, "logs": logs})
                }
                "view_agent" => {
                    let (c, guard) = state.as_ref().expect("init first");
                    ctx(guard, guard, 0, num(&cmd["now_ns"]) as u64);
                    json!({"ok": true, "result": c.get_agent(acc(&cmd["agent_id"]))})
                }
                "view_interaction" => {
                    let (c, _) = state.as_ref().expect("init first");
                    json!({"ok": true, "result": c.get_interaction(acc(&cmd["agent_id"]), acc(&cmd["receiver_id"]))})
                }
                other => json!({"ok": false, "error": format!("unknown cmd {other}")}),
            }
        }));
        let v = match res {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": panic_text(e)}),
        };
        writeln!(out, "{v}").unwrap();
        out.flush().unwrap();
    }
}
