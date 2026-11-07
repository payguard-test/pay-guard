use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::{testing_env, PromiseResult, RuntimeFeesConfig};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T0: u64 = 1_800_000_000 * 1_000_000_000; // some fixed time in ns

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn guard() -> AccountId {
    acc("guard.testnet")
}
fn owner() -> AccountId {
    acc("owner.testnet")
}
fn agent() -> AccountId {
    acc("agent.testnet")
}
fn shop() -> AccountId {
    acc("shop.testnet")
}

fn checker_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}
fn near_pk(k: &SigningKey) -> PublicKey {
    format!("ed25519:{}", bs58::encode(k.verifying_key().to_bytes()).into_string())
        .parse()
        .unwrap()
}

fn ctx(pred: &AccountId, deposit: u128, now: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(guard())
        .predecessor_account_id(pred.clone())
        .signer_account_id(pred.clone())
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .block_timestamp(now);
    testing_env!(b.build());
}

/// Contract with an agent funded with 10 NEAR. Caps: 2 NEAR per payment,
/// 0.5 NEAR per warn payment, 3 NEAR per day.
fn setup() -> PayGuard {
    ctx(&owner(), 0, T0);
    let mut c = PayGuard::new(owner(), near_pk(&checker_key()), U128(2 * NEAR), U128(NEAR / 2), U128(3 * NEAR));
    ctx(&owner(), 1, T0);
    c.add_agent(agent());
    ctx(&owner(), 10 * NEAR, T0);
    c.deposit(agent());
    c
}

struct Att {
    receiver: AccountId,
    amount: u128,
    verdict: String,
    nonce: u64,
    expires: u64,
    sig: Vec<u8>,
}

fn sign_with(k: &SigningKey, receiver: &AccountId, amount: u128, verdict: &str, nonce: u64, expires: u64) -> Att {
    let msg = attestation_message(guard().as_str(), agent().as_str(), receiver.as_str(), amount, verdict, nonce, expires);
    Att {
        receiver: receiver.clone(),
        amount,
        verdict: verdict.into(),
        nonce,
        expires,
        sig: k.sign(msg.as_bytes()).to_bytes().to_vec(),
    }
}
fn sign(receiver: &AccountId, amount: u128, verdict: &str, nonce: u64, expires: u64) -> Att {
    sign_with(&checker_key(), receiver, amount, verdict, nonce, expires)
}

fn pay(c: &mut PayGuard, a: &Att) {
    let _ = c.pay(a.receiver.clone(), U128(a.amount), a.verdict.clone(), U64(a.nonce), U64(a.expires), Base64VecU8(a.sig.clone()));
}

fn agent_view(c: &PayGuard) -> AgentView {
    c.get_agent(agent()).unwrap()
}

const SEC: u64 = 1_000_000_000;

#[test]
fn allow_payment_moves_escrow_and_logs() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC));
    let v = agent_view(&c);
    assert_eq!(v.balance.0, 9 * NEAR);
    assert_eq!(v.spent_today.0, NEAR);
    assert_eq!(v.last_nonce.0, 1);
    assert!(get_logs().iter().any(|l| l.contains("pay_started")));
}

#[test]
fn warn_payment_within_warn_cap_is_allowed() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR / 4, "warn", 1, T0 + 60 * SEC));
    assert_eq!(agent_view(&c).balance.0, 10 * NEAR - NEAR / 4);
}

#[test]
#[should_panic(expected = "over warn per-payment cap")]
fn warn_payment_over_warn_cap_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "warn", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "verdict does not permit payment")]
fn block_verdict_rejected_even_if_signed() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "block", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "invalid checker signature")]
fn forged_signature_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    pay(&mut c, &sign_with(&attacker, &shop(), NEAR, "allow", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "invalid checker signature")]
fn attestation_reused_for_other_receiver_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    let mut a = sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC);
    a.receiver = acc("attacker.testnet");
    pay(&mut c, &a);
}

#[test]
#[should_panic(expected = "invalid checker signature")]
fn attestation_reused_for_other_amount_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    let mut a = sign(&shop(), NEAR / 10, "allow", 1, T0 + 60 * SEC);
    a.amount = 2 * NEAR;
    pay(&mut c, &a);
}

#[test]
#[should_panic(expected = "invalid checker signature")]
fn warn_relabelled_as_allow_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    let mut a = sign(&shop(), NEAR, "warn", 1, T0 + 60 * SEC);
    a.verdict = "allow".into();
    pay(&mut c, &a);
}

#[test]
#[should_panic(expected = "nonce already used")]
fn replayed_nonce_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    let a = sign(&shop(), NEAR / 10, "allow", 1, T0 + 60 * SEC);
    pay(&mut c, &a);
    pay(&mut c, &a);
}

#[test]
#[should_panic(expected = "attestation expired")]
fn expired_attestation_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0 + 120 * SEC);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "attestation lifetime too long")]
fn long_lived_attestation_rejected() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 3600 * SEC));
}

#[test]
#[should_panic(expected = "over per-payment cap")]
fn per_payment_cap_enforced() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), 5 * NEAR, "allow", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "over daily cap")]
fn daily_cap_enforced() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), 2 * NEAR, "allow", 1, T0 + 60 * SEC));
    pay(&mut c, &sign(&shop(), 2 * NEAR, "allow", 2, T0 + 60 * SEC));
}

#[test]
fn daily_cap_resets_next_day() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), 2 * NEAR, "allow", 1, T0 + 60 * SEC));
    let later = T0 + DAY_NS;
    ctx(&agent(), 0, later);
    pay(&mut c, &sign(&shop(), 2 * NEAR, "allow", 2, later + 60 * SEC));
    assert_eq!(agent_view(&c).balance.0, 6 * NEAR);
}

#[test]
#[should_panic(expected = "unknown agent")]
fn unregistered_caller_rejected() {
    let mut c = setup();
    ctx(&acc("stranger.testnet"), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "agent is frozen")]
fn frozen_agent_rejected() {
    let mut c = setup();
    ctx(&owner(), 1, T0);
    c.set_agent_active(agent(), false);
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC));
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn owner_methods_need_one_yocto() {
    let mut c = setup();
    ctx(&owner(), 0, T0);
    let _ = c.withdraw(agent(), U128(NEAR));
}

#[test]
#[should_panic(expected = "owner only")]
fn agent_cannot_withdraw() {
    let mut c = setup();
    ctx(&agent(), 1, T0);
    let _ = c.withdraw(agent(), U128(NEAR));
}

#[test]
fn failed_transfer_refunds_escrow_and_daily_spend() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC));
    let mut b = VMContextBuilder::new();
    b.current_account_id(guard()).predecessor_account_id(guard()).block_timestamp(T0);
    testing_env!(b.build(), near_sdk::test_vm_config(), RuntimeFeesConfig::test(), Default::default(), vec![PromiseResult::Failed]);
    let ok = c.on_pay_complete(agent(), shop(), U128(NEAR), U64(current_day(T0)), Err(PromiseError::Failed));
    assert!(!ok);
    let v = agent_view(&c);
    assert_eq!(v.balance.0, 10 * NEAR);
    assert_eq!(v.spent_today.0, 0);
    assert_eq!(c.get_interaction(agent(), shop()).count.0, 0);
}

#[test]
fn successful_transfer_records_interaction() {
    let mut c = setup();
    ctx(&agent(), 0, T0);
    pay(&mut c, &sign(&shop(), NEAR, "allow", 1, T0 + 60 * SEC));
    let mut b = VMContextBuilder::new();
    b.current_account_id(guard()).predecessor_account_id(guard()).block_timestamp(T0);
    testing_env!(b.build());
    assert!(c.on_pay_complete(agent(), shop(), U128(NEAR), U64(current_day(T0)), Ok(())));
    let i = c.get_interaction(agent(), shop());
    assert_eq!(i.count.0, 1);
    assert_eq!(i.total.0, NEAR);
}

#[test]
fn view_message_matches_signing_format() {
    let c = setup();
    let m = c.get_attestation_message(agent(), shop(), U128(5), "allow".into(), U64(3), U64(99));
    assert_eq!(m, "pay-guard:v1|guard.testnet|agent.testnet|shop.testnet|5|allow|3|99");
}
