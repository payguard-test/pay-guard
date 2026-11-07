//! pay-guard: an escrow that only pays receivers a counterparty checker has signed off on.
//!
//! The agent never holds funds. Its only key is a function-call key scoped to this
//! contract and the `pay` method. Every payment must carry a fresh ed25519 attestation
//! from the checker service covering this contract, the agent, the receiver, the exact
//! amount, the verdict, a nonce and an expiry. Caps bound the loss even if the agent
//! and the attestation flow are both abused.

use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::serde_json::json;
use near_sdk::store::LookupMap;
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PublicKey,
};

/// Attestations may live at most 5 minutes.
pub const MAX_ATTESTATION_TTL_NS: u64 = 5 * 60 * 1_000_000_000;
/// Length of one spending window (UTC day).
pub const DAY_NS: u64 = 86_400 * 1_000_000_000;
/// Gas reserved for the payment callback.
const CALLBACK_GAS: Gas = Gas::from_tgas(10);
/// Domain tag that prefixes every signed message.
pub const MESSAGE_PREFIX: &str = "pay-guard:v1";

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Agents,
    Interactions,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct AgentState {
    pub balance: u128,
    pub last_nonce: u64,
    pub day: u64,
    pub spent_today: u128,
    pub active: bool,
}

#[near(serializers = [borsh])]
#[derive(Clone, Default)]
pub struct Interaction {
    pub count: u64,
    pub total: u128,
    pub last_at: u64,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct Limits {
    pub max_per_payment: u128,
    pub warn_max_per_payment: u128,
    pub daily_cap: u128,
}

#[near(serializers = [json])]
pub struct LimitsView {
    pub max_per_payment: U128,
    pub warn_max_per_payment: U128,
    pub daily_cap: U128,
}

#[near(serializers = [json])]
pub struct AgentView {
    pub balance: U128,
    pub last_nonce: U64,
    pub spent_today: U128,
    pub remaining_today: U128,
    pub active: bool,
}

#[near(serializers = [json])]
pub struct InteractionView {
    pub count: U64,
    pub total: U128,
    pub last_at: U64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PayGuard {
    owner_id: AccountId,
    checker_pk: [u8; 32],
    limits: Limits,
    agents: LookupMap<AccountId, AgentState>,
    interactions: LookupMap<(AccountId, AccountId), Interaction>,
}

fn ed25519_bytes(pk: &PublicKey) -> [u8; 32] {
    let raw = pk.as_bytes();
    // First byte is the curve type: 0 = ed25519.
    require!(raw.len() == 33 && raw[0] == 0, "checker key must be ed25519");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[1..]);
    out
}

fn current_day(now: u64) -> u64 {
    now / DAY_NS
}

fn emit(event: &str, data: near_sdk::serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        json!({"standard": "pay-guard", "version": "1.0.0", "event": event, "data": [data]})
    ));
}

/// The exact bytes the checker signs. Account IDs cannot contain '|', so the
/// encoding is unambiguous.
pub fn attestation_message(
    contract_id: &str,
    agent_id: &str,
    receiver_id: &str,
    amount: u128,
    verdict: &str,
    nonce: u64,
    expires_at_ns: u64,
) -> String {
    format!(
        "{MESSAGE_PREFIX}|{contract_id}|{agent_id}|{receiver_id}|{amount}|{verdict}|{nonce}|{expires_at_ns}"
    )
}

#[near]
impl PayGuard {
    #[init]
    pub fn new(
        owner_id: AccountId,
        checker_public_key: PublicKey,
        max_per_payment: U128,
        warn_max_per_payment: U128,
        daily_cap: U128,
    ) -> Self {
        let limits = Limits {
            max_per_payment: max_per_payment.0,
            warn_max_per_payment: warn_max_per_payment.0,
            daily_cap: daily_cap.0,
        };
        Self::check_limits(&limits);
        Self {
            owner_id,
            checker_pk: ed25519_bytes(&checker_public_key),
            limits,
            agents: LookupMap::new(StorageKey::Agents),
            interactions: LookupMap::new(StorageKey::Interactions),
        }
    }

    // ---------- owner methods (need full-access key: 1 yoctoNEAR attached) ----------

    #[payable]
    pub fn add_agent(&mut self, agent_id: AccountId) {
        self.assert_owner();
        require!(self.agents.get(&agent_id).is_none(), "agent already registered");
        self.agents.insert(
            agent_id.clone(),
            AgentState { balance: 0, last_nonce: 0, day: 0, spent_today: 0, active: true },
        );
        emit("agent_added", json!({"agent_id": agent_id}));
    }

    /// Kill switch: freeze or unfreeze an agent instantly.
    #[payable]
    pub fn set_agent_active(&mut self, agent_id: AccountId, active: bool) {
        self.assert_owner();
        let mut a = self.agent(&agent_id);
        a.active = active;
        self.agents.insert(agent_id.clone(), a);
        emit("agent_active", json!({"agent_id": agent_id, "active": active}));
    }

    #[payable]
    pub fn set_limits(&mut self, max_per_payment: U128, warn_max_per_payment: U128, daily_cap: U128) {
        self.assert_owner();
        let limits = Limits {
            max_per_payment: max_per_payment.0,
            warn_max_per_payment: warn_max_per_payment.0,
            daily_cap: daily_cap.0,
        };
        Self::check_limits(&limits);
        self.limits = limits;
    }

    #[payable]
    pub fn set_checker_key(&mut self, checker_public_key: PublicKey) {
        self.assert_owner();
        self.checker_pk = ed25519_bytes(&checker_public_key);
    }

    /// Owner pulls funds out of an agent's escrow back to the owner account.
    #[payable]
    pub fn withdraw(&mut self, agent_id: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        let mut a = self.agent(&agent_id);
        require!(amount.0 > 0 && amount.0 <= a.balance, "invalid amount");
        a.balance -= amount.0;
        self.agents.insert(agent_id, a);
        Promise::new(self.owner_id.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    // ---------- funding ----------

    /// Anyone may top up a registered agent's escrow.
    #[payable]
    pub fn deposit(&mut self, agent_id: AccountId) {
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach NEAR to deposit");
        let mut a = self.agent(&agent_id);
        a.balance = a.balance.checked_add(amount).expect("overflow");
        self.agents.insert(agent_id.clone(), a);
        emit("deposit", json!({"agent_id": agent_id, "amount": U128(amount)}));
    }

    // ---------- the agent's only method ----------

    pub fn pay(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        verdict: String,
        nonce: U64,
        expires_at: U64,
        signature: Base64VecU8,
    ) -> Promise {
        let agent_id = env::predecessor_account_id();
        let now = env::block_timestamp();
        let amount = amount.0;
        let mut a = self.agent(&agent_id);

        require!(a.active, "agent is frozen");
        require!(amount > 0, "amount must be positive");
        require!(verdict == "allow" || verdict == "warn", "verdict does not permit payment");
        require!(receiver_id != env::current_account_id(), "cannot pay the guard");
        require!(receiver_id != agent_id, "cannot pay self");
        require!(now <= expires_at.0, "attestation expired");
        require!(expires_at.0 - now <= MAX_ATTESTATION_TTL_NS, "attestation lifetime too long");
        require!(nonce.0 > a.last_nonce, "nonce already used");

        let msg = attestation_message(
            env::current_account_id().as_str(),
            agent_id.as_str(),
            receiver_id.as_str(),
            amount,
            &verdict,
            nonce.0,
            expires_at.0,
        );
        let sig: [u8; 64] = signature.0.as_slice().try_into().unwrap_or_else(|_| env::panic_str("bad signature length"));
        require!(env::ed25519_verify(&sig, msg.as_bytes(), &self.checker_pk), "invalid checker signature");

        require!(amount <= self.limits.max_per_payment, "over per-payment cap");
        if verdict == "warn" {
            require!(amount <= self.limits.warn_max_per_payment, "over warn per-payment cap");
        }
        let day = current_day(now);
        if a.day != day {
            a.day = day;
            a.spent_today = 0;
        }
        let spent = a.spent_today.checked_add(amount).expect("overflow");
        require!(spent <= self.limits.daily_cap, "over daily cap");
        require!(amount <= a.balance, "insufficient escrow");

        // Update state before the transfer (reentrancy rule); refund in callback on failure.
        a.balance -= amount;
        a.spent_today = spent;
        a.last_nonce = nonce.0;
        self.agents.insert(agent_id.clone(), a);

        emit(
            "pay_started",
            json!({"agent_id": agent_id, "receiver_id": receiver_id, "amount": U128(amount), "verdict": verdict, "nonce": nonce}),
        );

        Promise::new(receiver_id.clone())
            .transfer(NearToken::from_yoctonear(amount))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .on_pay_complete(agent_id, receiver_id, U128(amount), U64(day)),
            )
    }

    #[private]
    pub fn on_pay_complete(
        &mut self,
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        day: U64,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> bool {
        // Never panic here: a panic would skip the refund.
        let Some(mut a) = self.agents.get(&agent_id).cloned() else { return false };
        match result {
            Ok(()) => {
                let key = (agent_id.clone(), receiver_id.clone());
                let mut i = self.interactions.get(&key).cloned().unwrap_or_default();
                i.count += 1;
                i.total = i.total.saturating_add(amount.0);
                i.last_at = env::block_timestamp();
                self.interactions.insert(key, i);
                emit("pay_done", json!({"agent_id": agent_id, "receiver_id": receiver_id, "amount": amount}));
                true
            }
            Err(_) => {
                a.balance = a.balance.saturating_add(amount.0);
                if a.day == day.0 {
                    a.spent_today = a.spent_today.saturating_sub(amount.0);
                }
                self.agents.insert(agent_id.clone(), a);
                emit("pay_refunded", json!({"agent_id": agent_id, "receiver_id": receiver_id, "amount": amount}));
                false
            }
        }
    }

    // ---------- views ----------

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn get_limits(&self) -> LimitsView {
        LimitsView {
            max_per_payment: U128(self.limits.max_per_payment),
            warn_max_per_payment: U128(self.limits.warn_max_per_payment),
            daily_cap: U128(self.limits.daily_cap),
        }
    }

    pub fn get_agent(&self, agent_id: AccountId) -> Option<AgentView> {
        let day = current_day(env::block_timestamp());
        self.agents.get(&agent_id).map(|a| {
            let spent = if a.day == day { a.spent_today } else { 0 };
            AgentView {
                balance: U128(a.balance),
                last_nonce: U64(a.last_nonce),
                spent_today: U128(spent),
                remaining_today: U128(self.limits.daily_cap.saturating_sub(spent)),
                active: a.active,
            }
        })
    }

    /// Prior successful payments from this agent to this receiver (checker signal).
    pub fn get_interaction(&self, agent_id: AccountId, receiver_id: AccountId) -> InteractionView {
        let i = self.interactions.get(&(agent_id, receiver_id)).cloned().unwrap_or_default();
        InteractionView { count: U64(i.count), total: U128(i.total), last_at: U64(i.last_at) }
    }

    /// Returns the exact string the checker must sign, so clients can cross-check encoding.
    pub fn get_attestation_message(
        &self,
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        verdict: String,
        nonce: U64,
        expires_at: U64,
    ) -> String {
        attestation_message(
            env::current_account_id().as_str(),
            agent_id.as_str(),
            receiver_id.as_str(),
            amount.0,
            &verdict,
            nonce.0,
            expires_at.0,
        )
    }

    // ---------- internal ----------

    fn assert_owner(&self) {
        assert_one_yocto();
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    fn agent(&self, agent_id: &AccountId) -> AgentState {
        self.agents.get(agent_id).cloned().unwrap_or_else(|| env::panic_str("unknown agent"))
    }

    fn check_limits(l: &Limits) {
        require!(l.max_per_payment > 0, "max_per_payment must be positive");
        require!(l.warn_max_per_payment <= l.max_per_payment, "warn cap must be <= per-payment cap");
        require!(l.daily_cap >= l.max_per_payment, "daily cap must be >= per-payment cap");
    }
}

#[cfg(test)]
mod tests;
