//! pay-guard registry: a shared blocklist that agents report to with evidence, plus
//! signed attestations (for example "verified_merchant") from approved issuers.
//!
//! Sybil resistance: every report locks a bond, one report per reporter per subject,
//! and the checker only blocks on a curated entry, a trusted reporter, or several
//! independent reports. A single untrusted report only produces a warning.

use near_sdk::json_types::{U128, U64};
use near_sdk::serde_json::json;
use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, PanicOnDefault,
};

pub const MAX_REPORTS_PER_SUBJECT: usize = 50;
pub const MAX_EVIDENCE_TEXT: usize = 280;
pub const CATEGORIES: [&str; 5] = ["scam", "phishing", "drainer", "impersonation", "other"];

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    TrustedReporters,
    Issuers,
    Reports,
    Curated,
    Attestations,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Report {
    pub reporter: AccountId,
    pub category: String,
    /// Transaction hash that shows the bad behaviour, if any.
    pub evidence_tx: Option<String>,
    /// Short human readable evidence (max 280 chars).
    pub evidence_text: String,
    /// Hash (for example sha256 hex) of longer off-chain evidence.
    pub evidence_hash: Option<String>,
    pub reported_at: U64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Curated {
    pub blocked: bool,
    pub reason: String,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct Attestation {
    pub issuer: AccountId,
    pub expires_at: u64,
    pub revoked: bool,
}

#[near(serializers = [json])]
pub struct AttestationView {
    pub issuer: AccountId,
    pub expires_at: U64,
    pub revoked: bool,
    pub valid: bool,
}

#[near(serializers = [json])]
pub struct StatusView {
    pub report_count: u32,
    pub trusted_report_count: u32,
    pub categories: Vec<String>,
    pub curated: Option<Curated>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Registry {
    owner_id: AccountId,
    report_bond: u128,
    trusted_reporters: LookupSet<AccountId>,
    issuers: LookupSet<AccountId>,
    reports: LookupMap<AccountId, Vec<Report>>,
    curated: LookupMap<AccountId, Curated>,
    attestations: LookupMap<(AccountId, String), Attestation>,
}

fn emit(event: &str, data: near_sdk::serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        json!({"standard": "pay-guard-registry", "version": "1.0.0", "event": event, "data": [data]})
    ));
}

#[near]
impl Registry {
    #[init]
    pub fn new(owner_id: AccountId, report_bond: U128) -> Self {
        Self {
            owner_id,
            report_bond: report_bond.0,
            trusted_reporters: LookupSet::new(StorageKey::TrustedReporters),
            issuers: LookupSet::new(StorageKey::Issuers),
            reports: LookupMap::new(StorageKey::Reports),
            curated: LookupMap::new(StorageKey::Curated),
            attestations: LookupMap::new(StorageKey::Attestations),
        }
    }

    // ---------- reporting (any agent or person) ----------

    /// Report a bad account. Attach at least `report_bond` yoctoNEAR.
    #[payable]
    pub fn report(
        &mut self,
        subject: AccountId,
        category: String,
        evidence_text: String,
        evidence_tx: Option<String>,
        evidence_hash: Option<String>,
    ) {
        let reporter = env::predecessor_account_id();
        require!(
            env::attached_deposit().as_yoctonear() >= self.report_bond,
            format!("attach a report bond of at least {} yoctoNEAR", self.report_bond)
        );
        require!(reporter != subject, "cannot report yourself");
        require!(CATEGORIES.contains(&category.as_str()), "unknown category");
        require!(!evidence_text.is_empty(), "evidence_text is required");
        require!(evidence_text.len() <= MAX_EVIDENCE_TEXT, "evidence_text too long");
        if let Some(tx) = &evidence_tx {
            require!(tx.len() <= 64, "evidence_tx too long");
        }
        if let Some(h) = &evidence_hash {
            require!(h.len() <= 128, "evidence_hash too long");
        }
        let mut list = self.reports.get(&subject).cloned().unwrap_or_default();
        require!(!list.iter().any(|r| r.reporter == reporter), "already reported by this account");
        require!(list.len() < MAX_REPORTS_PER_SUBJECT, "report list full");
        list.push(Report {
            reporter: reporter.clone(),
            category: category.clone(),
            evidence_tx: evidence_tx.clone(),
            evidence_text,
            evidence_hash,
            reported_at: U64(env::block_timestamp()),
        });
        self.reports.insert(subject.clone(), list);
        emit(
            "report",
            json!({"subject": subject, "reporter": reporter, "category": category, "evidence_tx": evidence_tx}),
        );
    }

    // ---------- curation (owner, full-access key) ----------

    /// Remove a false report. The bond stays in the contract (slashed).
    #[payable]
    pub fn dismiss_report(&mut self, subject: AccountId, reporter: AccountId) {
        self.assert_owner();
        let mut list = self.reports.get(&subject).cloned().unwrap_or_default();
        let before = list.len();
        list.retain(|r| r.reporter != reporter);
        require!(list.len() < before, "no such report");
        self.reports.insert(subject.clone(), list);
        emit("report_dismissed", json!({"subject": subject, "reporter": reporter}));
    }

    #[payable]
    pub fn set_curated(&mut self, subject: AccountId, blocked: bool, reason: String) {
        self.assert_owner();
        require!(reason.len() <= MAX_EVIDENCE_TEXT, "reason too long");
        self.curated.insert(subject.clone(), Curated { blocked, reason: reason.clone() });
        emit("curated", json!({"subject": subject, "blocked": blocked, "reason": reason}));
    }

    #[payable]
    pub fn clear_curated(&mut self, subject: AccountId) {
        self.assert_owner();
        self.curated.remove(&subject);
    }

    #[payable]
    pub fn set_trusted_reporter(&mut self, account_id: AccountId, trusted: bool) {
        self.assert_owner();
        if trusted {
            self.trusted_reporters.insert(account_id);
        } else {
            self.trusted_reporters.remove(&account_id);
        }
    }

    #[payable]
    pub fn set_issuer(&mut self, account_id: AccountId, approved: bool) {
        self.assert_owner();
        if approved {
            self.issuers.insert(account_id);
        } else {
            self.issuers.remove(&account_id);
        }
    }

    // ---------- attestations (approved issuers) ----------

    /// An approved issuer states that `subject` holds `attribute` until `expires_at` (ns).
    pub fn attest(&mut self, subject: AccountId, attribute: String, expires_at: U64) {
        let issuer = env::predecessor_account_id();
        require!(self.issuers.contains(&issuer), "not an approved issuer");
        require!(!attribute.is_empty() && attribute.len() <= 64, "bad attribute");
        require!(expires_at.0 > env::block_timestamp(), "expiry must be in the future");
        self.attestations.insert(
            (subject.clone(), attribute.clone()),
            Attestation { issuer: issuer.clone(), expires_at: expires_at.0, revoked: false },
        );
        emit("attest", json!({"subject": subject, "attribute": attribute, "issuer": issuer, "expires_at": expires_at}));
    }

    /// The issuing account or the owner can revoke. Takes effect for every checker at once.
    pub fn revoke(&mut self, subject: AccountId, attribute: String) {
        let caller = env::predecessor_account_id();
        let key = (subject.clone(), attribute.clone());
        let mut a = self.attestations.get(&key).cloned().unwrap_or_else(|| env::panic_str("no such attestation"));
        require!(caller == a.issuer || caller == self.owner_id, "only the issuer or owner can revoke");
        a.revoked = true;
        self.attestations.insert(key, a);
        emit("revoke", json!({"subject": subject, "attribute": attribute, "by": caller}));
    }

    // ---------- views ----------

    pub fn get_status(&self, subject: AccountId) -> StatusView {
        let list = self.reports.get(&subject).cloned().unwrap_or_default();
        let mut categories: Vec<String> = list.iter().map(|r| r.category.clone()).collect();
        categories.sort();
        categories.dedup();
        StatusView {
            report_count: list.len() as u32,
            trusted_report_count: list.iter().filter(|r| self.trusted_reporters.contains(&r.reporter)).count() as u32,
            categories,
            curated: self.curated.get(&subject).cloned(),
        }
    }

    pub fn get_reports(&self, subject: AccountId, from_index: Option<u32>, limit: Option<u32>) -> Vec<Report> {
        let list = self.reports.get(&subject).cloned().unwrap_or_default();
        list.into_iter()
            .skip(from_index.unwrap_or(0) as usize)
            .take(limit.unwrap_or(20).min(50) as usize)
            .collect()
    }

    pub fn get_attestation(&self, subject: AccountId, attribute: String) -> Option<AttestationView> {
        self.attestations.get(&(subject, attribute)).map(|a| AttestationView {
            issuer: a.issuer.clone(),
            expires_at: U64(a.expires_at),
            revoked: a.revoked,
            valid: !a.revoked && a.expires_at > env::block_timestamp() && self.issuers.contains(&a.issuer),
        })
    }

    pub fn is_trusted_reporter(&self, account_id: AccountId) -> bool {
        self.trusted_reporters.contains(&account_id)
    }

    pub fn is_issuer(&self, account_id: AccountId) -> bool {
        self.issuers.contains(&account_id)
    }

    pub fn get_report_bond(&self) -> U128 {
        U128(self.report_bond)
    }

    // ---------- internal ----------

    fn assert_owner(&self) {
        assert_one_yocto();
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use near_sdk::NearToken;

    const BOND: u128 = 10_000_000_000_000_000_000_000; // 0.01 NEAR
    const T0: u64 = 1_800_000_000 * 1_000_000_000;

    fn acc(s: &str) -> AccountId {
        s.parse().unwrap()
    }
    fn ctx(pred: &str, deposit: u128, now: u64) {
        let mut b = VMContextBuilder::new();
        b.current_account_id(acc("registry.testnet"))
            .predecessor_account_id(acc(pred))
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .block_timestamp(now);
        testing_env!(b.build());
    }
    fn setup() -> Registry {
        ctx("owner.testnet", 0, T0);
        Registry::new(acc("owner.testnet"), U128(BOND))
    }
    fn report(r: &mut Registry, reporter: &str, subject: &str) {
        ctx(reporter, BOND, T0);
        r.report(acc(subject), "scam".into(), "took payment, sent nothing".into(), Some("4xTxHash".into()), None);
    }

    #[test]
    fn report_counts_and_categories() {
        let mut r = setup();
        report(&mut r, "a.testnet", "bad.testnet");
        report(&mut r, "b.testnet", "bad.testnet");
        let s = r.get_status(acc("bad.testnet"));
        assert_eq!(s.report_count, 2);
        assert_eq!(s.trusted_report_count, 0);
        assert_eq!(s.categories, vec!["scam".to_string()]);
        assert_eq!(r.get_reports(acc("bad.testnet"), None, None)[0].evidence_tx.as_deref(), Some("4xTxHash"));
    }

    #[test]
    #[should_panic(expected = "already reported by this account")]
    fn one_report_per_reporter() {
        let mut r = setup();
        report(&mut r, "a.testnet", "bad.testnet");
        report(&mut r, "a.testnet", "bad.testnet");
    }

    #[test]
    #[should_panic(expected = "attach a report bond")]
    fn report_needs_bond() {
        let mut r = setup();
        ctx("a.testnet", 0, T0);
        r.report(acc("bad.testnet"), "scam".into(), "x".into(), None, None);
    }

    #[test]
    #[should_panic(expected = "unknown category")]
    fn report_needs_known_category() {
        let mut r = setup();
        ctx("a.testnet", BOND, T0);
        r.report(acc("bad.testnet"), "spicy".into(), "x".into(), None, None);
    }

    #[test]
    fn trusted_reporter_counted() {
        let mut r = setup();
        ctx("owner.testnet", 1, T0);
        r.set_trusted_reporter(acc("sec.testnet"), true);
        report(&mut r, "sec.testnet", "bad.testnet");
        assert_eq!(r.get_status(acc("bad.testnet")).trusted_report_count, 1);
    }

    #[test]
    fn owner_can_dismiss_and_curate() {
        let mut r = setup();
        report(&mut r, "a.testnet", "shop.testnet");
        ctx("owner.testnet", 1, T0);
        r.dismiss_report(acc("shop.testnet"), acc("a.testnet"));
        assert_eq!(r.get_status(acc("shop.testnet")).report_count, 0);
        ctx("owner.testnet", 1, T0);
        r.set_curated(acc("bad.testnet"), true, "known drainer".into());
        assert!(r.get_status(acc("bad.testnet")).curated.unwrap().blocked);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn stranger_cannot_curate() {
        let mut r = setup();
        ctx("a.testnet", 1, T0);
        r.set_curated(acc("shop.testnet"), false, "trust me".into());
    }

    #[test]
    fn attestation_lifecycle() {
        let mut r = setup();
        ctx("owner.testnet", 1, T0);
        r.set_issuer(acc("kyc.testnet"), true);
        ctx("kyc.testnet", 0, T0);
        r.attest(acc("shop.testnet"), "verified_merchant".into(), U64(T0 + 1000));
        assert!(r.get_attestation(acc("shop.testnet"), "verified_merchant".into()).unwrap().valid);
        // expires
        ctx("kyc.testnet", 0, T0 + 2000);
        assert!(!r.get_attestation(acc("shop.testnet"), "verified_merchant".into()).unwrap().valid);
        // revoke
        ctx("kyc.testnet", 0, T0);
        r.attest(acc("shop.testnet"), "verified_merchant".into(), U64(T0 + 1000));
        r.revoke(acc("shop.testnet"), "verified_merchant".into());
        assert!(!r.get_attestation(acc("shop.testnet"), "verified_merchant".into()).unwrap().valid);
    }

    #[test]
    fn removing_issuer_invalidates_its_attestations() {
        let mut r = setup();
        ctx("owner.testnet", 1, T0);
        r.set_issuer(acc("kyc.testnet"), true);
        ctx("kyc.testnet", 0, T0);
        r.attest(acc("shop.testnet"), "verified_merchant".into(), U64(T0 + 1000));
        ctx("owner.testnet", 1, T0);
        r.set_issuer(acc("kyc.testnet"), false);
        assert!(!r.get_attestation(acc("shop.testnet"), "verified_merchant".into()).unwrap().valid);
    }

    #[test]
    #[should_panic(expected = "not an approved issuer")]
    fn unapproved_issuer_rejected() {
        let mut r = setup();
        ctx("fake.testnet", 0, T0);
        r.attest(acc("bad.testnet"), "verified_merchant".into(), U64(T0 + 1000));
    }

    #[test]
    #[should_panic(expected = "only the issuer or owner can revoke")]
    fn stranger_cannot_revoke() {
        let mut r = setup();
        ctx("owner.testnet", 1, T0);
        r.set_issuer(acc("kyc.testnet"), true);
        ctx("kyc.testnet", 0, T0);
        r.attest(acc("shop.testnet"), "verified_merchant".into(), U64(T0 + 1000));
        ctx("bad.testnet", 0, T0);
        r.revoke(acc("shop.testnet"), "verified_merchant".into());
    }
}
