//! The blocks of the phone features are listed on the lockouts page and can be lifted there.

use super::testkit::{add_user, principal, state};
use crate::{Actor, LockoutKind};

async fn admin(st: &crate::AppState) -> crate::Principal {
    st.add_user("root", "correct-horse-battery", true)
        .await
        .expect("admin");
    principal(st, "root", true).await
}

#[tokio::test]
async fn an_enrollment_block_is_listed_with_the_user_name() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    for _ in 0..5 {
        st.mfa_create_enroll_token(&anna).await.expect("token");
    }
    assert!(st.mfa_create_enroll_token(&anna).await.is_err(), "blocked");
    let root = admin(&st).await;
    let locks = st.active_lockouts(&Actor::User(&root)).await.expect("list");
    let l = locks
        .iter()
        .find(|l| l.key == format!("mfa-enroll:{}", anna.user_id))
        .unwrap_or_else(|| panic!("{locks:?}"));
    assert_eq!(
        (l.kind, l.by_address, l.who.as_str()),
        (LockoutKind::Phone, false, "anna")
    );
    assert_eq!(l.scope, "mfa-enroll");
}

#[tokio::test]
async fn a_blocked_phone_and_a_blocked_address_are_listed() {
    let (_d, st) = state().await;
    for _ in 0..5 {
        st.inner.mfa_limiter.record_failure("mfa-auth:dev_a");
        st.inner
            .mfa_limiter
            .record_failure("mfa-register:192.0.2.7");
        st.inner.mfa_limiter.record_failure("mfa-challenge:99");
    }
    let root = admin(&st).await;
    let locks = st.active_lockouts(&Actor::Cli).await.expect("list");
    let find = |k: &str| {
        locks
            .iter()
            .find(|l| l.key == k)
            .unwrap_or_else(|| panic!("{k}: {locks:?}"))
    };
    let dev = find("mfa-auth:dev_a");
    assert_eq!(
        (dev.kind, dev.by_address, dev.who.as_str()),
        (LockoutKind::Phone, false, "dev_a")
    );
    let addr = find("mfa-register:192.0.2.7");
    assert_eq!(
        (addr.kind, addr.by_address, addr.who.as_str()),
        (LockoutKind::Phone, true, "192.0.2.7")
    );
    let ch = find("mfa-challenge:99");
    assert_eq!(ch.kind, LockoutKind::Phone);
    drop(root);
}

#[tokio::test]
async fn unlocking_lifts_an_mfa_block_and_audits_it() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    for _ in 0..5 {
        st.mfa_create_enroll_token(&anna).await.expect("token");
    }
    let root = admin(&st).await;
    let key = format!("mfa-enroll:{}", anna.user_id);
    st.unlock(&Actor::User(&root), &key, LockoutKind::Phone)
        .await
        .expect("unlock");
    assert!(st.mfa_create_enroll_token(&anna).await.is_ok());
    let events = st.inner.db.events_since(0).await.expect("events");
    assert!(
        events
            .iter()
            .any(|e| e.action == "admin.unlocked" && e.target == key)
    );
}

#[tokio::test]
async fn unlocking_with_the_phone_kind_leaves_other_blocks_alone() {
    let (_d, st) = state().await;
    for _ in 0..10 {
        st.inner.limiter.record_failure("user:bob");
    }
    let root = admin(&st).await;
    st.unlock(&Actor::User(&root), "user:bob", LockoutKind::Phone)
        .await
        .expect("noop");
    let locks = st.active_lockouts(&Actor::Cli).await.expect("list");
    assert!(locks.iter().any(|l| l.key == "user:bob"), "{locks:?}");
}

#[tokio::test]
async fn a_user_who_is_no_administrator_cannot_list_or_unlock() {
    let (_d, st) = state().await;
    let anna = add_user(&st, "anna").await;
    let who = Actor::User(&anna);
    assert!(st.active_lockouts(&who).await.is_err());
    assert!(
        st.unlock(&who, "mfa-enroll:1", LockoutKind::Phone)
            .await
            .is_err()
    );
}
