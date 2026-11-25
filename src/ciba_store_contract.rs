//! [`CibaStore`] の契約の試験。実装ごとに 1 度 [`ciba_store_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! 期限切れの要求（list_pending から外れる・sweep_expired で履歴へ移る）は、trait から期限切れの要求を作れないので
//! ここでは見ない。

use crate::ciba::{AuthReqId, CibaHistoryEntry, CibaStatus, CibaStore};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const AD: &str = r#"[{"type":"payment","amount":"1500","currency":"JPY"}]"#;

async fn pending(s: &dyn CibaStore, client: &str, account: &str) -> AuthReqId {
    s.create(client, account, "openid", "msg", None)
        .await
        .unwrap()
}

async fn approved(s: &dyn CibaStore) -> AuthReqId {
    let id = pending(s, "rp", "u").await;
    assert!(
        s.transition_if_pending(id.as_str(), CibaStatus::Approved)
            .await
            .unwrap()
    );
    id
}

/// 作った要求は、渡した値のまま Pending で読め、期限は先にある。ID は文書 ID に使える形で、作るたびに違う。
pub(crate) async fn a_created_request_is_read_back_pending(s: &dyn CibaStore) {
    let id = s
        .create(
            "rp",
            "u@example.com",
            "openid profile",
            "確認してください",
            Some(AD),
        )
        .await
        .unwrap();
    assert!(AuthReqId::well_formed(id.as_str()), "{}", id.as_str());
    let r = s.get(id.as_str()).await.unwrap().expect("作った要求が無い");
    assert_eq!(r.auth_req_id, id);
    assert_eq!(
        (
            r.client_id.as_str(),
            r.account.as_str(),
            r.scope.as_str(),
            r.binding_message.as_str()
        ),
        ("rp", "u@example.com", "openid profile", "確認してください")
    );
    assert_eq!(r.authorization_details.as_deref(), Some(AD));
    assert_eq!(r.status, CibaStatus::Pending);
    assert!(r.expires_at > now() && !r.expired());

    let plain = pending(s, "rp", "u@example.com").await;
    assert_ne!(plain, id);
    assert_eq!(
        s.get(plain.as_str())
            .await
            .unwrap()
            .unwrap()
            .authorization_details,
        None
    );
    assert!(s.get("NOPE").await.unwrap().is_none());
}

/// Pending からの遷移は先勝ちで 1 度だけ。負けた側の状態は書かれない。知らない ID は遷移しない。
pub(crate) async fn transition_if_pending_is_first_wins(s: &dyn CibaStore) {
    let id = pending(s, "rp", "u").await;
    assert!(
        s.transition_if_pending(id.as_str(), CibaStatus::Approved)
            .await
            .unwrap()
    );
    assert!(
        !s.transition_if_pending(id.as_str(), CibaStatus::Denied)
            .await
            .unwrap(),
        "2 度遷移できた"
    );
    assert_eq!(
        s.get(id.as_str()).await.unwrap().unwrap().status,
        CibaStatus::Approved
    );
    assert!(
        !s.transition_if_pending("NOPE", CibaStatus::Approved)
            .await
            .unwrap()
    );
    assert!(
        s.get("NOPE").await.unwrap().is_none(),
        "知らない ID が作られた"
    );
}

/// 並んだ承認と拒否のうち、通るのは 1 つだけで、残る状態は通った側のもの。
pub(crate) async fn racing_transitions_let_one_through(s: &dyn CibaStore) {
    let id = pending(s, "rp", "u").await;
    let (a, d) = tokio::join!(
        s.transition_if_pending(id.as_str(), CibaStatus::Approved),
        s.transition_if_pending(id.as_str(), CibaStatus::Denied)
    );
    let (a, d) = (a.unwrap(), d.unwrap());
    assert!(a ^ d, "approved={a} denied={d}");
    let want = if a {
        CibaStatus::Approved
    } else {
        CibaStatus::Denied
    };
    assert_eq!(s.get(id.as_str()).await.unwrap().unwrap().status, want);
}

/// 消費できるのは Approved だけで、1 度きり。消費した要求は消える。Pending・Denied・知らない ID は消費できない。
pub(crate) async fn consume_if_approved_is_single_use(s: &dyn CibaStore) {
    let id = pending(s, "rp", "u").await;
    assert!(
        s.consume_if_approved(id.as_str()).await.unwrap().is_none(),
        "Pending を消費できた"
    );
    s.transition_if_pending(id.as_str(), CibaStatus::Approved)
        .await
        .unwrap();
    let got = s.consume_if_approved(id.as_str()).await.unwrap();
    assert_eq!(got.map(|r| r.auth_req_id), Some(id.clone()));
    assert!(
        s.consume_if_approved(id.as_str()).await.unwrap().is_none(),
        "2 度消費できた"
    );
    assert!(s.get(id.as_str()).await.unwrap().is_none());

    let denied = pending(s, "rp", "u").await;
    s.transition_if_pending(denied.as_str(), CibaStatus::Denied)
        .await
        .unwrap();
    assert!(
        s.consume_if_approved(denied.as_str())
            .await
            .unwrap()
            .is_none(),
        "Denied を消費できた"
    );
    assert!(s.consume_if_approved("NOPE").await.unwrap().is_none());
}

/// 並んだ poll のうち、承認済みの要求を消費できるのは 1 つだけ。
pub(crate) async fn racing_consumptions_let_one_through(s: &dyn CibaStore) {
    let id = approved(s).await;
    let (a, b) = tokio::join!(
        s.consume_if_approved(id.as_str()),
        s.consume_if_approved(id.as_str())
    );
    let won = [a.unwrap(), b.unwrap()]
        .iter()
        .filter(|r| r.is_some())
        .count();
    assert_eq!(won, 1);
}

/// 消した要求は読めない。知らない ID を消しても Err にならない。
pub(crate) async fn a_deleted_request_is_gone(s: &dyn CibaStore) {
    let id = pending(s, "rp", "u").await;
    let other = pending(s, "rp", "u").await;
    s.delete(id.as_str()).await.unwrap();
    assert!(s.get(id.as_str()).await.unwrap().is_none());
    assert!(s.get(other.as_str()).await.unwrap().is_some());
    s.delete(id.as_str()).await.unwrap();
    s.delete("NOPE").await.unwrap();
}

/// list_pending はその利用者の Pending だけを返す。承認・拒否した要求と、ほかの利用者の要求は入らない。
pub(crate) async fn list_pending_returns_only_that_accounts_pending(s: &dyn CibaStore) {
    let p1 = pending(s, "rp-a", "u").await;
    let p2 = pending(s, "rp-b", "u").await;
    let ap = pending(s, "rp-a", "u").await;
    let de = pending(s, "rp-a", "u").await;
    s.transition_if_pending(ap.as_str(), CibaStatus::Approved)
        .await
        .unwrap();
    s.transition_if_pending(de.as_str(), CibaStatus::Denied)
        .await
        .unwrap();
    let _elsewhere = pending(s, "rp-a", "v").await;

    let mut got: Vec<String> = s
        .list_pending("u")
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.auth_req_id.0)
        .collect();
    got.sort();
    let mut want = vec![p1.0, p2.0];
    want.sort();
    assert_eq!(got, want);
    assert!(s.list_pending("nobody").await.unwrap().is_empty());
}

/// find_pending_for は (client_id, account) の組で引く。どちらかが違えば None。
pub(crate) async fn find_pending_for_filters_by_client_and_account(s: &dyn CibaStore) {
    let a = pending(s, "rp-a", "u@example.com").await;
    let _b = pending(s, "rp-b", "u@example.com").await;
    let found = s
        .find_pending_for("rp-a", "u@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((found.auth_req_id, found.client_id.as_str()), (a, "rp-a"));
    assert!(
        s.find_pending_for("rp-c", "u@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        s.find_pending_for("rp-a", "other@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

fn entry(id: &str, account: &str, resolved_at: u64, outcome: &str) -> CibaHistoryEntry {
    CibaHistoryEntry {
        auth_req_id: id.into(),
        account: account.into(),
        client_id: "rp".into(),
        scope: "openid".into(),
        binding_message: "確認してください".into(),
        authorization_details: Some(AD.into()),
        outcome: outcome.into(),
        resolved_at,
    }
}

/// 履歴は書いたとおりに読め、新しい順に limit 件まで返る。ほかの利用者の履歴は混ざらない。
pub(crate) async fn history_is_listed_newest_first_per_account(s: &dyn CibaStore) {
    let t = now();
    s.record_history(&entry("a", "u", t - 300, "approved"))
        .await
        .unwrap();
    s.record_history(&entry("c", "u", t - 100, "expired"))
        .await
        .unwrap();
    s.record_history(&entry("b", "u", t - 200, "denied"))
        .await
        .unwrap();
    s.record_history(&entry("x", "v", t, "approved"))
        .await
        .unwrap();

    let h = s.list_history("u", 10).await.unwrap();
    let ids: Vec<&str> = h.iter().map(|e| e.auth_req_id.as_str()).collect();
    assert_eq!(ids, ["c", "b", "a"], "新しい順でない");
    let want = entry("b", "u", t - 200, "denied");
    let got = &h[1];
    assert_eq!(
        (
            got.account.as_str(),
            got.client_id.as_str(),
            got.scope.as_str(),
            got.binding_message.as_str(),
            got.authorization_details.as_deref(),
            got.outcome.as_str(),
            got.resolved_at
        ),
        (
            want.account.as_str(),
            want.client_id.as_str(),
            want.scope.as_str(),
            want.binding_message.as_str(),
            want.authorization_details.as_deref(),
            want.outcome.as_str(),
            want.resolved_at
        )
    );
    let top: Vec<String> = s
        .list_history("u", 2)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.auth_req_id)
        .collect();
    assert_eq!(top, ["c", "b"]);
    assert!(s.list_history("nobody", 10).await.unwrap().is_empty());
    assert_eq!(
        s.sweep_expired("u").await.unwrap(),
        0,
        "期限切れの要求が無いのに掃いた"
    );
}

/// `$make` は新しい空の保存先を返す async fn（`impl CibaStore`）。
macro_rules! ciba_store_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::ciba_store_contract as c;

            $crate::ciba_store_contract::ciba_store_contract_tests!(@each $make;
                a_created_request_is_read_back_pending,
                transition_if_pending_is_first_wins,
                racing_transitions_let_one_through,
                consume_if_approved_is_single_use,
                racing_consumptions_let_one_through,
                a_deleted_request_is_gone,
                list_pending_returns_only_that_accounts_pending,
                find_pending_for_filters_by_client_and_account,
                history_is_listed_newest_first_per_account,
            );
        }
    };
    (@each $make:path; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                c::$name(&$make().await).await;
            }
        )*
    };
}
pub(crate) use ciba_store_contract_tests;
