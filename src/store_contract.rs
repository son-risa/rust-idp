//! [`Store`] の契約の試験。実装ごとに 1 度 [`store_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! 実装に固有のこと（MemoryStore の保持期間と sweep、Firestore の障害時の扱い・ID の形など）は、
//! それぞれの実装の側に置く。

use crate::model::*;
use crate::store::{CodeTake, Store};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// 構造体に PartialEq が無いので、Debug の形で全 field を比べる。
fn same<T: std::fmt::Debug>(a: &T, b: &T) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

fn interaction(uid: &str) -> Interaction {
    Interaction {
        uid: uid.into(),
        raw_query: "client_id=rp&scope=openid".into(),
        account_id: None,
        auth_time: None,
        request_uri: Some("urn:ietf:params:oauth:request_uri:R".into()),
        browser_binding: "BB".into(),
    }
}

fn code(c: &str) -> AuthorizationCode {
    AuthorizationCode {
        code: c.into(),
        client_id: "cl".into(),
        account_id: "a".into(),
        redirect_uri: "https://rp/cb".into(),
        scope: "openid".into(),
        nonce: Some("n".into()),
        code_challenge: Some("ch".into()),
        code_challenge_method: Some("S256".into()),
        auth_time: 1_700_000_000,
        acr: Some("urn:acr:bronze".into()),
        dpop_jkt: Some("JKT".into()),
        resource: Some("https://api.example".into()),
        expires_at: now() + 600,
    }
}

fn at(t: &str, account: &str) -> AccessToken {
    AccessToken {
        token: t.into(),
        client_id: "cl".into(),
        account_id: account.into(),
        scope: "openid".into(),
        jkt: Some("JKT".into()),
        aud: Some("https://api.example".into()),
        acr: Some("urn:acr:bronze".into()),
        auth_time: Some(1_700_000_000),
        authorization_details: Some(r#"[{"type":"payment"}]"#.into()),
        mandate_consumed: false,
    }
}

fn rt(token: &str, family: &str, replaced_by: Option<&str>) -> RefreshToken {
    RefreshToken {
        token: token.into(),
        client_id: "cl".into(),
        account_id: "a".into(),
        scope: "openid offline_access".into(),
        resource: Some("https://api.example".into()),
        jkt: Some("JKT".into()),
        acr: Some("urn:acr:bronze".into()),
        auth_time: Some(1_700_000_000),
        family_id: family.into(),
        used: replaced_by.is_some(),
        replaced_by: replaced_by.map(str::to_string),
    }
}

/// interaction は保存したとおりに読め、ログインの完了は在る間だけ書ける。消費は 1 度だけで、消費した後の
/// 完了は interaction を蘇らせない。
pub(crate) async fn an_interaction_is_completed_only_while_it_exists_and_consumed_once(
    s: &dyn Store,
) {
    s.save_interaction(interaction("U1")).await;
    assert!(same(
        &s.get_interaction("U1").await.unwrap(),
        &interaction("U1")
    ));
    assert!(s.complete_interaction("U1", "a", 42).await);
    let done = s.get_interaction("U1").await.unwrap();
    assert_eq!(
        (done.account_id.as_deref(), done.auth_time),
        (Some("a"), Some(42))
    );

    assert!(s.consume_interaction("U1").await);
    assert!(!s.consume_interaction("U1").await, "2 度消費できた");
    assert!(
        !s.complete_interaction("U1", "a", 43).await,
        "消費した interaction に完了を書けた"
    );
    assert!(
        s.get_interaction("U1").await.is_none(),
        "消費した interaction が蘇った"
    );
    assert!(!s.consume_interaction("NOPE").await);
    assert!(!s.complete_interaction("NOPE", "a", 1).await);
}

/// 並んだ resume のうち、interaction を消費できるのは 1 つだけ。
pub(crate) async fn racing_interaction_consumptions_let_one_through(s: &dyn Store) {
    s.save_interaction(interaction("U1")).await;
    let (a, b) = tokio::join!(s.consume_interaction("U1"), s.consume_interaction("U1"));
    assert_eq!([a, b].iter().filter(|w| **w).count(), 1);
}

/// session は保存したとおりに読め、消すと読めない。
pub(crate) async fn a_session_is_saved_read_and_deleted(s: &dyn Store) {
    let session = Session {
        sid: "S1".into(),
        account_id: "a".into(),
        auth_time: 42,
    };
    s.save_session(session.clone()).await.unwrap();
    assert!(same(&s.get_session("S1").await.unwrap().unwrap(), &session));
    s.delete_session("S1").await.unwrap();
    assert!(s.get_session("S1").await.unwrap().is_none());
    s.delete_session("S1").await.unwrap();
    assert!(s.get_session("NOPE").await.unwrap().is_none());
}

/// 認可コードは 1 度だけ Fresh で取れ、2 度目からは Reused。再利用で失効させると、そのコードから出た AT と RT が
/// 消える（失効は take_code ではなく revoke_code_tokens で起きる）。知らないコードは Unknown。
pub(crate) async fn code_reuse_revokes_issued_tokens(s: &dyn Store) {
    s.save_code(code("C1")).await.unwrap();
    s.save_access_token(at("AT1", "a")).await.unwrap();
    s.save_refresh_token(rt("RT1", "F", None)).await.unwrap();
    s.link_issued_tokens("C1", "AT1", Some("RT1"))
        .await
        .unwrap();

    assert!(
        matches!(s.take_code("C1").await.unwrap(), CodeTake::Fresh(c) if same(&c, &code("C1")))
    );
    assert!(matches!(s.take_code("C1").await.unwrap(), CodeTake::Reused(c) if c.client_id == "cl"));
    assert!(
        s.get_access_token("AT1").await.unwrap().is_some(),
        "take_code が失効させた"
    );
    s.revoke_code_tokens("C1").await;
    assert!(s.get_access_token("AT1").await.unwrap().is_none());
    assert!(s.get_refresh_token("RT1").await.unwrap().is_none());
    assert!(matches!(
        s.take_code("NOPE").await.unwrap(),
        CodeTake::Unknown
    ));
}

/// access token は保存したとおりに読め、失効させると読めない。知らない token の失効は誤りにしない。
pub(crate) async fn an_access_token_is_saved_read_and_revoked(s: &dyn Store) {
    s.save_access_token(at("AT1", "a")).await.unwrap();
    assert!(same(
        &s.get_access_token("AT1").await.unwrap().unwrap(),
        &at("AT1", "a")
    ));
    s.revoke_access_token("AT1").await.unwrap();
    assert!(s.get_access_token("AT1").await.unwrap().is_none());
    s.revoke_access_token("NOPE").await.unwrap();
}

/// mandate の消費は 1 度だけ。消費したことは token に残り、知らない token は消費できない。
pub(crate) async fn consume_mandate_is_single_use(s: &dyn Store) {
    s.save_access_token(at("AT1", "a")).await.unwrap();
    assert!(s.consume_mandate_if_unused("AT1").await.unwrap());
    assert!(!s.consume_mandate_if_unused("AT1").await.unwrap());
    assert!(
        s.get_access_token("AT1")
            .await
            .unwrap()
            .unwrap()
            .mandate_consumed
    );
    assert!(!s.consume_mandate_if_unused("NOPE").await.unwrap());
}

/// 並んだ mandate の消費のうち、通るのは 1 つだけ。
pub(crate) async fn racing_mandate_consumptions_let_one_through(s: &dyn Store) {
    s.save_access_token(at("AT1", "a")).await.unwrap();
    let (a, b) = tokio::join!(
        s.consume_mandate_if_unused("AT1"),
        s.consume_mandate_if_unused("AT1")
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|w| **w).count(), 1);
}

/// refresh token は保存したとおりに読め、読んでも消費しない。失効させると読めない。
pub(crate) async fn a_refresh_token_is_read_without_being_consumed(s: &dyn Store) {
    s.save_refresh_token(rt("RT1", "F", None)).await.unwrap();
    for _ in 0..2 {
        assert!(same(
            &s.get_refresh_token("RT1").await.unwrap().unwrap(),
            &rt("RT1", "F", None)
        ));
    }
    s.revoke_refresh_token("RT1").await.unwrap();
    assert!(s.get_refresh_token("RT1").await.unwrap().is_none());
    s.revoke_refresh_token("NOPE").await.unwrap();
}

/// RT の使用済み化は 1 度だけ通り、replaced_by は最初の値が残る。知らない RT は使用済みにできない。
pub(crate) async fn mark_refresh_used_is_single_use(s: &dyn Store) {
    s.save_refresh_token(rt("RT1", "F", None)).await.unwrap();
    assert!(s.mark_refresh_used("RT1", Some("RT2")).await.unwrap());
    assert!(
        !s.mark_refresh_used("RT1", Some("RT3")).await.unwrap(),
        "使用済みの RT をもう 1 度回せた"
    );
    let used = s.get_refresh_token("RT1").await.unwrap().unwrap();
    assert!(used.used);
    assert_eq!(used.replaced_by.as_deref(), Some("RT2"));
    assert!(!s.mark_refresh_used("NOPE", None).await.unwrap());
}

/// 並んだローテーションのうち、通るのは 1 つだけ。
pub(crate) async fn racing_rotations_let_one_through(s: &dyn Store) {
    s.save_refresh_token(rt("RT1", "F", None)).await.unwrap();
    let (a, b) = tokio::join!(
        s.mark_refresh_used("RT1", Some("Ra")),
        s.mark_refresh_used("RT1", Some("Rb"))
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|w| **w).count(), 1);
}

/// 系列の失効は札を書き、start から replaced_by を辿って鎖を長さによらず全部消す。ほかの系列には触れない。
pub(crate) async fn revoke_family_deletes_entire_chain(s: &dyn Store) {
    s.save_refresh_token(rt("X1", "G", None)).await.unwrap();
    for n in 1..=5usize {
        let fam = format!("F{n}");
        let tok = |i: usize| format!("F{n}R{i}");
        for i in 1..=n {
            let next = (i < n).then(|| tok(i + 1));
            s.save_refresh_token(rt(&tok(i), &fam, next.as_deref()))
                .await
                .unwrap();
        }
        assert!(!s.refresh_family_revoked(&fam).await.unwrap());
        s.revoke_refresh_family(&fam, &tok(1)).await;
        assert!(
            s.refresh_family_revoked(&fam).await.unwrap(),
            "n={n} 札が無い"
        );
        for i in 1..=n {
            assert!(
                s.get_refresh_token(&tok(i)).await.unwrap().is_none(),
                "n={n} {} が残っている",
                tok(i)
            );
        }
    }
    assert!(
        s.get_refresh_token("X1").await.unwrap().is_some(),
        "ほかの系列の RT が消えた"
    );
    assert!(
        !s.refresh_family_revoked("G").await.unwrap(),
        "ほかの系列に札が付いた"
    );
}

/// replaced_by が循環していても、系列の失効は止まり、鎖を全部消す。
pub(crate) async fn revoke_family_cyclic_chain_terminates(s: &dyn Store) {
    s.save_refresh_token(rt("C1", "F", Some("C2")))
        .await
        .unwrap();
    s.save_refresh_token(rt("C2", "F", Some("C1")))
        .await
        .unwrap();
    s.revoke_refresh_family("F", "C1").await;
    assert!(s.get_refresh_token("C1").await.unwrap().is_none());
    assert!(s.get_refresh_token("C2").await.unwrap().is_none());
}

/// account の失効は、その account の session（keep_sid を除く）・AT・RT を消して数を返す。ほかの account には触れない。
pub(crate) async fn revoke_account_removes_only_that_accounts_records(s: &dyn Store) {
    for (sid, account) in [("S1", "a"), ("S2", "a"), ("S3", "b")] {
        s.save_session(Session {
            sid: sid.into(),
            account_id: account.into(),
            auth_time: 0,
        })
        .await
        .unwrap();
    }
    for (t, account) in [("AT1", "a"), ("AT2", "b")] {
        s.save_access_token(at(t, account)).await.unwrap();
    }
    s.save_refresh_token(rt("RT1", "F", None)).await.unwrap();
    s.save_refresh_token(RefreshToken {
        account_id: "b".into(),
        ..rt("RT2", "G", None)
    })
    .await
    .unwrap();

    let counts = s.revoke_account("a", "S2").await;
    assert_eq!(
        (counts.sessions, counts.access_tokens, counts.refresh_tokens),
        (1, 1, 1)
    );
    assert!(counts.query_errors.is_empty());
    assert!(s.get_session("S1").await.unwrap().is_none());
    assert!(
        s.get_session("S2").await.unwrap().is_some(),
        "keep_sid の session が消えた"
    );
    assert!(s.get_access_token("AT1").await.unwrap().is_none());
    assert!(s.get_refresh_token("RT1").await.unwrap().is_none());
    assert!(s.get_session("S3").await.unwrap().is_some());
    assert!(s.get_access_token("AT2").await.unwrap().is_some());
    assert!(s.get_refresh_token("RT2").await.unwrap().is_some());
}

/// `$make` は新しい空の保存先を返す async fn（`impl Store`）。
macro_rules! store_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::store_contract as c;

            $crate::store_contract::store_contract_tests!(@each $make;
                an_interaction_is_completed_only_while_it_exists_and_consumed_once,
                racing_interaction_consumptions_let_one_through,
                a_session_is_saved_read_and_deleted,
                code_reuse_revokes_issued_tokens,
                an_access_token_is_saved_read_and_revoked,
                consume_mandate_is_single_use,
                racing_mandate_consumptions_let_one_through,
                a_refresh_token_is_read_without_being_consumed,
                mark_refresh_used_is_single_use,
                racing_rotations_let_one_through,
                revoke_family_deletes_entire_chain,
                revoke_family_cyclic_chain_terminates,
                revoke_account_removes_only_that_accounts_records,
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
pub(crate) use store_contract_tests;
