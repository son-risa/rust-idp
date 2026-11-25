//! [`GrantHandler`] の契約の試験。実装ごとに 1 度 [`grant_handler_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! token endpoint は、grant_type でこの口を選び、client を認証し、その client に grant_type が許されているかと DPoP の
//! proof を確かめてから `handle` を呼ぶ（`web::oidc::token`）。`handle` が見るのは、form が持つ資格（code・
//! refresh_token・auth_req_id など）が、認証済みの client に向けて出したものか、と 1 度きりか。
//!
//! この macro は、OP が前に出した資格を 1 度だけ token に引き換える grant に当てる。資格の用意は実装ごとの
//! [`Issuer`] がする（code を保存する・CIBA の要求を承認済みにする、など）。

use crate::ciba::CibaStatus;
use crate::error::OAuthError;
use crate::grants::GrantHandler;
use crate::model::{AuthorizationCode, Client, RefreshToken, TokenResponse};
use crate::provider::Provider;
use async_trait::async_trait;
use std::collections::HashMap;

pub(crate) const ISSUER: &str = "https://op.example.com";
pub(crate) const REDIRECT_URI: &str = "https://rp.example/cb";
const ACCOUNT: &str = "acc-1";

/// 試験する grant と、その grant が引き換える資格を用意する口。
#[async_trait]
pub(crate) trait Issuer: Send + Sync {
    fn grant(&self) -> &dyn GrantHandler;
    /// `p` の上で、`client` と `account` に向けて資格を 1 つ用意し、それを引き換える form（grant_type を含む）を返す。
    /// 呼ぶごとに別の資格を用意する。
    async fn issue(&self, p: &Provider, client: &Client, account: &str) -> HashMap<String, String>;
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// client_secret_basic の confidential client。grant_types には試験する grant と組み込みの grant を入れる。
fn client(id: &str, grant_type: &str) -> Client {
    Client {
        client_id: id.into(),
        redirect_uris: vec![REDIRECT_URI.into()],
        token_endpoint_auth_method: "client_secret_basic".into(),
        client_secret: Some(crate::dcr::hash_token("s3cret")),
        grant_types: vec![
            grant_type.into(),
            "authorization_code".into(),
            "refresh_token".into(),
            "urn:openid:params:grant-type:ciba".into(),
        ],
        post_logout_redirect_uris: vec![],
        initiate_login_uri: None,
        dpop_bound: false,
        jwks: vec![],
        jwks_uri: None,
        require_par: false,
        require_pkce: false,
        id_token_signed_response_alg: None,
    }
}

fn shown(r: &Result<TokenResponse, OAuthError>) -> String {
    match r {
        Ok(t) => format!("Ok(token_type={})", t.token_type),
        Err(e) => format!("Err({})", e.code()),
    }
}

fn assert_invalid_grant(r: Result<TokenResponse, OAuthError>, what: &str) {
    assert!(
        matches!(r, Err(OAuthError::InvalidGrant(_))),
        "{what}: {}",
        shown(&r)
    );
}

async fn redeem(
    i: &dyn Issuer,
    p: &Provider,
    c: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> Result<TokenResponse, OAuthError> {
    i.grant().handle(p, c, form, jkt.map(str::to_string)).await
}

/// 出した資格は、出した先の client が引き換えられる。出る access token は、その client とその利用者のもので、
/// DPoP の鍵が無ければ Bearer。form の grant_type はこの grant の名。
pub(crate) async fn redeems_what_was_issued_to_the_client(i: &dyn Issuer) {
    let p = Provider::new(ISSUER);
    let gt = i.grant().grant_type();
    let rp = client("rp", gt);
    let form = i.issue(&p, &rp, ACCOUNT).await;
    assert_eq!(form.get("grant_type").map(String::as_str), Some(gt));

    let r = redeem(i, &p, &rp, &form, None).await;
    let t = r.unwrap_or_else(|e| panic!("Err({}): {}", e.code(), e.description()));
    assert!(
        t.token_type.eq_ignore_ascii_case("Bearer"),
        "{}",
        t.token_type
    );
    let at = p
        .store
        .get_access_token(&t.access_token)
        .await
        .unwrap()
        .expect("出した access token が保存されていない");
    assert_eq!(at.client_id, "rp");
    assert_eq!(at.account_id, ACCOUNT);
    assert_eq!(at.jkt, None);
}

/// DPoP の鍵（token endpoint が proof から得た jkt）を渡すと、出る access token はその鍵に束縛され、token_type は DPoP。
pub(crate) async fn binds_the_token_to_the_dpop_key_it_is_given(i: &dyn Issuer) {
    let p = Provider::new(ISSUER);
    let rp = client("rp", i.grant().grant_type());
    let form = i.issue(&p, &rp, ACCOUNT).await;
    let t = redeem(i, &p, &rp, &form, Some("JKT-C"))
        .await
        .unwrap_or_else(|e| panic!("Err({}): {}", e.code(), e.description()));
    assert!(
        t.token_type.eq_ignore_ascii_case("DPoP"),
        "{}",
        t.token_type
    );
    let at = p
        .store
        .get_access_token(&t.access_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(at.jkt.as_deref(), Some("JKT-C"));
}

/// 同じ form は 1 度しか token にならない。2 度目は invalid_grant。
pub(crate) async fn redeems_once(i: &dyn Issuer) {
    let p = Provider::new(ISSUER);
    let rp = client("rp", i.grant().grant_type());
    let form = i.issue(&p, &rp, ACCOUNT).await;
    assert!(redeem(i, &p, &rp, &form, None).await.is_ok());
    assert_invalid_grant(redeem(i, &p, &rp, &form, None).await, "2 度目");
}

/// ほかの client に出した資格は、認証済みの client が出しても引き換えない。
pub(crate) async fn refuses_what_was_issued_to_another_client(i: &dyn Issuer) {
    let p = Provider::new(ISSUER);
    let gt = i.grant().grant_type();
    let form = i.issue(&p, &client("rp", gt), ACCOUNT).await;
    assert_invalid_grant(
        redeem(i, &p, &client("evil", gt), &form, None).await,
        "別の client",
    );
}

/// form の値（grant_type の他）を 1 つでも変えたら引き換えない。でっち上げた資格も、資格に合わない付き物
/// （redirect_uri・code_verifier など）も。
pub(crate) async fn refuses_any_altered_value(i: &dyn Issuer) {
    let p = Provider::new(ISSUER);
    let rp = client("rp", i.grant().grant_type());
    let keys: Vec<String> = i
        .issue(&p, &rp, ACCOUNT)
        .await
        .into_keys()
        .filter(|k| k != "grant_type")
        .collect();
    assert!(!keys.is_empty(), "form に資格が無い");
    for k in keys {
        let mut form = i.issue(&p, &rp, ACCOUNT).await;
        let v = form.get_mut(&k).unwrap();
        v.push('x');
        assert_invalid_grant(redeem(i, &p, &rp, &form, None).await, &k);
    }
}

/// 自分の資格を持たない form は引き換えない。同じ client に出したほかの grant の資格（code・refresh_token・
/// auth_req_id のうち、自分の form に無い名のもの）だけを持つ form も。
pub(crate) async fn refuses_a_form_without_its_own_credential(i: &dyn Issuer) {
    let p = Provider::new(ISSUER);
    let gt = i.grant().grant_type();
    let rp = client("rp", gt);
    let own = i.issue(&p, &rp, ACCOUNT).await;

    let only_type = HashMap::from([("grant_type".to_string(), gt.to_string())]);
    let r = redeem(i, &p, &rp, &only_type, None).await;
    assert!(
        matches!(
            r,
            Err(OAuthError::InvalidRequest(_) | OAuthError::InvalidGrant(_))
        ),
        "grant_type だけの form: {}",
        shown(&r)
    );

    let mut foreign = only_type.clone();
    for (k, v) in others_credentials(&p, &rp).await {
        if !own.contains_key(&k) {
            foreign.insert(k, v);
        }
    }
    let r = redeem(i, &p, &rp, &foreign, None).await;
    assert!(
        matches!(
            r,
            Err(OAuthError::InvalidRequest(_) | OAuthError::InvalidGrant(_))
        ),
        "ほかの grant の資格の form {:?}: {}",
        foreign.keys().collect::<Vec<_>>(),
        shown(&r)
    );
}

/// 組み込みの grant が引き換える資格を、`client` に向けて 1 つずつ用意する（form の名と値）。
async fn others_credentials(p: &Provider, client: &Client) -> Vec<(String, String)> {
    let code = uuid::Uuid::new_v4().simple().to_string();
    p.store
        .save_code(AuthorizationCode {
            code: code.clone(),
            client_id: client.client_id.clone(),
            account_id: ACCOUNT.into(),
            redirect_uri: REDIRECT_URI.into(),
            scope: "openid".into(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            auth_time: now(),
            acr: None,
            dpop_jkt: None,
            resource: None,
            expires_at: now() + 60,
        })
        .await
        .unwrap();
    let rt = uuid::Uuid::new_v4().simple().to_string();
    p.store
        .save_refresh_token(RefreshToken {
            token: rt.clone(),
            client_id: client.client_id.clone(),
            account_id: ACCOUNT.into(),
            scope: "openid offline_access".into(),
            resource: None,
            jkt: None,
            acr: None,
            auth_time: Some(now()),
            family_id: uuid::Uuid::new_v4().to_string(),
            used: false,
            replaced_by: None,
        })
        .await
        .unwrap();
    let req = p
        .ciba
        .create(&client.client_id, ACCOUNT, "openid", "msg", None)
        .await
        .unwrap();
    p.ciba
        .transition_if_pending(req.as_str(), CibaStatus::Approved)
        .await
        .unwrap();
    vec![
        ("code".into(), code),
        ("redirect_uri".into(), REDIRECT_URI.into()),
        ("refresh_token".into(), rt),
        ("auth_req_id".into(), req.0),
    ]
}

/// 利用を止めた利用者と消した利用者には、止める・消す前に出した資格からも token を出さない。
#[cfg(feature = "gcp")]
pub(crate) async fn gives_no_tokens_to_a_disabled_or_deleted_account(i: &dyn Issuer) {
    let (host, _state) = crate::firestore::fake_firestore::spawn().await;
    let fs = std::sync::Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
    let outcome = crate::webauthn::RegOutcome {
        credential_id: "cred-1".into(),
        pub_x: "x".into(),
        pub_y: "y".into(),
        sign_count: 0,
        aaguid: String::new(),
    };
    crate::registration::save_credential(&*fs, "u@example.com", ACCOUNT, &outcome)
        .await
        .unwrap();
    let p = Provider::new(ISSUER).with_firestore(fs.clone());
    let rp = client("rp", i.grant().grant_type());

    let before = i.issue(&p, &rp, ACCOUNT).await;
    let pending = i.issue(&p, &rp, ACCOUNT).await;
    assert!(
        redeem(i, &p, &rp, &before, None).await.is_ok(),
        "止める前は使える"
    );

    crate::registration::set_disabled(&*fs, "u@example.com", true)
        .await
        .unwrap();
    assert_invalid_grant(redeem(i, &p, &rp, &pending, None).await, "止めた後");

    let after_delete = i.issue(&p, &rp, ACCOUNT).await;
    crate::account_admin::delete_account(
        &*fs,
        &crate::firestore_store::FirestoreStore::new(fs.clone()),
        "cli",
        "u@example.com",
    )
    .await
    .unwrap();
    assert_invalid_grant(redeem(i, &p, &rp, &after_delete, None).await, "消した後");
}

/// `$make` は [`Issuer`] を返す async fn。
macro_rules! grant_handler_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::grant_handler_contract as c;

            $crate::grant_handler_contract::grant_handler_contract_tests!(@each $make;
                redeems_what_was_issued_to_the_client,
                binds_the_token_to_the_dpop_key_it_is_given,
                redeems_once,
                refuses_what_was_issued_to_another_client,
                refuses_any_altered_value,
                refuses_a_form_without_its_own_credential,
            );
            #[cfg(feature = "gcp")]
            $crate::grant_handler_contract::grant_handler_contract_tests!(@each $make;
                gives_no_tokens_to_a_disabled_or_deleted_account,
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
pub(crate) use grant_handler_contract_tests;
