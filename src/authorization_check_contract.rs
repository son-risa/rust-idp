//! [`AuthorizationCheck`] の契約の試験。実装ごとに 1 度 [`authorization_check_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! /authorize は、client と redirect_uri を確かめた後（`resolve_addressee`）、登録した確かめを順に回し、最初の誤りを
//! redirect_uri へ認可の応答として返す（`web::oidc::run_checks`・`authorize_error`）。確かめは並べる順を問わない
//! 前提なので、要求を読むだけで、同じ要求には同じ答えを返す。
//!
//! ここでは、試しの要求の組（正しい要求・値の欠けた要求・変わった値の要求）を、public と confidential の client で
//! 確かめに通し、答えの形を見る。どの要求を通すかは確かめごとの規則なので、ここでは見ない。

use crate::auth_checks::AuthorizationCheck;
use crate::context::AddressedRequest;
use crate::error::OAuthError;
use crate::model::{AuthParams, Client};
use crate::provider::Provider;

const REDIRECT_URI: &str = "https://rp.example/cb";

fn client(public: bool) -> Client {
    Client {
        client_id: "rp".into(),
        redirect_uris: vec![REDIRECT_URI.into()],
        token_endpoint_auth_method: if public {
            "none"
        } else {
            "client_secret_basic"
        }
        .into(),
        client_secret: (!public).then(|| crate::dcr::hash_token("s")),
        grant_types: vec!["authorization_code".into()],
        post_logout_redirect_uris: vec![],
        initiate_login_uri: None,
        dpop_bound: false,
        jwks: vec![],
        jwks_uri: None,
        require_par: false,
        require_pkce: false,
        id_token_signed_response_alg: None,
        scope: None,
    }
}

fn valid() -> AuthParams {
    AuthParams {
        client_id: Some("rp".into()),
        redirect_uri: Some(REDIRECT_URI.into()),
        response_type: Some("code".into()),
        scope: Some("openid".into()),
        state: Some("st".into()),
        nonce: Some("n".into()),
        prompt: None,
        max_age: None,
        response_mode: None,
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
        code_challenge_method: Some("S256".into()),
        dpop_jkt: None,
        resource: None,
    }
}

/// 試しの要求の組。値の欠け・空・変わった値・とても長い値を含む。
fn samples() -> Vec<AddressedRequest> {
    let odd = "\u{0}\u{202e}状態%00<script>".to_string();
    let long = "a".repeat(64 * 1024);
    let mut params = vec![
        valid(),
        AuthParams {
            client_id: None,
            redirect_uri: None,
            response_type: None,
            scope: None,
            state: None,
            nonce: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            resource: None,
        },
        AuthParams {
            response_type: Some("token".into()),
            ..valid()
        },
        AuthParams {
            response_type: Some("code id_token".into()),
            ..valid()
        },
        AuthParams {
            scope: Some("profile email".into()),
            ..valid()
        },
        AuthParams {
            scope: Some("openid offline_access".into()),
            prompt: Some("login consent".into()),
            max_age: Some("0".into()),
            resource: Some("https://api.example".into()),
            dpop_jkt: Some("jkt".into()),
            ..valid()
        },
        AuthParams {
            code_challenge: None,
            code_challenge_method: None,
            ..valid()
        },
        AuthParams {
            code_challenge_method: Some("plain".into()),
            ..valid()
        },
        AuthParams {
            code_challenge_method: None,
            ..valid()
        },
    ];
    for v in [String::new(), odd, long] {
        params.push(AuthParams {
            response_type: Some(v.clone()),
            scope: Some(v.clone()),
            state: Some(v.clone()),
            nonce: Some(v.clone()),
            prompt: Some(v.clone()),
            max_age: Some(v.clone()),
            response_mode: Some(v.clone()),
            code_challenge: Some(v.clone()),
            code_challenge_method: Some(v.clone()),
            dpop_jkt: Some(v.clone()),
            resource: Some(v),
            ..valid()
        });
    }
    let mut out = Vec::new();
    for public in [true, false] {
        for p in &params {
            out.push(AddressedRequest {
                params: p.clone(),
                client: client(public),
                redirect_uri: REDIRECT_URI.into(),
                request_uri: None,
            });
        }
    }
    out
}

/// 答えを比べられる形にする（Ok か、誤りの code）。
async fn verdict(
    c: &dyn AuthorizationCheck,
    p: &Provider,
    r: &AddressedRequest,
) -> Result<(), &'static str> {
    c.check(p, r).await.map_err(|e| e.code())
}

/// 同じ要求には、何度確かめても、ほかの確かめを先に回しても、同じ答えを返す（並べる順を問わない前提）。
pub(crate) async fn answers_the_same_whatever_ran_before(c: &dyn AuthorizationCheck) {
    let p = Provider::new("https://op.example.com");
    let reqs = samples();
    let first: Vec<_> = {
        let mut v = Vec::new();
        for r in &reqs {
            v.push(verdict(c, &p, r).await);
        }
        v
    };
    // ほかの確かめ（既定の組と自分）を、要求の組の逆の順で回してから、もう一度見る。
    for r in reqs.iter().rev() {
        for other in &p.checks {
            let _ = other.check(&p, r).await;
        }
        let _ = c.check(&p, r).await;
    }
    for (i, r) in reqs.iter().enumerate() {
        assert_eq!(verdict(c, &p, r).await, first[i], "samples[{i}]");
    }
}

/// 認可の応答で RP に返せる誤り（RFC 6749 §4.1.2.1・OIDC Core §3.1.2.6・RFC 8707）だけで断る。
/// token endpoint の誤り（invalid_client・invalid_grant など）は、redirect_uri へ返す誤りとして意味を持たない。
pub(crate) async fn refuses_only_with_authorization_response_errors(c: &dyn AuthorizationCheck) {
    let p = Provider::new("https://op.example.com");
    for (i, r) in samples().iter().enumerate() {
        if let Err(e) = c.check(&p, r).await {
            assert!(
                matches!(
                    e,
                    OAuthError::InvalidRequest(_)
                        | OAuthError::UnauthorizedClient(_)
                        | OAuthError::AccessDenied(_)
                        | OAuthError::UnsupportedResponseType(_)
                        | OAuthError::InvalidScope(_)
                        | OAuthError::ServerError(_)
                        | OAuthError::LoginRequired(_)
                        | OAuthError::RequestUriNotSupported(_)
                        | OAuthError::InvalidTarget(_)
                ),
                "samples[{i}]: 認可の応答に無い誤り {}",
                e.code()
            );
        }
    }
}

/// `$make` は確かめを返す async fn（`impl AuthorizationCheck`）。
macro_rules! authorization_check_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::authorization_check_contract as c;

            $crate::authorization_check_contract::authorization_check_contract_tests!(@each $make;
                answers_the_same_whatever_ran_before,
                refuses_only_with_authorization_response_errors,
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
pub(crate) use authorization_check_contract_tests;
