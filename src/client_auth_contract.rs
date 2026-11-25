//! [`ClientAuthMethod`] の契約の試験。実装ごとに 1 度 [`client_auth_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! token endpoint は、要求が持つ材料（Basic・client_assertion・body の client_id）で方式を 1 つ選び、その方式が返した
//! client を認証済みとして扱う（`web::authenticate_client`）。方式の選び方は材料の形だけで決まるので、方式は
//! 自分の材料が無い・自分の方式で登録していない client の要求を、自分で断る。断るときは invalid_client。

use crate::client_auth::{ClientAuthInput, ClientAuthMethod};
use crate::error::OAuthError;
use crate::es256::b64url_encode;
use crate::model::Client;
use crate::provider::Provider;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use p256::elliptic_curve::Generate;

/// 試験が作る Provider の issuer。assertion の aud はこれに合わせる。
pub(crate) const ISSUER: &str = "https://op.example.com";

/// 方式の名として知られているもの。自分の名を除いたものを「別の方式」として使う。
const METHODS: [&str; 6] = [
    "none",
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "tls_client_auth",
];

/// 試験する方式と、その方式で登録した client と、その client の材料。
pub(crate) struct Case {
    pub auth: Box<dyn ClientAuthMethod>,
    /// `auth.method()` で登録した client。資格（secret のハッシュ・jwks など）を持つ。
    pub client: Client,
    /// その client の正しい材料。使い捨ての材料（assertion の jti）があるので、呼ぶごとに新しく作る。
    pub good: Box<dyn Fn() -> ClientAuthInput + Send + Sync>,
    /// 同じ client を名乗るが、資格の合わない材料（別の secret・別の鍵の署名など）。資格を持たない方式は空。
    pub forged: Vec<ClientAuthInput>,
}

fn provider_with(clients: impl IntoIterator<Item = Client>) -> Provider {
    clients
        .into_iter()
        .fold(Provider::new(ISSUER), |p, c| p.with_client(c))
}

fn shown(r: &Result<Client, OAuthError>) -> String {
    match r {
        Ok(c) => format!("Ok({})", c.client_id),
        Err(e) => format!("Err({})", e.code()),
    }
}

fn assert_invalid_client(r: Result<Client, OAuthError>, what: &str) {
    assert!(
        matches!(r, Err(OAuthError::InvalidClient(_))),
        "{what}: {}",
        shown(&r)
    );
}

/// 別の鍵で署名した、client を名乗る private_key_jwt 形の assertion。
fn foreign_assertion(client_id: &str) -> String {
    let key = SigningKey::generate();
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let h =
        b64url_encode(serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": "k1"}).to_string());
    let p = b64url_encode(
        serde_json::json!({
            "iss": client_id, "sub": client_id, "aud": ISSUER, "exp": exp,
            "jti": uuid::Uuid::new_v4().to_string(),
        })
        .to_string(),
    );
    let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", b64url_encode(sig.to_bytes()))
}

/// 正しい材料なら、その材料が名乗る client を返す。同じ方式の別の client が登録されていても取り違えない。
pub(crate) async fn authenticates_its_client_with_its_material(c: &Case) {
    let decoy = Client {
        client_id: format!("{}-other", c.client.client_id),
        ..c.client.clone()
    };
    let p = provider_with([decoy, c.client.clone()]);
    let got = c.auth.authenticate(&p, &(c.good)()).await;
    assert!(
        matches!(&got, Ok(found) if found.client_id == c.client.client_id),
        "{}",
        shown(&got)
    );
}

/// 資格の合わない材料は断る。
pub(crate) async fn refuses_forged_material(c: &Case) {
    let p = provider_with([c.client.clone()]);
    for (i, input) in c.forged.iter().enumerate() {
        assert_invalid_client(
            c.auth.authenticate(&p, input).await,
            &format!("forged[{i}]"),
        );
    }
}

/// 登録の無い client は断る。
pub(crate) async fn refuses_an_unknown_client(c: &Case) {
    let p = provider_with([]);
    assert_invalid_client(c.auth.authenticate(&p, &(c.good)()).await, "unknown");
}

/// 別の方式で登録した client は、その client の材料が揃っていても通さない（方式の格下げを許さない）。
pub(crate) async fn refuses_a_client_registered_for_another_method(c: &Case) {
    for other in METHODS.iter().filter(|m| **m != c.auth.method()) {
        let p = provider_with([Client {
            token_endpoint_auth_method: other.to_string(),
            ..c.client.clone()
        }]);
        assert_invalid_client(
            c.auth.authenticate(&p, &(c.good)()).await,
            &format!("registered as {other}"),
        );
    }
}

/// 自分の材料を持たない要求は通さない。材料が空の要求も、ほかの方式の材料（同じ client を名乗る Basic・
/// body の client_id・assertion のうち、自分の正しい材料に無いもの）だけを持つ要求も。
pub(crate) async fn refuses_requests_without_its_own_material(c: &Case) {
    let p = provider_with([c.client.clone()]);
    let empty = ClientAuthInput {
        basic: None,
        body_client_id: None,
        client_assertion: None,
    };
    assert_invalid_client(c.auth.authenticate(&p, &empty).await, "empty");

    let good = (c.good)();
    let id = c.client.client_id.clone();
    let others = ClientAuthInput {
        basic: good
            .basic
            .is_none()
            .then(|| (id.clone(), "not-the-secret".to_string())),
        body_client_id: good.body_client_id.is_none().then(|| id.clone()),
        client_assertion: good
            .client_assertion
            .is_none()
            .then(|| foreign_assertion(&id)),
    };
    assert_invalid_client(
        c.auth.authenticate(&p, &others).await,
        "other methods' material",
    );
}

/// `$make` は [`Case`] を返す async fn。
macro_rules! client_auth_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::client_auth_contract as c;

            $crate::client_auth_contract::client_auth_contract_tests!(@each $make;
                authenticates_its_client_with_its_material,
                refuses_forged_material,
                refuses_an_unknown_client,
                refuses_a_client_registered_for_another_method,
                refuses_requests_without_its_own_material,
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
pub(crate) use client_auth_contract_tests;
