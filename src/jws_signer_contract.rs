//! [`JwsSigner`] の契約の試験。実装ごとに 1 度 [`jws_signer_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! RP は id_token を、header の alg と kid で /jwks の鍵を選び、その鍵で検証する（`web::oidc::own_id_token` も同じ）。
//! ここではその手順で検証できることを、実装の中を見ずに確かめる。

use crate::jws::{JwsSigner, b64url};
use serde_json::{Value, json};

fn b64d(s: &str) -> Vec<u8> {
    crate::es256::b64url_decode(s).unwrap()
}

fn part<'a>(jwk: &'a Value, name: &str) -> &'a str {
    jwk[name]
        .as_str()
        .unwrap_or_else(|| panic!("JWK に {name} が無い: {jwk}"))
}

/// `signing_input` に対する `sig` を、JWK の公開鍵と alg で検証する。
fn verifies(jwk: &Value, alg: &str, signing_input: &str, sig: &[u8]) -> bool {
    match alg {
        "ES256" => {
            use p256::ecdsa::{Signature, signature::Verifier};
            let vk =
                crate::es256::verifying_key_from_xy(&b64d(part(jwk, "x")), &b64d(part(jwk, "y")))
                    .unwrap();
            Signature::from_slice(sig)
                .is_ok_and(|sig| vk.verify(signing_input.as_bytes(), &sig).is_ok())
        }
        "RS256" => {
            use rsa::{BoxedUint, Pkcs1v15Sign, PublicKey};
            use sha2::Digest;
            let n = BoxedUint::from_be_slice_vartime(&b64d(part(jwk, "n")));
            let e = BoxedUint::from_be_slice_vartime(&b64d(part(jwk, "e")));
            let pk = PublicKey::new(n, e).unwrap();
            let hashed = sha2::Sha256::digest(signing_input.as_bytes());
            pk.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed, sig)
                .is_ok()
        }
        other => panic!("この試験が知らない alg: {other}"),
    }
}

/// RFC 7638 の JWK Thumbprint。必須の公開鍵の要素だけを、名の辞書順に並べた JSON の SHA-256。
fn thumbprint(jwk: &Value) -> String {
    use sha2::Digest;
    let canonical = match part(jwk, "kty") {
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            part(jwk, "crv"),
            part(jwk, "x"),
            part(jwk, "y")
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            part(jwk, "e"),
            part(jwk, "n")
        ),
        other => panic!("この試験が知らない kty: {other}"),
    };
    b64url(sha2::Sha256::digest(canonical.as_bytes()))
}

fn split(jwt: &str) -> (String, String, String) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWS Compact の形でない: {jwt}");
    (parts[0].into(), parts[1].into(), parts[2].into())
}

/// 署名は JWS Compact で、header の alg・kid が alg() と /jwks の鍵に合い、payload は渡した claims のまま。
/// header の alg と kid で選んだ公開鍵で署名を検証でき、payload を差し替えると検証で落ちる。
pub(crate) async fn a_signature_verifies_with_the_published_jwk(s: &dyn JwsSigner) {
    let claims = json!({"iss": "https://op.example", "sub": "alice", "aud": "rp", "n": 1});
    let (h, p, sig) = split(&s.sign(&claims).await);
    let header: Value = serde_json::from_slice(&b64d(&h)).unwrap();
    let jwk = s.public_jwk();
    assert_eq!(header["alg"], s.alg());
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], jwk["kid"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&b64d(&p)).unwrap(),
        claims,
        "payload が claims のままでない"
    );
    assert!(
        verifies(&jwk, s.alg(), &format!("{h}.{p}"), &b64d(&sig)),
        "公開鍵で検証できない"
    );
    // 同じ署名は、payload を差し替えると検証で落ちる（この検証が何でも通すのでないことも、ここで分かる）。
    let forged = b64url(json!({"sub": "attacker"}).to_string());
    assert!(
        !verifies(&jwk, s.alg(), &format!("{h}.{forged}"), &b64d(&sig)),
        "payload を差し替えても検証が通った"
    );
}

/// /jwks に出す JWK は、alg が alg() と合い、use は sig、kid は公開鍵の RFC 7638 Thumbprint。秘密の要素を含まない。
pub(crate) async fn the_jwk_names_the_alg_and_its_thumbprint_as_kid(s: &dyn JwsSigner) {
    let jwk = s.public_jwk();
    assert_eq!(jwk["alg"], s.alg());
    assert_eq!(jwk["use"], "sig");
    assert_eq!(
        part(&jwk, "kty"),
        match s.alg() {
            "ES256" => "EC",
            "RS256" => "RSA",
            other => panic!("この試験が知らない alg: {other}"),
        }
    );
    assert_eq!(part(&jwk, "kid"), thumbprint(&jwk));
    for secret in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(jwk.get(secret).is_none(), "JWK に秘密の {secret} が在る");
    }
}

/// `$make` は署名鍵を返す async fn（`impl JwsSigner`）。
macro_rules! jws_signer_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::jws_signer_contract as c;

            $crate::jws_signer_contract::jws_signer_contract_tests!(@each $make;
                a_signature_verifies_with_the_published_jwk,
                the_jwk_names_the_alg_and_its_thumbprint_as_kid,
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
pub(crate) use jws_signer_contract_tests;
