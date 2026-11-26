//! [`DpopVerifier`] の契約の試験。実装ごとに 1 度 [`dpop_verifier_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! 呼び手（token endpoint と、DPoP の token を受ける経路）は、検証が返した jkt を token の束縛に使い、
//! Err なら要求を断る。ここでは RFC 9449 §4.3 の確かめを、ES256 の鍵で作った proof で外から見る。

use crate::dpop::DpopVerifier;
use crate::es256::b64url_encode;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use p256::elliptic_curve::Generate;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const HTM: &str = "POST";
const HTU: &str = "https://op.example/token";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jwk(key: &SigningKey) -> Value {
    let pt = key.verifying_key().to_sec1_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(pt.x().unwrap()),
        "y": b64url_encode(pt.y().unwrap()),
    })
}

fn header(key: &SigningKey) -> Value {
    json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk(key)})
}

pub(crate) fn claims(htm: &str, htu: &str, iat: i64) -> Value {
    json!({"htm": htm, "htu": htu, "iat": iat, "jti": uuid::Uuid::new_v4().to_string()})
}

/// header と payload を `signer` で署名した JWS Compact。
fn signed(signer: &SigningKey, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string()),
        b64url_encode(payload.to_string())
    );
    let sig: Signature = signer.sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(sig.to_bytes()))
}

pub(crate) fn proof(key: &SigningKey, payload: &Value) -> String {
    signed(key, &header(key), payload)
}

/// RFC 7638 の JWK Thumbprint（EC）。
fn thumbprint(key: &SigningKey) -> String {
    let j = jwk(key);
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        j["x"].as_str().unwrap(),
        j["y"].as_str().unwrap()
    );
    b64url_encode(Sha256::digest(canonical.as_bytes()))
}

fn ath(token: &str) -> String {
    b64url_encode(Sha256::digest(token.as_bytes()))
}

/// 正しい proof には、proof に埋めた公開鍵の RFC 7638 Thumbprint を返す（token はこの値に束縛される）。
/// htu の query と fragment は比べない（RFC 9449 §4.3）。
pub(crate) async fn returns_the_thumbprint_of_the_proof_key(v: &dyn DpopVerifier) {
    let key = SigningKey::generate();
    let got = v
        .verify(&proof(&key, &claims(HTM, HTU, now())), HTM, HTU, None)
        .await;
    assert_eq!(got, Ok(thumbprint(&key)));

    let with_extra = format!("{HTU}?foo=bar#frag");
    let got = v
        .verify(
            &proof(&key, &claims(HTM, &with_extra, now())),
            HTM,
            HTU,
            None,
        )
        .await;
    assert_eq!(got, Ok(thumbprint(&key)), "htu の query・fragment で断った");
}

/// 署名が埋めた鍵で検証できない proof は断る。payload の差し替えも、別の鍵での署名も。
pub(crate) async fn rejects_a_signature_the_embedded_key_did_not_make(v: &dyn DpopVerifier) {
    let key = SigningKey::generate();
    let other = SigningKey::generate();

    let p = proof(&key, &claims(HTM, HTU, now()));
    let parts: Vec<&str> = p.split('.').collect();
    let evil = "https://evil.example/x";
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        b64url_encode(claims(HTM, evil, now()).to_string()),
        parts[2]
    );
    assert!(
        v.verify(&forged, HTM, evil, None).await.is_err(),
        "payload を差し替えた proof を通した"
    );

    let by_other = signed(&other, &header(&key), &claims(HTM, HTU, now()));
    assert!(
        v.verify(&by_other, HTM, HTU, None).await.is_err(),
        "埋めた鍵と別の鍵で署名した proof を通した"
    );
}

/// htm と htu が、この要求のものでない proof は断る。
pub(crate) async fn rejects_a_proof_made_for_another_request(v: &dyn DpopVerifier) {
    let key = SigningKey::generate();
    let p = proof(&key, &claims(HTM, HTU, now()));
    assert!(v.verify(&p, "GET", HTU, None).await.is_err(), "htm");
    let p = proof(&key, &claims(HTM, HTU, now()));
    assert!(
        v.verify(&p, HTM, "https://op.example/userinfo", None)
            .await
            .is_err(),
        "htu の path"
    );
    let p = proof(&key, &claims(HTM, HTU, now()));
    assert!(
        v.verify(&p, HTM, "https://evil.example/token", None)
            .await
            .is_err(),
        "htu の host"
    );
}

/// iat が今から離れすぎた proof は断る。値の端（i64 の最小・最大）でも断る。
pub(crate) async fn rejects_an_iat_out_of_the_window(v: &dyn DpopVerifier) {
    let key = SigningKey::generate();
    for iat in [i64::MIN, i64::MAX, now() - 600, now() + 600] {
        let p = proof(&key, &claims(HTM, HTU, iat));
        assert!(v.verify(&p, HTM, HTU, None).await.is_err(), "iat {iat}");
    }
}

/// 同じ proof（同じ jti）は 1 度しか通らない。
pub(crate) async fn rejects_jti_replay(v: &dyn DpopVerifier) {
    let key = SigningKey::generate();
    let c = claims(HTM, HTU, now());
    assert!(v.verify(&proof(&key, &c), HTM, HTU, None).await.is_ok());
    assert!(
        v.verify(&proof(&key, &c), HTM, HTU, None).await.is_err(),
        "同じ jti を 2 度通した"
    );
}

/// ath を求めるとき（token を伴う要求）は、その token の ath を持つ proof だけを通す。
pub(crate) async fn checks_ath_when_asked(v: &dyn DpopVerifier) {
    let key = SigningKey::generate();
    let want = ath("the-access-token");
    let mut c = claims(HTM, HTU, now());
    c["ath"] = json!(want);
    assert!(
        v.verify(&proof(&key, &c), HTM, HTU, Some(&want))
            .await
            .is_ok()
    );

    let missing = proof(&key, &claims(HTM, HTU, now()));
    assert!(
        v.verify(&missing, HTM, HTU, Some(&want)).await.is_err(),
        "ath の無い proof を通した"
    );
    let mut c = claims(HTM, HTU, now());
    c["ath"] = json!(ath("another-token"));
    assert!(
        v.verify(&proof(&key, &c), HTM, HTU, Some(&want))
            .await
            .is_err(),
        "別の token の ath を通した"
    );
}

/// 形の崩れた proof は断る: JWS Compact でない・typ が dpop+jwt でない・alg が none・jwk に秘密の d がある・
/// 必須の claim（htm・htu・iat・jti）が欠ける。
pub(crate) async fn rejects_a_malformed_proof(v: &dyn DpopVerifier) {
    assert!(v.verify("only.two", HTM, HTU, None).await.is_err());

    let key = SigningKey::generate();
    let mut h = header(&key);
    h["typ"] = json!("jwt");
    assert!(
        v.verify(&signed(&key, &h, &claims(HTM, HTU, now())), HTM, HTU, None)
            .await
            .is_err(),
        "typ"
    );

    let mut h = header(&key);
    h["alg"] = json!("none");
    let unsigned = format!(
        "{}.{}.",
        b64url_encode(h.to_string()),
        b64url_encode(claims(HTM, HTU, now()).to_string())
    );
    assert!(
        v.verify(&unsigned, HTM, HTU, None).await.is_err(),
        "alg none"
    );

    let mut h = header(&key);
    h["jwk"]["d"] = json!("c29tZS1wcml2YXRl");
    assert!(
        v.verify(&signed(&key, &h, &claims(HTM, HTU, now())), HTM, HTU, None)
            .await
            .is_err(),
        "jwk の d"
    );

    for name in ["htm", "htu", "iat", "jti"] {
        let mut c = claims(HTM, HTU, now());
        c.as_object_mut().unwrap().remove(name);
        assert!(
            v.verify(&proof(&key, &c), HTM, HTU, None).await.is_err(),
            "{name} の無い proof を通した"
        );
    }
}

/// `$make` は新しい検証器を返す async fn（`impl DpopVerifier`）。jti の記憶は呼ぶごとに空から始まること。
macro_rules! dpop_verifier_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::dpop_verifier_contract as c;

            $crate::dpop_verifier_contract::dpop_verifier_contract_tests!(@each $make;
                returns_the_thumbprint_of_the_proof_key,
                rejects_a_signature_the_embedded_key_did_not_make,
                rejects_a_proof_made_for_another_request,
                rejects_an_iat_out_of_the_window,
                rejects_jti_replay,
                checks_ath_when_asked,
                rejects_a_malformed_proof,
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
pub(crate) use dpop_verifier_contract_tests;
