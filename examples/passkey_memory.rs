//! gcp の feature 無しで、メモリ上の保存先だけを使い、passkey の登録 → passkey のログイン → 認可コード →
//! /token まで HTTP で通す。passkey の認証器は、この例の中で p256 の鍵から作る（本物の認証器は要らない）。
//!
//! ```sh
//! cargo run --example passkey_memory
//! ```
//!
//! 登録のメールは送らず、[`Mailer`] の実装でリンクを受け取って、その token で登録を進める。

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value as Cbor};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use rust_idp::{Client, Lang, Mailer, MemoryDocumentStore, MemoryStore, Provider};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CLIENT_ID: &str = "example-rp";
const REDIRECT_URI: &str = "http://127.0.0.1:3000/callback";
const EMAIL: &str = "alice@example.com";

/// 登録のメールの代わりに、確認のリンクを取っておく。
#[derive(Default)]
struct Outbox(Mutex<Vec<String>>);

#[async_trait]
impl Mailer for Outbox {
    async fn send_verification(
        &self,
        _to: &str,
        verify_url: &str,
        _lang: Option<Lang>,
    ) -> Result<(), String> {
        self.0.lock().unwrap().push(verify_url.to_string());
        Ok(())
    }
    async fn send_already_registered(&self, _to: &str, _lang: Option<Lang>) -> Result<(), String> {
        Ok(())
    }
    async fn send_recovery(
        &self,
        _to: &str,
        _url: &str,
        _lang: Option<Lang>,
    ) -> Result<(), String> {
        Ok(())
    }
    async fn send_passkey_added(&self, _to: &str, _lang: Option<Lang>) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    run().await;
}

// `cargo test` でもこの例を通しで走らせる（Cargo.toml の [[example]] の test = true）。
#[tokio::test]
async fn the_example_runs() {
    run().await;
}

async fn run() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let rp_id = "127.0.0.1";

    // 利用者・passkey・登録の token などの保存先。MemoryStore にも渡すと、id_token の email をここから引く。
    let docs = Arc::new(MemoryDocumentStore::default());
    let outbox = Arc::new(Outbox::default());
    let provider = Provider::new(issuer.clone())
        .with_document_store(docs.clone())
        .with_store(Arc::new(MemoryStore::with_documents(docs)))
        .with_mailer(outbox.clone())
        .with_client(Client {
            client_id: CLIENT_ID.into(),
            redirect_uris: vec![REDIRECT_URI.into()],
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into()],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: None,
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: true,
            id_token_signed_response_alg: None,
            scope: None,
        });
    tokio::spawn(async move {
        axum::serve(listener, rust_idp::router(provider))
            .await
            .unwrap()
    });
    println!("OP: {issuer}");

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let key = SigningKey::generate();
    let cred_id = b"example-credential".to_vec();

    // 1. 登録: メールアドレスを送り、届いたリンクの token で passkey を作る。
    let resp = http
        .post(format!("{issuer}/signup/email-challenge"))
        .json(&json!({ "email": EMAIL }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "{}", resp.text().await.unwrap());
    let link = outbox.0.lock().unwrap().pop().expect("verification link");
    let token = query_of(&link)
        .into_iter()
        .find(|(k, _)| k == "token" || k == "t")
        .expect("token in the link")
        .1;
    println!("1. signup: リンク {link}");

    let opts: Value = http
        .post(format!("{issuer}/signup/passkey/options"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge = opts["challenge"].as_str().expect("challenge");
    let account_id = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(opts["user"]["id"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let (attestation, cdj) = registration(&key, &cred_id, challenge, &issuer, rp_id);
    let resp = http
        .post(format!("{issuer}/signup/passkey/verify"))
        .json(&json!({ "token": token, "response": { "clientDataJSON": cdj, "attestationObject": attestation } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    println!("2. passkey 登録: account_id={account_id}");

    // 2. ログイン: RP が /authorize へ送り、ログイン画面の代わりに passkey の options と verify を呼ぶ。
    let verifier = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
    let pkce = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let query = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid email"),
        ("state", "example-state"),
        ("nonce", "example-nonce"),
        ("code_challenge", &pkce),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    let mut cookies = HashMap::new();
    let resp = http
        .get(format!("{issuer}/authorize?{query}"))
        .send()
        .await
        .unwrap();
    keep_cookies(&resp, &mut cookies);
    let login = location(&resp);
    let uid = login
        .split('?')
        .next()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    println!("3. authorize: {} → {login}", resp.status());

    let opts: Value = http
        .post(format!("{issuer}/login/{uid}/passkey/options"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (auth_data, signature, cdj) =
        assertion(&key, 1, opts["challenge"].as_str().unwrap(), &issuer, rp_id);
    let resp = http
        .post(format!("{issuer}/login/{uid}/passkey/verify"))
        .header(reqwest::header::COOKIE, cookie_header(&cookies))
        .json(&json!({
            "id": URL_SAFE_NO_PAD.encode(&cred_id),
            "response": { "clientDataJSON": cdj, "authenticatorData": auth_data, "signature": signature, "userHandle": URL_SAFE_NO_PAD.encode(account_id.as_bytes()) },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    keep_cookies(&resp, &mut cookies);
    let resume = resp.json::<Value>().await.unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_string();
    println!("4. passkey ログイン: → {resume}");

    let resp = http
        .get(format!("{issuer}{resume}"))
        .header(reqwest::header::COOKIE, cookie_header(&cookies))
        .send()
        .await
        .unwrap();
    let callback = location(&resp);
    assert!(callback.starts_with(REDIRECT_URI), "{callback}");
    let code = query_of(&callback)
        .into_iter()
        .find(|(k, _)| k == "code")
        .expect("code")
        .1;
    println!("5. resume: {} → code={code}", resp.status());

    // 3. 認可コードを id_token に替える。
    let body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", &verifier),
    ])
    .unwrap();
    let resp = http
        .post(format!("{issuer}/token"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let tokens: Value = resp.json().await.unwrap();
    assert!(status.is_success(), "{tokens}");
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                tokens["id_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["sub"], account_id.as_str());
    println!("6. token: {status}");
    println!("   id_token の中身: {claims:#}");

    // email は userinfo で返る（登録の保存先から引く）。
    let userinfo: Value = http
        .get(format!("{issuer}/userinfo"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(userinfo["sub"], account_id.as_str());
    assert_eq!(userinfo["email"], EMAIL);
    println!("7. userinfo: {userinfo}");
}

/// 登録の ceremony（attestation は "none"）。(attestationObject, clientDataJSON) を base64url で返す。
fn registration(
    key: &SigningKey,
    cred_id: &[u8],
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> (String, String) {
    let pt = key.verifying_key().to_sec1_point(false);
    let int = |i: i64| Cbor::Integer(Integer::from(i));
    let cose = Cbor::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Cbor::Bytes(pt.x().unwrap().to_vec())),
        (int(-3), Cbor::Bytes(pt.y().unwrap().to_vec())),
    ]);
    // aaguid(16) || credIdLen(2) || credId || COSE_Key
    let mut attested = vec![0u8; 16];
    attested.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    attested.extend_from_slice(cred_id);
    attested.extend_from_slice(&cbor(&cose));
    let auth_data = auth_data(rp_id, 0x01 | 0x40, 0, &attested);
    let att = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
    ]);
    let cdj = client_data("webauthn.create", challenge, origin);
    (
        URL_SAFE_NO_PAD.encode(cbor(&att)),
        URL_SAFE_NO_PAD.encode(cdj),
    )
}

/// ログインの ceremony。(authenticatorData, signature, clientDataJSON) を base64url で返す。
fn assertion(
    key: &SigningKey,
    sign_count: u32,
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> (String, String, String) {
    let auth_data = auth_data(rp_id, 0x01 | 0x04, sign_count, &[]);
    let cdj = client_data("webauthn.get", challenge, origin);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig: Signature = key.sign(&signed);
    (
        URL_SAFE_NO_PAD.encode(auth_data),
        URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
        URL_SAFE_NO_PAD.encode(cdj),
    )
}

/// rpIdHash(32) || flags(1) || signCount(4) || attestedCredentialData
fn auth_data(rp_id: &str, flags: u8, sign_count: u32, attested: &[u8]) -> Vec<u8> {
    let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
    ad.push(flags);
    ad.extend_from_slice(&sign_count.to_be_bytes());
    ad.extend_from_slice(attested);
    ad
}

fn client_data(typ: &str, challenge: &str, origin: &str) -> Vec<u8> {
    json!({ "type": typ, "challenge": challenge, "origin": origin })
        .to_string()
        .into_bytes()
}

fn cbor(v: &Cbor) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).unwrap();
    buf
}

fn query_of(url: &str) -> Vec<(String, String)> {
    serde_urlencoded::from_str(url.split_once('?').map_or("", |(_, q)| q)).unwrap()
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

fn keep_cookies(resp: &reqwest::Response, jar: &mut HashMap<String, String>) {
    for v in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        if let Some((name, value)) = v
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .and_then(|kv| kv.split_once('='))
        {
            jar.insert(name.to_string(), value.to_string());
        }
    }
}

fn cookie_header(jar: &HashMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}
