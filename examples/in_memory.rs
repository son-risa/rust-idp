//! メモリ上の保存先と起動ごとの鍵（ephemeral）で OP を localhost に立て、同じ process の中から
//! RP として discovery → /authorize → 認可コード → /token まで通す。
//!
//! ```sh
//! cargo run --example in_memory
//! ```
//!
//! passkey のログイン画面は gcp の feature 無しでは使えない（利用者と passkey の保存先が Firestore に
//! しか無い）。そこでこの例は、ログイン済みのセッションを保存先へ直接入れ、その cookie を付けて
//! /authorize を呼ぶ。OP はセッションを見て、ログイン画面を出さずに認可コードを返す。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rust_idp::{Client, MemoryStore, Provider, Session, Store};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const CLIENT_ID: &str = "example-rp";
const REDIRECT_URI: &str = "http://127.0.0.1:3000/callback";
const SID: &str = "example-session";

#[tokio::main]
async fn main() {
    // reqwest は rustls の provider を自分では選ばない（rust-idp の Cargo.toml の注記）。
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());

    let store = Arc::new(MemoryStore::default());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    store
        .save_session(Session { sid: SID.into(), account_id: "alice".into(), auth_time: now })
        .await;

    let provider = Provider::new(issuer.clone()).with_store(store).with_client(Client {
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
    });
    tokio::spawn(async move { axum::serve(listener, rust_idp::router(provider)).await.unwrap() });
    println!("OP: {issuer}");

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let discovery: Value = http
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let authorization_endpoint = discovery["authorization_endpoint"].as_str().unwrap();
    let token_endpoint = discovery["token_endpoint"].as_str().unwrap();
    println!("1. discovery: authorization_endpoint={authorization_endpoint}");

    let verifier = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let query = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid profile"),
        ("state", "example-state"),
        ("nonce", "example-nonce"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    let resp = http
        .get(format!("{authorization_endpoint}?{query}"))
        .header(reqwest::header::COOKIE, format!("__Host-sid={SID}"))
        .send()
        .await
        .unwrap();
    let location = resp.headers()[reqwest::header::LOCATION].to_str().unwrap().to_string();
    let (_, callback_query) = location.split_once('?').expect("redirect to the callback");
    let callback: HashMap<String, String> = serde_urlencoded::from_str(callback_query).unwrap();
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert_eq!(callback["state"], "example-state");
    assert_eq!(callback["iss"], issuer);
    let code = &callback["code"];
    println!("2. authorize: {} → code={code}", resp.status());

    let body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", &verifier),
    ])
    .unwrap();
    let resp = http
        .post(token_endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let tokens: Value = resp.json().await.unwrap();
    assert!(status.is_success(), "{tokens}");
    let id_token = tokens["id_token"].as_str().unwrap();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(id_token.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    println!("3. token: {status} token_type={}", tokens["token_type"]);
    println!("   id_token の中身: {claims:#}");
}
