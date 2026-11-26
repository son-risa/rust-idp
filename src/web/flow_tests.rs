//! 登録→ログイン→CIBA承認を流し、account_id(UUID)が一貫して使われ、email が sub/user.id/CIBA account に
//! 漏れないことを検証する。保存先は gcp 付きなら fake Firestore（`firestore::fake_firestore`）と
//! FirestoreStore、gcp 無しなら MemoryDocumentStore と MemoryStore（同じ試験で 2 つの実装を確かめる）。

use super::*;
use crate::ciba::CibaStatus;
use crate::fido::verify::test_support::*;
use crate::fido::verify::{FLAG_AT, FLAG_UP, FLAG_UV};
use crate::model::Client;
use ciborium::value::Value as Cbor;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::assert_matches;

#[cfg(not(feature = "gcp"))]
async fn test_provider() -> Arc<Provider> {
    let docs: Arc<dyn crate::document_store::DocumentStore> =
        Arc::new(crate::document_store::MemoryDocumentStore::default());
    with_test_clients(
        Provider::new("http://localhost:8099".to_string())
            .with_document_store(docs.clone())
            .with_store(Arc::new(crate::store::MemoryStore::with_documents(docs))),
    )
}

#[cfg(feature = "gcp")]
async fn test_provider() -> Arc<Provider> {
    test_provider_and_fake().await.0
}

/// test_provider と、その下の fake Firestore（失敗を入れるため）。
#[cfg(feature = "gcp")]
async fn test_provider_and_fake() -> (
    Arc<Provider>,
    Arc<crate::firestore::fake_firestore::FakeState>,
) {
    let (host, state) = crate::firestore::fake_firestore::spawn().await;
    let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
    // with_firestore は registration:: の直叩き用、with_store は Store トレイト
    // (interaction/session/find_account 等)用で別物。本番(Cloud Run)は両方 Firestore を指すので
    // テストでもここを MemoryStore の既定のままにしない（find_account が PoC ダミー生成に
    // フォールバックしてしまい、firestore_store.rs の実装を検証できなくなる）。
    let p = Provider::new("http://localhost:8099".to_string())
        .with_firestore(fs.clone())
        .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(fs)));
    (with_test_clients(p), state)
}

fn with_test_clients(p: Provider) -> Arc<Provider> {
    let p = p
        .with_client(Client {
            client_id: "test-ciba-rp".into(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["urn:openid:params:grant-type:ciba".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        })
        .with_client(Client {
            client_id: "rp-entry".into(),
            redirect_uris: vec!["https://rp.example.com/cb".into()],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: Some("https://rp.example.com/auth/login".into()),
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        });
    Arc::new(p)
}

fn make_reg_ceremony(
    key: &SigningKey,
    cred_id: &[u8],
    challenge: &str,
    origin: &str,
    rp_id: &str,
) -> (String, String) {
    let (x, y) = ec_xy(key);
    let cose = cose_es256(&x, &y);
    let acd = attested_cred_data(cred_id, &cose);
    let auth_data = build_auth_data(rp_id, FLAG_UP | FLAG_AT, 0, Some(&acd));
    let att = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
    ]);
    let cdj = client_data_json("webauthn.create", challenge, origin);
    (
        crate::webauthn::b64e(&cbor_to_vec(&att)),
        crate::webauthn::b64e(&cdj),
    )
}

fn make_auth_ceremony(
    key: &SigningKey,
    sign_count: u32,
    challenge: &str,
    origin: &str,
    rp_id: &str,
    uv: bool,
) -> (String, String, String) {
    let flags = if uv { FLAG_UP | FLAG_UV } else { FLAG_UP };
    let auth_data = build_auth_data(rp_id, flags, sign_count, None);
    let cdj = client_data_json("webauthn.get", challenge, origin);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig: Signature = key.sign(&signed);
    (
        crate::webauthn::b64e(&auth_data),
        crate::webauthn::b64e(sig.to_der().as_bytes()),
        crate::webauthn::b64e(&cdj),
    )
}

/// その interaction を始めたブラウザが送ってくる cookie（interaction には browser_binding_hash("b") を置く）。
/// 応答に Set-Cookie として出し直さないよう、送られてきた形（from_headers）で作る。
fn bound_jar(uid: &str) -> CookieJar {
    let mut h = HeaderMap::new();
    h.insert(
        header::COOKIE,
        format!("{}=b", super::browser_cookie_name(uid))
            .parse()
            .unwrap(),
    );
    CookieJar::from_headers(&h)
}

/// `/ciba` の画面から、account_id の利用者のブラウザが自分の origin で呼ぶときの (ヘッダ, cookie)。
async fn ciba_page_of(p: &Provider, account_id: &str) -> (HeaderMap, CookieJar) {
    let sid = format!("sid-{account_id}");
    p.store
        .save_session(Session {
            sid: sid.clone(),
            account_id: account_id.into(),
            auth_time: 0,
        })
        .await
        .unwrap();
    let mut c = HeaderMap::new();
    c.insert(
        header::COOKIE,
        format!("{SID_COOKIE}={sid}").parse().unwrap(),
    );
    let mut h = HeaderMap::new();
    h.insert(header::ORIGIN, p.origin().parse().unwrap());
    (h, CookieJar::from_headers(&c))
}

async fn body_json(resp: Response) -> serde_json::Value {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "status={status} body not json: {e} raw={}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

async fn body_text(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// email 確認は registration:: を直接叩き、passkey 登録は実 HTTP ハンドラを通す。
/// 戻り値: (SigningKey, credential_id, account_id)。
async fn register_test_account(p: &Arc<Provider>, email: &str) -> (SigningKey, Vec<u8>, String) {
    let fs = p.docs.as_deref().unwrap();
    let email_token = crate::registration::create_email_challenge(fs, email)
        .await
        .unwrap();

    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": email_token })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();
    let user_id_b64 = opts_json["user"]["id"].as_str().unwrap().to_string();
    let account_id_from_options =
        String::from_utf8(crate::es256::b64url_decode(&user_id_b64).unwrap()).unwrap();
    // WebAuthn user.id は不透明な account_id(UUID) であり、email を含んではならない。
    assert!(
        !account_id_from_options.contains('@'),
        "user.id leaks email: {account_id_from_options}"
    );
    assert!(
        uuid::Uuid::parse_str(&account_id_from_options).is_ok(),
        "user.id is not a uuid: {account_id_from_options}"
    );

    let key = SigningKey::generate();
    let cred_id = b"probe-credential-id".to_vec();
    let (att_b64, cdj_b64) = make_reg_ceremony(&key, &cred_id, &challenge, &p.origin(), &p.rp_id());

    let verify_req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": email_token,
        "response": { "clientDataJSON": cdj_b64, "attestationObject": att_b64 },
    }))
    .unwrap();
    let verify =
        register::register_passkey_verify(State(p.clone()), CookieJar::default(), Json(verify_req))
            .await;
    let verify_status = verify.status();
    let verify_body = body_json(verify).await;
    assert_eq!(
        verify_status,
        StatusCode::CREATED,
        "register_passkey_verify failed: {verify_body:?}"
    );

    let cred = crate::registration::get_account(fs, email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cred.account_id, account_id_from_options,
        "options 時点の account_id と保存後の accountId が食い違う"
    );

    // 逆引きインデックスも書けている。
    let looked_up = crate::registration::find_email_by_account_id(fs, &cred.account_id)
        .await
        .unwrap();
    assert_eq!(
        looked_up.as_deref(),
        Some(email),
        "accountsByUuid の逆引きが email と一致しない"
    );

    (key, cred_id, cred.account_id)
}

/// ログイン成功後の Interaction.account_id（= 最終的に発行される sub）を返す。
async fn login_with_email(
    p: &Arc<Provider>,
    email: &str,
    key: &SigningKey,
    sign_count: u32,
) -> String {
    let (uid, verify) = email_login_response(p, email, key, sign_count).await;
    let status = verify.status();
    let body = body_json(verify).await;
    assert_eq!(status, StatusCode::OK, "login (email) failed: {body:?}");

    // finalize_login は Interaction を削除せず account_id を書いて保存し直す
    // （/authorize/resume がこれを読んでコード発行に進むため）。
    let interaction = p
        .store
        .get_interaction(&uid)
        .await
        .expect("interaction should still exist after login");
    interaction
        .account_id
        .expect("account_id should be set after successful login")
}

async fn email_login_response(
    p: &Arc<Provider>,
    email: &str,
    key: &SigningKey,
    sign_count: u32,
) -> (String, Response) {
    email_login_response_with(p, email, key, sign_count, |sig| sig).await
}

/// 署名（b64url）を書き換えてから送る email ログイン。
async fn email_login_response_with(
    p: &Arc<Provider>,
    email: &str,
    key: &SigningKey,
    sign_count: u32,
    tamper: impl Fn(String) -> String,
) -> (String, Response) {
    email_login_with_credential(p, email, b"probe-credential-id", key, sign_count, tamper).await
}

async fn email_login_with_credential(
    p: &Arc<Provider>,
    email: &str,
    cred_id: &[u8],
    key: &SigningKey,
    sign_count: u32,
    tamper: impl Fn(String) -> String,
) -> (String, Response) {
    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: super::browser_binding_hash("b"),
        })
        .await;

    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone())).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    // options は常に discoverable なので、ブラウザと同じく userHandle（= その email の account_id）で名乗る。
    let account_id = crate::registration::get_account(p.docs.as_deref().unwrap(), email)
        .await
        .unwrap()
        .map(|a| a.account_id)
        .unwrap_or_default();
    let (ad, sig, cdj) =
        make_auth_ceremony(key, sign_count, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(cred_id),
        "response": {
            "clientDataJSON": cdj, "authenticatorData": ad, "signature": tamper(sig),
            "userHandle": crate::webauthn::b64e(account_id.as_bytes()),
        },
    }))
    .unwrap();
    let verify = login::login_passkey_verify(
        State(p.clone()),
        bound_jar(&uid),
        Path(uid.clone()),
        Json(verify_req),
    )
    .await;
    (uid, verify)
}

async fn login_discoverable(
    p: &Arc<Provider>,
    account_id: &str,
    key: &SigningKey,
    sign_count: u32,
) {
    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: super::browser_binding_hash("b"),
        })
        .await;

    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone())).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) =
        make_auth_ceremony(key, sign_count, &challenge, &p.origin(), &p.rp_id(), false);
    // userHandle = account_id(UUID)。email は一切登場しない。
    let user_handle_b64 = crate::webauthn::b64e(account_id.as_bytes());
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": user_handle_b64 },
    }))
    .unwrap();
    let verify = login::login_passkey_verify(
        State(p.clone()),
        bound_jar(&uid),
        Path(uid.clone()),
        Json(verify_req),
    )
    .await;
    let status = verify.status();
    let body = body_json(verify).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login (discoverable) failed: {body:?}"
    );

    let interaction = p
        .store
        .get_interaction(&uid)
        .await
        .expect("interaction should still exist after login");
    assert_eq!(
        interaction.account_id.as_deref(),
        Some(account_id),
        "discoverable ログインの最終 sub が userHandle の account_id と一致しない"
    );
}

/// ログインの options は、登録の有無で中身が変わらない（challenge 以外は同じで、allowCredentials は空）。
/// email を送っても読まない。
#[tokio::test]
async fn login_options_do_not_reveal_whether_an_email_is_registered() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_key, _cred_id, _account_id) = register_test_account(&p, &email).await;

    // 本文を JSON で受けるかどうかまで見るため、handler を直に呼ばず router を通す。
    let app = super::router(
        Provider::new(p.issuer().to_string()).with_document_store(p.docs.clone().unwrap()),
    );
    let options_for = |body: serde_json::Value| {
        let app = app.clone();
        async move {
            let req = axum::http::Request::post("/login/u/passkey/options")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap();
            let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let mut v = body_json(resp).await;
            v.as_object_mut()
                .unwrap()
                .remove("challenge")
                .expect("challenge");
            v
        }
    };
    let registered = options_for(json!({ "email": email })).await;
    let unknown = options_for(json!({ "email": "nobody@example.com" })).await;
    let blank = options_for(json!({})).await;
    assert_eq!(registered["allowCredentials"], json!([]), "{registered}");
    assert_eq!(registered, unknown);
    assert_eq!(registered, blank);
}

/// DCR登録エンドポイント(oidc::register)が ConfidentialSecret プロファイルの IAT を
/// 正しく処理し、生成した client_secret をレスポンスへ一度だけ平文で載せつつ、
/// Firestore にはハッシュのみを保存することを実HTTPハンドラ経由で検証する。
/// dcr.rs の単体テストは validate_registration の戻り値を直接見るのみで、
/// raw_client_secret が register() ハンドラ経由で実際に配線されているかは見ていなかった。
#[tokio::test]
async fn register_confidential_secret_returns_raw_secret_once() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();

    let constraints = crate::dcr::IatConstraints {
        allowed_redirect_hosts: vec!["rp.example.com".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        profile: crate::dcr::ClientProfile::ConfidentialSecret,
    };
    let (raw_iat, iat_hash) = crate::dcr::gen_random_token();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    crate::dcr_store::put_iat(fs, &iat_hash, &constraints, expires_at, false)
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {raw_iat}").parse().unwrap(),
    );
    let body = json!({ "redirect_uris": ["https://rp.example.com/cb"] }).to_string();

    let resp = oidc::register(State(p.clone()), headers, body).await;
    let status = resp.status();
    let resp_body = body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "register failed: {resp_body:?}"
    );
    assert_eq!(
        resp_body["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(resp_body["client_secret_expires_at"], 0);
    let raw_secret = resp_body["client_secret"]
        .as_str()
        .expect("ConfidentialSecretはclient_secretを平文で返す");

    // 保存されているのはハッシュのみ(レスポンスで返した平文そのものではない)。
    let client_id = resp_body["client_id"].as_str().unwrap();
    let stored = crate::dcr_store::load_client(fs, client_id)
        .await
        .expect("client should be saved");
    assert_eq!(
        stored.client_secret.as_deref(),
        Some(crate::dcr::hash_token(raw_secret).as_str())
    );
    assert_ne!(stored.client_secret.as_deref(), Some(raw_secret));
}

/// 使い捨ての IAT は 1 度の登録で消費され、同じ IAT での 2 度目の登録は断られる。
#[tokio::test]
async fn a_single_use_initial_access_token_registers_only_once() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let constraints = crate::dcr::IatConstraints {
        allowed_redirect_hosts: vec!["rp.example.com".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        profile: crate::dcr::ClientProfile::Public,
    };
    let (raw_iat, iat_hash) = crate::dcr::gen_random_token();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    crate::dcr_store::put_iat(fs, &iat_hash, &constraints, expires_at, false)
        .await
        .unwrap();
    let register = || {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {raw_iat}").parse().unwrap(),
        );
        let body = json!({ "redirect_uris": ["https://rp.example.com/cb"] }).to_string();
        oidc::register(State(p.clone()), headers, body)
    };

    let first = register().await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = register().await;
    let status = second.status();
    let body = body_json(second).await;
    assert!(
        status.is_client_error(),
        "2 度目が通った: {status} {body:?}"
    );
    assert_eq!(body["error"], "invalid_token");
    assert!(
        crate::dcr_store::peek_iat(fs, &iat_hash)
            .await
            .unwrap()
            .is_none(),
        "IAT が残っている"
    );
}

fn from_ip(ip: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-forwarded-for", ip.parse().unwrap());
    h
}

/// 使い捨ての IAT による登録は、IP ごとに回数の上限がある（IAT を毎回替えても、上限を超えた分は 429）。
/// ほかの IP からは続けて登録できる。
#[tokio::test]
async fn registration_with_initial_access_tokens_is_rate_limited_per_ip() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let register = |ip: &'static str| {
        let p = p.clone();
        async move {
            let constraints = crate::dcr::IatConstraints {
                allowed_redirect_hosts: vec!["rp.example.com".into()],
                allowed_grant_types: vec!["authorization_code".into()],
                profile: crate::dcr::ClientProfile::Public,
            };
            let (raw_iat, iat_hash) = crate::dcr::gen_random_token();
            crate::dcr_store::put_iat(fs, &iat_hash, &constraints, expires_at, false)
                .await
                .unwrap();
            let mut headers = from_ip(ip);
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {raw_iat}").parse().unwrap(),
            );
            let body = json!({ "redirect_uris": ["https://rp.example.com/cb"] }).to_string();
            oidc::register(State(p), headers, body).await.status()
        }
    };

    for i in 0..5 {
        assert_eq!(register("192.0.2.1").await, StatusCode::CREATED, "{i} 回目");
    }
    assert_eq!(
        register("192.0.2.1").await,
        StatusCode::TOO_MANY_REQUESTS,
        "上限を超えても登録できた"
    );
    assert_eq!(
        register("192.0.2.2").await,
        StatusCode::CREATED,
        "ほかの IP まで止まった"
    );
}

/// signup のメールは、同じ IP からも、同じアドレスへも、回数の上限を超えて送らない（429）。
#[tokio::test]
async fn signup_emails_are_rate_limited_per_ip_and_per_address() {
    let p = test_provider().await;
    let signup = |ip: String, email: String| {
        register::register_email_challenge(
            State(p.clone()),
            from_ip(&ip),
            Json(serde_json::from_value(json!({ "email": email })).unwrap()),
        )
    };

    // IP ごとは 1 時間に 30 通。30 通目までは通る。
    for i in 0..30 {
        assert_eq!(
            signup("192.0.2.10".into(), format!("a{i}@example.com"))
                .await
                .status(),
            StatusCode::NO_CONTENT,
            "{i} 通目"
        );
    }
    let over = signup("192.0.2.10".into(), "a30@example.com".into()).await;
    assert_eq!(
        over.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "同じ IP から上限を超えて送れた"
    );

    // アドレスごとは 1 時間に 5 通。
    for i in 0..5 {
        assert_eq!(
            signup(format!("198.51.100.{i}"), "same@example.com".into())
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let over = signup("198.51.100.99".into(), "same@example.com".into()).await;
    assert_eq!(
        over.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "同じアドレスへ上限を超えて送れた"
    );
}

/// 復旧のメールも、同じ IP からも、同じアドレスへも、回数の上限を超えて送らない（429）。
#[tokio::test]
async fn recovery_emails_are_rate_limited_per_ip_and_per_address() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let recover = |ip: String, email: String| {
        let form: recover::RecoverForm = serde_json::from_value(json!({ "email": email })).unwrap();
        recover::recover_submit(
            State(p.clone()),
            from_ip(&ip),
            CookieJar::default(),
            Form(form),
        )
    };

    // IP ごとは 1 時間に 30 通。30 通目までは通る。
    for i in 0..30 {
        assert_eq!(
            recover("192.0.2.20".into(), format!("b{i}@example.com"))
                .await
                .status(),
            StatusCode::OK,
            "{i} 通目"
        );
    }
    let over = recover("192.0.2.20".into(), "b30@example.com".into()).await;
    assert_eq!(
        over.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "同じ IP から上限を超えて送れた"
    );

    // アドレスごとは 1 時間に 5 通。
    for i in 0..5 {
        assert_eq!(
            recover(format!("198.51.100.{i}"), email.clone())
                .await
                .status(),
            StatusCode::OK
        );
    }
    let over = recover("198.51.100.99".into(), email.clone()).await;
    assert_eq!(
        over.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "同じアドレスへ上限を超えて送れた"
    );
}

/// account_admin::disable_account で凍結したアカウントが、実HTTPハンドラ(login_passkey_verify)
/// 経由でログインを拒否されることを検証する。login.rs 側の disabled チェックの配線確認。
#[tokio::test]
async fn disabled_account_cannot_login() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, account_id) = register_test_account(&p, &email).await;

    let fs = p.docs.as_deref().unwrap();
    let out = crate::account_admin::disable_account(fs, &*p.store, "test", &email)
        .await
        .unwrap();
    assert_matches!(out, crate::account_admin::DisableOutcome::Disabled { .. });

    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: super::browser_binding_hash("b"),
        })
        .await;

    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone())).await;
    assert_eq!(
        opts.status(),
        StatusCode::OK,
        "options自体は通す(disabled状態を先出ししない)"
    );
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(&key, 0, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": {
            "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig,
            "userHandle": crate::webauthn::b64e(account_id.as_bytes()),
        },
    }))
    .unwrap();
    let verify = login::login_passkey_verify(
        State(p.clone()),
        bound_jar(&uid),
        Path(uid.clone()),
        Json(verify_req),
    )
    .await;
    assert_eq!(
        verify.status(),
        StatusCode::FORBIDDEN,
        "disabled account should be rejected"
    );
}

/// 管理UI経由でIATをmint→一度だけ表示→再訪問で「表示済み」になる一連の流れを実HTTPハンドラ
/// 経由で検証する。「一度きり表示」は read-then-delete の順序を間違えやすく、実装ミスに
/// 気付きにくいため、web/admin.rs のユニットテストとは別にここで通しで確認する。
#[tokio::test]
async fn admin_mint_iat_flash_is_shown_once() {
    let p = test_provider().await;
    let email = format!("admin-{}@example.com", uuid::Uuid::new_v4());
    let (_key, _cred_id, account_id) = register_test_account(&p, &email).await;
    let fs = p.docs.as_deref().unwrap();
    crate::admin_store::grant_admin(fs, &account_id, "test")
        .await
        .unwrap();

    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session {
            sid: sid.clone(),
            account_id: account_id.clone(),
            auth_time: 0,
        })
        .await
        .unwrap();
    let jar = CookieJar::default().add(Cookie::new(SID_COOKIE, sid));

    let form: admin::IatMintForm = serde_json::from_value(json!({
        "profile": "confidential-secret",
        "redirect_hosts": "rp.example.com",
        "grant_types": "",
        "ttl_hours": 1,
    }))
    .unwrap();
    let mint_resp =
        admin::iat_mint_submit(State(p.clone()), HeaderMap::new(), jar.clone(), Form(form)).await;
    assert!(
        mint_resp.status().is_redirection(),
        "mint成功後はリダイレクトすること: {}",
        mint_resp.status()
    );
    let location = mint_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header required")
        .to_string();
    let flash_id = location.rsplit('/').next().unwrap().to_string();

    let mut ja = HeaderMap::new();
    ja.insert(header::ACCEPT_LANGUAGE, "ja".parse().unwrap());
    let first = admin::iat_show_once(
        State(p.clone()),
        ja.clone(),
        jar.clone(),
        Path(flash_id.clone()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = body_text(first).await;
    assert!(
        first_body.contains("IATを発行しました"),
        "1回目は生トークンを表示すること: {first_body}"
    );

    let second = admin::iat_show_once(State(p.clone()), ja, jar.clone(), Path(flash_id)).await;
    let second_body = body_text(second).await;
    assert!(
        second_body.contains("表示済みです"),
        "2回目は「表示済み」になること: {second_body}"
    );
}

/// 一度きりの IAT は発行した管理者にだけ見せる。flash_id を知るほかの管理者には「表示済み」を返し、
/// 消費もさせない（発行した管理者はその後も 1 回見られる）。
#[tokio::test]
async fn admin_iat_flash_is_shown_only_to_the_admin_who_minted_it() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let mut jars = vec![];
    for account_id in ["admin-minter", "admin-other"] {
        crate::admin_store::grant_admin(fs, account_id, "test")
            .await
            .unwrap();
        let sid = uuid::Uuid::new_v4().to_string();
        p.store
            .save_session(Session {
                sid: sid.clone(),
                account_id: account_id.into(),
                auth_time: 0,
            })
            .await
            .unwrap();
        jars.push(CookieJar::default().add(Cookie::new(SID_COOKIE, sid)));
    }
    let (minter, other) = (jars[0].clone(), jars[1].clone());

    let form: admin::IatMintForm = serde_json::from_value(json!({
        "profile": "confidential-secret",
        "redirect_hosts": "rp.example.com",
        "grant_types": "",
        "ttl_hours": 1,
    }))
    .unwrap();
    let mint = admin::iat_mint_submit(
        State(p.clone()),
        HeaderMap::new(),
        minter.clone(),
        Form(form),
    )
    .await;
    let location = mint
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let flash_id = location.rsplit('/').next().unwrap().to_string();

    let mut ja = HeaderMap::new();
    ja.insert(header::ACCEPT_LANGUAGE, "ja".parse().unwrap());
    let show = |jar: CookieJar| {
        admin::iat_show_once(State(p.clone()), ja.clone(), jar, Path(flash_id.clone()))
    };
    let by_other = body_text(show(other).await).await;
    assert!(
        by_other.contains("表示済みです") && !by_other.contains("IATを発行しました"),
        "{by_other}"
    );
    let by_minter = body_text(show(minter).await).await;
    assert!(
        by_minter.contains("IATを発行しました"),
        "発行した管理者は見られること: {by_minter}"
    );
}

#[tokio::test]
async fn register_then_login_uses_account_id_not_email() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, account_id) = register_test_account(&p, &email).await;

    // email 入力ログイン。最終 sub は email ではなく account_id であること。
    let sub_from_email_login = login_with_email(&p, &email, &key, 0).await;
    assert_eq!(sub_from_email_login, account_id);
    assert_ne!(sub_from_email_login, email);
    // discoverable ログイン（userHandle のみ）。email は一切送らない。
    login_discoverable(&p, &account_id, &key, 1).await;

    // find_account(FirestoreStore) が account_id から正しく email claim を逆引きできる。
    let account = p.store.find_account(&account_id).await;
    assert_eq!(account.sub, account_id);
    assert_eq!(
        account.claims.get("email").and_then(|v| v.as_str()),
        Some(email.as_str())
    );
    assert_eq!(
        account
            .claims
            .get("email_verified")
            .and_then(|v| v.as_bool()),
        Some(true)
    );

    // 未知の account_id では email claim が付かない（逆引き失敗を静かに許容し、値をでっち上げない）。
    let unknown = p
        .store
        .find_account("00000000-0000-0000-0000-000000000000")
        .await;
    assert!(!unknown.claims.contains_key("email"));
}

#[tokio::test]
async fn reregistration_reuses_existing_account_id() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_key1, _cred1, account_id1) = register_test_account(&p, &email).await;

    // 管理者が passkey だけを消した後に、同じ email で作り直す。account_id は変わってはならない
    // （変わると、過去に発行済みの sub を持つ他システムとの紐付けが切れる）。
    let fs = p.docs.as_deref().unwrap();
    crate::registration::remove_all_credentials(fs, &email)
        .await
        .unwrap();
    let email_token = crate::registration::create_email_challenge(fs, &email)
        .await
        .unwrap();
    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": email_token })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    let opts_json = body_json(opts).await;
    let user_id_b64 = opts_json["user"]["id"].as_str().unwrap().to_string();
    let account_id2 =
        String::from_utf8(crate::es256::b64url_decode(&user_id_b64).unwrap()).unwrap();

    assert_eq!(
        account_id1, account_id2,
        "再登録で account_id が変わってしまっている"
    );
}

#[tokio::test]
async fn leftover_signup_token_is_refused_once_registered() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let fs = p.docs.as_deref().unwrap();
    // 確認のメールを 2 通出し、1 通目で登録した後に残りの 1 通を使う。
    let leftover = crate::registration::create_email_challenge(fs, &email)
        .await
        .unwrap();
    register_test_account(&p, &email).await;

    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": leftover })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::CONFLICT);

    let ver_req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": leftover,
        "response": { "clientDataJSON": "", "attestationObject": "" },
    }))
    .unwrap();
    let ver =
        register::register_passkey_verify(State(p.clone()), CookieJar::new(), Json(ver_req)).await;
    assert_eq!(ver.status(), StatusCode::CONFLICT);
    let account = crate::registration::get_account(fs, &email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::registration::list_credentials(fs, &account)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn sign_count_update_preserves_account_id() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, account_id) = register_test_account(&p, &email).await;

    // 複数回ログインして signCount を書く経路を通す。
    login_with_email(&p, &email, &key, 1).await;
    login_with_email(&p, &email, &key, 2).await;

    let fs = p.docs.as_deref().unwrap();
    let account = crate::registration::get_account(fs, &email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        account.account_id, account_id,
        "signCount 更新のたびに accountId が消えていないこと"
    );
    let cred = crate::registration::sole_credential(fs, &email)
        .await
        .unwrap();
    assert_eq!(cred.sign_count, 2);
    assert!(cred.last_used_at.is_some());
}

#[tokio::test]
async fn ciba_flow_uses_account_id_consistently() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, cred_id, account_id) = register_test_account(&p, &email).await;

    // backchannel-authentication: login_hint は email(RP起点のヒント)。
    let mut form = HashMap::new();
    form.insert("client_id".to_string(), "test-ciba-rp".to_string());
    form.insert("login_hint".to_string(), email.clone());
    form.insert("scope".to_string(), "openid".to_string());
    let resp = ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(form)).await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "backchannel_auth failed: {body:?}");
    let auth_req_id = body["auth_req_id"].as_str().unwrap().to_string();

    // CIBA 要求本体の account は account_id であって login_hint(email) ではない。
    let stored = p.ciba.get(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(
        stored.account, account_id,
        "CIBA 要求の account に email が残っている"
    );
    assert_ne!(stored.account, email);

    // 未解決のうちに同じ RP が同じ人へ要求し直しても、新しい要求（と push）は作らず同じ auth_req_id を返す。
    let mut again = HashMap::new();
    again.insert("client_id".to_string(), "test-ciba-rp".to_string());
    again.insert("login_hint".to_string(), email.clone());
    again.insert("scope".to_string(), "openid".to_string());
    let body =
        body_json(ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(again)).await)
            .await;
    assert_eq!(
        body["auth_req_id"].as_str(),
        Some(auth_req_id.as_str()),
        "重複よけが効いていない: {body:?}"
    );

    // 承認オプション → 承認（UV 必須）。
    let (h, jar) = ciba_page_of(&p, &account_id).await;
    let opts =
        ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone()), h, jar).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
    let approve_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(&cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let approve = ciba::ciba_approve(
        State(p.clone()),
        Path(auth_req_id.clone()),
        Json(approve_req),
    )
    .await;
    let approve_status = approve.status();
    let approve_body = body_json(approve).await;
    assert_eq!(
        approve_status,
        StatusCode::OK,
        "ciba_approve failed: {approve_body:?}"
    );

    let approved = p.ciba.get(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(approved.status, CibaStatus::Approved);
    assert_eq!(approved.account, account_id);
}

/// 凍結したアカウントは、正しい passkey を持っていても CIBA を承認できない（ciba_approve の disabled 検査の配線）。
#[tokio::test]
async fn disabled_account_cannot_approve_ciba() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, cred_id, account_id) = register_test_account(&p, &email).await;

    let mut form = HashMap::new();
    form.insert("client_id".to_string(), "test-ciba-rp".to_string());
    form.insert("login_hint".to_string(), email.clone());
    form.insert("scope".to_string(), "openid".to_string());
    let body =
        body_json(ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(form)).await)
            .await;
    let auth_req_id = body["auth_req_id"].as_str().unwrap().to_string();

    let fs = p.docs.as_deref().unwrap();
    crate::account_admin::disable_account(fs, &*p.store, "test", &email)
        .await
        .unwrap();

    let (h, jar) = ciba_page_of(&p, &account_id).await;
    let opts = body_json(
        ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone()), h, jar).await,
    )
    .await;
    let challenge = opts["challenge"].as_str().unwrap().to_string();
    let (ad, sig, cdj) = make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
    let approve_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(&cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let approve = ciba::ciba_approve(
        State(p.clone()),
        Path(auth_req_id.clone()),
        Json(approve_req),
    )
    .await;
    assert_eq!(approve.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        p.ciba.get(&auth_req_id).await.unwrap().unwrap().status,
        CibaStatus::Pending
    );
}

/// 管理画面の POST は SSO セッション cookie だけで認可される。別サイトからの POST に cookie が付かないよう、
/// SameSite=Lax（と HttpOnly・Secure）で張られていることを押さえる（CSRF の守りはこの属性だけ）。
#[tokio::test]
async fn the_session_cookie_is_lax_httponly_and_secure() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, _account_id) = register_test_account(&p, &email).await;
    let (_uid, resp) = email_login_response(&p, &email, &key, 0).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    for attr in ["SameSite=Lax", "HttpOnly", "Secure"] {
        assert!(cookie.contains(attr), "{attr} が無い: {cookie}");
    }
}

/// 他人の鍵ではログインできない。email 入力でも、discoverable（userHandle に他人の account_id を入れる）でも同じ。
/// 凍結されたアカウントでも、署名が通らなければ 403 ではなく 401（凍結の有無を漏らさない）。
#[tokio::test]
async fn a_passkey_logs_in_only_its_own_account() {
    let p = test_provider().await;
    let victim = format!("victim-{}@example.com", uuid::Uuid::new_v4());
    let (_victim_key, _cred, victim_id) = register_test_account(&p, &victim).await;
    let attacker = SigningKey::generate();

    let (_uid, by_email) = email_login_response(&p, &victim, &attacker, 0).await;
    assert_eq!(by_email.status(), StatusCode::UNAUTHORIZED);

    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: super::browser_binding_hash("b"),
        })
        .await;
    let opts =
        body_json(login::login_passkey_options(State(p.clone()), Path(uid.clone())).await).await;
    let challenge = opts["challenge"].as_str().unwrap().to_string();
    let (ad, sig, cdj) =
        make_auth_ceremony(&attacker, 0, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": {
            "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig,
            "userHandle": crate::webauthn::b64e(victim_id.as_bytes()),
        },
    }))
    .unwrap();
    let by_handle = login::login_passkey_verify(
        State(p.clone()),
        bound_jar(&uid),
        Path(uid.clone()),
        Json(verify_req),
    )
    .await;
    assert_eq!(by_handle.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        p.store.get_interaction(&uid).await.unwrap().account_id,
        None
    );

    let fs = p.docs.as_deref().unwrap();
    crate::account_admin::disable_account(fs, &*p.store, "test", &victim)
        .await
        .unwrap();
    let (_uid, frozen) = email_login_response(&p, &victim, &attacker, 0).await;
    assert_eq!(
        frozen.status(),
        StatusCode::UNAUTHORIZED,
        "署名が通らないうちは凍結を明かさない"
    );
}

/// WebAuthn の ES256 の署名は DER。同じ署名を DER でない形（r||s の 64 バイト）にすると、正しい鍵でも 401。
#[tokio::test]
async fn a_passkey_signature_that_is_not_der_is_refused() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, _account_id) = register_test_account(&p, &email).await;
    let to_raw = |der_b64: String| {
        let der = crate::es256::b64url_decode(&der_b64).unwrap();
        let sig = Signature::from_der(&der).unwrap();
        crate::webauthn::b64e(&sig.to_bytes())
    };
    let (uid, resp) = email_login_response_with(&p, &email, &key, 0, to_raw).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        p.store.get_interaction(&uid).await.unwrap().account_id,
        None
    );
}

/// 2 本目の passkey を、登録の検証を通さずに直に足す。
async fn add_passkey(
    p: &Arc<Provider>,
    email: &str,
    account_id: &str,
    cred_id: &[u8],
) -> SigningKey {
    let key = SigningKey::generate();
    let (x, y) = ec_xy(&key);
    let outcome = crate::webauthn::RegOutcome {
        credential_id: crate::webauthn::b64e(cred_id),
        pub_x: crate::webauthn::b64e(&x),
        pub_y: crate::webauthn::b64e(&y),
        sign_count: 0,
        aaguid: String::new(),
    };
    crate::registration::save_credential(p.docs.as_deref().unwrap(), email, account_id, &outcome)
        .await
        .unwrap();
    key
}

#[tokio::test]
async fn either_of_two_passkeys_signs_in_as_the_same_account() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key1, cred1, account_id) = register_test_account(&p, &email).await;
    let key2 = add_passkey(&p, &email, &account_id, b"second-credential").await;

    let (_, r) = email_login_with_credential(&p, &email, &cred1, &key1, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);
    let (uid, r) =
        email_login_with_credential(&p, &email, b"second-credential", &key2, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        p.store
            .get_interaction(&uid)
            .await
            .unwrap()
            .account_id
            .as_deref(),
        Some(account_id.as_str())
    );

    // 名乗った passkey と違う鍵の署名は通らない。
    let (_, r) =
        email_login_with_credential(&p, &email, b"second-credential", &key1, 2, |s| s).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

/// 他人の passkey の id を名乗っても、その人として入れない（id で直に引いて持ち主を確かめる）。
#[tokio::test]
async fn another_accounts_passkey_id_is_not_accepted() {
    let p = test_provider().await;
    let victim = format!("victim-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, victim_id) = register_test_account(&p, &victim).await;
    let victim_key = add_passkey(&p, &victim, &victim_id, b"victim-second").await;
    let me = format!("me-{}@example.com", uuid::Uuid::new_v4());
    let fs = p.docs.as_deref().unwrap();
    let my_id = uuid::Uuid::new_v4().to_string();
    let outcome = crate::webauthn::RegOutcome {
        credential_id: "mine".into(),
        pub_x: "x".into(),
        pub_y: "y".into(),
        sign_count: 0,
        aaguid: String::new(),
    };
    crate::registration::save_credential(fs, &me, &my_id, &outcome)
        .await
        .unwrap();

    // 自分の email で options を取り、相手の passkey で答える。
    let (_, r) =
        email_login_with_credential(&p, &me, b"victim-second", &victim_key, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_an_account_removes_its_passkeys() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second-credential").await;
    let fs = p.docs.as_deref().unwrap();
    crate::account_admin::disable_account(fs, &*p.store, "cli", &email)
        .await
        .unwrap();
    crate::account_admin::delete_account(fs, &*p.store, "cli", &email)
        .await
        .unwrap();
    for id in [
        crate::webauthn::b64e(&cred1),
        crate::webauthn::b64e(b"second-credential"),
    ] {
        assert!(
            fs.get_doc("credentials", &id).await.unwrap().is_none(),
            "{id} が残った"
        );
    }
}

/// CIBA の承認も 2 本目の passkey で通る。他人の passkey の id を名乗ると通らない。
#[tokio::test]
async fn ciba_is_approved_with_either_passkey_but_not_anothers() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let key2 = add_passkey(&p, &email, &account_id, b"second-credential").await;
    let other = format!("other-{}@example.com", uuid::Uuid::new_v4());
    let other_id = uuid::Uuid::new_v4().to_string();
    let other_key = add_passkey(&p, &other, &other_id, b"other-credential").await;

    let approve = |cred: &'static [u8], key: SigningKey| {
        let p = p.clone();
        let email = email.clone();
        let account_id = account_id.clone();
        async move {
            let mut form = HashMap::new();
            form.insert("client_id".to_string(), "test-ciba-rp".to_string());
            form.insert("login_hint".to_string(), email);
            form.insert("scope".to_string(), "openid".to_string());
            let body = body_json(
                ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(form)).await,
            )
            .await;
            let auth_req_id = body["auth_req_id"].as_str().unwrap().to_string();
            let (h, jar) = ciba_page_of(&p, &account_id).await;
            let opts = body_json(
                ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone()), h, jar)
                    .await,
            )
            .await;
            assert_eq!(opts["allowCredentials"].as_array().unwrap().len(), 2);
            let challenge = opts["challenge"].as_str().unwrap().to_string();
            let (ad, sig, cdj) =
                make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
            let req: AuthVerifyReq = serde_json::from_value(json!({
                "id": crate::webauthn::b64e(cred),
                "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
            }))
            .unwrap();
            let status = ciba::ciba_approve(State(p.clone()), Path(auth_req_id.clone()), Json(req))
                .await
                .status();
            // 同じ要求の dedup に当たらないよう、次の試しの前に片づける。
            p.ciba
                .transition_if_pending(&auth_req_id, CibaStatus::Denied)
                .await
                .unwrap();
            status
        }
    };
    assert_eq!(
        approve(b"other-credential", other_key).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(approve(b"second-credential", key2).await, StatusCode::OK);
}

/* ===== 本人の passkey の画面（/account） ===== */

async fn session_jar(p: &Arc<Provider>, account_id: &str, auth_time: u64) -> CookieJar {
    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session {
            sid: sid.clone(),
            account_id: account_id.into(),
            auth_time,
        })
        .await
        .unwrap();
    CookieJar::default().add(Cookie::new(SID_COOKIE, sid))
}

/// 応答が張った sid cookie を、次のリクエストの cookie にする。
fn jar_after(resp: &Response) -> CookieJar {
    let set = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("cookie を張る")
        .to_str()
        .unwrap();
    super::assert_host_cookie(set);
    let c = Cookie::parse(set.to_string()).unwrap();
    assert_eq!(c.name(), SID_COOKIE);
    CookieJar::default().add(Cookie::new(SID_COOKIE, c.value().to_string()))
}

/// /account から passkey を 1 本足す。options か verify が断ったら、その応答を返す。
async fn account_add(
    p: &Arc<Provider>,
    jar: &CookieJar,
    cred_id: &[u8],
) -> Result<SigningKey, Response> {
    let opts = account::add_options(State(p.clone()), jar.clone()).await;
    if opts.status() != StatusCode::OK {
        return Err(opts);
    }
    let challenge = body_json(opts).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(&key, cred_id, &challenge, &p.origin(), &p.rp_id());
    let req: account::AddVerifyReq = serde_json::from_value(
        json!({ "response": { "clientDataJSON": cdj, "attestationObject": att } }),
    )
    .unwrap();
    let v = account::add_verify(State(p.clone()), jar.clone(), Json(req)).await;
    if v.status() != StatusCode::CREATED {
        return Err(v);
    }
    Ok(key)
}

/// /account で passkey により本人と確かめる。
async fn account_signin(
    p: &Arc<Provider>,
    jar: &CookieJar,
    cred_id: &[u8],
    key: &SigningKey,
    count: u32,
    account_id: &str,
) -> Response {
    let opts = body_json(account::signin_options(State(p.clone()), jar.clone()).await).await;
    let challenge = opts["challenge"].as_str().unwrap().to_string();
    let (ad, sig, cdj) = make_auth_ceremony(key, count, &challenge, &p.origin(), &p.rp_id(), false);
    let req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": crate::webauthn::b64e(account_id.as_bytes()) },
    }))
    .unwrap();
    account::signin_verify(State(p.clone()), jar.clone(), Json(req)).await
}

async fn delete_via_account(p: &Arc<Provider>, jar: &CookieJar, cred_id: &[u8]) -> Response {
    let req: account::DeleteReq =
        serde_json::from_value(json!({ "id": crate::webauthn::b64e(cred_id) })).unwrap();
    account::delete_passkey(State(p.clone()), jar.clone(), Json(req)).await
}

async fn error_body(r: Response) -> (StatusCode, String) {
    let s = r.status();
    (s, body_text(r).await)
}

/// 登録の直後はログイン済み。そのまま /account で 2 本目を足せ、足した passkey でログインできる。
#[tokio::test]
async fn a_passkey_added_on_the_account_page_signs_in() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;

    let key2 = account_add(&p, &jar, b"added-on-account-page")
        .await
        .unwrap_or_else(|r| panic!("{}", r.status()));
    let (uid, r) =
        email_login_with_credential(&p, &email, b"added-on-account-page", &key2, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        p.store
            .get_interaction(&uid)
            .await
            .unwrap()
            .account_id
            .as_deref(),
        Some(account_id.as_str())
    );

    let fs = p.docs.as_deref().unwrap();
    let audit = fs
        .query_eq("auditLog", "action", "add_passkey")
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);

    // 同じ passkey は 2 度足せない（excludeCredentials に入る）。
    let opts = body_json(account::add_options(State(p.clone()), jar.clone()).await).await;
    assert_eq!(opts["excludeCredentials"].as_array().unwrap().len(), 2);
}

/// 登録の検証が成功すると sid cookie を張る（そのまま /account で足せる）。
#[tokio::test]
async fn registration_signs_the_user_in() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let token = crate::registration::create_email_challenge(fs, &email)
        .await
        .unwrap();
    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": token })).unwrap();
    let opts =
        body_json(register::register_passkey_options(State(p.clone()), Json(opts_req)).await).await;
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(
        &key,
        b"first",
        opts["challenge"].as_str().unwrap(),
        &p.origin(),
        &p.rp_id(),
    );
    let req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": token, "response": { "clientDataJSON": cdj, "attestationObject": att },
    }))
    .unwrap();
    let r =
        register::register_passkey_verify(State(p.clone()), CookieJar::default(), Json(req)).await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let jar = jar_after(&r);
    assert_eq!(body_json(r).await["gpm"], json!(false));
    assert!(account_add(&p, &jar, b"second").await.is_ok());
}

/// ログインしていなければ足せない。本人と確かめてから時間が経っていれば、もう一度確かめるまで足せない。
#[tokio::test]
async fn adding_needs_a_recent_confirmation() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, cred, account_id) = register_test_account(&p, &email).await;

    let (s, b) = error_body(
        account_add(&p, &CookieJar::default(), b"x")
            .await
            .err()
            .unwrap(),
    )
    .await;
    assert_eq!(
        (s, b.as_str()),
        (StatusCode::UNAUTHORIZED, "sign-in required")
    );

    let stale = session_jar(&p, &account_id, now() - 11 * 60).await;
    let (s, b) = error_body(account_add(&p, &stale, b"x").await.err().unwrap()).await;
    assert_eq!(
        (s, b.as_str()),
        (StatusCode::UNAUTHORIZED, "confirmation required")
    );

    // 確かめた後は新しいセッションで足せる。前のセッションは消える。
    let r = account_signin(&p, &stale, &cred, &key, 1, &account_id).await;
    assert_eq!(r.status(), StatusCode::OK);
    let fresh = jar_after(&r);
    let old_sid = stale.get(SID_COOKIE).unwrap().value().to_string();
    assert!(
        p.store.get_session(&old_sid).await.unwrap().is_none(),
        "前のセッションが残った"
    );
    assert!(account_add(&p, &fresh, b"after-confirm").await.is_ok());
}

/// 他人の passkey では本人の確かめにならない（ログインしている人の passkey に絞り、持ち主を確かめる）。
#[tokio::test]
async fn confirmation_with_another_accounts_passkey_fails() {
    let p = test_provider().await;
    let me = format!("me-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, my_id) = register_test_account(&p, &me).await;
    let other = format!("other-{}@example.com", uuid::Uuid::new_v4());
    let fs = p.docs.as_deref().unwrap();
    let other_id = uuid::Uuid::new_v4().to_string();
    let other_key = SigningKey::generate();
    let (x, y) = ec_xy(&other_key);
    let outcome = crate::webauthn::RegOutcome {
        credential_id: crate::webauthn::b64e(b"others"),
        pub_x: crate::webauthn::b64e(&x),
        pub_y: crate::webauthn::b64e(&y),
        sign_count: 0,
        aaguid: String::new(),
    };
    crate::registration::save_credential(fs, &other, &other_id, &outcome)
        .await
        .unwrap();

    let stale = session_jar(&p, &my_id, now() - 11 * 60).await;
    // 他人の passkey の id を名乗り、自分の account_id を userHandle に入れる。
    let r = account_signin(&p, &stale, b"others", &other_key, 1, &my_id).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // 他人の passkey で確かめると、その他人のセッションになる（自分のアカウントに足す権限は得ない）。
    let r = account_signin(&p, &stale, b"others", &other_key, 1, &other_id).await;
    assert_eq!(r.status(), StatusCode::OK);
    let jar = jar_after(&r);
    account_add(&p, &jar, b"added-by-other").await.unwrap();
    let mine = crate::registration::get_account(fs, &me)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::registration::list_credentials(fs, &mine)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// 本人は passkey を消せる。最後の 1 本と、他人の passkey は消せない。
#[tokio::test]
async fn removing_passkeys_on_the_account_page() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key1, cred1, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;
    let key2 = account_add(&p, &jar, b"second")
        .await
        .unwrap_or_else(|r| panic!("{}", r.status()));

    let other = format!("other-{}@example.com", uuid::Uuid::new_v4());
    add_passkey(
        &p,
        &other,
        &uuid::Uuid::new_v4().to_string(),
        b"others-second",
    )
    .await;
    let (s, _) = error_body(delete_via_account(&p, &jar, b"others-second").await).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    assert_eq!(
        delete_via_account(&p, &jar, &cred1).await.status(),
        StatusCode::OK
    );
    let (_, r) = email_login_with_credential(&p, &email, &cred1, &key1, 1, |s| s).await;
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "消した passkey で入れた"
    );
    let (_, r) = email_login_with_credential(&p, &email, b"second", &key2, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);

    let (s, b) = error_body(delete_via_account(&p, &jar, b"second").await).await;
    assert_eq!((s, b.as_str()), (StatusCode::CONFLICT, "last passkey"));

    // 前の版が読む古いフィールドは、残った passkey を指す。
    let fs = p.docs.as_deref().unwrap();
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(
        crate::firestore::field_str(&f, "credentialId"),
        Some(crate::webauthn::b64e(b"second").as_str())
    );
}

/// 登録の challenge では /account に足せず、/account の challenge では登録できない。
#[tokio::test]
async fn signup_and_account_challenges_are_not_interchangeable() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;

    let signup_challenge = crate::registration::create_webauthn_challenge(
        fs,
        &email,
        crate::registration::ChallengeKind::Reg,
        "",
        &account_id,
    )
    .await
    .unwrap();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(
        &key,
        b"via-signup",
        &signup_challenge,
        &p.origin(),
        &p.rp_id(),
    );
    let req: account::AddVerifyReq = serde_json::from_value(
        json!({ "response": { "clientDataJSON": cdj, "attestationObject": att } }),
    )
    .unwrap();
    let (s, b) =
        error_body(account::add_verify(State(p.clone()), jar.clone(), Json(req)).await).await;
    assert_eq!(
        (s, b.as_str()),
        (StatusCode::BAD_REQUEST, "challenge context mismatch")
    );

    let token = crate::registration::create_email_challenge(fs, &email)
        .await
        .unwrap();
    let account_challenge = body_json(account::add_options(State(p.clone()), jar.clone()).await)
        .await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let (att, cdj) = make_reg_ceremony(
        &key,
        b"via-account",
        &account_challenge,
        &p.origin(),
        &p.rp_id(),
    );
    let req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": token, "response": { "clientDataJSON": cdj, "attestationObject": att },
    }))
    .unwrap();
    let r =
        register::register_passkey_verify(State(p.clone()), CookieJar::default(), Json(req)).await;
    assert_ne!(r.status(), StatusCode::CREATED);
}

/// 管理画面の「パスキーだけ削除」: passkey とセッションは消え、アカウントは残り、同じ account_id で登録し直せる。
#[tokio::test]
async fn admin_removes_passkeys_only_and_the_user_registers_again_as_the_same_person() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key1, cred1, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second").await;
    let jar = session_jar(&p, &account_id, now()).await;

    assert_eq!(
        crate::account_admin::delete_passkeys(fs, &*p.store, "acc-admin", &email)
            .await
            .unwrap(),
        Some(2)
    );
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();
    assert!(
        p.store.get_session(&sid).await.unwrap().is_none(),
        "セッションが残った"
    );
    let (_, r) = email_login_with_credential(&p, &email, &cred1, &key1, 1, |s| s).await;
    assert_ne!(r.status(), StatusCode::OK);
    let a = crate::registration::get_account(fs, &email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.account_id, account_id);
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(
        crate::firestore::field_str(&f, "credentialId"),
        Some(""),
        "前の版が読むフィールドも空にする"
    );

    let (_, _, again) = register_test_account(&p, &email).await;
    assert_eq!(again, account_id);
}

/// 同じアカウントの 2 本を同時に消しても、1 本は残る（アカウントの鍵で 1 つずつ通す）。
#[tokio::test]
async fn removing_two_passkeys_at_once_leaves_one() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second").await;
    let (id1, id2) = (
        crate::webauthn::b64e(&cred1),
        crate::webauthn::b64e(b"second"),
    );
    let (a, b) = tokio::join!(
        crate::registration::remove_credential(fs, &email, &id1),
        crate::registration::remove_credential(fs, &email, &id2),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()].map(|o| format!("{o:?}"));
    outcomes.sort();
    assert_eq!(outcomes, ["LastOne", "Removed"]);
    let acct = crate::registration::get_account(fs, &email)
        .await
        .unwrap()
        .unwrap();
    let left = crate::registration::list_credentials(fs, &acct)
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(
        crate::firestore::field_str(&f, "credentialId"),
        Some(left[0].credential_id.as_str()),
        "古いフィールドは残った 1 本を指す"
    );
    assert!(
        fs.get_doc("accountLocks", &email).await.unwrap().is_none(),
        "鍵が残った"
    );
}

/// 落ちた操作が残した鍵は、期限が過ぎていれば外して進む。期限内なら待ってから断る。
#[tokio::test]
async fn a_stale_account_lock_is_taken_over() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let lock = |t: u64| json!({ "expiresAt": crate::firestore::ts(&crate::firestore::rfc3339(t)) });
    fs.set_doc("accountLocks", &email, lock(now() - 1))
        .await
        .unwrap();
    add_passkey(&p, &email, &account_id, b"after-stale-lock").await;

    fs.set_doc("accountLocks", &email, lock(now() + 600))
        .await
        .unwrap();
    let r = crate::registration::remove_credential(
        fs,
        &email,
        &crate::webauthn::b64e(b"after-stale-lock"),
    )
    .await;
    assert_eq!(r.err().as_deref(), Some("account busy"));
}

/// 古いフィールドが一覧に無い passkey を指していたら（向け直しが途中で失敗した）、次の削除で直す。
#[tokio::test]
async fn a_dangling_mirror_is_repaired_on_the_next_removal() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, _) = register_test_account(&p, &email).await;
    fs.update_fields(
        "accounts",
        &email,
        json!({ "credentialId": crate::firestore::s("gone") }),
    )
    .await
    .unwrap();
    let r = crate::registration::remove_credential(fs, &email, "gone")
        .await
        .unwrap();
    assert_eq!(r, crate::registration::RemoveOutcome::NotFound);
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(
        crate::firestore::field_str(&f, "credentialId"),
        Some(crate::webauthn::b64e(&cred1).as_str())
    );
}

/// 確かめた後に管理者が passkey を全部消してセッションを失効させたら、その後に届いた追加は取り消す。
#[tokio::test]
async fn an_add_that_lands_after_the_admin_removed_all_passkeys_is_discarded() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;

    let opts = body_json(account::add_options(State(p.clone()), jar.clone()).await).await;
    crate::account_admin::delete_passkeys(fs, &*p.store, "acc-admin", &email)
        .await
        .unwrap();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(
        &key,
        b"late",
        opts["challenge"].as_str().unwrap(),
        &p.origin(),
        &p.rp_id(),
    );
    let req: account::AddVerifyReq = serde_json::from_value(
        json!({ "response": { "clientDataJSON": cdj, "attestationObject": att } }),
    )
    .unwrap();
    let (s, b) =
        error_body(account::add_verify(State(p.clone()), jar.clone(), Json(req)).await).await;
    assert_eq!(
        (s, b.as_str()),
        (StatusCode::UNAUTHORIZED, "sign-in required")
    );
    assert!(
        !crate::registration::has_passkey(fs, &email).await.unwrap(),
        "失効の後に足した passkey が残った"
    );
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(crate::firestore::field_str(&f, "credentialId"), Some(""));
}

/// account に access token と refresh token を 1 本ずつ発行したことにし、その 2 つを返す。
async fn issue_tokens(p: &Arc<Provider>, account_id: &str) -> (String, String) {
    let (at, rt) = (
        format!("at-{}", uuid::Uuid::new_v4()),
        format!("rt-{}", uuid::Uuid::new_v4()),
    );
    p.store
        .save_access_token(crate::model::AccessToken {
            token: at.clone(),
            client_id: "rp-entry".into(),
            account_id: account_id.into(),
            scope: "openid".into(),
            jkt: None,
            aud: None,
            acr: None,
            auth_time: None,
            authorization_details: None,
            mandate_consumed: false,
        })
        .await
        .unwrap();
    p.store
        .save_refresh_token(crate::model::RefreshToken {
            token: rt.clone(),
            client_id: "rp-entry".into(),
            account_id: account_id.into(),
            scope: "openid".into(),
            resource: None,
            jkt: None,
            acr: None,
            auth_time: None,
            family_id: format!("fam-{}", uuid::Uuid::new_v4()),
            used: false,
            replaced_by: None,
        })
        .await
        .unwrap();
    (at, rt)
}

async fn tokens_alive(p: &Arc<Provider>, (at, rt): &(String, String)) -> (bool, bool) {
    (
        p.store.get_access_token(at).await.unwrap().is_some(),
        p.store.get_refresh_token(rt).await.unwrap().is_some(),
    )
}

/// 本人が passkey を消すと、ほかのセッションとトークンも失効する。いまのセッションは残る。
#[tokio::test]
async fn removing_a_passkey_signs_out_the_other_devices() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, account_id) = register_test_account(&p, &email).await;
    let here = session_jar(&p, &account_id, now()).await;
    let there = session_jar(&p, &account_id, now() - 3600).await;
    account_add(&p, &here, b"second")
        .await
        .unwrap_or_else(|r| panic!("{}", r.status()));
    let mine = issue_tokens(&p, &account_id).await;
    let others = issue_tokens(&p, &uuid::Uuid::new_v4().to_string()).await;

    assert_eq!(
        delete_via_account(&p, &here, &cred1).await.status(),
        StatusCode::OK
    );
    let sid = |j: &CookieJar| j.get(SID_COOKIE).unwrap().value().to_string();
    assert!(p.store.get_session(&sid(&here)).await.unwrap().is_some());
    assert!(
        p.store.get_session(&sid(&there)).await.unwrap().is_none(),
        "ほかの端末のセッションが残った"
    );
    assert_eq!(
        tokens_alive(&p, &mine).await,
        (false, false),
        "access token か refresh token が残った"
    );
    assert_eq!(
        tokens_alive(&p, &others).await,
        (true, true),
        "ほかの account のトークンまで消えた"
    );
}

/// passkey は 10 本まで。
#[tokio::test]
async fn at_most_ten_passkeys() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    for i in 1..10 {
        add_passkey(&p, &email, &account_id, format!("extra-{i}").as_bytes()).await;
    }
    let jar = session_jar(&p, &account_id, now()).await;
    let (s, b) = error_body(account_add(&p, &jar, b"eleventh").await.err().unwrap()).await;
    assert_eq!((s, b.as_str()), (StatusCode::CONFLICT, "too many passkeys"));
}

/// /recover でメールの token を使い、passkey を 1 本足す。options か verify が断ったら、その応答を返す。
async fn recover_add(
    p: &Arc<Provider>,
    token: &str,
    jar: CookieJar,
    cred_id: &[u8],
) -> Result<(SigningKey, Response), Response> {
    let opts_req: recover::RecoverOptionsReq =
        serde_json::from_value(json!({ "token": token })).unwrap();
    let opts = recover::recover_options(State(p.clone()), Json(opts_req)).await;
    if opts.status() != StatusCode::OK {
        return Err(opts);
    }
    let challenge = body_json(opts).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(&key, cred_id, &challenge, &p.origin(), &p.rp_id());
    let req: recover::RecoverVerifyReq = serde_json::from_value(json!({
        "token": token,
        "response": { "clientDataJSON": cdj, "attestationObject": att },
    }))
    .unwrap();
    let v = recover::recover_verify(State(p.clone()), HeaderMap::new(), jar, Json(req)).await;
    if v.status() != StatusCode::CREATED {
        return Err(v);
    }
    Ok((key, v))
}

#[tokio::test]
async fn recovery_adds_a_passkey_keeps_the_others_and_signs_out_everywhere_else() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (old_key, _, account_id) = register_test_account(&p, &email).await;
    let elsewhere = session_jar(&p, &account_id, now()).await;
    let elsewhere_sid = elsewhere.get(SID_COOKIE).unwrap().value().to_string();
    let issued = issue_tokens(&p, &account_id).await;

    let token = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();
    let (new_key, resp) = recover_add(&p, &token, CookieJar::default(), b"recovered-credential")
        .await
        .unwrap();
    let here = jar_after(&resp);

    assert!(
        p.store.get_session(&elsewhere_sid).await.unwrap().is_none(),
        "ほかの端末のセッションが残った"
    );
    assert_eq!(
        tokens_alive(&p, &issued).await,
        (false, false),
        "access token か refresh token が残った"
    );
    let account = crate::registration::get_account(fs, &email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.account_id, account_id, "sub が変わった");
    assert_eq!(
        crate::registration::list_credentials(fs, &account)
            .await
            .unwrap()
            .len(),
        2
    );
    // 前の passkey も、足した passkey も使える。
    assert_eq!(login_with_email(&p, &email, &old_key, 1).await, account_id);
    let (_, r) =
        email_login_with_credential(&p, &email, b"recovered-credential", &new_key, 1, |s| s).await;
    assert!(
        r.status().is_success() || r.status().is_redirection(),
        "足した passkey で入れない: {}",
        r.status()
    );
    // 足した直後は確かめ済みなので、/account で失くした passkey を消せる。
    assert_eq!(
        account::add_options(State(p.clone()), here).await.status(),
        StatusCode::OK
    );
    // token は 1 回きり。
    let again = recover_add(&p, &token, CookieJar::default(), b"recovered-again")
        .await
        .unwrap_err();
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recovery_is_not_offered_to_admins_or_disabled_accounts() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let admin = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, admin_id) = register_test_account(&p, &admin).await;
    crate::admin_store::grant_admin(fs, &admin_id, "test")
        .await
        .unwrap();
    let token = crate::registration::create_recovery_challenge(fs, &admin)
        .await
        .unwrap();
    let r = recover_add(&p, &token, CookieJar::default(), b"admin-recovered")
        .await
        .unwrap_err();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(
        recover::recovery_for(fs, &admin).await.unwrap(),
        recover::Recovery::Refused
    );

    let frozen = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let fid = uuid::Uuid::new_v4().to_string();
    add_passkey(&p, &frozen, &fid, b"frozen-credential").await;
    crate::account_admin::disable_account(fs, &*p.store, "test", &frozen)
        .await
        .unwrap();
    let token = crate::registration::create_recovery_challenge(fs, &frozen)
        .await
        .unwrap();
    let r = recover_add(&p, &token, CookieJar::default(), b"frozen-recovered")
        .await
        .unwrap_err();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn recovery_and_signup_tokens_are_not_interchangeable() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let id = uuid::Uuid::new_v4().to_string();
    add_passkey(&p, &email, &id, b"some-credential").await;
    crate::registration::remove_all_credentials(fs, &email)
        .await
        .unwrap();

    // passkey が 0 本の人に残った復旧の token でも、登録の口は通さない。
    let recovery = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();
    let req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": recovery })).unwrap();
    let r = register::register_passkey_options(State(p.clone()), Json(req)).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let signup = crate::registration::create_email_challenge(fs, &email)
        .await
        .unwrap();
    let r = recover_add(&p, &signup, CookieJar::default(), b"x")
        .await
        .unwrap_err();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signing_up_again_sends_a_recovery_link_only_when_recoverable() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let recovery_tokens = || async {
        fs.list_collection("emailChallenges")
            .await
            .unwrap()
            .into_iter()
            .filter(|(_, f, _)| crate::firestore::field_str(f, "purpose") == Some("recovery"))
            .count()
    };
    let user = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, _) = register_test_account(&p, &user).await;
    register::issue_register_email(&p, fs, &user, "192.0.2.1", None, &Default::default())
        .await
        .unwrap();
    assert_eq!(recovery_tokens().await, 1);

    let admin = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let aid = uuid::Uuid::new_v4().to_string();
    add_passkey(&p, &admin, &aid, b"admin-credential").await;
    crate::admin_store::grant_admin(fs, &aid, "test")
        .await
        .unwrap();
    register::issue_register_email(&p, fs, &admin, "192.0.2.2", None, &Default::default())
        .await
        .unwrap();
    assert_eq!(recovery_tokens().await, 1, "管理者に復旧のリンクを出した");
}

#[tokio::test]
async fn passkeys_from_before_a_recovery_cannot_be_removed_for_a_day() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let token = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();
    let (_, resp) = recover_add(&p, &token, CookieJar::default(), b"recovered-credential")
        .await
        .unwrap();
    let here = jar_after(&resp);

    // メールを奪った人が、本人の passkey を消して締め出すことはできない。
    let (status, body) =
        error_body(delete_via_account(&p, &here, b"probe-credential-id").await).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::CONFLICT, "recently recovered")
    );
    // 足した 1 本は消せる（本人が、覚えの無い 1 本を消す）。
    assert_eq!(
        delete_via_account(&p, &here, b"recovered-credential")
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_failed_recovery_attempt_does_not_use_up_the_link() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let token = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();

    let opts_req: recover::RecoverOptionsReq =
        serde_json::from_value(json!({ "token": token })).unwrap();
    let challenge = body_json(recover::recover_options(State(p.clone()), Json(opts_req)).await)
        .await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let key = SigningKey::generate();
    let (_, cdj) = make_reg_ceremony(&key, b"broken", &challenge, &p.origin(), &p.rp_id());
    let req: recover::RecoverVerifyReq = serde_json::from_value(json!({
        "token": token,
        "response": { "clientDataJSON": cdj, "attestationObject": "AAAA" },
    }))
    .unwrap();
    let r = recover::recover_verify(
        State(p.clone()),
        HeaderMap::new(),
        CookieJar::default(),
        Json(req),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    recover_add(&p, &token, CookieJar::default(), b"recovered-credential")
        .await
        .unwrap();
}

#[tokio::test]
async fn recovery_for_an_account_without_passkeys_points_to_sign_up() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let token = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();
    crate::registration::remove_all_credentials(fs, &email)
        .await
        .unwrap();
    let (status, body) = error_body(
        recover_add(&p, &token, CookieJar::default(), b"x")
            .await
            .unwrap_err(),
    )
    .await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::CONFLICT, "no passkey to recover")
    );
}

#[tokio::test]
async fn the_recovery_page_names_the_account_and_the_request_page_does_not_tell_who_is_registered()
{
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let token = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();
    let page = recover::recover_page(
        State(p.clone()),
        HeaderMap::new(),
        CookieJar::default(),
        Query(serde_json::from_value(json!({ "t": token })).unwrap()),
    )
    .await;
    let html = body_text(page).await;
    assert!(
        html.contains(&email),
        "どのアカウントに足すのかが出ていない"
    );
    assert!(html.contains(&token));

    let mut bodies = vec![];
    for (i, who) in [
        email.clone(),
        format!("nobody-{}@example.com", uuid::Uuid::new_v4()),
    ]
    .iter()
    .enumerate()
    {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            format!("192.0.2.{}", 10 + i).parse().unwrap(),
        );
        let form: recover::RecoverForm = serde_json::from_value(json!({ "email": who })).unwrap();
        let r =
            recover::recover_submit(State(p.clone()), h, CookieJar::default(), Form(form)).await;
        assert_eq!(r.status(), StatusCode::OK);
        bodies.push(body_text(r).await);
    }
    assert_eq!(bodies[0], bodies[1], "登録済みかどうかで画面が変わる");
}

/* ===== メールのリンクの後、元のアプリへ戻す ===== */

/// RP の /authorize から来たログイン画面（このブラウザが始めた interaction）と、そのブラウザの cookie。
async fn sign_in_started_here(p: &Arc<Provider>, client_id: &str) -> (String, CookieJar) {
    let uid = uuid::Uuid::new_v4().to_string();
    let (secret, hash) = super::new_browser_binding();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: format!("response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb"),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: hash,
        })
        .await;
    let jar = CookieJar::default().add(Cookie::new(super::browser_cookie_name(&uid), secret));
    (uid, jar)
}

/// /recover のフォームから送り、届いた復旧の token を返す。
async fn send_recovery_from(p: &Arc<Provider>, email: &str, uid: &str, jar: CookieJar) -> String {
    let fs = p.docs.as_deref().unwrap();
    let mut h = HeaderMap::new();
    h.insert(
        "x-forwarded-for",
        format!("198.51.100.{}", uuid::Uuid::new_v4().as_bytes()[0])
            .parse()
            .unwrap(),
    );
    let form: recover::RecoverForm =
        serde_json::from_value(json!({ "email": email, "uid": uid })).unwrap();
    assert_eq!(
        recover::recover_submit(State(p.clone()), h, jar, Form(form))
            .await
            .status(),
        StatusCode::OK
    );
    fs.list_collection("emailChallenges")
        .await
        .unwrap()
        .into_iter()
        .find(|(_, f, _)| {
            crate::firestore::field_str(f, "purpose") == Some("recovery")
                && crate::firestore::field_str(f, "email") == Some(email)
        })
        .map(|(id, _, _)| id)
        .expect("復旧の token が無い")
}

#[tokio::test]
async fn recovery_from_the_sign_in_screen_continues_that_sign_in_in_the_same_browser() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let (uid, jar) = sign_in_started_here(&p, "rp-entry").await;

    let token = send_recovery_from(&p, &email, &uid, jar.clone()).await;
    let from = crate::registration::came_from(fs, &token).await;
    assert_eq!(
        (from.uid.as_str(), from.client_id.as_str()),
        (uid.as_str(), "rp-entry")
    );

    let (_, resp) = recover_add(&p, &token, jar, b"recovered-here")
        .await
        .unwrap();
    let redirect = body_json(resp).await["redirect"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(redirect, p.path(&format!("/authorize/resume?uid={uid}")));
    let i = p.store.get_interaction(&uid).await.unwrap();
    assert_eq!(
        i.account_id.as_deref(),
        Some(account_id.as_str()),
        "ログインが済んでいない"
    );
}

/// 既にこの端末に passkey があったとき、復旧の画面はその場でログインする。行き先はリンクを開いたブラウザで決まる。
#[tokio::test]
async fn the_recovery_page_signs_in_with_an_existing_passkey_in_place() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let (uid, jar) = sign_in_started_here(&p, "rp-entry").await;
    let token = send_recovery_from(&p, &email, &uid, jar.clone()).await;
    let open = |jar: CookieJar| {
        let p = p.clone();
        let token = token.clone();
        async move {
            let q = Query(serde_json::from_value(json!({ "t": token })).unwrap());
            body_text(recover::recover_page(State(p), HeaderMap::new(), jar, q).await).await
        }
    };

    let same = open(jar).await;
    assert!(
        same.contains(&format!(
            r#"LOGIN_OPT="{}""#,
            p.path(&format!("/login/{uid}/passkey/options"))
        )),
        "{same}"
    );
    assert!(
        same.contains(r#"LOGIN_DONE="""#),
        "元のログインの続きは verify の redirect に任せる"
    );
    assert!(
        !same.contains("<a href"),
        "ログイン画面へのリンクでもう一度押させない"
    );

    let other = open(CookieJar::default()).await;
    assert!(
        other.contains(&format!(
            r#"LOGIN_OPT="{}""#,
            p.path("/account/signin/options")
        )),
        "{other}"
    );
    assert!(
        other.contains(&format!(
            r#"LOGIN_DONE="{}?client_id=rp-entry""#,
            p.path("/account")
        )),
        "{other}"
    );
}

#[tokio::test]
async fn recovery_in_another_browser_offers_the_apps_entry_instead() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let (uid, jar) = sign_in_started_here(&p, "rp-entry").await;

    // 送ったのはログインを始めたブラウザ、リンクを開いたのは別のブラウザ。
    let token = send_recovery_from(&p, &email, &uid, jar).await;
    let (_, resp) = recover_add(&p, &token, CookieJar::default(), b"recovered-elsewhere")
        .await
        .unwrap();
    let here = jar_after(&resp);
    let redirect = body_json(resp).await["redirect"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        redirect,
        format!("{}?recovered=1&client_id=rp-entry", p.path("/account"))
    );
    assert!(
        p.store
            .get_interaction(&uid)
            .await
            .unwrap()
            .account_id
            .is_none(),
        "別のブラウザが元のログインを済ませた"
    );

    let q: account::AccountQuery =
        serde_json::from_value(json!({ "recovered": "1", "client_id": "rp-entry" })).unwrap();
    let html = body_text(
        account::account_page(State(p.clone()), HeaderMap::new(), here.clone(), Query(q)).await,
    )
    .await;
    assert!(
        html.contains(r#"href="https://rp.example.com/auth/login?iss="#),
        "{html}"
    );
    // 入口の無い client、知らない client にはボタンを出さない。
    for other in ["test-ciba-rp", "https://evil.example/"] {
        let q: account::AccountQuery =
            serde_json::from_value(json!({ "client_id": other })).unwrap();
        let html = body_text(
            account::account_page(State(p.clone()), HeaderMap::new(), here.clone(), Query(q)).await,
        )
        .await;
        assert!(!html.contains(r#"class="primary" href"#), "{other}: {html}");
    }
}

#[tokio::test]
async fn a_sign_in_started_in_another_browser_is_not_carried_by_the_email() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    // 他人の uid を持ち込んでも、その interaction を始めたブラウザでなければ token に残らない。
    let (uid, _) = sign_in_started_here(&p, "rp-entry").await;
    let token = send_recovery_from(&p, &email, &uid, CookieJar::default()).await;
    assert_eq!(
        crate::registration::came_from(fs, &token).await,
        Default::default()
    );
}

#[tokio::test]
async fn signing_up_from_the_sign_in_screen_continues_that_sign_in() {
    let p = test_provider().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (uid, jar) = sign_in_started_here(&p, "rp-entry").await;
    let from = super::came_from(&p, &jar, &uid).await;
    let token = crate::registration::create_email_challenge_from(fs, &email, &from)
        .await
        .unwrap();
    assert!(
        crate::registration::peek_invite(fs, &token)
            .await
            .unwrap()
            .is_none(),
        "招待として扱われた"
    );

    let options_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": token })).unwrap();
    let opts =
        body_json(register::register_passkey_options(State(p.clone()), Json(options_req)).await)
            .await;
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(
        &key,
        b"signed-up-here",
        opts["challenge"].as_str().unwrap(),
        &p.origin(),
        &p.rp_id(),
    );
    let req: register::RegVerifyReq = serde_json::from_value(
        json!({ "token": token, "response": { "clientDataJSON": cdj, "attestationObject": att } }),
    )
    .unwrap();
    let resp = register::register_passkey_verify(State(p.clone()), jar, Json(req)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(
        v["redirect"].as_str().unwrap(),
        p.path(&format!("/authorize/resume?uid={uid}"))
    );
    assert_eq!(v["resume"], json!(true));
}

/// 別のアカウントでログイン中のブラウザでメールのリンクを開くと、passkey を作る前に切り替えの確認を出す
/// （攻撃者が自分のアカウントのリンクを踏ませるログイン CSRF。Fable の査読 H4）。
#[tokio::test]
async fn an_email_link_asks_before_switching_a_signed_in_browser_to_another_account() {
    let p = test_provider().await;
    let fs = p.docs.clone().unwrap();
    let me = format!("me-{}@example.com", uuid::Uuid::new_v4());
    // & がエスケープされることを確かめるために入れる
    let other = format!("other&{}@example.com", uuid::Uuid::new_v4());
    let other_html = other.replace('&', "&amp;");
    let (_, _, my_id) = register_test_account(&p, &me).await;
    let open_recovery = |jar: CookieJar, email: String| {
        let p = p.clone();
        let fs = fs.clone();
        async move {
            let t = crate::registration::create_recovery_challenge(&*fs, &email)
                .await
                .unwrap();
            let q = Query(serde_json::from_value(json!({ "t": t })).unwrap());
            body_text(recover::recover_page(State(p), HeaderMap::new(), jar, q).await).await
        }
    };
    let asked = open_recovery(session_jar(&p, &my_id, 0).await, other.clone()).await;
    assert!(
        asked.contains("Switch accounts?") && asked.contains(r#"<div id="main" hidden>"#),
        "{asked}"
    );
    assert!(
        asked.contains(&format!("<strong>{me}</strong>"))
            && asked.contains(&format!("<strong>{other_html}</strong>")),
        "{asked}"
    );
    for (jar, email) in [
        (session_jar(&p, &my_id, 0).await, me.clone()),
        (CookieJar::default(), other.clone()),
    ] {
        let plain = open_recovery(jar, email).await;
        assert!(
            !plain.contains("Switch accounts?") && plain.contains(r#"<div id="main" >"#),
            "{plain}"
        );
    }

    // 宛先に置換の印を書かれても、ほかの置換に展開されない
    let newcomer = format!("__TOKEN__{}@example.com", uuid::Uuid::new_v4());
    let signup = crate::registration::create_email_challenge(&*fs, &newcomer)
        .await
        .unwrap();
    let verify = |jar: CookieJar| {
        let q = Query(serde_json::from_value(json!({ "token": signup.clone() })).unwrap());
        register::verify_form(State(p.clone()), HeaderMap::new(), jar, q)
    };
    let page = body_text(verify(session_jar(&p, &my_id, 0).await).await).await;
    assert!(
        page.contains("Switch accounts?") && page.contains(r#"<div id="main" hidden>"#),
        "{page}"
    );
    assert!(
        page.contains(&format!("<strong>{newcomer}</strong>")),
        "{page}"
    );
    // ログインしていない人には確認を出さないが、誰のパスキーを作るかは見せる
    let page = body_text(verify(CookieJar::default()).await).await;
    assert!(
        !page.contains("Switch accounts?") && page.contains(r#"<div id="main" >"#),
        "{page}"
    );
    assert!(
        page.contains(&format!("<p><strong>{newcomer}</strong></p>")),
        "{page}"
    );

    let q = Query(serde_json::from_value(json!({ "t": signup.clone() })).unwrap());
    let page = body_text(
        register::magic_redirect(
            State(p.clone()),
            HeaderMap::new(),
            session_jar(&p, &my_id, 0).await,
            q,
        )
        .await,
    )
    .await;
    assert!(
        page.contains("Switch accounts?") && page.contains(r#"<div id="main" hidden>"#),
        "/r: {page}"
    );

    let invited = format!("invited-{}@example.com", uuid::Uuid::new_v4());
    let t = crate::registration::create_invite_challenge(
        &*fs,
        &invited,
        "https://rp.example.com/after",
    )
    .await
    .unwrap();
    let q = Query(serde_json::from_value(json!({ "t": t })).unwrap());
    let page = body_text(
        register::invite_page(
            State(p.clone()),
            HeaderMap::new(),
            session_jar(&p, &my_id, 0).await,
            q,
        )
        .await,
    )
    .await;
    assert!(
        page.contains("Switch accounts?") && page.contains(r#"<div id="main" hidden>"#),
        "invite: {page}"
    );
    assert!(
        page.contains(&format!("<strong>{me}</strong>"))
            && page.contains(&format!("<strong>{invited}</strong>")),
        "{page}"
    );
}

#[cfg(feature = "gcp")]
mod firestore_ops;
mod two_instances;

/// session を一時に読めなかったら、確かめの画面を飛ばして RP へ戻しはしない（無いものと扱わない）。
/// 読めないままなら 500 の画面で止め、session も cookie も残す。
#[cfg(feature = "gcp")]
#[tokio::test]
async fn sign_out_does_not_skip_the_confirmation_when_the_session_cannot_be_read() {
    const BYE: &str = "https://rp.example.com/bye";
    let (host, fake) = crate::firestore::fake_firestore::spawn().await;
    let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
    let bye = Client {
        client_id: "rp-bye".into(),
        post_logout_redirect_uris: vec![BYE.into()],
        ..test_provider().await.clients["rp-entry"].clone()
    };
    let p = Arc::new(
        Provider::new("http://localhost:8099".to_string())
            .with_firestore(fs.clone())
            .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(fs)))
            .with_client(bye),
    );
    let jar = session_jar(&p, "acct", now()).await;
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();

    fake.fail_once("GET", "sessions", Some(&sid));
    let r = oidc::end_session(
        State(p.clone()),
        HeaderMap::new(),
        jar,
        Query(
            serde_json::from_value(
                json!({ "client_id": "rp-bye", "post_logout_redirect_uri": BYE }),
            )
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(r.headers().get(header::SET_COOKIE).is_none());
    assert!(p.store.get_session(&sid).await.unwrap().is_some());
}

#[cfg(feature = "gcp")]
async fn passkeys_of(p: &Provider, email: &str) -> usize {
    let fs = p.docs.as_deref().unwrap();
    let a = crate::registration::get_account(fs, email)
        .await
        .unwrap()
        .unwrap();
    crate::registration::list_credentials(fs, &a)
        .await
        .unwrap()
        .len()
}

/// /account で passkey を足した後、失効されていないかを確かめる段で session を読めなければ、足した 1 本を消して
/// 500 を返す（読めないのを「生きている」とは扱わない）。
#[cfg(feature = "gcp")]
#[tokio::test]
async fn a_passkey_added_when_the_session_cannot_be_read_again_is_discarded() {
    let (p, fake) = test_provider_and_fake().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();

    // options と verify の本人の確かめ（2 回）は通し、足した後の確かめで読めなくする。
    fake.fail_after(2, "GET", "sessions", Some(&sid));
    let r = account_add(&p, &jar, b"added")
        .await
        .err()
        .expect("読めないのに足せたと返した");
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(passkeys_of(&p, &email).await, 1, "足した passkey が残った");
}

/// /account の passkey の削除で、ほかの端末の session を消せなければ、passkey は消さずに 500 を返す。
/// もう一度押せば、失効し直してから消す。
#[cfg(feature = "gcp")]
#[tokio::test]
async fn a_passkey_removal_that_could_not_sign_out_the_other_devices_can_be_retried() {
    let (p, fake) = test_provider_and_fake().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second").await;
    let jar = session_jar(&p, &account_id, now()).await;
    let other = session_jar(&p, &account_id, now()).await;
    let other_sid = other.get(SID_COOKIE).unwrap().value().to_string();

    fake.fail_once("DELETE", "sessions", Some(&other_sid));
    let r = delete_via_account(&p, &jar, b"second").await;
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(passkeys_of(&p, &email).await, 2, "失効しきれないまま消した");
    assert!(p.store.get_session(&other_sid).await.unwrap().is_some());

    let r = delete_via_account(&p, &jar, b"second").await;
    assert_eq!(r.status(), StatusCode::OK, "やり直しで収まらない");
    assert_eq!(passkeys_of(&p, &email).await, 1);
    assert!(p.store.get_session(&other_sid).await.unwrap().is_none());
}

/// 回復で、ほかの端末の session を消せなければ、passkey は足したまま「もう一度ログインして」の 500 を返す。
#[cfg(feature = "gcp")]
#[tokio::test]
async fn a_recovery_that_could_not_sign_out_the_other_devices_asks_to_sign_in_again() {
    let (p, fake) = test_provider_and_fake().await;
    let fs = p.docs.as_deref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let elsewhere = session_jar(&p, &account_id, now()).await;
    let elsewhere_sid = elsewhere.get(SID_COOKIE).unwrap().value().to_string();
    let token = crate::registration::create_recovery_challenge(fs, &email)
        .await
        .unwrap();

    fake.fail_once("DELETE", "sessions", Some(&elsewhere_sid));
    let r = recover_add(&p, &token, CookieJar::default(), b"recovered")
        .await
        .err()
        .expect("失効しきれないのに成功と返した");
    let (status, body) = error_body(r).await;
    assert_eq!(
        (status, body.as_str()),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "passkey saved, sign in again"
        )
    );
    assert_eq!(passkeys_of(&p, &email).await, 2);
}
