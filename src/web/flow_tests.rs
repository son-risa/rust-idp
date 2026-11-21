//! 登録→ログイン→CIBA承認を fake Firestore（`firestore::fake_firestore`）に対して流し、account_id(UUID)が
//! 一貫して使われ、email が sub/user.id/CIBA account に漏れないことを検証する。
//! 以前は実 Firestore エミュレータを前提に `#[ignore]` で、CI では走っていなかった。

use std::assert_matches;
use p256::elliptic_curve::Generate;
use super::*;
use crate::ciba::CibaStatus;
use crate::fido::verify::test_support::*;
use crate::fido::verify::{FLAG_AT, FLAG_UP, FLAG_UV};
use crate::model::Client;
use ciborium::value::Value as Cbor;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

async fn test_provider() -> Arc<Provider> {
    let (host, _state) = crate::firestore::fake_firestore::spawn().await;
    let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
    // with_firestore は registration:: の直叩き用、with_store は Store トレイト
    // (interaction/session/find_account 等)用で別物。本番(Cloud Run)は両方 Firestore を指すので
    // テストでもここを MemoryStore の既定のままにしない（find_account が PoC ダミー生成に
    // フォールバックしてしまい、firestore_store.rs の実装を検証できなくなる）。
    let p = Provider::new("http://localhost:8099".to_string())
        .with_firestore(fs.clone())
        .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(fs)))
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
        });
    Arc::new(p)
}

fn make_reg_ceremony(key: &SigningKey, cred_id: &[u8], challenge: &str, origin: &str, rp_id: &str) -> (String, String) {
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
    (crate::webauthn::b64e(&cbor_to_vec(&att)), crate::webauthn::b64e(&cdj))
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

async fn body_json(resp: Response) -> serde_json::Value {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("status={status} body not json: {e} raw={}", String::from_utf8_lossy(&bytes)))
}

async fn body_text(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// email 確認は registration:: を直接叩き、passkey 登録は実 HTTP ハンドラを通す。
/// 戻り値: (SigningKey, credential_id, account_id)。
async fn register_test_account(p: &Arc<Provider>, email: &str) -> (SigningKey, Vec<u8>, String) {
    let fs = p.firestore.as_ref().unwrap();
    let email_token = crate::registration::create_email_challenge(fs, email).await.unwrap();

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
    assert!(!account_id_from_options.contains('@'), "user.id leaks email: {account_id_from_options}");
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
    let verify = register::register_passkey_verify(State(p.clone()), CookieJar::default(), Json(verify_req)).await;
    let verify_status = verify.status();
    let verify_body = body_json(verify).await;
    assert_eq!(verify_status, StatusCode::CREATED, "register_passkey_verify failed: {verify_body:?}");

    let cred = crate::registration::get_account(fs, email).await.unwrap().unwrap();
    assert_eq!(cred.account_id, account_id_from_options, "options 時点の account_id と保存後の accountId が食い違う");

    // 逆引きインデックスも書けている。
    let looked_up = crate::registration::find_email_by_account_id(fs, &cred.account_id).await.unwrap();
    assert_eq!(looked_up.as_deref(), Some(email), "accountsByUuid の逆引きが email と一致しない");

    (key, cred_id, cred.account_id)
}

/// ログイン成功後の Interaction.account_id（= 最終的に発行される sub）を返す。
async fn login_with_email(p: &Arc<Provider>, email: &str, key: &SigningKey, sign_count: u32) -> String {
    let (uid, verify) = email_login_response(p, email, key, sign_count).await;
    let status = verify.status();
    let body = body_json(verify).await;
    assert_eq!(status, StatusCode::OK, "login (email) failed: {body:?}");

    // finalize_login は Interaction を削除せず account_id を書いて保存し直す
    // （/authorize/resume がこれを読んでコード発行に進むため）。
    let interaction = p.store.get_interaction(&uid).await.expect("interaction should still exist after login");
    interaction.account_id.expect("account_id should be set after successful login")
}

async fn email_login_response(p: &Arc<Provider>, email: &str, key: &SigningKey, sign_count: u32) -> (String, Response) {
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
            browser_binding: String::new(),
        })
        .await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({ "email": email })).unwrap();
    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(key, sign_count, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": tamper(sig), "userHandle": null },
    }))
    .unwrap();
    let verify =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req))
            .await;
    (uid, verify)
}

async fn login_discoverable(p: &Arc<Provider>, account_id: &str, key: &SigningKey, sign_count: u32) {
    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: String::new(),
        })
        .await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({})).unwrap();
    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(key, sign_count, &challenge, &p.origin(), &p.rp_id(), false);
    // userHandle = account_id(UUID)。email は一切登場しない。
    let user_handle_b64 = crate::webauthn::b64e(account_id.as_bytes());
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": user_handle_b64 },
    }))
    .unwrap();
    let verify =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req))
            .await;
    let status = verify.status();
    let body = body_json(verify).await;
    assert_eq!(status, StatusCode::OK, "login (discoverable) failed: {body:?}");

    let interaction = p.store.get_interaction(&uid).await.expect("interaction should still exist after login");
    assert_eq!(
        interaction.account_id.as_deref(),
        Some(account_id),
        "discoverable ログインの最終 sub が userHandle の account_id と一致しない"
    );
}

/// DCR登録エンドポイント(oidc::register)が ConfidentialSecret プロファイルの IAT を
/// 正しく処理し、生成した client_secret をレスポンスへ一度だけ平文で載せつつ、
/// Firestore にはハッシュのみを保存することを実HTTPハンドラ経由で検証する。
/// dcr.rs の単体テストは validate_registration の戻り値を直接見るのみで、
/// raw_client_secret が register() ハンドラ経由で実際に配線されているかは見ていなかった。
#[tokio::test]
async fn register_confidential_secret_returns_raw_secret_once() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();

    let constraints = crate::dcr::IatConstraints {
        allowed_redirect_hosts: vec!["rp.example.com".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        profile: crate::dcr::ClientProfile::ConfidentialSecret,
    };
    let (raw_iat, iat_hash) = crate::dcr::gen_random_token();
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
    crate::dcr_store::put_iat(fs, &iat_hash, &constraints, expires_at, false).await.unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, format!("Bearer {raw_iat}").parse().unwrap());
    let body = json!({ "redirect_uris": ["https://rp.example.com/cb"] }).to_string();

    let resp = oidc::register(State(p.clone()), headers, body).await;
    let status = resp.status();
    let resp_body = body_json(resp).await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {resp_body:?}");
    assert_eq!(resp_body["token_endpoint_auth_method"], "client_secret_basic");
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

/// account_admin::disable_account で凍結したアカウントが、実HTTPハンドラ(login_passkey_verify)
/// 経由でログインを拒否されることを検証する。login.rs 側の disabled チェックの配線確認。
#[tokio::test]
async fn disabled_account_cannot_login() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, _account_id) = register_test_account(&p, &email).await;

    let fs = p.firestore.as_ref().unwrap();
    let out = crate::account_admin::disable_account(fs, "test", &email).await.unwrap();
    assert_matches!(out, crate::account_admin::DisableOutcome::Disabled { .. });

    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: String::new(),
        })
        .await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({ "email": email })).unwrap();
    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK, "options自体は通す(disabled状態を先出ししない)");
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(&key, 0, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let verify =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req))
            .await;
    assert_eq!(verify.status(), StatusCode::FORBIDDEN, "disabled account should be rejected");
}

/// 管理UI経由でIATをmint→一度だけ表示→再訪問で「表示済み」になる一連の流れを実HTTPハンドラ
/// 経由で検証する。「一度きり表示」は read-then-delete の順序を間違えやすく、実装ミスに
/// 気付きにくいため、web/admin.rs のユニットテストとは別にここで通しで確認する。
#[tokio::test]
async fn admin_mint_iat_flash_is_shown_once() {
    let p = test_provider().await;
    let email = format!("admin-{}@example.com", uuid::Uuid::new_v4());
    let (_key, _cred_id, account_id) = register_test_account(&p, &email).await;
    let fs = p.firestore.as_ref().unwrap();
    crate::admin_store::grant_admin(fs, &account_id, "test").await.unwrap();

    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session { sid: sid.clone(), account_id: account_id.clone(), auth_time: 0 })
        .await;
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
    assert!(first_body.contains("IATを発行しました"), "1回目は生トークンを表示すること: {first_body}");

    let second = admin::iat_show_once(
        State(p.clone()),
        ja,
        jar.clone(),
        Path(flash_id),
    )
    .await;
    let second_body = body_text(second).await;
    assert!(second_body.contains("表示済みです"), "2回目は「表示済み」になること: {second_body}");
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
    assert_eq!(account.claims.get("email").and_then(|v| v.as_str()), Some(email.as_str()));
    assert_eq!(account.claims.get("email_verified").and_then(|v| v.as_bool()), Some(true));

    // 未知の account_id では email claim が付かない（逆引き失敗を静かに許容し、値をでっち上げない）。
    let unknown = p.store.find_account("00000000-0000-0000-0000-000000000000").await;
    assert!(!unknown.claims.contains_key("email"));
}

#[tokio::test]
async fn reregistration_reuses_existing_account_id() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_key1, _cred1, account_id1) = register_test_account(&p, &email).await;

    // 管理者が passkey だけを消した後に、同じ email で作り直す。account_id は変わってはならない
    // （変わると、過去に発行済みの sub を持つ他システムとの紐付けが切れる）。
    let fs = p.firestore.as_ref().unwrap();
    crate::registration::remove_all_credentials(fs, &email).await.unwrap();
    let email_token = crate::registration::create_email_challenge(fs, &email).await.unwrap();
    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": email_token })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    let opts_json = body_json(opts).await;
    let user_id_b64 = opts_json["user"]["id"].as_str().unwrap().to_string();
    let account_id2 = String::from_utf8(crate::es256::b64url_decode(&user_id_b64).unwrap()).unwrap();

    assert_eq!(account_id1, account_id2, "再登録で account_id が変わってしまっている");
}

#[tokio::test]
async fn leftover_signup_token_is_refused_once_registered() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let fs = p.firestore.as_ref().unwrap();
    // 確認のメールを 2 通出し、1 通目で登録した後に残りの 1 通を使う。
    let leftover = crate::registration::create_email_challenge(fs, &email).await.unwrap();
    register_test_account(&p, &email).await;

    let opts_req: register::RegPkOptionsReq = serde_json::from_value(json!({ "token": leftover })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::CONFLICT);

    let ver_req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": leftover,
        "response": { "clientDataJSON": "", "attestationObject": "" },
    }))
    .unwrap();
    let ver = register::register_passkey_verify(State(p.clone()), CookieJar::new(), Json(ver_req)).await;
    assert_eq!(ver.status(), StatusCode::CONFLICT);
    let account = crate::registration::get_account(fs, &email).await.unwrap().unwrap();
    assert_eq!(crate::registration::list_credentials(fs, &account).await.unwrap().len(), 1);
}

#[tokio::test]
async fn sign_count_update_preserves_account_id() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, account_id) = register_test_account(&p, &email).await;

    // 複数回ログインして signCount を書く経路を通す。
    login_with_email(&p, &email, &key, 1).await;
    login_with_email(&p, &email, &key, 2).await;

    let fs = p.firestore.as_ref().unwrap();
    let account = crate::registration::get_account(fs, &email).await.unwrap().unwrap();
    assert_eq!(account.account_id, account_id, "signCount 更新のたびに accountId が消えていないこと");
    let cred = crate::registration::sole_credential(fs, &email).await.unwrap();
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
    assert_eq!(stored.account, account_id, "CIBA 要求の account に email が残っている");
    assert_ne!(stored.account, email);

    // 承認オプション → 承認（UV 必須）。
    let opts = ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone())).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
    let approve_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(&cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let approve = ciba::ciba_approve(State(p.clone()), Path(auth_req_id.clone()), Json(approve_req)).await;
    let approve_status = approve.status();
    let approve_body = body_json(approve).await;
    assert_eq!(approve_status, StatusCode::OK, "ciba_approve failed: {approve_body:?}");

    let approved = p.ciba.get(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(approved.status, CibaStatus::Approved);
    assert_eq!(approved.account, account_id);
}

/// 凍結したアカウントは、正しい passkey を持っていても CIBA を承認できない（ciba_approve の disabled 検査の配線）。
#[tokio::test]
async fn disabled_account_cannot_approve_ciba() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, cred_id, _account_id) = register_test_account(&p, &email).await;

    let mut form = HashMap::new();
    form.insert("client_id".to_string(), "test-ciba-rp".to_string());
    form.insert("login_hint".to_string(), email.clone());
    form.insert("scope".to_string(), "openid".to_string());
    let body = body_json(ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(form)).await).await;
    let auth_req_id = body["auth_req_id"].as_str().unwrap().to_string();

    let fs = p.firestore.as_ref().unwrap();
    crate::account_admin::disable_account(fs, "test", &email).await.unwrap();

    let opts = body_json(ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone())).await).await;
    let challenge = opts["challenge"].as_str().unwrap().to_string();
    let (ad, sig, cdj) = make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
    let approve_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(&cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let approve = ciba::ciba_approve(State(p.clone()), Path(auth_req_id.clone()), Json(approve_req)).await;
    assert_eq!(approve.status(), StatusCode::FORBIDDEN);
    assert_eq!(p.ciba.get(&auth_req_id).await.unwrap().unwrap().status, CibaStatus::Pending);
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
    let cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
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
            browser_binding: String::new(),
        })
        .await;
    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({})).unwrap();
    let opts = body_json(login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await).await;
    let challenge = opts["challenge"].as_str().unwrap().to_string();
    let (ad, sig, cdj) = make_auth_ceremony(&attacker, 0, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": {
            "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig,
            "userHandle": crate::webauthn::b64e(victim_id.as_bytes()),
        },
    }))
    .unwrap();
    let by_handle =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req)).await;
    assert_eq!(by_handle.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(p.store.get_interaction(&uid).await.unwrap().account_id, None);

    let fs = p.firestore.as_ref().unwrap();
    crate::account_admin::disable_account(fs, "test", &victim).await.unwrap();
    let (_uid, frozen) = email_login_response(&p, &victim, &attacker, 0).await;
    assert_eq!(frozen.status(), StatusCode::UNAUTHORIZED, "署名が通らないうちは凍結を明かさない");
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
    assert_eq!(p.store.get_interaction(&uid).await.unwrap().account_id, None);
}

/// 2 本目の passkey を、登録の検証を通さずに直に足す。
async fn add_passkey(p: &Arc<Provider>, email: &str, account_id: &str, cred_id: &[u8]) -> SigningKey {
    let key = SigningKey::generate();
    let (x, y) = ec_xy(&key);
    let outcome = crate::webauthn::RegOutcome {
        credential_id: crate::webauthn::b64e(cred_id),
        pub_x: crate::webauthn::b64e(&x),
        pub_y: crate::webauthn::b64e(&y),
        sign_count: 0,
        aaguid: String::new(),
    };
    crate::registration::save_credential(p.firestore.as_ref().unwrap(), email, account_id, &outcome).await.unwrap();
    key
}

#[tokio::test]
async fn either_of_two_passkeys_signs_in_as_the_same_account() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key1, cred1, account_id) = register_test_account(&p, &email).await;
    let key2 = add_passkey(&p, &email, &account_id, b"second-credential").await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({ "email": email })).unwrap();
    let opts = body_json(login::login_passkey_options(State(p.clone()), Path("u".into()), Json(opts_req)).await).await;
    let mut allowed: Vec<String> = opts["allowCredentials"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect();
    let mut want = vec![crate::webauthn::b64e(&cred1), crate::webauthn::b64e(b"second-credential")];
    allowed.sort();
    want.sort();
    assert_eq!(allowed, want);

    let (_, r) = email_login_with_credential(&p, &email, &cred1, &key1, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);
    let (uid, r) = email_login_with_credential(&p, &email, b"second-credential", &key2, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(p.store.get_interaction(&uid).await.unwrap().account_id.as_deref(), Some(account_id.as_str()));

    // 名乗った passkey と違う鍵の署名は通らない。
    let (_, r) = email_login_with_credential(&p, &email, b"second-credential", &key1, 2, |s| s).await;
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
    let fs = p.firestore.as_ref().unwrap();
    let my_id = uuid::Uuid::new_v4().to_string();
    let outcome = crate::webauthn::RegOutcome { credential_id: "mine".into(), pub_x: "x".into(), pub_y: "y".into(), sign_count: 0, aaguid: String::new() };
    crate::registration::save_credential(fs, &me, &my_id, &outcome).await.unwrap();

    // 自分の email で options を取り、相手の passkey で答える。
    let (_, r) = email_login_with_credential(&p, &me, b"victim-second", &victim_key, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_an_account_removes_its_passkeys() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second-credential").await;
    let fs = p.firestore.as_ref().unwrap();
    crate::account_admin::disable_account(fs, "cli", &email).await.unwrap();
    crate::account_admin::delete_account(fs, "cli", &email).await.unwrap();
    for id in [crate::webauthn::b64e(&cred1), crate::webauthn::b64e(b"second-credential")] {
        assert!(fs.get_doc("credentials", &id).await.unwrap().is_none(), "{id} が残った");
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
        async move {
            let mut form = HashMap::new();
            form.insert("client_id".to_string(), "test-ciba-rp".to_string());
            form.insert("login_hint".to_string(), email);
            form.insert("scope".to_string(), "openid".to_string());
            let body = body_json(ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(form)).await).await;
            let auth_req_id = body["auth_req_id"].as_str().unwrap().to_string();
            let opts = body_json(ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone())).await).await;
            assert_eq!(opts["allowCredentials"].as_array().unwrap().len(), 2);
            let challenge = opts["challenge"].as_str().unwrap().to_string();
            let (ad, sig, cdj) = make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
            let req: AuthVerifyReq = serde_json::from_value(json!({
                "id": crate::webauthn::b64e(cred),
                "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
            }))
            .unwrap();
            let status = ciba::ciba_approve(State(p.clone()), Path(auth_req_id.clone()), Json(req)).await.status();
            // 同じ要求の dedup に当たらないよう、次の試しの前に片づける。
            p.ciba.transition_if_pending(&auth_req_id, CibaStatus::Denied).await.unwrap();
            status
        }
    };
    assert_eq!(approve(b"other-credential", other_key).await, StatusCode::BAD_REQUEST);
    assert_eq!(approve(b"second-credential", key2).await, StatusCode::OK);
}

/* ===== 本人の passkey の画面（/account） ===== */

async fn session_jar(p: &Arc<Provider>, account_id: &str, auth_time: u64) -> CookieJar {
    let sid = uuid::Uuid::new_v4().to_string();
    p.store.save_session(Session { sid: sid.clone(), account_id: account_id.into(), auth_time }).await;
    CookieJar::default().add(Cookie::new(SID_COOKIE, sid))
}

/// 応答が張った sid cookie を、次のリクエストの cookie にする。
fn jar_after(resp: &Response) -> CookieJar {
    let set = resp.headers().get(header::SET_COOKIE).expect("cookie を張る").to_str().unwrap();
    let c = Cookie::parse(set.to_string()).unwrap();
    assert_eq!(c.name(), SID_COOKIE);
    CookieJar::default().add(Cookie::new(SID_COOKIE, c.value().to_string()))
}

/// /account から passkey を 1 本足す。options か verify が断ったら、その応答を返す。
async fn account_add(p: &Arc<Provider>, jar: &CookieJar, cred_id: &[u8]) -> Result<SigningKey, Response> {
    let opts = account::add_options(State(p.clone()), jar.clone()).await;
    if opts.status() != StatusCode::OK {
        return Err(opts);
    }
    let challenge = body_json(opts).await["challenge"].as_str().unwrap().to_string();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(&key, cred_id, &challenge, &p.origin(), &p.rp_id());
    let req: account::AddVerifyReq =
        serde_json::from_value(json!({ "response": { "clientDataJSON": cdj, "attestationObject": att } })).unwrap();
    let v = account::add_verify(State(p.clone()), jar.clone(), Json(req)).await;
    if v.status() != StatusCode::CREATED {
        return Err(v);
    }
    Ok(key)
}

/// /account で passkey により本人と確かめる。
async fn account_signin(p: &Arc<Provider>, jar: &CookieJar, cred_id: &[u8], key: &SigningKey, count: u32, account_id: &str) -> Response {
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
    let req: account::DeleteReq = serde_json::from_value(json!({ "id": crate::webauthn::b64e(cred_id) })).unwrap();
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

    let key2 = account_add(&p, &jar, b"added-on-account-page").await.unwrap_or_else(|r| panic!("{}", r.status()));
    let (uid, r) = email_login_with_credential(&p, &email, b"added-on-account-page", &key2, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(p.store.get_interaction(&uid).await.unwrap().account_id.as_deref(), Some(account_id.as_str()));

    let fs = p.firestore.as_ref().unwrap();
    let audit = fs.query_eq("auditLog", "action", "add_passkey").await.unwrap();
    assert_eq!(audit.len(), 1);

    // 同じ passkey は 2 度足せない（excludeCredentials に入る）。
    let opts = body_json(account::add_options(State(p.clone()), jar.clone()).await).await;
    assert_eq!(opts["excludeCredentials"].as_array().unwrap().len(), 2);
}

/// 登録の検証が成功すると sid cookie を張る（そのまま /account で足せる）。
#[tokio::test]
async fn registration_signs_the_user_in() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let token = crate::registration::create_email_challenge(fs, &email).await.unwrap();
    let opts_req: register::RegPkOptionsReq = serde_json::from_value(json!({ "token": token })).unwrap();
    let opts = body_json(register::register_passkey_options(State(p.clone()), Json(opts_req)).await).await;
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(&key, b"first", opts["challenge"].as_str().unwrap(), &p.origin(), &p.rp_id());
    let req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": token, "response": { "clientDataJSON": cdj, "attestationObject": att },
    }))
    .unwrap();
    let r = register::register_passkey_verify(State(p.clone()), CookieJar::default(), Json(req)).await;
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

    let (s, b) = error_body(account_add(&p, &CookieJar::default(), b"x").await.err().unwrap()).await;
    assert_eq!((s, b.as_str()), (StatusCode::UNAUTHORIZED, "sign-in required"));

    let stale = session_jar(&p, &account_id, now() - 11 * 60).await;
    let (s, b) = error_body(account_add(&p, &stale, b"x").await.err().unwrap()).await;
    assert_eq!((s, b.as_str()), (StatusCode::UNAUTHORIZED, "confirmation required"));

    // 確かめた後は新しいセッションで足せる。前のセッションは消える。
    let r = account_signin(&p, &stale, &cred, &key, 1, &account_id).await;
    assert_eq!(r.status(), StatusCode::OK);
    let fresh = jar_after(&r);
    let old_sid = stale.get(SID_COOKIE).unwrap().value().to_string();
    assert!(p.store.get_session(&old_sid).await.is_none(), "前のセッションが残った");
    assert!(account_add(&p, &fresh, b"after-confirm").await.is_ok());
}

/// 他人の passkey では本人の確かめにならない（ログインしている人の passkey に絞り、持ち主を確かめる）。
#[tokio::test]
async fn confirmation_with_another_accounts_passkey_fails() {
    let p = test_provider().await;
    let me = format!("me-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, my_id) = register_test_account(&p, &me).await;
    let other = format!("other-{}@example.com", uuid::Uuid::new_v4());
    let fs = p.firestore.as_ref().unwrap();
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
    crate::registration::save_credential(fs, &other, &other_id, &outcome).await.unwrap();

    let stale = session_jar(&p, &my_id, now() - 11 * 60).await;
    // 他人の passkey の id を名乗り、自分の account_id を userHandle に入れる。
    let r = account_signin(&p, &stale, b"others", &other_key, 1, &my_id).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // 他人の passkey で確かめると、その他人のセッションになる（自分のアカウントに足す権限は得ない）。
    let r = account_signin(&p, &stale, b"others", &other_key, 1, &other_id).await;
    assert_eq!(r.status(), StatusCode::OK);
    let jar = jar_after(&r);
    account_add(&p, &jar, b"added-by-other").await.unwrap();
    let mine = crate::registration::get_account(fs, &me).await.unwrap().unwrap();
    assert_eq!(crate::registration::list_credentials(fs, &mine).await.unwrap().len(), 1);
}

/// 本人は passkey を消せる。最後の 1 本と、他人の passkey は消せない。
#[tokio::test]
async fn removing_passkeys_on_the_account_page() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key1, cred1, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;
    let key2 = account_add(&p, &jar, b"second").await.unwrap_or_else(|r| panic!("{}", r.status()));

    let other = format!("other-{}@example.com", uuid::Uuid::new_v4());
    add_passkey(&p, &other, &uuid::Uuid::new_v4().to_string(), b"others-second").await;
    let (s, _) = error_body(delete_via_account(&p, &jar, b"others-second").await).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    assert_eq!(delete_via_account(&p, &jar, &cred1).await.status(), StatusCode::OK);
    let (_, r) = email_login_with_credential(&p, &email, &cred1, &key1, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "消した passkey で入れた");
    let (_, r) = email_login_with_credential(&p, &email, b"second", &key2, 1, |s| s).await;
    assert_eq!(r.status(), StatusCode::OK);

    let (s, b) = error_body(delete_via_account(&p, &jar, b"second").await).await;
    assert_eq!((s, b.as_str()), (StatusCode::CONFLICT, "last passkey"));

    // 前の版が読む古いフィールドは、残った passkey を指す。
    let fs = p.firestore.as_ref().unwrap();
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(crate::firestore::field_str(&f, "credentialId"), Some(crate::webauthn::b64e(b"second").as_str()));
}

/// 登録の challenge では /account に足せず、/account の challenge では登録できない。
#[tokio::test]
async fn signup_and_account_challenges_are_not_interchangeable() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;

    let signup_challenge =
        crate::registration::create_webauthn_challenge(fs, &email, crate::registration::ChallengeKind::Reg, "", &account_id).await.unwrap();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(&key, b"via-signup", &signup_challenge, &p.origin(), &p.rp_id());
    let req: account::AddVerifyReq =
        serde_json::from_value(json!({ "response": { "clientDataJSON": cdj, "attestationObject": att } })).unwrap();
    let (s, b) = error_body(account::add_verify(State(p.clone()), jar.clone(), Json(req)).await).await;
    assert_eq!((s, b.as_str()), (StatusCode::BAD_REQUEST, "challenge context mismatch"));

    let token = crate::registration::create_email_challenge(fs, &email).await.unwrap();
    let account_challenge = body_json(account::add_options(State(p.clone()), jar.clone()).await).await["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let (att, cdj) = make_reg_ceremony(&key, b"via-account", &account_challenge, &p.origin(), &p.rp_id());
    let req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": token, "response": { "clientDataJSON": cdj, "attestationObject": att },
    }))
    .unwrap();
    let r = register::register_passkey_verify(State(p.clone()), CookieJar::default(), Json(req)).await;
    assert_ne!(r.status(), StatusCode::CREATED);
}

/// 管理画面の「パスキーだけ削除」: passkey とセッションは消え、アカウントは残り、同じ account_id で登録し直せる。
#[tokio::test]
async fn admin_removes_passkeys_only_and_the_user_registers_again_as_the_same_person() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key1, cred1, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second").await;
    let jar = session_jar(&p, &account_id, now()).await;

    assert_eq!(crate::account_admin::delete_passkeys(fs, "acc-admin", &email).await.unwrap(), Some(2));
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();
    assert!(p.store.get_session(&sid).await.is_none(), "セッションが残った");
    let (_, r) = email_login_with_credential(&p, &email, &cred1, &key1, 1, |s| s).await;
    assert_ne!(r.status(), StatusCode::OK);
    let a = crate::registration::get_account(fs, &email).await.unwrap().unwrap();
    assert_eq!(a.account_id, account_id);
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(crate::firestore::field_str(&f, "credentialId"), Some(""), "前の版が読むフィールドも空にする");

    let (_, _, again) = register_test_account(&p, &email).await;
    assert_eq!(again, account_id);
}

/// 同じアカウントの 2 本を同時に消しても、1 本は残る（アカウントの鍵で 1 つずつ通す）。
#[tokio::test]
async fn removing_two_passkeys_at_once_leaves_one() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, account_id) = register_test_account(&p, &email).await;
    add_passkey(&p, &email, &account_id, b"second").await;
    let (id1, id2) = (crate::webauthn::b64e(&cred1), crate::webauthn::b64e(b"second"));
    let (a, b) = tokio::join!(
        crate::registration::remove_credential(fs, &email, &id1),
        crate::registration::remove_credential(fs, &email, &id2),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()].map(|o| format!("{o:?}"));
    outcomes.sort();
    assert_eq!(outcomes, ["LastOne", "Removed"]);
    let acct = crate::registration::get_account(fs, &email).await.unwrap().unwrap();
    let left = crate::registration::list_credentials(fs, &acct).await.unwrap();
    assert_eq!(left.len(), 1);
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(crate::firestore::field_str(&f, "credentialId"), Some(left[0].credential_id.as_str()), "古いフィールドは残った 1 本を指す");
    assert!(fs.get_doc("accountLocks", &email).await.unwrap().is_none(), "鍵が残った");
}

/// 落ちた操作が残した鍵は、期限が過ぎていれば外して進む。期限内なら待ってから断る。
#[tokio::test]
async fn a_stale_account_lock_is_taken_over() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let lock = |t: u64| json!({ "expiresAt": crate::firestore::ts(&crate::firestore::rfc3339(t)) });
    fs.set_doc("accountLocks", &email, lock(now() - 1)).await.unwrap();
    add_passkey(&p, &email, &account_id, b"after-stale-lock").await;

    fs.set_doc("accountLocks", &email, lock(now() + 600)).await.unwrap();
    let r = crate::registration::remove_credential(fs, &email, &crate::webauthn::b64e(b"after-stale-lock")).await;
    assert_eq!(r.err().as_deref(), Some("account busy"));
}

/// 古いフィールドが一覧に無い passkey を指していたら（向け直しが途中で失敗した）、次の削除で直す。
#[tokio::test]
async fn a_dangling_mirror_is_repaired_on_the_next_removal() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, _) = register_test_account(&p, &email).await;
    fs.update_fields("accounts", &email, json!({ "credentialId": crate::firestore::s("gone") })).await.unwrap();
    let r = crate::registration::remove_credential(fs, &email, "gone").await.unwrap();
    assert_eq!(r, crate::registration::RemoveOutcome::NotFound);
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(crate::firestore::field_str(&f, "credentialId"), Some(crate::webauthn::b64e(&cred1).as_str()));
}

/// 確かめた後に管理者が passkey を全部消してセッションを失効させたら、その後に届いた追加は取り消す。
#[tokio::test]
async fn an_add_that_lands_after_the_admin_removed_all_passkeys_is_discarded() {
    let p = test_provider().await;
    let fs = p.firestore.as_ref().unwrap();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let jar = session_jar(&p, &account_id, now()).await;

    let opts = body_json(account::add_options(State(p.clone()), jar.clone()).await).await;
    crate::account_admin::delete_passkeys(fs, "acc-admin", &email).await.unwrap();
    let key = SigningKey::generate();
    let (att, cdj) = make_reg_ceremony(&key, b"late", opts["challenge"].as_str().unwrap(), &p.origin(), &p.rp_id());
    let req: account::AddVerifyReq =
        serde_json::from_value(json!({ "response": { "clientDataJSON": cdj, "attestationObject": att } })).unwrap();
    let (s, b) = error_body(account::add_verify(State(p.clone()), jar.clone(), Json(req)).await).await;
    assert_eq!((s, b.as_str()), (StatusCode::UNAUTHORIZED, "sign-in required"));
    assert!(!crate::registration::has_passkey(fs, &email).await.unwrap(), "失効の後に足した passkey が残った");
    let f = fs.get_doc("accounts", &email).await.unwrap().unwrap();
    assert_eq!(crate::firestore::field_str(&f, "credentialId"), Some(""));
}

/// 本人が passkey を消すと、ほかのセッションとトークンも失効する。いまのセッションは残る。
#[tokio::test]
async fn removing_a_passkey_signs_out_the_other_devices() {
    let p = test_provider().await;
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, cred1, account_id) = register_test_account(&p, &email).await;
    let here = session_jar(&p, &account_id, now()).await;
    let there = session_jar(&p, &account_id, now() - 3600).await;
    account_add(&p, &here, b"second").await.unwrap_or_else(|r| panic!("{}", r.status()));

    assert_eq!(delete_via_account(&p, &here, &cred1).await.status(), StatusCode::OK);
    let sid = |j: &CookieJar| j.get(SID_COOKIE).unwrap().value().to_string();
    assert!(p.store.get_session(&sid(&here)).await.is_some());
    assert!(p.store.get_session(&sid(&there)).await.is_none(), "ほかの端末のセッションが残った");
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
