//! 同じ保存先を共有する台（Cloud Run の instance）を 1 つの process の中に 2 つ以上作り、台をまたいでも
//! 回数の上限・一度きり・失効・途中の状態が崩れないことを確かめる。
//!
//! 保存先は gcp 付きなら fake Firestore（台ごとに別の client で同じ server を見る）、sqlite 付きなら同じ file の
//! SQLite、どちらも無ければ Arc で共有した MemoryDocumentStore・MemoryStore・MemoryCibaStore。
//! 署名鍵は、本番（KMS・Secret Manager）と同じく全ての台で同じものを使う。

use super::*;
#[cfg(not(any(feature = "gcp", feature = "sqlite")))]
use crate::ciba::CibaStore;
use crate::grants::{AuthorizationCodeGrant, CibaGrant, GrantHandler, RefreshTokenGrant};
use crate::jws::JwsSigner;
#[cfg(not(any(feature = "gcp", feature = "sqlite")))]
use crate::store::Store;

const CLIENT: &str = "multi-rp";
const CB: &str = "https://rp.example.com/cb";

struct Cluster {
    signer: Arc<dyn JwsSigner>,
    #[cfg(feature = "gcp")]
    host: String,
    #[cfg(all(feature = "sqlite", not(feature = "gcp")))]
    dir: tempfile::TempDir,
    #[cfg(not(feature = "gcp"))]
    docs: Arc<dyn crate::document_store::DocumentStore>,
    #[cfg(not(any(feature = "gcp", feature = "sqlite")))]
    store: Arc<dyn Store>,
    #[cfg(not(any(feature = "gcp", feature = "sqlite")))]
    ciba: Arc<dyn CibaStore>,
}

impl Cluster {
    #[cfg(feature = "gcp")]
    async fn new() -> Self {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        Self {
            signer: Arc::new(crate::jws::Es256Signer::generate()),
            host,
        }
    }

    #[cfg(all(feature = "sqlite", not(feature = "gcp")))]
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let docs = Arc::new(
            crate::sqlite::SqliteDocumentStore::open(dir.path().join("idp.sqlite")).unwrap(),
        );
        Self {
            signer: Arc::new(crate::jws::Es256Signer::generate()),
            dir,
            docs,
        }
    }

    #[cfg(not(any(feature = "gcp", feature = "sqlite")))]
    async fn new() -> Self {
        let docs: Arc<dyn crate::document_store::DocumentStore> =
            Arc::new(crate::document_store::MemoryDocumentStore::default());
        Self {
            signer: Arc::new(crate::jws::Es256Signer::generate()),
            store: Arc::new(crate::store::MemoryStore::with_documents(docs.clone())),
            ciba: Arc::new(crate::ciba::MemoryCibaStore::default()),
            docs,
        }
    }

    /// 同じ保存先を見る、新しい台。gcp では台ごとに Firestore の client を作り直す（本番の配線 gcp.rs と同じ組み立て）。
    fn instance(&self) -> Arc<Provider> {
        let p = Provider::new("http://localhost:8099").with_signer(self.signer.clone());
        #[cfg(feature = "gcp")]
        let p = {
            let fs = Arc::new(crate::firestore::Firestore::new_for_test(
                "proj",
                self.host.clone(),
            ));
            let mut p = p
                .with_dpop(Arc::new(crate::dpop::Es256Dpop::with_store(fs.clone())))
                .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(
                    fs.clone(),
                )))
                .with_ciba(Arc::new(crate::ciba::FirestoreCibaStore::new(fs.clone())));
            p.client_auth.insert(
                "private_key_jwt".into(),
                Arc::new(crate::client_auth::PrivateKeyJwt::with_store(fs.clone())),
            );
            p.with_firestore(fs)
        };
        #[cfg(all(feature = "sqlite", not(feature = "gcp")))]
        let p = p
            .with_document_store(self.docs.clone())
            .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(
                self.docs.clone(),
            )))
            .with_ciba(Arc::new(crate::ciba::FirestoreCibaStore::new(
                self.docs.clone(),
            )));
        #[cfg(not(any(feature = "gcp", feature = "sqlite")))]
        let p = p
            .with_document_store(self.docs.clone())
            .with_store(self.store.clone())
            .with_ciba(self.ciba.clone());
        with_test_clients(p.with_client(Client {
            client_id: CLIENT.into(),
            redirect_uris: vec![CB.into()],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: None,
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec![
                "authorization_code".into(),
                "refresh_token".into(),
                "urn:openid:params:grant-type:ciba".into(),
            ],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }))
    }

    /// 台を全て止めて、新しい台を立てる。SQLite は file を開き直す。
    #[cfg(all(feature = "sqlite", not(feature = "gcp")))]
    fn restart(&mut self) {
        self.docs = Arc::new(
            crate::sqlite::SqliteDocumentStore::open(self.dir.path().join("idp.sqlite")).unwrap(),
        );
    }

    #[cfg(not(all(feature = "sqlite", not(feature = "gcp"))))]
    fn restart(&mut self) {}
}

fn client_of(p: &Provider) -> Client {
    p.clients[CLIENT].clone()
}

fn form(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// 2 台に 4 つずつ、同じ要求を同時に投げ（worker の thread は 4 本）、成功した数を返す。
async fn successes<F, Fut, T, E>(instances: &[Arc<Provider>], run: F) -> usize
where
    F: Fn(Arc<Provider>) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    const EACH: usize = 4;
    let start = Arc::new(tokio::sync::Barrier::new(instances.len() * EACH));
    let tasks: Vec<_> = instances
        .iter()
        .cycle()
        .take(instances.len() * EACH)
        .map(|p| {
            let (start, req) = (start.clone(), run(p.clone()));
            tokio::spawn(async move {
                start.wait().await;
                req.await
            })
        })
        .collect();
    let mut n = 0;
    for t in tasks {
        n += t.await.unwrap().is_ok() as usize;
    }
    n
}

/* ===== a. 回数の上限は台をまたいで 1 つ ===== */

/// 台 A で上限まで送ったら、台 B でも断る。IP ごとも、アドレスごとも。
#[tokio::test]
async fn signup_email_limit_is_one_across_two_instances() {
    let c = Cluster::new().await;
    let (a, b) = (c.instance(), c.instance());
    let signup = |p: &Arc<Provider>, ip: &str, email: &str| {
        register::register_email_challenge(
            State(p.clone()),
            from_ip(ip),
            Json(serde_json::from_value(json!({ "email": email })).unwrap()),
        )
    };

    for i in 0..5 {
        let r = signup(&a, "192.0.2.10", &format!("a{i}@example.com")).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "{i} 回目");
    }
    assert_eq!(
        signup(&b, "192.0.2.10", "a5@example.com").await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "台 A で使い切った IP の上限が、台 B では残っていた"
    );

    for i in 0..5 {
        let p = if i % 2 == 0 { &a } else { &b };
        let r = signup(p, &format!("198.51.100.{i}"), "same@example.com").await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "{i} 回目");
    }
    for p in [&a, &b] {
        assert_eq!(
            signup(p, "198.51.100.99", "same@example.com")
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
            "2 台に分けると、同じアドレスへ上限を超えて送れた"
        );
    }
}

/// CIBA の (client, login_hint) の上限も、台 A・B・A で使い切ったら台 B でも断る。
#[tokio::test]
async fn ciba_limit_is_one_across_two_instances() {
    let c = Cluster::new().await;
    let (a, b) = (c.instance(), c.instance());
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&a, &email).await;
    let ask = |p: &Arc<Provider>| {
        ciba::backchannel_auth(
            State(p.clone()),
            HeaderMap::new(),
            Form(form(&[
                ("client_id", "test-ciba-rp"),
                ("login_hint", &email),
                ("scope", "openid"),
            ])),
        )
    };

    for (i, p) in [&a, &b, &a].into_iter().enumerate() {
        let r = ask(p).await;
        assert_eq!(r.status(), StatusCode::OK, "{i} 回目");
        let id = body_json(r).await["auth_req_id"]
            .as_str()
            .unwrap()
            .to_string();
        // 未解決の要求があると重ねて作らない（数えない）ので、拒んで片付けておく。
        assert!(
            p.ciba
                .transition_if_pending(&id, CibaStatus::Denied)
                .await
                .unwrap()
        );
    }
    let r = ask(&b).await;
    assert_eq!(
        r.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "台 A で使った分が台 B で数えられていない"
    );
}

/* ===== b. 一度きりは 2 台から同時に来ても 1 回 ===== */

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_is_redeemed_once_across_two_instances() {
    let c = Cluster::new().await;
    let ps = [c.instance(), c.instance()];
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&ps[0], &email).await;
    ps[0]
        .store
        .save_code(AuthorizationCode {
            code: "C1".into(),
            client_id: CLIENT.into(),
            account_id: account_id.clone(),
            redirect_uri: CB.into(),
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
    let n = successes(&ps, |p| async move {
        let f = form(&[("code", "C1"), ("redirect_uri", CB)]);
        AuthorizationCodeGrant
            .handle(&p, &client_of(&p), &f, None)
            .await
    })
    .await;
    assert_eq!(n, 1, "同じコードで {n} 回 token が出た");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_token_is_rotated_once_across_two_instances() {
    let c = Cluster::new().await;
    let ps = [c.instance(), c.instance()];
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&ps[0], &email).await;
    ps[1]
        .store
        .save_refresh_token(crate::model::RefreshToken {
            token: "RT1".into(),
            client_id: CLIENT.into(),
            account_id: account_id.clone(),
            scope: "openid offline_access".into(),
            resource: None,
            jkt: Some("KEY-A".into()),
            acr: None,
            auth_time: None,
            family_id: "F1".into(),
            used: false,
            replaced_by: None,
        })
        .await
        .unwrap();
    let n = successes(&ps, |p| async move {
        let f = form(&[("refresh_token", "RT1")]);
        RefreshTokenGrant
            .handle(&p, &client_of(&p), &f, Some("KEY-A".into()))
            .await
    })
    .await;
    assert_eq!(n, 1, "同じ refresh token で {n} 回回った");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ciba_approval_is_redeemed_once_across_two_instances() {
    let c = Cluster::new().await;
    let ps = [c.instance(), c.instance()];
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&ps[0], &email).await;
    let id = ps[0]
        .ciba
        .create(CLIENT, &account_id, "openid", "", None)
        .await
        .unwrap();
    assert!(
        ps[1]
            .ciba
            .transition_if_pending(&id.0, CibaStatus::Approved)
            .await
            .unwrap()
    );
    let n = successes(&ps, |p| {
        let id = id.0.clone();
        async move {
            let f = form(&[("auth_req_id", &id)]);
            CibaGrant.handle(&p, &client_of(&p), &f, None).await
        }
    })
    .await;
    assert_eq!(n, 1, "同じ承認で {n} 回 token が出た");
}

/// DPoP の jti は Firestore で台をまたいで 1 度きり（gcp の配線）。Memory・SQLite の配線では jti は process の
/// メモリにあり、台を増やせない前提なので、ここでは当てない。
#[cfg(feature = "gcp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dpop_proof_is_accepted_once_across_two_instances() {
    let c = Cluster::new().await;
    let ps = [c.instance(), c.instance()];
    let key = SigningKey::generate();
    let htu = "http://localhost:8099/token";
    let now = now() as i64;
    let proof = crate::dpop_verifier_contract::proof(
        &key,
        &crate::dpop_verifier_contract::claims("POST", htu, now),
    );
    let n = successes(&ps, |p| {
        let proof = proof.clone();
        async move { p.dpop.verify(&proof, "POST", htu, None).await }
    })
    .await;
    assert_eq!(n, 1, "同じ DPoP の proof を {n} 回受けた");
}

/* ===== c. 失効は別の台にもすぐ効く ===== */

fn bearer(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    h
}

/// 台 A の /revoke で消した token は、台 B の userinfo で通らない。
#[tokio::test]
async fn a_token_revoked_on_one_instance_is_refused_on_the_other() {
    let c = Cluster::new().await;
    let (a, b) = (c.instance(), c.instance());
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&a, &email).await;
    let (at, rt) = issue_tokens(&a, &account_id).await;
    assert_eq!(
        oidc::userinfo_get(State(b.clone()), bearer(&at))
            .await
            .status(),
        StatusCode::OK
    );

    for t in [&at, &rt] {
        let r = oidc::revoke(
            State(a.clone()),
            HeaderMap::new(),
            Form(form(&[("client_id", "rp-entry"), ("token", t)])),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }
    assert_eq!(
        oidc::userinfo_get(State(b.clone()), bearer(&at))
            .await
            .status(),
        StatusCode::UNAUTHORIZED,
        "台 A で失効した access token が台 B で通った"
    );
    assert_eq!(tokens_alive(&b, &(at, rt)).await, (false, false));
}

/// 台 A でログアウトした session は、台 B で使えない。
#[tokio::test]
async fn a_logout_on_one_instance_ends_the_session_on_the_other() {
    let c = Cluster::new().await;
    let (a, b) = (c.instance(), c.instance());
    let jar = session_jar(&a, "acct", now()).await;
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();
    assert!(b.store.get_session(&sid).await.is_some());

    // 確かめの画面の「ログアウト」の POST（自分の origin から、confirm 付き）。
    let mut h = HeaderMap::new();
    h.insert(header::ORIGIN, a.origin().parse().unwrap());
    let r = oidc::end_session_post(
        State(a.clone()),
        h,
        jar,
        Form(serde_json::from_value(json!({ "confirm": "1" })).unwrap()),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        b.store.get_session(&sid).await.is_none(),
        "台 A でログアウトした session が台 B に残った"
    );
}

/// 台 A でアカウントを止めたら、台 B ではその session・token が消えていて、passkey でもログインできない。
#[tokio::test]
async fn disabling_an_account_on_one_instance_holds_on_the_other() {
    let c = Cluster::new().await;
    let (a, b) = (c.instance(), c.instance());
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _, account_id) = register_test_account(&a, &email).await;
    let jar = session_jar(&a, &account_id, now()).await;
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();
    let tokens = issue_tokens(&a, &account_id).await;

    crate::account_admin::disable_account(a.docs.as_deref().unwrap(), &*a.store, "test", &email)
        .await
        .unwrap();

    assert!(
        b.store.get_session(&sid).await.is_none(),
        "session が残った"
    );
    assert_eq!(tokens_alive(&b, &tokens).await, (false, false));
    assert_eq!(
        oidc::userinfo_get(State(b.clone()), bearer(&tokens.0))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let (_, r) = email_login_response(&b, &email, &key, 1).await;
    assert_ne!(
        r.status(),
        StatusCode::OK,
        "止めたアカウントが台 B でログインできた"
    );
}

/* ===== d. 台が入れ替わっても状態が残る ===== */

/// 台 A で /authorize を始め、台を入れ替えて B でログイン、また入れ替えて C で resume、D で token を引き換える。
#[tokio::test]
async fn a_sign_in_survives_instances_being_replaced() {
    let mut c = Cluster::new().await;
    let a = c.instance();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, cred_id, account_id) = register_test_account(&a, &email).await;
    let verifier = "v".repeat(43);
    let challenge = crate::es256::b64url_encode(Sha256::digest(verifier.as_bytes()));
    let q = format!(
        "client_id={CLIENT}&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    );
    let r = oidc::authorize(
        State(a.clone()),
        HeaderMap::new(),
        CookieJar::default(),
        RawQuery(Some(q)),
    )
    .await;
    let loc = r.headers()[header::LOCATION].to_str().unwrap().to_string();
    let uid = loc
        .split("/login/")
        .nth(1)
        .and_then(|s| s.split('?').next())
        .expect("login へ送る")
        .to_string();
    let mark = Cookie::parse(
        r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string(),
    )
    .unwrap();
    let mut h = HeaderMap::new();
    h.insert(
        header::COOKIE,
        format!("{}={}", mark.name(), mark.value()).parse().unwrap(),
    );
    let browser = CookieJar::from_headers(&h);
    drop(a);

    c.restart();
    let b = c.instance();
    let opts =
        body_json(login::login_passkey_options(State(b.clone()), Path(uid.clone())).await).await;
    let (ad, sig, cdj) = make_auth_ceremony(
        &key,
        1,
        opts["challenge"].as_str().unwrap(),
        &b.origin(),
        &b.rp_id(),
        false,
    );
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(&cred_id),
        "response": {
            "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig,
            "userHandle": crate::webauthn::b64e(account_id.as_bytes()),
        },
    }))
    .unwrap();
    let r = login::login_passkey_verify(
        State(b.clone()),
        browser.clone(),
        Path(uid.clone()),
        Json(verify_req),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let sid = jar_after(&r).get(SID_COOKIE).unwrap().value().to_string();
    drop(b);

    c.restart();
    let cc = c.instance();
    assert_eq!(
        cc.store.get_session(&sid).await.map(|s| s.account_id),
        Some(account_id.clone()),
        "入れ替えた台で session が消えた"
    );
    let r = oidc::authorize_resume(
        State(cc.clone()),
        HeaderMap::new(),
        browser,
        Query(HashMap::from([("uid".to_string(), uid)])),
    )
    .await;
    let loc = r.headers()[header::LOCATION].to_str().unwrap().to_string();
    let code = loc
        .split("code=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("コードが出る")
        .to_string();
    drop(cc);

    c.restart();
    let d = c.instance();
    let f = form(&[
        ("code", &code),
        ("redirect_uri", CB),
        ("code_verifier", &verifier),
    ]);
    let t = AuthorizationCodeGrant
        .handle(&d, &client_of(&d), &f, None)
        .await
        .expect("入れ替えた台でコードを引き換えられない");
    drop(d);

    c.restart();
    let e = c.instance();
    assert_eq!(
        oidc::userinfo_get(State(e.clone()), bearer(&t.access_token))
            .await
            .status(),
        StatusCode::OK,
        "入れ替えた台で access token が消えた"
    );
}

/* ===== e. 保存先が落ちたら通さない ===== */

/// `docs` の上の台。Store・CibaStore も、gcp・sqlite の配線と同じく docs の上に置く（Memory の配線では docs だけ）。
fn instance_on(docs: Arc<crate::document_store::FailingDocs>) -> Arc<Provider> {
    let p = Provider::new("http://localhost:8099").with_document_store(docs.clone());
    #[cfg(any(feature = "gcp", feature = "sqlite"))]
    let p = p
        .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(
            docs.clone(),
        )))
        .with_ciba(Arc::new(crate::ciba::FirestoreCibaStore::new(docs)));
    with_test_clients(p)
}

/// 数を置く集まりだけが落ちたら、登録のメールも CIBA の要求も通さない（ほかの読み書きは通る）。
#[tokio::test]
async fn rate_limited_paths_refuse_when_the_counts_cannot_be_read() {
    let docs = Arc::new(crate::document_store::FailingDocs::only(
        crate::rate_limit::COLLECTION,
    ));
    let p = instance_on(docs);
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    register_test_account(&p, &email).await;
    let r = register::register_email_challenge(
        State(p.clone()),
        from_ip("192.0.2.1"),
        Json(serde_json::from_value(json!({ "email": "new@example.com" })).unwrap()),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "数えずに送った"
    );
    let r = ciba::backchannel_auth(
        State(p.clone()),
        HeaderMap::new(),
        Form(form(&[
            ("client_id", "test-ciba-rp"),
            ("login_hint", &email),
            ("scope", "openid"),
        ])),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "数えずに要求を作った"
    );
}

/// 保存先が落ちたら、在るコード・refresh token・承認済みの CIBA も引き換えず、session・interaction・
/// access token は無いものとして扱う。
#[cfg(any(feature = "gcp", feature = "sqlite"))]
#[tokio::test]
async fn single_use_and_session_reads_refuse_when_the_store_is_down() {
    let docs = Arc::new(crate::document_store::FailingDocs::up());
    let p = instance_on(docs.clone());
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_, _, account_id) = register_test_account(&p, &email).await;
    let c = Client {
        grant_types: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "urn:openid:params:grant-type:ciba".into(),
        ],
        ..p.clients["rp-entry"].clone()
    };
    p.store
        .save_code(AuthorizationCode {
            code: "C1".into(),
            client_id: c.client_id.clone(),
            account_id: account_id.clone(),
            redirect_uri: CB.into(),
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
    let (at, rt) = issue_tokens(&p, &account_id).await;
    let ciba_id = p
        .ciba
        .create(&c.client_id, &account_id, "openid", "", None)
        .await
        .unwrap();
    p.ciba
        .transition_if_pending(&ciba_id.0, CibaStatus::Approved)
        .await
        .unwrap();
    let jar = session_jar(&p, &account_id, now()).await;
    let sid = jar.get(SID_COOKIE).unwrap().value().to_string();
    let (uid, _) = sign_in_started_here(&p, &c.client_id).await;

    docs.go_down();
    let code = form(&[("code", "C1"), ("redirect_uri", CB)]);
    assert!(
        AuthorizationCodeGrant
            .handle(&p, &c, &code, None)
            .await
            .is_err()
    );
    let rt = form(&[("refresh_token", &rt)]);
    assert!(RefreshTokenGrant.handle(&p, &c, &rt, None).await.is_err());
    let ciba = form(&[("auth_req_id", &ciba_id.0)]);
    assert!(CibaGrant.handle(&p, &c, &ciba, None).await.is_err());
    assert!(p.store.get_session(&sid).await.is_none());
    assert!(p.store.get_interaction(&uid).await.is_none());
    assert!(!p.store.consume_interaction(&uid).await);
    assert_ne!(
        oidc::userinfo_get(State(p.clone()), bearer(&at))
            .await
            .status(),
        StatusCode::OK
    );
}
