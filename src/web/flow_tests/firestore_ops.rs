//! 典型の流れ 1 回が、Firestore を何回読み・書き・消すか（課金の単位）。無料枠で 1 日に何回ログインできるかの元にする。
//!
//! router を通し、ブラウザ（ログイン画面・登録画面の JS）と RP が送る要求を順に送る。配線は本番（gcp.rs）と同じで、
//! client も Firestore（clients/）から引く。数え方は fake Firestore の `take_ops` を見る:
//! 文書の読み 1 件が 1 読み（無い文書も 1）、query と一覧は返した文書の数（0 件でも 1）、書き・消しは 1 要求が 1 回。
//! 数を固定しておき、変わったら試験が落ちて気づけるようにする。数を直すときは、どの要求が増えたか（失敗の表示）を見る。
//!
//! ここに出ない消しがある: 期限のある文書（challenge・session・認可コード・token・回数の上限）は、Firestore の
//! TTL ポリシーが後で消す。各試験は、流れの後に増えた文書も集まりごとに固定する（アカウント・パスキー・氏名の
//! ほかは、期限が来ると TTL が 1 件 1 消しで消す）。

use super::*;
use crate::firestore::fake_firestore::{FakeState, Op};
use axum::body::Body;
use std::collections::{BTreeMap, BTreeSet};
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8099";
const CB: &str = "https://rp.example.com/cb";
const BYE: &str = "https://rp.example.com/bye";
const PUBLIC: &str = "count-public";
const CONFIDENTIAL: &str = "count-confidential";
const SECRET: &str = "count-secret-0123456789";

/// 読み・書き・消しの回数と、集まりごとの内訳（失敗の表示用）。
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    reads: usize,
    writes: usize,
    deletes: usize,
}

struct World {
    app: Router,
    fake: Arc<FakeState>,
    rp_id: String,
    /// ブラウザの cookie（名前 → 値）。
    cookies: BTreeMap<String, String>,
}

fn client(id: &str, method: &str, secret: Option<String>, grants: &[&str]) -> Client {
    Client {
        client_id: id.into(),
        redirect_uris: vec![CB.into()],
        post_logout_redirect_uris: vec![BYE.into()],
        initiate_login_uri: None,
        token_endpoint_auth_method: method.into(),
        client_secret: secret,
        grant_types: grants.iter().map(|g| g.to_string()).collect(),
        dpop_bound: false,
        jwks: vec![],
        jwks_uri: None,
        require_par: false,
        require_pkce: true,
        id_token_signed_response_alg: None,
        scope: None,
    }
}

impl World {
    /// 本番の配線（gcp.rs）と同じ組み立て。client は静的に持たず、Firestore に置いて引かせる。
    async fn new() -> Self {
        let (host, fake) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        for c in [
            client(PUBLIC, "none", None, &["authorization_code"]),
            client(
                CONFIDENTIAL,
                "client_secret_basic",
                Some(crate::hash_token(SECRET)),
                &["authorization_code", "refresh_token"],
            ),
        ] {
            crate::dcr_store::save_client(&*fs, &c).await.unwrap();
        }
        let mut p = Provider::new(ORIGIN)
            .with_dpop(Arc::new(crate::dpop::Es256Dpop::with_store(fs.clone())))
            .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(
                fs.clone(),
            )))
            .with_ciba(Arc::new(crate::ciba::FirestoreCibaStore::new(fs.clone())));
        p.client_auth.insert(
            "private_key_jwt".into(),
            Arc::new(crate::client_auth::PrivateKeyJwt::with_store(fs.clone())),
        );
        let p = p.with_firestore(fs);
        let rp_id = p.rp_id();
        fake.take_ops();
        World {
            app: router(p),
            fake,
            rp_id,
            cookies: BTreeMap::new(),
        }
    }

    async fn send(&mut self, req: axum::http::request::Builder, body: Body) -> Response {
        let mut req = req.header("x-forwarded-for", "198.51.100.7");
        if !self.cookies.is_empty() {
            let c: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            req = req.header(header::COOKIE, c.join("; "));
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        for set in resp.headers().get_all(header::SET_COOKIE) {
            let set = set.to_str().unwrap();
            let (name, value) = set.split(';').next().unwrap().split_once('=').unwrap();
            if value.is_empty() || set.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.into(), value.into());
            }
        }
        resp
    }

    async fn get(&mut self, uri: &str) -> Response {
        self.send(axum::http::Request::get(uri), Body::empty())
            .await
    }

    /// 画面の JS が自分の origin から送る JSON。
    async fn post_json(&mut self, uri: &str, body: serde_json::Value) -> Response {
        let req = axum::http::Request::post(uri)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        self.send(req, Body::from(body.to_string())).await
    }

    async fn post_form(
        &mut self,
        uri: &str,
        pairs: &[(&str, &str)],
        auth: Option<&str>,
        origin: Option<&str>,
    ) -> Response {
        let mut req = axum::http::Request::post(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(a) = auth {
            req = req.header(header::AUTHORIZATION, a);
        }
        if let Some(o) = origin {
            req = req.header(header::ORIGIN, o);
        }
        let body = serde_urlencoded::to_string(pairs).unwrap();
        self.send(req, Body::from(body)).await
    }

    /// ここまでの操作を数えて空にする。数が合わないときに見られるよう、内訳も返す。
    fn take_counts(&self) -> (Counts, String) {
        let ops = self.fake.take_ops();
        let n = |op| ops.iter().filter(|(o, _)| *o == op).count();
        let mut by: BTreeMap<(Op, &str), usize> = BTreeMap::new();
        for (op, col) in &ops {
            *by.entry((*op, col.as_str())).or_default() += 1;
        }
        let detail = by
            .iter()
            .map(|((op, col), k)| format!("{op:?} {col} x{k}"))
            .collect::<Vec<_>>()
            .join(", ");
        (
            Counts {
                reads: n(Op::Read),
                writes: n(Op::Write),
                deletes: n(Op::Delete),
            },
            detail,
        )
    }

    /// 文書の (集まり, id) の全て。流れの前後で比べ、後で TTL が消す残りを数える。
    fn docs(&self) -> BTreeSet<(String, String)> {
        self.fake.all_doc_keys().into_iter().collect()
    }

    /// 流れの前後の差: 増えた文書の集まりごとの数。
    fn left_since(&self, before: &BTreeSet<(String, String)>) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for (col, _) in self.docs().difference(before) {
            *m.entry(col.clone()).or_default() += 1;
        }
        m
    }

    /// メールの確かめ → パスキーの登録。ログイン画面からではなく、/signup を直に開いた人。
    /// 戻り値: (鍵, credential id, account_id)。
    async fn sign_up(&mut self, email: &str) -> (SigningKey, Vec<u8>, String) {
        assert_eq!(self.get("/signup").await.status(), StatusCode::OK);
        let r = self
            .post_form("/signup", &[("email", email)], None, Some(ORIGIN))
            .await;
        assert_eq!(r.status(), StatusCode::OK, "{}", body_text(r).await);
        // メールに載る token（emailChallenges の id）。fake の中を直に見るので数に入らない。
        let token = self
            .fake
            .doc_ids("emailChallenges")
            .pop()
            .expect("確かめのメールの token が無い");
        let r = self.get(&format!("/r?t={token}")).await;
        assert_eq!(r.status(), StatusCode::OK);

        let r = self
            .post_json("/signup/passkey/options", json!({ "token": token }))
            .await;
        assert_eq!(r.status(), StatusCode::OK);
        let opts = body_json(r).await;
        let challenge = opts["challenge"].as_str().unwrap().to_string();
        let account_id = String::from_utf8(
            crate::es256::b64url_decode(opts["user"]["id"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let key = SigningKey::generate();
        let cred_id = b"count-credential".to_vec();
        let (att, cdj) = make_reg_ceremony(&key, &cred_id, &challenge, ORIGIN, &self.rp_id);
        let r = self
            .post_json(
                "/signup/passkey/verify",
                json!({
                    "token": token,
                    "name": "Count Person",
                    "response": { "clientDataJSON": cdj, "attestationObject": att },
                }),
            )
            .await;
        assert_eq!(r.status(), StatusCode::CREATED, "{}", body_text(r).await);
        (key, cred_id, account_id)
    }

    /// RP の /authorize → ログイン画面 → パスキー → /authorize/resume。認可コードを返す。
    /// 画面の JS は開いたときに options を先取りし、確かめに成功すれば画面を去るので、options は 1 回送る
    /// （次の options は確かめに失敗したときだけもらう。以前は操作の直後にももらい、challenge の書きが 1 回多かった）。
    async fn sign_in(
        &mut self,
        client_id: &str,
        scope: &str,
        challenge: &str,
        (key, cred_id, account_id): &(SigningKey, Vec<u8>, String),
    ) -> String {
        let q = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", CB),
            ("scope", scope),
            ("state", "st"),
            ("nonce", "nn"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ])
        .unwrap();
        let r = self.get(&format!("/authorize?{q}")).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER, "{}", body_text(r).await);
        let login = r.headers()[header::LOCATION].to_str().unwrap().to_string();
        let uid = login
            .strip_prefix("/login/")
            .and_then(|s| s.split('?').next())
            .unwrap()
            .to_string();
        assert_eq!(self.get(&login).await.status(), StatusCode::OK);

        let r = self
            .post_json(&format!("/login/{uid}/passkey/options"), json!({}))
            .await;
        let challenge = body_json(r).await["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let (ad, sig, cdj) = make_auth_ceremony(key, 0, &challenge, ORIGIN, &self.rp_id, false);
        let r = self
            .post_json(
                &format!("/login/{uid}/passkey/verify"),
                json!({
                    "id": crate::webauthn::b64e(cred_id),
                    "response": {
                        "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig,
                        "userHandle": crate::webauthn::b64e(account_id.as_bytes()),
                    },
                }),
            )
            .await;
        assert_eq!(r.status(), StatusCode::OK);
        let resume = body_json(r).await["redirect"].as_str().unwrap().to_string();
        let r = self.get(&resume).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER, "{}", body_text(r).await);
        let back = r.headers()[header::LOCATION].to_str().unwrap().to_string();
        let q: HashMap<String, String> =
            serde_urlencoded::from_str(back.split_once('?').unwrap().1).unwrap();
        assert_eq!(q["state"], "st");
        q["code"].clone()
    }

    /// RP の /token（authorization_code）。戻りは token の応答。
    async fn redeem(&mut self, client_id: &str, code: &str, verifier: &str) -> serde_json::Value {
        let basic = basic_for(client_id);
        let r = self
            .post_form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", CB),
                    ("client_id", client_id),
                    ("code_verifier", verifier),
                ],
                basic.as_deref(),
                None,
            )
            .await;
        assert_eq!(r.status(), StatusCode::OK);
        body_json(r).await
    }

    async fn userinfo(&mut self, access_token: &str) {
        let req = axum::http::Request::get("/userinfo")
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"));
        let r = self.send(req, Body::empty()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await["name"], "Count Person");
    }
}

fn basic_for(client_id: &str) -> Option<String> {
    use base64::Engine;
    (client_id == CONFIDENTIAL).then(|| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{CONFIDENTIAL}:{SECRET}"))
        )
    })
}

fn left<const N: usize>(cols: [(&str, usize); N]) -> BTreeMap<String, usize> {
    cols.into_iter().map(|(c, k)| (c.to_string(), k)).collect()
}

/// PKCE の (verifier, S256 の challenge)。
fn pkce() -> (String, String) {
    let verifier = format!("v-{}-{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let challenge = crate::jws::b64url(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// 登録を済ませた world と、その人の鍵。登録の分の数は捨てる。
async fn signed_up() -> (World, (SigningKey, Vec<u8>, String)) {
    let mut w = World::new().await;
    let who = w
        .sign_up(&format!("count-{}@example.com", uuid::Uuid::new_v4()))
        .await;
    // 登録で張った session は捨て、ログインしていないブラウザから始める。
    w.cookies.clear();
    w.take_counts();
    (w, who)
}

/// a. public client（PKCE だけ）: /authorize → パスキーでログイン → /token → /userinfo。
#[tokio::test]
async fn login_with_a_passkey_for_a_public_client() {
    let (mut w, who) = signed_up().await;
    let before = w.docs();
    let (verifier, challenge) = pkce();
    let code = w
        .sign_in(PUBLIC, "openid profile email", &challenge, &who)
        .await;
    let t = w.redeem(PUBLIC, &code, &verifier).await;
    assert!(t.get("refresh_token").is_none());
    w.userinfo(t["access_token"].as_str().unwrap()).await;

    let (n, detail) = w.take_counts();
    assert_eq!(
        n,
        Counts {
            reads: 19,
            writes: 9,
            deletes: 2
        },
        "{detail}"
    );
    assert_eq!(
        w.left_since(&before),
        left([("accessTokens", 1), ("authCodes", 1), ("sessions", 1),])
    );
}

/// a. confidential client（client_secret_basic と PKCE、offline_access つき）: ログイン → /token → /userinfo。
#[tokio::test]
async fn login_with_a_passkey_for_a_confidential_client() {
    let (mut w, who) = signed_up().await;
    let before = w.docs();
    let (verifier, challenge) = pkce();
    let code = w
        .sign_in(
            CONFIDENTIAL,
            "openid profile email offline_access",
            &challenge,
            &who,
        )
        .await;
    let t = w.redeem(CONFIDENTIAL, &code, &verifier).await;
    assert!(t["refresh_token"].is_string());
    w.userinfo(t["access_token"].as_str().unwrap()).await;

    let (n, detail) = w.take_counts();
    assert_eq!(
        n,
        Counts {
            reads: 19,
            writes: 10,
            deletes: 2
        },
        "{detail}"
    );
    assert_eq!(
        w.left_since(&before),
        left([
            ("accessTokens", 1),
            ("authCodes", 1),
            ("refreshTokens", 1),
            ("sessions", 1),
        ])
    );
}

/// confidential client でログインし、token の応答を返す（b・c の前置き。この分の数は捨てる）。
async fn signed_in_confidential() -> (World, serde_json::Value) {
    let (mut w, who) = signed_up().await;
    let (verifier, challenge) = pkce();
    let code = w
        .sign_in(
            CONFIDENTIAL,
            "openid profile offline_access",
            &challenge,
            &who,
        )
        .await;
    let t = w.redeem(CONFIDENTIAL, &code, &verifier).await;
    w.take_counts();
    (w, t)
}

/// b. refresh token での更新 1 回（confidential client、回すと古い refresh token は使えなくなる）。
#[tokio::test]
async fn one_refresh() {
    let (mut w, t) = signed_in_confidential().await;
    let before = w.docs();
    let basic = basic_for(CONFIDENTIAL);
    let r = w
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", t["refresh_token"].as_str().unwrap()),
            ],
            basic.as_deref(),
            None,
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(body_json(r).await["refresh_token"].is_string());

    let (n, detail) = w.take_counts();
    assert_eq!(
        n,
        Counts {
            reads: 6,
            writes: 3,
            deletes: 0
        },
        "{detail}"
    );
    assert_eq!(
        w.left_since(&before),
        left([("accessTokens", 1), ("refreshTokens", 1)])
    );
}

/// c. RP からのログアウト 1 回（GET、id_token_hint・client_id・post_logout_redirect_uri つき。確かめの画面は出ない）。
#[tokio::test]
async fn one_logout() {
    let (mut w, t) = signed_in_confidential().await;
    let q = serde_urlencoded::to_string([
        ("id_token_hint", t["id_token"].as_str().unwrap()),
        ("client_id", CONFIDENTIAL),
        ("post_logout_redirect_uri", BYE),
        ("state", "s1"),
    ])
    .unwrap();
    let r = w.get(&format!("/end-session?{q}")).await;
    assert!(r.status().is_redirection(), "{}", r.status());
    assert_eq!(r.headers()[header::LOCATION], format!("{BYE}?state=s1"));

    let (n, detail) = w.take_counts();
    assert_eq!(
        n,
        Counts {
            reads: 3,
            writes: 0,
            deletes: 1
        },
        "{detail}"
    );
}

/// d. 新規登録 1 回: /signup で確かめのメール → メールのリンク → パスキーの登録（氏名つき）。
#[tokio::test]
async fn one_sign_up() {
    let mut w = World::new().await;
    let before = w.docs();
    w.sign_up("count-new@example.com").await;

    let (n, detail) = w.take_counts();
    assert_eq!(
        n,
        Counts {
            reads: 16,
            writes: 10,
            deletes: 3
        },
        "{detail}"
    );
    assert_eq!(
        w.left_since(&before),
        left([
            ("accounts", 1),
            ("accountsByUuid", 1),
            ("credentials", 1),
            ("profiles", 1),
            ("rateLimits", 2),
            ("sessions", 1),
        ])
    );
}

/// e. discovery と jwks は Firestore を読まない（RP が何度引いても枠を使わない）。
#[tokio::test]
async fn discovery_and_jwks_do_not_touch_firestore() {
    let mut w = World::new().await;
    for uri in ["/.well-known/openid-configuration", "/jwks"] {
        assert_eq!(w.get(uri).await.status(), StatusCode::OK, "{uri}");
    }
    let (n, detail) = w.take_counts();
    assert_eq!(
        n,
        Counts {
            reads: 0,
            writes: 0,
            deletes: 0
        },
        "{detail}"
    );
}
