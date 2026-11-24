use super::*;

// pkLogin は discoverable のモーダル方式のみ。allowCredentials 空で OS の passkey ピッカーに
// 全候補を出して選ばせる。Conditional UI(autofill) は自動起動しない。
// 理由: アプリ webview(ASWebAuthenticationSession)内では autofill が「最近使った1件」
// だけを勝手に提示して紛らわしいため(TS 版も同方針)。userHandle でユーザー解決。
#[derive(serde::Deserialize)]
pub(super) struct LoginQuery {
    client_id: Option<String>,
}

/// 期限切れなら、client に入口（initiate_login_uri）があればそこへ送り直し、
/// 新しい state・nonce で RP にログインを始め直させる（OIDC Core §4）。古い authorize の
/// 引数で作り直すと RP 側のセッションと state が合わず callback で弾かれる。
/// 別のブラウザで始めたログイン（アプリ内ブラウザから Safari へ URL を移した等）も、画面を出すと
/// パスキーを通した後に完了で断ることになるので、入口へのリンクを出してこのブラウザで始め直させる。
/// 自動で送らないのは、cookie を保存しないブラウザでは入口 → /authorize → ここ を回り続けるため。
pub(super) async fn login_form(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(uid): Path<String>,
    Query(q): Query<LoginQuery>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let Some(interaction) = p.store.get_interaction(&uid).await else {
        let Some(entry) = client_entry(&p, q.client_id.as_deref().unwrap_or("")).await else {
            return plain_error(&localize("[[This sign-in has expired. Please start again.]]", lang));
        };
        tracing::info!(event = "login_reinitiated", client_id = q.client_id.as_deref().unwrap_or(""));
        return Redirect::to(&entry).into_response();
    };
    if !started_in_this_browser(&jar, &interaction) {
        // client_id は URL でなく interaction の要求から取る（URL の client_id は誰でも書き換えられる）。
        let client_id = requested_client_id(&interaction);
        tracing::info!(event = "login_from_another_browser", client_id = %client_id);
        return match client_entry(&p, &client_id).await {
            Some(entry) => Html(localize(
                &format!(
                    r#"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Sign in]]</title></head>
<body style="font-family:-apple-system,sans-serif;max-width:360px;margin:0 auto;padding:56px 24px;text-align:center">
<p>[[This sign-in was started in another browser.]]</p>
<p><a href="{}">[[Sign in again in this browser]]</a></p></body></html>"#,
                    super::admin::esc(&entry)
                ),
                lang,
            ))
            .into_response(),
            None => plain_error(&localize(
                "[[This sign-in was started in another browser. Please start again from the app.]]",
                lang,
            )),
        };
    }
    // パソコンでは、スマホのパスキーを QR コード（hybrid）で使えることを添える（qrhint）。
    let body = r##"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Sign in]]</title>
<style>
:root{--indigo:#3f51b5;--indigo-d:#303f9f}
body{font-family:Roboto,-apple-system,'Helvetica Neue',sans-serif;max-width:360px;margin:0 auto;padding:56px 24px;color:#1a1a1a;text-align:center}
.fp{width:72px;height:72px;color:var(--indigo)}
h1{font-size:1.3rem;font-weight:500;margin:18px 0 28px}
input{display:block;width:100%;box-sizing:border-box;padding:14px;margin:0 0 16px;font-size:16px;border:1px solid #b0b0b0;border-radius:8px}
.filled{width:100%;padding:14px;font-size:16px;font-weight:500;background:var(--indigo);color:#fff;border:0;border-radius:24px;cursor:pointer}
.filled:active{background:var(--indigo-d)}
.outlined{width:100%;padding:12px;font-size:16px;font-weight:500;background:#fff;color:var(--indigo);border:1.5px solid var(--indigo);border-radius:24px;margin-top:12px;cursor:pointer}
#msg{color:#c5221f;font-size:14px;margin-top:14px;min-height:1em}
details{margin-top:36px;color:#9a9a9a;font-size:13px;text-align:left}
summary{cursor:pointer}
details input{font-size:14px;padding:8px;margin-top:8px}</style>
</head><body>
<svg class="fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
<path d="M5.5 10a6.5 6.5 0 0 1 13 0v4a8 8 0 0 1-1 3.8"/>
<path d="M8 11a4 4 0 0 1 8 0v3a6 6 0 0 0 .8 3"/>
<path d="M12 11v4a7 7 0 0 0 1.4 4.3"/>
<path d="M12 19v.01"/></svg>
<h1>[[Sign in with a passkey]]</h1>
<input id="email" placeholder="[[Email address (optional)]]" autocomplete="off">
<button class="filled" onclick="pkLogin()">[[Sign in]]</button>
<button class="outlined" onclick="location.href='__REGISTER__'">[[Sign up with email]]</button>
<p style="font-size:13px;text-align:center;margin-top:12px"><a href="__RECOVER__">[[Can’t use your passkey?]]</a></p>
<p id="qrhint" style="font-size:12px;color:#5f6368;text-align:center;margin-top:8px" hidden>[[If this computer has no passkey, press sign in and scan the QR code that appears with the phone that has your passkey.]]</p>
<button class="outlined" onclick="location.href='__CANCEL__'">[[Cancel]]</button>
<p id="msg"></p>
<script>
__WEBAUTHN_JS__
__SERVER_ERROR_JS__
const OPT="__OPT__",VER="__VER__";
const OPT_FRESH_MS=(__CEREMONY_TTL_SECS__-60)*1000;
const msgEl=document.getElementById('msg');
document.getElementById('qrhint').hidden=/Android|iPad|iPhone|iPod/i.test(navigator.userAgent)||/(Macintosh).*Mobile/i.test(navigator.userAgent);
let cachedOpts=null,cachedAt=0;
async function prefetch(){
  try{const r=await fetch(OPT,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});cachedOpts=r.ok?await r.json():null;cachedAt=Date.now();}
  catch{cachedOpts=null;}
}
function fresh(){return cachedOpts&&Date.now()-cachedAt<OPT_FRESH_MS;}
prefetch();
setInterval(()=>{if(!fresh())prefetch();},30000);
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&!fresh())prefetch();});
async function pkLogin(){
 msgEl.textContent='';
 if(!window.PublicKeyCredential){msgEl.textContent='[[This browser does not support passkeys. Open this page in the standard Safari or Chrome app.]]';return;}
 try{
  let o=fresh()?cachedOpts:null;
  if(!o){const r=await fetch(OPT,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});if(!r.ok){msgEl.textContent=await errorText(r);return;}o=await r.json();}
  const cred=await navigator.credentials.get({publicKey:{challenge:b64ToBuf(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:o.userVerification,allowCredentials:[]}});
  cachedOpts=null;prefetch();
  const body={id:cred.id,response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),authenticatorData:bufToB64(cred.response.authenticatorData),signature:bufToB64(cred.response.signature),userHandle:cred.response.userHandle?bufToB64(cred.response.userHandle):null}};
  const v=await fetch(VER,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  if(!v.ok){if(await v.clone().text()==='interaction not found'){location.reload();return;}msgEl.textContent=await errorText(v);return;}
  location.href=(await v.json()).redirect;
 }catch(e){
  if(e.name==='NotAllowedError'){
   msgEl.textContent='[[Could not start the passkey. Open this page in the standard Safari or Chrome app (in-app browsers are not supported).]]';
  }else{msgEl.textContent=passkeyErrorText(e);}
 }
}
</script></body></html>"##;
    Html(
        localize(&body.replace("__SERVER_ERROR_JS__", SERVER_ERROR_JS), lang)
            .replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
            .replace("__OPT__", &p.path(&format!("/login/{uid}/passkey/options")))
            .replace("__VER__", &p.path(&format!("/login/{uid}/passkey/verify")))
            // 先取りした options は、サーバの challenge の期限より 1 分早く捨てて取り直す。開いたまま置いた画面が
            // 切れた challenge で検証に行かないため。端末が眠ると setInterval も止まるので、画面に戻ったときにも取り直す。
            .replace("__CEREMONY_TTL_SECS__", &crate::registration::CEREMONY_TTL_SECS.to_string())
            .replace("__CANCEL__", &p.path(&format!("/login/{uid}/cancel")))
            .replace("__REGISTER__", &p.path(&format!("/signup?uid={uid}")))
            .replace("__RECOVER__", &p.path(&format!("/recover?uid={uid}"))),
    )
    .into_response()
}

/// ログイン確定: まだ在る interaction にアカウントを書き、SSO セッション cookie を張り、resume パスを返す。
/// interaction が無い（消費済み・期限切れ）なら None。
/// 誤りは画面が訳す固定文（SERVER_ERRORS）。
async fn finalize_login(
    p: &Provider,
    jar: CookieJar,
    uid: &str,
    account_sub: String,
) -> Result<(CookieJar, String), &'static str> {
    let interaction = p.store.get_interaction(uid).await.ok_or("interaction not found")?;
    if !started_in_this_browser(&jar, &interaction) {
        tracing::warn!(event = "login_from_another_browser");
        return Err("started in another browser");
    }
    let auth_time = now();
    if !p.store.complete_interaction(uid, &account_sub, auth_time).await {
        return Err("interaction not found");
    }
    tracing::info!(event = "login_success", sub = %super::pseudonymize_sub(&account_sub));
    let jar = start_session(p, jar, account_sub, auth_time).await;
    Ok((jar, p.path(&format!("/authorize/resume?uid={uid}"))))
}

/* ===== passkey ログイン ===== */

#[derive(serde::Deserialize)]
pub(super) struct LoginPkOptionsReq {
    #[serde(default)]
    email: String,
}

pub(super) async fn login_passkey_options(
    State(p): State<Arc<Provider>>,
    Path(uid): Path<String>,
    Json(req): Json<LoginPkOptionsReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = req.email.trim().to_lowercase();
    // email 指定があり credential があれば allowCredentials を絞る。無指定/未登録なら
    // discoverable（allowCredentials 空）＝OS の passkey ピッカーに全候補を出す。
    // discoverable のときは verify 時に assertion の userHandle でユーザーを解決する。
    let (allow, chal_email) = if email.is_empty() {
        (serde_json::json!([]), String::new())
    } else {
        let creds = match crate::registration::get_account(fs, &email).await {
            Ok(Some(a)) => crate::registration::list_credentials(fs, &a).await.unwrap_or_default(),
            _ => vec![],
        };
        if creds.is_empty() {
            (serde_json::json!([]), String::new())
        } else {
            let allow: Vec<_> = creds
                .iter()
                .map(|c| serde_json::json!({ "type": "public-key", "id": c.credential_id, "transports": ["internal", "hybrid"] }))
                .collect();
            (serde_json::json!(allow), email.clone())
        }
    };
    let challenge = match crate::registration::create_webauthn_challenge(fs, &chal_email, crate::registration::ChallengeKind::Auth, &uid, "").await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("create challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    Json(serde_json::json!({
        "challenge": challenge,
        "rpId": p.rp_id(),
        "timeout": 60000,
        "userVerification": "preferred",
        "allowCredentials": allow,
    }))
    .into_response()
}

pub(super) async fn login_passkey_verify(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(uid): Path<String>,
    Json(req): Json<AuthVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let account = match verify_assertion(&p, fs, &req, &uid).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let account = p.store.find_account(&account.account_id).await;
    match finalize_login(&p, jar, &uid, account.sub).await {
        Ok((jar, resume)) => (jar, Json(serde_json::json!({ "redirect": resume }))).into_response(),
        // "interaction not found" のとき、画面は期限切れと見て読み直す（login_form の JS）。
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

/// passkey の assertion を検証し、持ち主のアカウントを返す。challenge はログイン用で uid が合うものに限る。
/// 凍結したアカウントと accountId の無いアカウントは断る。誤りは画面が訳す固定文（SERVER_ERRORS）。
pub(super) async fn verify_assertion(
    p: &Provider,
    fs: &crate::firestore::Firestore,
    req: &AuthVerifyReq,
    expected_uid: &str,
) -> Result<crate::registration::Account, Response> {
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return Err((StatusCode::BAD_REQUEST, "no challenge").into_response()),
    };
    let (email, kind, uid2, _) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return Err((StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response()),
        Err(e) => {
            tracing::error!("consume challenge: {e}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "error").into_response());
        }
    };
    if kind != crate::registration::ChallengeKind::Auth || uid2 != expected_uid {
        return Err((StatusCode::BAD_REQUEST, "challenge context mismatch").into_response());
    }
    // discoverable（challenge の email が空）なら assertion の userHandle で解決。
    // userHandle = registration 時の user.id = account_id(UUID)。account_id → email を逆引きする。
    let email = match req
        .response
        .user_handle
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        Some(uh) => {
            let account_id = crate::es256::b64url_decode(uh)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            match crate::registration::find_email_by_account_id(fs, &account_id).await {
                Ok(Some(e)) => e,
                _ => return Err((StatusCode::BAD_REQUEST, "cannot resolve user").into_response()),
            }
        }
        None => email,
    };
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "cannot resolve user").into_response());
    }
    let account = match crate::registration::get_account(fs, &email).await {
        Ok(Some(a)) => a,
        _ => return Err((StatusCode::BAD_REQUEST, "credential not found").into_response()),
    };
    let cred = match crate::registration::find_credential(fs, &account, &req.id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err((StatusCode::BAD_REQUEST, "credential id mismatch").into_response()),
        Err(e) => {
            tracing::error!("find_credential: {e}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "error").into_response());
        }
    };
    match crate::webauthn::verify_authentication(
        &req.response.client_data_json,
        &req.response.authenticator_data,
        &req.response.signature,
        &challenge,
        &p.origin(),
        &p.rp_id(),
        &cred.pub_x,
        &cred.pub_y,
        cred.sign_count,
        false, // 通常ログインは UP のみ（従来通り）
    ) {
        Ok(new_count) => {
            if let Err(e) = crate::registration::record_use(fs, &account, &cred, new_count).await {
                tracing::warn!(event = "passkey_use_not_recorded", "{e}");
            }
        }
        Err(e) => {
            tracing::warn!(event = "login_failed", method = "passkey", "webauthn auth failed: {e}");
            return Err((StatusCode::UNAUTHORIZED, format!("passkey verify failed: {e}")).into_response());
        }
    }
    // disabled チェックは署名検証の後: これより前に判定を分岐させると、実 passkey を
    // 持たない第三者でも「このアカウントは凍結されているか」を判別できるオラクルになる。
    // 署名を検証し終えた=正規の所有者だと確認できてから初めて拒否理由を返す。
    if account.disabled {
        tracing::warn!(event = "login_blocked_disabled", sub = %super::pseudonymize_sub(&account.account_id));
        return Err((StatusCode::FORBIDDEN, "account disabled").into_response());
    }
    if account.account_id.is_empty() {
        // 移行前（accountId 未発行）のアカウント。再登録が必要。
        return Err((StatusCode::BAD_REQUEST, "account needs re-registration").into_response());
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Client;

    fn provider(store: Arc<dyn crate::store::Store>) -> Arc<Provider> {
        Arc::new(Provider::new("https://op.example").with_store(store).with_client(Client {
            client_id: "rp".into(),
            redirect_uris: vec!["https://rp.example/cb".into()],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("hash".into()),
            grant_types: vec!["authorization_code".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }))
    }

    async fn resume(p: &Arc<Provider>, uid: &str) -> Response {
        let q = HashMap::from([("uid".to_string(), uid.to_string())]);
        super::super::oidc::authorize_resume(State(p.clone()), HeaderMap::new(), bound_jar(uid), Query(q)).await
    }

    const RP_QUERY: &str = "response_type=code&client_id=rp&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb\
        &scope=openid&state=s&nonce=n&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

    async fn provider_with_interaction(binding: String) -> Arc<Provider> {
        let p = Arc::new(Provider::new("https://idp.example/oidc".to_string()).with_client(super::super::i18n_tests::client("rp")));
        p.store
            .save_interaction(Interaction {
                uid: "U1".into(),
                raw_query: RP_QUERY.into(),
                account_id: None,
                auth_time: None,
                request_uri: None,
                browser_binding: binding,
            })
            .await;
        p
    }

    async fn form_of(p: &Arc<Provider>, jar: CookieJar) -> (StatusCode, String) {
        let q: LoginQuery = serde_urlencoded::from_str("").unwrap();
        let r = login_form(State(p.clone()), HeaderMap::new(), jar, Path("U1".into()), Query(q)).await;
        let status = r.status();
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// 別のブラウザで開いたログイン画面は、入口の無い client では案内を出して止まる。
    /// キャンセルが RP へ access_denied を返すのも、始めたブラウザからだけ。
    #[tokio::test]
    async fn another_browser_gets_no_sign_in_page_and_cannot_cancel() {
        let p = provider_with_interaction(super::super::browser_binding_hash("b")).await;
        let (status, body) = form_of(&p, CookieJar::default()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("another browser"), "{body}");
        assert_eq!(form_of(&p, bound_jar("U1")).await.0, StatusCode::OK);

        let cancel = |jar: CookieJar| super::super::oidc::authorize_cancel(State(p.clone()), HeaderMap::new(), jar, Path("U1".into()));
        let elsewhere = cancel(CookieJar::default()).await;
        assert_eq!(elsewhere.status(), StatusCode::BAD_REQUEST);
        assert!(elsewhere.headers().get(header::LOCATION).is_none());
        let here = cancel(bound_jar("U1")).await;
        let loc = here.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        assert!(loc.starts_with("https://rp.example.com/cb?") && loc.contains("error=access_denied"), "{loc}");
    }

    /// 印の無い interaction は、cookie が何であっても始めたブラウザと見なさない。
    #[tokio::test]
    async fn an_interaction_without_a_binding_is_never_from_this_browser() {
        let p = provider_with_interaction(String::new()).await;
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("{}=", super::super::browser_cookie_name("U1")).parse().unwrap());
        let jar = CookieJar::from_headers(&h);
        assert_ne!(form_of(&p, jar.clone()).await.0, StatusCode::OK);
        assert_eq!(finalize_login(&p, jar, "U1", "acct".into()).await.err(), Some("started in another browser"));
    }

    /// 試験の interaction を始めたブラウザの cookie。interaction には browser_binding_hash("b") を置く。
    fn bound_jar(uid: &str) -> CookieJar {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("{}=b", super::super::browser_cookie_name(uid)).parse().unwrap());
        CookieJar::from_headers(&h)
    }

    fn gave_code(r: &Response) -> bool {
        r.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|l| l.contains("code="))
    }

    /// resume で消費した後に遅れて届いた verify が、同じ uid の interaction を作り直してはならない。
    /// 作り直すと 2 回目の resume が 2 つ目のコードを受け取る。
    async fn a_late_verify_cannot_revive_a_consumed_interaction(p: Arc<Provider>) {
        p.store
            .save_interaction(Interaction {
                uid: "U1".into(),
                raw_query: "client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid".into(),
                account_id: None,
                auth_time: None,
                request_uri: None,
                browser_binding: super::super::browser_binding_hash("b"),
            })
            .await;
        assert!(finalize_login(&p, bound_jar("U1"), "U1", "acct".into()).await.is_ok());
        let first = resume(&p, "U1").await;
        assert!(gave_code(&first), "1 回目の resume はコードを出す");

        assert!(finalize_login(&p, bound_jar("U1"), "U1", "acct".into()).await.is_err(), "遅れた verify は書けない");
        assert!(p.store.get_interaction("U1").await.is_none(), "消費済みの interaction は作り直されない");
        let second = resume(&p, "U1").await;
        assert!(!gave_code(&second));
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    }

    /// 攻撃者が自分で始めたログインの URL を被害者に踏ませても、被害者のブラウザでは完了できず、
    /// 攻撃者のブラウザ（認証していない側）でも resume でコードを取れない。
    #[tokio::test]
    async fn a_sign_in_completes_only_in_the_browser_that_started_it() {
        let p = provider(Arc::new(crate::store::MemoryStore::default()));
        let (secret, binding) = super::super::new_browser_binding();
        p.store
            .save_interaction(Interaction {
                uid: "U1".into(),
                raw_query: "client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid".into(),
                account_id: None,
                auth_time: None,
                request_uri: None,
                browser_binding: binding,
            })
            .await;
        // リクエストの Cookie ヘッダから作る（add で作ると「応答で足す cookie」になり、remove が消去を出さない）。
        let jar_with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::COOKIE, format!("{}={v}", super::super::browser_cookie_name("U1")).parse().unwrap());
            CookieJar::from_headers(&h)
        };
        let starter = jar_with(&secret);
        let forged = jar_with("guess");

        for other in [CookieJar::default(), forged] {
            assert_eq!(
                finalize_login(&p, other, "U1", "acct".into()).await.err(),
                Some("started in another browser")
            );
        }
        assert!(p.store.get_interaction("U1").await.is_some_and(|i| i.account_id.is_none()), "別のブラウザでは完了が書かれない");

        assert!(finalize_login(&p, starter.clone(), "U1", "acct".into()).await.is_ok());
        let stolen = resume(&p, "U1").await;
        assert!(!gave_code(&stolen), "cookie の無いブラウザは resume でコードを取れない");
        assert!(p.store.get_interaction("U1").await.is_some(), "断った resume は interaction を消費しない");

        let q = HashMap::from([("uid".to_string(), "U1".to_string())]);
        let own = super::super::oidc::authorize_resume(State(p.clone()), HeaderMap::new(), starter, Query(q)).await;
        assert!(gave_code(&own));
        let cleared: Vec<&str> =
            own.headers().get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).filter(|c| c.starts_with("__Host-ix_U1=;")).collect();
        assert_eq!(cleared.len(), 1, "使い終えた印の cookie を消す");
        super::super::assert_host_cookie(cleared[0]);
    }

    /// `/authorize` は interaction ごとに印の cookie を張り、interaction にはそのハッシュだけを残す。
    #[tokio::test]
    async fn authorize_marks_the_browser_that_starts_the_sign_in() {
        let p = provider(Arc::new(crate::store::MemoryStore::default()));
        let q = "client_id=rp&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid".to_string();
        let r = super::super::oidc::authorize(State(p.clone()), HeaderMap::new(), CookieJar::default(), RawQuery(Some(q))).await;
        let loc = r.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let uid = loc.split("/login/").nth(1).and_then(|s| s.split('?').next()).expect("login へ送る").to_string();
        let set = r.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).expect("cookie を張る").to_string();
        super::super::assert_host_cookie(&set);
        let c = Cookie::parse(set).unwrap();
        assert_eq!(c.name(), super::super::browser_cookie_name(&uid));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Lax));
        let i = p.store.get_interaction(&uid).await.unwrap();
        assert_ne!(i.browser_binding, c.value(), "cookie の値そのものは保存しない");
        assert_eq!(i.browser_binding, super::super::browser_binding_hash(c.value()));
    }

    #[tokio::test]
    async fn a_late_verify_cannot_revive_a_consumed_interaction_in_memory() {
        a_late_verify_cannot_revive_a_consumed_interaction(provider(Arc::new(crate::store::MemoryStore::default()))).await;
    }

    #[tokio::test]
    async fn a_late_verify_cannot_revive_a_consumed_interaction_in_firestore() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        a_late_verify_cannot_revive_a_consumed_interaction(provider(Arc::new(crate::firestore_store::FirestoreStore::new(fs)))).await;
    }

    /// verify の読みと書きの間に resume が消費しても、書きは消費済みの interaction を作り直さない（CAS で負ける）。
    #[tokio::test]
    async fn a_verify_racing_a_resume_does_not_revive_the_interaction_in_firestore() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let store: Arc<dyn crate::store::Store> = Arc::new(crate::firestore_store::FirestoreStore::new(fs));
        store
            .save_interaction(Interaction {
                uid: "U1".into(),
                raw_query: String::new(),
                account_id: Some("acct".into()),
                auth_time: Some(1),
                request_uri: None,
                browser_binding: String::new(),
            })
            .await;
        let (consumed, completed) = tokio::join!(store.consume_interaction("U1"), store.complete_interaction("U1", "acct", 2));
        let alive = store.get_interaction("U1").await.is_some();
        assert!(!(consumed && completed), "消費と書きの両方は通らない");
        if consumed {
            assert!(!alive, "消費済みの interaction が残っていない");
        }
    }
}
