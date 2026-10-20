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
pub(super) async fn login_form(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Path(uid): Path<String>,
    Query(q): Query<LoginQuery>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    if p.store.get_interaction(&uid).await.is_none() {
        let entry = match &q.client_id {
            Some(id) => p.resolve_client(id).await.and_then(|c| c.initiate_login_uri),
            None => None,
        };
        let Some(entry) = entry else {
            return plain_error(&localize("[[This sign-in has expired. Please start again.]]", lang));
        };
        tracing::info!(event = "login_reinitiated", client_id = q.client_id.as_deref().unwrap_or(""));
        let sep = if entry.contains('?') { '&' } else { '?' };
        let iss = serde_urlencoded::to_string([("iss", &p.issuer)]).unwrap_or_default();
        return Redirect::to(&format!("{entry}{sep}{iss}")).into_response();
    }
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
<button class="outlined" onclick="location.href='__CANCEL__'">[[Cancel]]</button>
<p id="msg"></p>
<script>
__WEBAUTHN_JS__
__SERVER_ERROR_JS__
const OPT="__OPT__",VER="__VER__";
const msgEl=document.getElementById('msg');
let cachedOpts=null;
async function prefetch(){
  try{const r=await fetch(OPT,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});cachedOpts=r.ok?await r.json():null;}
  catch{cachedOpts=null;}
}
prefetch();
async function pkLogin(){
 msgEl.textContent='';
 if(!window.PublicKeyCredential){msgEl.textContent='[[This browser does not support passkeys. Open this page in the standard Safari or Chrome app.]]';return;}
 try{
  let o=cachedOpts;
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
            .replace("__CANCEL__", &p.path(&format!("/login/{uid}/cancel")))
            .replace("__REGISTER__", &p.path("/signup")),
    )
    .into_response()
}

/// ログイン確定: まだ在る interaction にアカウントを書き、SSO セッション cookie を張り、resume パスを返す。
/// interaction が無い（消費済み・期限切れ）なら None。
async fn finalize_login(
    p: &Provider,
    jar: CookieJar,
    uid: &str,
    account_sub: String,
) -> Option<(CookieJar, String)> {
    let auth_time = now();
    if !p.store.complete_interaction(uid, &account_sub, auth_time).await {
        return None;
    }
    tracing::info!(event = "login_success", sub = %super::pseudonymize_sub(&account_sub));
    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session { sid: sid.clone(), account_id: account_sub, auth_time })
        .await;
    let cookie = Cookie::build((SID_COOKIE, sid))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    Some((jar.add(cookie), p.path(&format!("/authorize/resume?uid={uid}"))))
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
        match crate::registration::get_credential(fs, &email).await {
            Ok(Some(c)) => (
                serde_json::json!([{ "type": "public-key", "id": c.credential_id, "transports": ["internal", "hybrid"] }]),
                email.clone(),
            ),
            _ => (serde_json::json!([]), String::new()),
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
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email, kind, uid2, _) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
        Err(e) => {
            tracing::error!("consume challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    if kind != crate::registration::ChallengeKind::Auth || uid2 != uid {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
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
                _ => return (StatusCode::BAD_REQUEST, "cannot resolve user").into_response(),
            }
        }
        None => email,
    };
    if email.is_empty() {
        return (StatusCode::BAD_REQUEST, "cannot resolve user").into_response();
    }
    let cred = match crate::registration::get_credential(fs, &email).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::BAD_REQUEST, "credential not found").into_response(),
    };
    if cred.credential_id != req.id {
        return (StatusCode::BAD_REQUEST, "credential id mismatch").into_response();
    }
    let origin = p.origin();
    let rp_id = p.rp_id();
    match crate::webauthn::verify_authentication(
        &req.response.client_data_json,
        &req.response.authenticator_data,
        &req.response.signature,
        &challenge,
        &origin,
        &rp_id,
        &cred.pub_x,
        &cred.pub_y,
        cred.sign_count,
        false, // 通常ログインは UP のみ（従来通り）
    ) {
        Ok(new_count) => {
            let _ = crate::registration::update_sign_count(fs, &email, new_count).await;
        }
        Err(e) => {
            tracing::warn!(event = "login_failed", method = "passkey", "webauthn auth failed: {e}");
            return (StatusCode::UNAUTHORIZED, format!("passkey verify failed: {e}")).into_response();
        }
    }
    // disabled チェックは署名検証の後: これより前に判定を分岐させると、実 passkey を
    // 持たない第三者でも「このアカウントは凍結されているか」を判別できるオラクルになる。
    // 署名を検証し終えた=正規の所有者だと確認できてから初めて拒否理由を返す。
    if cred.disabled {
        tracing::warn!(event = "login_blocked_disabled", sub = %super::pseudonymize_sub(&cred.account_id));
        return (StatusCode::FORBIDDEN, "account disabled").into_response();
    }
    if cred.account_id.is_empty() {
        // 移行前（accountId 未発行）のアカウント。再登録が必要。
        return (StatusCode::BAD_REQUEST, "account needs re-registration").into_response();
    }
    let account = p.store.find_account(&cred.account_id).await;
    match finalize_login(&p, jar, &uid, account.sub).await {
        Some((jar, resume)) => (jar, Json(serde_json::json!({ "redirect": resume }))).into_response(),
        // 画面はこの固定文で期限切れと見て読み直す（SERVER_ERRORS・login_form の JS）。
        None => (StatusCode::BAD_REQUEST, "interaction not found").into_response(),
    }
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
        super::super::oidc::authorize_resume(State(p.clone()), HeaderMap::new(), Query(q)).await
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
            })
            .await;
        assert!(finalize_login(&p, CookieJar::default(), "U1", "acct".into()).await.is_some());
        let first = resume(&p, "U1").await;
        assert!(gave_code(&first), "1 回目の resume はコードを出す");

        assert!(finalize_login(&p, CookieJar::default(), "U1", "acct".into()).await.is_none(), "遅れた verify は書けない");
        assert!(p.store.get_interaction("U1").await.is_none(), "消費済みの interaction は作り直されない");
        let second = resume(&p, "U1").await;
        assert!(!gave_code(&second));
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
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
