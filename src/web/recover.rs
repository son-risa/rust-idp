//! メールで確かめて passkey を 1 本足す口（/recover）。passkey を失くした・この端末では使えない人のため。
//!
//! 既存の passkey は消さない（本人が自分の passkey で入り直し、覚えの無い 1 本を /account で消せるように）。
//! メールだけで確かめるので、足したら全部のセッションとトークンを失効させ、本人に知らせる。
//! 管理者はこの口を使えない（受信箱を取られると IdP ごと取られるため）。管理者は別の管理者が戻す。

use super::*;
use crate::registration::{self, ChallengeKind};

/// この画面の challenge に入れる uid。登録・/account の challenge と分ける。
const CEREMONY_UID: &str = "recovery";

fn internal(context: &str, e: &str) -> Response {
    tracing::error!("{context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
}

/// メールで passkey を足してよいアカウントか。passkey が 1 本も無い人は登録し直しの道（/signup）へ行く。
pub(super) async fn recoverable(fs: &crate::firestore::Firestore, email: &str) -> Result<bool, String> {
    let Some(a) = registration::get_account(fs, email).await? else {
        return Ok(false);
    };
    if a.disabled || a.account_id.is_empty() {
        return Ok(false);
    }
    if registration::list_credentials(fs, &a).await?.is_empty() {
        return Ok(false);
    }
    Ok(!crate::admin_store::is_admin(fs, &a.account_id).await?)
}

fn shell(lang: Lang, body: &str) -> String {
    let html = format!(
        r#"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Can’t use your passkey?]]</title>
<style>body{{font-family:-apple-system,sans-serif;max-width:400px;margin:40px auto;padding:0 16px;color:#222;line-height:1.6}}
h1{{font-size:20px;margin:0 0 8px}}p{{font-size:14px}}.small{{font-size:12px;color:#5f6368}}
input{{display:block;width:100%;box-sizing:border-box;padding:10px;margin:8px 0;font-size:16px}}
button{{display:block;width:100%;padding:13px;margin-top:12px;font-size:16px;border:0;border-radius:8px;cursor:pointer;background:#3367d6;color:#fff}}
#msg{{font-size:14px;margin-top:14px;min-height:1.4em}}</style></head><body>{body}</body></html>"#
    );
    localize(&html, lang)
}

fn no_store(html: String) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

fn page(lang: Lang, body: &str) -> Response {
    no_store(shell(lang, body))
}

#[derive(serde::Deserialize)]
pub(super) struct RecoverQuery {
    #[serde(default)]
    t: String,
}

/// GET /recover: t が無ければメールアドレスを聞く。t があれば、この端末に passkey を足す画面。
pub(super) async fn recover_page(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Query(q): Query<RecoverQuery>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    if q.t.is_empty() {
        let action = p.path("/recover");
        return page(
            lang,
            &format!(
                r#"<h1>[[Can’t use your passkey?]]</h1>
<p>[[Enter your email address. We will send a link to add a passkey on this device. When you use it, you are signed out on your other devices.]]</p>
<form method="post" action="{action}">
<input name="email" type="email" placeholder="[[Email address]]" autocomplete="email" autofocus>
<button type="submit">[[Send email]]</button></form>"#
            ),
        );
    }
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    match registration::peek_recovery(fs, &q.t).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return page(
                lang,
                &format!(
                    r#"<h1>[[This link cannot be used]]</h1><p>[[This link has expired or has already been used.]]</p><p><a href="{again}">[[Send the email again]]</a></p>"#,
                    again = p.path("/recover")
                ),
            );
        }
        Err(e) => return internal("recover_page: peek", &e),
    }
    let token: String = q.t.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    let body = r##"<h1>[[Add a passkey on this device]]</h1>
<p>[[Create a passkey on this device to sign in again. Your other passkeys are kept. When you finish, you are signed out on your other devices.]]</p>
<p class="small" id="ioshint" hidden>[[On iPhone, choose “Passwords” (iCloud) when asked where to save the passkey. A passkey saved in Google Password Manager may ask for a PIN at sign-in.]]</p>
<button onclick="add()">[[Create a passkey]]</button>
<p id="msg"></p>
<script>
__WEBAUTHN_JS__
__SERVER_ERROR_JS__
const TOKEN="__TOKEN__",OPT="__OPT__",VER="__VER__",ACCOUNT="__ACCOUNT__";
const isIOS=/iPad|iPhone|iPod/i.test(navigator.userAgent)||(/(Macintosh).*Mobile/i.test(navigator.userAgent));
document.getElementById('ioshint').hidden=!isIOS;
const msg=document.getElementById('msg');
function post(u,b){return fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});}
async function add(){
 msg.textContent='[[Working…]]';
 try{
  const r=await post(OPT,{token:TOKEN});
  if(!r.ok){msg.textContent=await errorText(r);return;}
  const o=await r.json();
  const cred=await navigator.credentials.create({publicKey:{challenge:b64ToBuf(o.challenge),rp:o.rp,user:{id:b64ToBuf(o.user.id),name:o.user.name,displayName:o.user.displayName},pubKeyCredParams:o.pubKeyCredParams,authenticatorSelection:o.authenticatorSelection,attestation:o.attestation,timeout:o.timeout,excludeCredentials:(o.excludeCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id)}))}});
  const v=await post(VER,{token:TOKEN,response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),attestationObject:bufToB64(cred.response.attestationObject)}});
  if(!v.ok){msg.textContent=await errorText(v);return;}
  location.href=ACCOUNT;
 }catch(e){msg.textContent=(e&&e.name==='InvalidStateError')?(isIOS?'[[A passkey for this account is already saved in the place you chose. Try again and choose “Passwords” (iCloud) as where to save it.]]':'[[A passkey for this account is already saved here.]]'):passkeyErrorText(e);}
}
</script>"##
        .replace("__SERVER_ERROR_JS__", SERVER_ERROR_JS);
    let html = shell(lang, &body)
        .replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
        .replace("__TOKEN__", &token)
        .replace("__OPT__", &p.path("/recover/options"))
        .replace("__VER__", &p.path("/recover/verify"))
        .replace("__ACCOUNT__", &p.path("/account"));
    no_store(html)
}

#[derive(serde::Deserialize)]
pub(super) struct RecoverForm {
    email: String,
}

/// POST /recover: 登録済みなら復旧のリンク、未登録なら登録のリンクを送る（どちらでも同じ画面を返す）。
pub(super) async fn recover_submit(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<RecoverForm>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = form.email.trim().to_lowercase();
    match super::register::issue_register_email(&p, fs, &email, &client_ip(&headers), Some(lang)).await {
        Ok(()) => page(
            lang,
            "<h1>[[Email sent]]</h1><p>[[If this address is registered, we sent a link to add a passkey on this device. Open it on the device you want to use (the link expires in 15 minutes).]]</p>",
        ),
        Err(e) if e == "invalid email" => plain_error(&localize("[[Enter a valid email address.]]", lang)),
        Err(e) if e == "rate_limited" => (
            StatusCode::TOO_MANY_REQUESTS,
            localize("[[Too many requests. Please try again later.]]", lang),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("recover_submit: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, localize("[[Something went wrong. Please try again.]]", lang)).into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub(super) struct RecoverOptionsReq {
    token: String,
}

pub(super) async fn recover_options(State(p): State<Arc<Provider>>, Json(req): Json<RecoverOptionsReq>) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = match registration::peek_recovery(fs, &req.token).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => return internal("recover_options: peek", &e),
    };
    match recoverable(fs, &email).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::CONFLICT, "recovery unavailable").into_response(),
        Err(e) => return internal("recover_options: recoverable", &e),
    }
    let account = match registration::get_account(fs, &email).await {
        Ok(Some(a)) => a,
        Ok(None) => return (StatusCode::CONFLICT, "recovery unavailable").into_response(),
        Err(e) => return internal("recover_options: get_account", &e),
    };
    let creds = match registration::list_credentials(fs, &account).await {
        Ok(c) => c,
        Err(e) => return internal("recover_options: list_credentials", &e),
    };
    let challenge =
        match registration::create_webauthn_challenge(fs, &email, ChallengeKind::Reg, CEREMONY_UID, &account.account_id).await {
            Ok(c) => c,
            Err(e) => return internal("recover_options: create challenge", &e),
        };
    Json(super::register::creation_options(&p, &challenge, &account.account_id, &email, &creds)).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct RecoverVerifyReq {
    token: String,
    response: super::register::RegResponse,
}

/// passkey を足し、全部のセッションとトークンを失効させてから、この端末に新しいセッションを張り、本人に知らせる。
pub(super) async fn recover_verify(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<RecoverVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = match registration::consume_recovery(fs, &req.token).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => return internal("recover_verify: consume token", &e),
    };
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email2, kind, uid, account_id) = match registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
        Err(e) => return internal("recover_verify: consume challenge", &e),
    };
    if kind != ChallengeKind::Reg || uid != CEREMONY_UID || email2 != email {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
    }
    match recoverable(fs, &email).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::CONFLICT, "recovery unavailable").into_response(),
        Err(e) => return internal("recover_verify: recoverable", &e),
    }
    match registration::get_account(fs, &email).await {
        Ok(Some(a)) if a.account_id == account_id => {}
        Ok(_) => return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response(),
        Err(e) => return internal("recover_verify: get_account", &e),
    }
    let outcome = match crate::webauthn::verify_registration(
        &req.response.client_data_json,
        &req.response.attestation_object,
        &challenge,
        &p.origin(),
        &p.rp_id(),
    ) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("webauthn reg failed: {e}");
            return (StatusCode::BAD_REQUEST, format!("registration failed: {e}")).into_response();
        }
    };
    if let Err(e) = registration::save_credential(fs, &email, &account_id, &outcome).await {
        return internal("recover_verify: save_credential", &e);
    }
    let c = crate::account_admin::revoke_other_sessions(fs, &account_id, "").await;
    if let Some(old) = jar.get(SID_COOKIE).map(|c| c.value().to_string()) {
        p.store.delete_session(&old).await;
    }
    crate::audit_log::record(
        fs,
        &account_id,
        "recover_passkey",
        &account_id,
        &format!(
            "credential_id={} aaguid={} sessions={} access_tokens={} refresh_tokens={} query_errors={:?}",
            outcome.credential_id, outcome.aaguid, c.sessions, c.access_tokens, c.refresh_tokens, c.query_errors
        ),
    )
    .await;
    if let Err(e) = p.mailer.send_passkey_added(&email, Some(Lang::from_headers(&headers))).await {
        tracing::error!("send_passkey_added failed: {e}");
    }
    tracing::info!(event = "recover_passkey", sub = %pseudonymize_sub(&account_id));
    let jar = start_session(&p, jar, account_id, now()).await;
    (jar, (StatusCode::CREATED, Json(serde_json::json!({ "ok": true })))).into_response()
}
