//! メールで確かめて passkey を 1 本足す口（/recover）。passkey を失くした・この端末では使えない人のため。
//!
//! 既存の passkey は消さない（本人が自分の passkey で入り直し、覚えの無い 1 本を /account で消せるように）。
//! 足す前からあった passkey は、足してから RECOVERY_HOLD_SECS の間 /account で消せない（メールを奪った人が、
//! 本人の passkey を消して締め出せないように）。
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Recovery {
    Allowed,
    /// アカウントが無いか、passkey が 1 本も無い。登録し直しの道（/signup）へ行く。
    NoPasskey,
    /// 管理者か、凍結中か、accountId の無い壊れた文書。
    Refused,
}

/// メールで passkey を足してよいアカウントか。
pub(super) async fn recovery_for(fs: &crate::firestore::Firestore, email: &str) -> Result<Recovery, String> {
    let Some(a) = registration::get_account(fs, email).await? else {
        return Ok(Recovery::NoPasskey);
    };
    if a.disabled || a.account_id.is_empty() {
        return Ok(Recovery::Refused);
    }
    if registration::list_credentials(fs, &a).await?.is_empty() {
        return Ok(Recovery::NoPasskey);
    }
    if crate::admin_store::is_admin(fs, &a.account_id).await? {
        return Ok(Recovery::Refused);
    }
    Ok(Recovery::Allowed)
}

fn refused(r: Recovery) -> Response {
    match r {
        Recovery::NoPasskey => (StatusCode::CONFLICT, "no passkey to recover").into_response(),
        _ => (StatusCode::CONFLICT, "recovery unavailable").into_response(),
    }
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
    /// ログイン画面から来たときの interaction。送信で token の文書に移す（確かめるのは送信時）。
    #[serde(default)]
    uid: String,
}

fn clean_uid(uid: &str) -> String {
    uid.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(64).collect()
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
        let uid = clean_uid(&q.uid);
        let back = if uid.is_empty() {
            String::new()
        } else {
            format!(r#"<p class="small"><a href="{}">[[Back to sign in]]</a></p>"#, p.path(&format!("/login/{uid}")))
        };
        return page(
            lang,
            &format!(
                r#"<h1>[[Can’t use your passkey?]]</h1>
<p>[[Enter your email address. We will send a link to add a passkey on this device. When you use it, you are signed out on your other devices.]]</p>
<form method="post" action="{action}">
<input name="email" type="email" placeholder="[[Email address]]" autocomplete="email" autofocus>
<input type="hidden" name="uid" value="{uid}">
<button type="submit">[[Send email]]</button></form>{back}"#
            ),
        );
    }
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = match registration::peek_recovery(fs, &q.t).await {
        Ok(Some(e)) => e,
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
    };
    let token: String = q.t.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    // 既にこの端末に passkey があったときのログイン先。元のログインがまだ在ればそこ、無ければ /account。
    let from = registration::came_from(fs, &token).await;
    let login = if !from.uid.is_empty() && p.store.get_interaction(&from.uid).await.is_some() {
        p.path(&format!("/login/{}", from.uid))
    } else {
        super::account_url(&p, &from.client_id, false)
    };
    let body = r##"<h1>[[Add a passkey on this device]]</h1>
<p class="small">__EMAIL__</p>
<p>[[Create a passkey on this device to sign in again. Your other passkeys are kept. When you finish, you are signed out on your other devices.]]</p>
<p class="small" id="ioshint" hidden>[[On iPhone, choose “Passwords” (iCloud) when asked where to save the passkey. A passkey saved in Google Password Manager may ask for a PIN at sign-in.]]</p>
<button onclick="add()">[[Create a passkey]]</button>
<p id="msg"></p>
<script>
__WEBAUTHN_JS__
__SERVER_ERROR_JS__
const TOKEN="__TOKEN__",OPT="__OPT__",VER="__VER__",LOGIN="__LOGIN__";
const isIOS=/iPad|iPhone|iPod/i.test(navigator.userAgent)||(/(Macintosh).*Mobile/i.test(navigator.userAgent));
document.getElementById('ioshint').hidden=!isIOS;
const msg=document.getElementById('msg');
function post(u,b){return fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});}
async function add(){
 if(!window.PublicKeyCredential||!navigator.credentials){msg.textContent='[[Passkeys cannot be used in this browser. Open the link in Safari or Chrome.]]';return;}
 msg.textContent='[[Working…]]';
 try{
  const r=await post(OPT,{token:TOKEN});
  if(!r.ok){msg.textContent=await errorText(r);return;}
  const o=await r.json();
  const cred=await navigator.credentials.create({publicKey:{challenge:b64ToBuf(o.challenge),rp:o.rp,user:{id:b64ToBuf(o.user.id),name:o.user.name,displayName:o.user.displayName},pubKeyCredParams:o.pubKeyCredParams,authenticatorSelection:o.authenticatorSelection,attestation:o.attestation,timeout:o.timeout,excludeCredentials:(o.excludeCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id)}))}});
  const v=await post(VER,{token:TOKEN,response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),attestationObject:bufToB64(cred.response.attestationObject)}});
  if(!v.ok){msg.textContent=await errorText(v);return;}
  location.href=(await v.json()).redirect;
 }catch(e){
  if(e&&e.name==='InvalidStateError'){
   // 既に持っている。iOS は保存先を選び直せば足せる場合もあるが、どちらでもログインへ送れるようにする。
   msg.innerHTML=(isIOS?'[[A passkey for this account is already saved in the place you chose. Try again and choose “Passwords” (iCloud) as where to save it.]]':'[[A passkey for this account is already available on this device.]]')+' <a href="'+LOGIN+'">[[Sign in with it]]</a>';
   return;
  }
  msg.textContent=passkeyErrorText(e);
 }
}
</script>"##
        .replace("__SERVER_ERROR_JS__", SERVER_ERROR_JS);
    let html = shell(lang, &body)
        .replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
        .replace("__TOKEN__", &token)
        .replace("__EMAIL__", &super::admin::esc(&email))
        .replace("__OPT__", &p.path("/recover/options"))
        .replace("__VER__", &p.path("/recover/verify"))
        .replace("__LOGIN__", &login);
    // ページの URL に token が在る。外へのリンクで Referer に載せない。
    ([(header::CACHE_CONTROL, "no-store"), (header::REFERRER_POLICY, "no-referrer")], Html(html)).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct RecoverForm {
    email: String,
    #[serde(default)]
    uid: String,
}

/// POST /recover: 登録済みなら復旧のリンク、未登録なら登録のリンクを送る（どちらでも同じ画面を返す）。
pub(super) async fn recover_submit(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<RecoverForm>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = form.email.trim().to_lowercase();
    let from = super::came_from(&p, &jar, &form.uid).await;
    match super::register::issue_register_email(&p, fs, &email, &client_ip(&headers), Some(lang), &from).await {
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
    match recovery_for(fs, &email).await {
        Ok(Recovery::Allowed) => {}
        Ok(r) => return refused(r),
        Err(e) => return internal("recover_options: recovery_for", &e),
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
    // token は最後まで消費しない（challenge 切れや検証の失敗で、メールからやり直しにならないように）。
    let email = match registration::peek_recovery(fs, &req.token).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => return internal("recover_verify: peek token", &e),
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
    match recovery_for(fs, &email).await {
        Ok(Recovery::Allowed) => {}
        Ok(r) => return refused(r),
        Err(e) => return internal("recover_verify: recovery_for", &e),
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
    let from = registration::came_from(fs, &req.token).await;
    match registration::consume_recovery(fs, &req.token).await {
        Ok(Some(e)) if e == email => {}
        Ok(_) => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => return internal("recover_verify: consume token", &e),
    }
    // 保存から失効・監査までは、接続が切れても途中で止まらないよう別のタスクで最後まで行う。
    let task = {
        let p = p.clone();
        let (email, account_id) = (email.clone(), account_id.clone());
        tokio::spawn(async move { add_and_revoke(&p, &email, &account_id, &outcome).await })
    };
    let still_open = match task.await {
        Ok(Ok(open)) => open,
        Ok(Err(e)) => return internal("recover_verify", &e),
        Err(e) => return internal("recover_verify: task", &e.to_string()),
    };
    if let Some(old) = jar.get(SID_COOKIE).map(|c| c.value().to_string()) {
        p.store.delete_session(&old).await;
    }
    {
        let p = p.clone();
        let (email, lang) = (email.clone(), Lang::from_headers(&headers));
        tokio::spawn(async move {
            if let Err(e) = p.mailer.send_passkey_added(&email, Some(lang)).await {
                tracing::error!("send_passkey_added failed: {e}");
            }
        });
    }
    if !still_open {
        return (StatusCode::FORBIDDEN, "account disabled").into_response();
    }
    tracing::info!(event = "recover_passkey", sub = %pseudonymize_sub(&account_id));
    let redirect = super::continue_after_email(&p, &jar, &from, &account_id, true).await;
    let jar = start_session(&p, jar, account_id, now()).await;
    (jar, (StatusCode::CREATED, Json(serde_json::json!({ "ok": true, "redirect": redirect })))).into_response()
}

/// 復旧の時刻を残して passkey を足し、全部のセッションとトークンを失効させ、監査ログに残す。
/// 戻り値は、終わった時点でアカウントが凍結されていないか（凍結と重なったら、新しいセッションを張らない）。
async fn add_and_revoke(
    p: &Provider,
    email: &str,
    account_id: &str,
    outcome: &crate::webauthn::RegOutcome,
) -> Result<bool, String> {
    let fs = p.firestore.as_ref().ok_or("no firestore")?;
    registration::mark_recovered(fs, email, &outcome.credential_id).await?;
    registration::save_credential(fs, email, account_id, outcome).await?;
    let c = crate::account_admin::revoke_other_sessions(fs, account_id, "").await;
    if !c.query_errors.is_empty() {
        tracing::error!("recover_passkey: revocation incomplete for account_id={account_id}: {:?}", c.query_errors);
    }
    crate::audit_log::record(
        fs,
        account_id,
        "recover_passkey",
        account_id,
        &format!(
            "credential_id={} aaguid={} sessions={} access_tokens={} refresh_tokens={} query_errors={:?}",
            outcome.credential_id, outcome.aaguid, c.sessions, c.access_tokens, c.refresh_tokens, c.query_errors
        ),
    )
    .await;
    Ok(matches!(registration::get_account(fs, email).await?, Some(a) if !a.disabled))
}
