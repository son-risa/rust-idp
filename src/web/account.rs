//! 本人の passkey の画面（/account）。ログインしている人が、自分の passkey を見て、足して、消す。
//!
//! 足すと消すは、passkey で本人と確かめてから RECENT_AUTH_SECS の間だけ許す。セッションは 7 日続くので、
//! cookie を盗んだ人が自分の passkey を足して居座れないようにする。

use super::admin::esc;
use super::*;
use crate::registration::{self, ChallengeKind, RemoveOutcome};

const RECENT_AUTH_SECS: u64 = 10 * 60;
/// 1 アカウントの passkey の上限。
const MAX_PASSKEYS: usize = 10;
/// この画面の challenge に入れる uid。ログイン（interaction の uid）と登録（空）の challenge と分ける。
const CEREMONY_UID: &str = "account";
/// メールで passkey を足した（復旧した）後、それより前からあった passkey を消せない時間。
const RECOVERY_HOLD_SECS: u64 = 24 * 60 * 60;

/// 復旧の直後で、この passkey を本人の画面から消せないか。
fn held_by_recovery(a: &registration::Account, c: &registration::Credential) -> bool {
    a.recovered_at > 0
        && now().saturating_sub(a.recovered_at) < RECOVERY_HOLD_SECS
        && c.created_at <= a.recovered_at
        && c.credential_id != a.recovered_with
}

struct Me {
    sid: String,
    auth_time: u64,
    account: registration::Account,
}

impl Me {
    fn confirmed_recently(&self) -> bool {
        now().saturating_sub(self.auth_time) <= RECENT_AUTH_SECS
    }
}

async fn me(p: &Provider, fs: &crate::firestore::Firestore, jar: &CookieJar) -> Result<Option<Me>, String> {
    let Some(sid) = jar.get(SID_COOKIE).map(|c| c.value().to_string()) else {
        return Ok(None);
    };
    let Some(s) = p.store.get_session(&sid).await else {
        return Ok(None);
    };
    let Some(email) = registration::find_email_by_account_id(fs, &s.account_id).await? else {
        return Ok(None);
    };
    let Some(account) = registration::get_account(fs, &email).await? else {
        return Ok(None);
    };
    if account.disabled || account.account_id != s.account_id {
        return Ok(None);
    }
    Ok(Some(Me { sid, auth_time: s.auth_time, account }))
}

fn internal(context: &str, e: &str) -> Response {
    tracing::error!("{context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
}

/// 足す・消すの前の確かめ。ログインしていなければ 401 の "sign-in required"、
/// 本人と確かめてから時間が経っていれば 401 の "confirmation required"。
async fn me_confirmed(p: &Provider, jar: &CookieJar) -> Result<Me, Response> {
    let fs = p
        .firestore
        .as_ref()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response())?;
    let me = match me(p, fs, jar).await {
        Ok(Some(m)) => m,
        Ok(None) => return Err((StatusCode::UNAUTHORIZED, "sign-in required").into_response()),
        Err(e) => return Err(internal("account: me", &e)),
    };
    if !me.confirmed_recently() {
        return Err((StatusCode::UNAUTHORIZED, "confirmation required").into_response());
    }
    Ok(me)
}

#[derive(serde::Deserialize, Default)]
pub(super) struct AccountQuery {
    #[serde(default)]
    recovered: Option<String>,
    /// メールのリンクで passkey を作った後、元の RP へ戻るボタンを出すための client。入口が登録済みのときだけ出す。
    #[serde(default)]
    client_id: Option<String>,
}

pub(super) async fn account_page(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<AccountQuery>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let me = match me(&p, fs, &jar).await {
        Ok(m) => m,
        Err(e) => return internal("account_page: me", &e),
    };
    let (main, confirmed) = match &me {
        None => (
            r#"<p>[[Sign in with your passkey to see and add passkeys.]]</p>
<button class="primary" onclick="signIn().then(ok=>{if(ok)location.reload();})">[[Sign in with a passkey]]</button>
<p class="small"><a href="__RECOVER__">[[Can’t use your passkey?]]</a></p>
<p class="small" id="qrhint" hidden>[[If this computer has no passkey, press sign in and scan the QR code that appears with the phone that has your passkey.]]</p>"#
                .to_string(),
            false,
        ),
        Some(m) => {
            let creds = match registration::list_credentials(fs, &m.account).await {
                Ok(c) => c,
                Err(e) => return internal("account_page: list_credentials", &e),
            };
            let only_one = creds.len() <= 1;
            let rows: String = creds
                .iter()
                .map(|c| {
                    let name = crate::webauthn::authenticator_name(&c.aaguid).unwrap_or("[[Passkey]]");
                    let last = match c.last_used_at {
                        Some(t) => format!(r#"[[Last used]]: <time data-ts="{t}"></time>"#),
                        None => "[[Not used yet]]".to_string(),
                    };
                    let remove = if only_one {
                        String::new()
                    } else if held_by_recovery(&m.account, c) {
                        r#"<div class="sub">[[This passkey can be removed 24 hours after a passkey was added with email.]]</div>"#.to_string()
                    } else {
                        format!(
                            r#"<button class="link" data-id="{id}" onclick="del(this.dataset.id)">[[Remove]]</button>"#,
                            id = esc(&c.credential_id)
                        )
                    };
                    // 11-21 の移し替え前の passkey は登録日を持たない（0）。
                    let created = if c.created_at == 0 {
                        String::new()
                    } else {
                        format!(r#"[[Registered]]: <time data-ts="{}"></time> · "#, c.created_at)
                    };
                    format!(
                        r#"<li><div class="nm">{name}</div><div class="sub">{created}{last}</div>{remove}</li>"#,
                        name = esc(name),
                    )
                })
                .collect();
            let gpm_only = !creds.is_empty()
                && creds.iter().all(|c| c.aaguid == crate::webauthn::GOOGLE_PASSWORD_MANAGER);
            let gpm_hint = if gpm_only {
                r#"<p class="small" id="gpmhint" hidden>[[Your passkey is saved in Google Password Manager, which may ask for a PIN at sign-in on iPhone. Add a passkey and choose “Passwords” (iCloud) as where to save it.]]</p>"#
            } else {
                ""
            };
            let back = match super::client_entry(&p, q.client_id.as_deref().unwrap_or("")).await {
                Some(entry) => {
                    let host = entry.split("://").nth(1).and_then(|r| r.split(['/', '?', ':']).next()).unwrap_or("");
                    format!(
                        r#"<a class="primary" href="{href}">[[Back to the app]]</a><p class="small" style="text-align:center">{host}</p>"#,
                        href = esc(&entry),
                        host = esc(host),
                    )
                }
                None => String::new(),
            };
            (
                format!(
                    r#"{recovered}{back}{phone}<p class="sub">{email}</p>
<ul class="pk">{rows}</ul>
{gpm_hint}
<button class="primary" onclick="add()">[[Add a passkey on this device]]</button>
<p class="small">[[On iPhone, choose “Passwords” (iCloud) when asked where to save the passkey.]]</p>
<form class="small" method="post" action="__LOGOUT__"><input type="hidden" name="confirm" value="1"><button type="submit" class="signout">[[Sign out]]</button></form>"#,
                    email = esc(&m.account.email),
                    // メールのリンクで作り終えて来た（別の端末で始めたかもしれない）ときだけ、元のパソコンでの続け方を添える。
                    phone = if q.recovered.is_some() || q.client_id.is_some() {
                        r#"<p class="small" id="phonehint" hidden>[[To continue on your computer, press sign in there and scan the QR code that appears with this phone.]]</p>"#
                    } else {
                        ""
                    },
                    recovered = if q.recovered.is_some() {
                        r#"<p>[[The passkey was added. Go back to the app or service and sign in again.]]</p>"#
                    } else {
                        ""
                    },
                ),
                m.confirmed_recently(),
            )
        }
    };
    let body = r##"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Passkeys]]</title>
<style>body{font-family:-apple-system,sans-serif;max-width:420px;margin:40px auto;padding:0 16px;color:#222}
h1{font-size:20px;margin:0 0 8px}p{font-size:14px;line-height:1.6}.sub{color:#5f6368;font-size:13px}
.small{font-size:12px;color:#5f6368;margin-top:8px}
button.primary,a.primary{display:block;box-sizing:border-box;width:100%;padding:13px;margin-top:16px;font-size:16px;border:0;border-radius:8px;cursor:pointer;background:#3367d6;color:#fff;text-align:center;text-decoration:none}
button.link{background:none;border:0;color:#c5221f;padding:4px 0;font-size:13px;cursor:pointer}
button.signout{background:none;border:0;padding:0;font:inherit;color:#3367d6;text-decoration:underline;cursor:pointer}
ul.pk{list-style:none;padding:0;margin:12px 0}ul.pk li{border:1px solid #e0e0e0;border-radius:8px;padding:10px 12px;margin:8px 0}
.nm{font-size:15px}#msg{font-size:14px;margin-top:14px;min-height:1.4em}</style></head><body>
<h1>[[Passkeys]]</h1>
__MAIN__
<p id="msg"></p>
<script>
__WEBAUTHN_JS__
__SERVER_ERROR_JS__
const SIGNIN_OPT="__SIGNIN_OPT__",SIGNIN_VER="__SIGNIN_VER__",ADD_OPT="__ADD_OPT__",ADD_VER="__ADD_VER__",DEL="__DEL__";
let confirmed=__CONFIRMED__;
const isIOS=/iPad|iPhone|iPod/i.test(navigator.userAgent)||(/(Macintosh).*Mobile/i.test(navigator.userAgent));
const hint=document.getElementById('gpmhint');if(hint)hint.hidden=!isIOS;
const isPhone=isIOS||/Android/i.test(navigator.userAgent);
const qr=document.getElementById('qrhint');if(qr)qr.hidden=isPhone;
const ph=document.getElementById('phonehint');if(ph)ph.hidden=!isPhone;
document.querySelectorAll('time[data-ts]').forEach(t=>{t.textContent=new Date(Number(t.dataset.ts)*1000).toLocaleDateString(document.documentElement.lang);});
const msg=document.getElementById('msg');
function post(u,b){return fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b||{})});}
async function signIn(){
 msg.textContent='[[Working…]]';
 try{
  const r=await post(SIGNIN_OPT);
  if(!r.ok){msg.textContent=await errorText(r);return false;}
  const o=await r.json();
  const a=await navigator.credentials.get({publicKey:{challenge:b64ToBuf(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:o.userVerification,allowCredentials:(o.allowCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id),transports:c.transports}))}});
  const v=await post(SIGNIN_VER,{id:a.id,response:{clientDataJSON:bufToB64(a.response.clientDataJSON),authenticatorData:bufToB64(a.response.authenticatorData),signature:bufToB64(a.response.signature),userHandle:a.response.userHandle?bufToB64(a.response.userHandle):null}});
  if(!v.ok){msg.textContent=await errorText(v);return false;}
  msg.textContent='';confirmed=true;return true;
 }catch(e){msg.textContent=passkeyErrorText(e);return false;}
}
async function add(){
 if(!confirmed&&!await signIn())return;
 msg.textContent='[[Working…]]';
 try{
  const r=await post(ADD_OPT);
  if(!r.ok){msg.textContent=await errorText(r);return;}
  const o=await r.json();
  const cred=await navigator.credentials.create({publicKey:{challenge:b64ToBuf(o.challenge),rp:o.rp,user:{id:b64ToBuf(o.user.id),name:o.user.name,displayName:o.user.displayName},pubKeyCredParams:o.pubKeyCredParams,authenticatorSelection:o.authenticatorSelection,attestation:o.attestation,timeout:o.timeout,excludeCredentials:(o.excludeCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id)}))}});
  const v=await post(ADD_VER,{response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),attestationObject:bufToB64(cred.response.attestationObject)}});
  if(!v.ok){msg.textContent=await errorText(v);return;}
  location.reload();
 }catch(e){msg.textContent=(e&&e.name==='InvalidStateError')?(isIOS?'[[A passkey for this account is already saved in the place you chose. Try again and choose “Passwords” (iCloud) as where to save it.]]':'[[A passkey for this account is already saved here.]]'):passkeyErrorText(e);}
}
async function del(id){
 if(!confirm('[[Remove this passkey? You can no longer sign in with it, and you are signed out on your other devices.]]'))return;
 if(!confirmed&&!await signIn())return;
 const v=await post(DEL,{id:id});
 if(!v.ok){msg.textContent=await errorText(v);return;}
 location.reload();
}
</script></body></html>"##;
    let html = localize(
        &body
            .replace("__SERVER_ERROR_JS__", SERVER_ERROR_JS)
            .replace("__MAIN__", &main),
        lang,
    )
    .replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
    .replace("__SIGNIN_OPT__", &p.path("/account/signin/options"))
    .replace("__SIGNIN_VER__", &p.path("/account/signin/verify"))
    .replace("__ADD_OPT__", &p.path("/account/passkeys/options"))
    .replace("__ADD_VER__", &p.path("/account/passkeys/verify"))
    .replace("__DEL__", &p.path("/account/passkeys/delete"))
    .replace("__RECOVER__", &p.path("/recover"))
    .replace("__LOGOUT__", &p.path("/end-session"))
    .replace("__CONFIRMED__", if confirmed { "true" } else { "false" });
    ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

/// 本人と確かめる（ログインしていなければ、ログインする）ための assertion の options。
/// ログインしていればその人の passkey に絞る。
pub(super) async fn signin_options(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let me = match me(&p, fs, &jar).await {
        Ok(m) => m,
        Err(e) => return internal("signin_options: me", &e),
    };
    let (allow, email) = match &me {
        Some(m) => match registration::list_credentials(fs, &m.account).await {
            Ok(creds) => (
                creds
                    .iter()
                    .map(|c| serde_json::json!({ "type": "public-key", "id": c.credential_id, "transports": ["internal", "hybrid"] }))
                    .collect::<Vec<_>>(),
                m.account.email.clone(),
            ),
            Err(e) => return internal("signin_options: list_credentials", &e),
        },
        None => (vec![], String::new()),
    };
    let challenge = match registration::create_webauthn_challenge(fs, &email, ChallengeKind::Auth, CEREMONY_UID, "").await {
        Ok(c) => c,
        Err(e) => return internal("signin_options: create challenge", &e),
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

/// assertion を確かめ、新しいセッションを張る（auth_time は今）。前のセッションは消す。
pub(super) async fn signin_verify(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Json(req): Json<AuthVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let account = match super::login::verify_assertion(&p, fs, &req, CEREMONY_UID).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(old) = jar.get(SID_COOKIE).map(|c| c.value().to_string()) {
        p.store.delete_session(&old).await;
    }
    tracing::info!(event = "account_signin", sub = %pseudonymize_sub(&account.account_id));
    let jar = start_session(&p, jar, account.account_id, now()).await;
    (jar, Json(serde_json::json!({ "ok": true }))).into_response()
}

pub(super) async fn add_options(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let me = match me_confirmed(&p, &jar).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let fs = p.firestore.as_ref().expect("me_confirmed checked firestore");
    let creds = match registration::list_credentials(fs, &me.account).await {
        Ok(c) => c,
        Err(e) => return internal("add_options: list_credentials", &e),
    };
    if creds.len() >= MAX_PASSKEYS {
        return (StatusCode::CONFLICT, "too many passkeys").into_response();
    }
    let a = &me.account;
    let challenge = match registration::create_webauthn_challenge(fs, &a.email, ChallengeKind::Reg, CEREMONY_UID, &a.account_id).await {
        Ok(c) => c,
        Err(e) => return internal("add_options: create challenge", &e),
    };
    Json(super::register::creation_options(&p, &challenge, &a.account_id, &a.email, &creds)).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct AddVerifyReq {
    response: super::register::RegResponse,
}

pub(super) async fn add_verify(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Json(req): Json<AddVerifyReq>,
) -> Response {
    let me = match me_confirmed(&p, &jar).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let fs = p.firestore.as_ref().expect("me_confirmed checked firestore");
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email, kind, uid, account_id) = match registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
        Err(e) => return internal("add_verify: consume challenge", &e),
    };
    if kind != ChallengeKind::Reg || uid != CEREMONY_UID || email != me.account.email || account_id != me.account.account_id {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
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
    match registration::list_credentials(fs, &me.account).await {
        Ok(c) if c.len() >= MAX_PASSKEYS => return (StatusCode::CONFLICT, "too many passkeys").into_response(),
        Ok(_) => {}
        Err(e) => return internal("add_verify: list_credentials", &e),
    }
    if let Err(e) = registration::save_credential(fs, &email, &account_id, &outcome).await {
        return internal("add_verify: save_credential", &e);
    }
    // 確かめた後に、管理者が passkey を全部消してセッションを失効させていたら、足した 1 本も消す
    // （失効させてから消すので、消す前に足したものは消され、消した後に足したものはここで見つかる）。
    if p.store.get_session(&me.sid).await.is_none() {
        if let Err(e) = registration::discard_credential(fs, &email, &outcome.credential_id).await {
            tracing::error!("add_verify: passkey added after revocation was not removed: {e}");
        }
        return (StatusCode::UNAUTHORIZED, "sign-in required").into_response();
    }
    crate::audit_log::record(
        fs,
        &account_id,
        "add_passkey",
        &account_id,
        &format!("credential_id={} aaguid={}", outcome.credential_id, outcome.aaguid),
    )
    .await;
    (StatusCode::CREATED, Json(serde_json::json!({ "ok": true }))).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct DeleteReq {
    id: String,
}

pub(super) async fn delete_passkey(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Json(req): Json<DeleteReq>,
) -> Response {
    let me = match me_confirmed(&p, &jar).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let fs = p.firestore.as_ref().expect("me_confirmed checked firestore");
    let a = &me.account;
    match registration::list_credentials(fs, a).await {
        Ok(creds) if creds.iter().any(|c| c.credential_id == req.id && held_by_recovery(a, c)) => {
            return (StatusCode::CONFLICT, "recently recovered").into_response();
        }
        Ok(_) => {}
        Err(e) => return internal("delete_passkey: list_credentials", &e),
    }
    match registration::remove_credential(fs, &a.email, &req.id).await {
        Ok(RemoveOutcome::Removed) => {
            let c = crate::account_admin::revoke_other_sessions(fs, &a.account_id, &me.sid).await;
            crate::audit_log::record(
                fs,
                &a.account_id,
                "delete_passkey",
                &a.account_id,
                &format!(
                    "credential_id={} other_sessions={} access_tokens={} refresh_tokens={} query_errors={:?}",
                    req.id, c.sessions, c.access_tokens, c.refresh_tokens, c.query_errors
                ),
            )
            .await;
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Ok(RemoveOutcome::NotFound) => (StatusCode::NOT_FOUND, "passkey not found").into_response(),
        Ok(RemoveOutcome::LastOne) => (StatusCode::CONFLICT, "last passkey").into_response(),
        Err(e) => internal("delete_passkey", &e),
    }
}
