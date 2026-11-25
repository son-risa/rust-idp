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

async fn me(p: &Provider, fs: &dyn crate::document_store::DocumentStore, jar: &CookieJar) -> Result<Option<Me>, String> {
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
        .docs
        .as_deref()
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

/// 利用者の名前を、localize と後ろの `__X__` の置き換えに拾われない形で HTML に入れる。
fn esc_name(s: &str) -> String {
    esc(s).replace('[', "&#91;").replace('_', "&#95;")
}

pub(super) async fn account_page(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<AccountQuery>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let fs = match p.docs.as_deref() {
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
            let name = match registration::get_profile(fs, &m.account.account_id).await {
                Ok(mut pr) => pr.remove("name").unwrap_or_default(),
                Err(e) => return internal("account_page: get_profile", &e),
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
<form class="name" onsubmit="saveName();return false;"><label for="name">[[Name]]</label><div><input id="name" name="name" maxlength="80" autocomplete="name" value="{name}"><button type="submit">[[Save]]</button></div></form><p class="small" id="namemsg"></p>
<ul class="pk">{rows}</ul>
{gpm_hint}
<button class="primary" onclick="add()">[[Add a passkey on this device]]</button>
<p class="small">[[On iPhone, choose “Passwords” (iCloud) when asked where to save the passkey.]]</p>
<form class="small" method="post" action="__LOGOUT__"><input type="hidden" name="confirm" value="1"><button type="submit" class="signout">[[Sign out]]</button></form>"#,
                    email = esc(&m.account.email),
                    name = esc_name(&name),
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
form.name label{display:block;font-size:14px;margin-top:12px}form.name div{display:flex;gap:8px;margin-top:4px}form.name input{flex:1;min-width:0;padding:10px;font-size:16px}form.name button{padding:0 16px;font-size:15px;border:1px solid #3367d6;border-radius:8px;background:#fff;color:#3367d6;cursor:pointer}
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
const SIGNIN_OPT="__SIGNIN_OPT__",SIGNIN_VER="__SIGNIN_VER__",ADD_OPT="__ADD_OPT__",ADD_VER="__ADD_VER__",DEL="__DEL__",PROFILE="__PROFILE__";
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
async function saveName(){
 const f=document.getElementById('name'),m=document.getElementById('namemsg');
 m.textContent='';
 if(!confirmed&&!await signIn())return;
 let v=await post(PROFILE,{name:f.value});
 if(v.status===401){confirmed=false;if(!await signIn())return;v=await post(PROFILE,{name:f.value});}
 if(!v.ok){m.textContent=await errorText(v);return;}
 f.value=(await v.json()).name;
 m.textContent='[[The name was saved.]]';
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
    .replace("__PROFILE__", &p.path("/account/profile"))
    .replace("__RECOVER__", &p.path("/recover"))
    .replace("__LOGOUT__", &p.path("/end-session"))
    .replace("__CONFIRMED__", if confirmed { "true" } else { "false" });
    ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

/// 本人と確かめる（ログインしていなければ、ログインする）ための assertion の options。
/// ログインしていればその人の passkey に絞る。
pub(super) async fn signin_options(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let fs = match p.docs.as_deref() {
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
    let fs = match p.docs.as_deref() {
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
    let fs = p.docs.as_deref().expect("me_confirmed checked firestore");
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
    let fs = p.docs.as_deref().expect("me_confirmed checked firestore");
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
    let fs = p.docs.as_deref().expect("me_confirmed checked firestore");
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

#[derive(serde::Deserialize)]
pub(super) struct ProfileReq {
    #[serde(default)]
    name: String,
}

/// 名前（profiles の name）を変える。検査は save_profile のもの（RP の `PUT /me/profile` と同じ）。
/// 空にすれば name を消す。保存した値（前後の空白を除いたもの）を返す。
/// 画面の saveName() は、確かめが切れて 401 なら確かめ直して 1 度だけ送り直す。打った値は残す。
pub(super) async fn save_name(State(p): State<Arc<Provider>>, jar: CookieJar, Json(f): Json<ProfileReq>) -> Response {
    let me = match me_confirmed(&p, &jar).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let fs = p.docs.as_deref().expect("me_confirmed checked firestore");
    let saved = f.name.trim().to_string();
    let updates = HashMap::from([("name".to_string(), f.name)]);
    match registration::save_profile(fs, &me.account.account_id, &updates).await {
        Ok(()) => Json(serde_json::json!({ "ok": true, "name": saved })).into_response(),
        Err(registration::ProfileError::Invalid(_)) => (StatusCode::BAD_REQUEST, "invalid name").into_response(),
        Err(e) => internal("save_name", &e.to_string()),
    }
}

#[cfg(all(test, feature = "gcp"))]
mod tests {
    use super::*;
    use crate::firestore::{fake_firestore, Firestore};
    use tower::ServiceExt;

    const ORIGIN: &str = "https://idp.example";

    struct World {
        app: Router,
        fs: Arc<Firestore>,
        store: Arc<crate::firestore_store::FirestoreStore>,
    }

    /// u@example.com（acc-u）が passkey を 1 本持つ。
    async fn world() -> World {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Arc::new(Firestore::new_for_test("proj", host));
        let store = Arc::new(crate::firestore_store::FirestoreStore::new(fs.clone()));
        let outcome = crate::webauthn::RegOutcome {
            credential_id: "cred-u".into(),
            pub_x: "x".into(),
            pub_y: "y".into(),
            sign_count: 0,
            aaguid: String::new(),
        };
        registration::save_credential(&*fs, "u@example.com", "acc-u", &outcome).await.unwrap();
        let p = Provider::new(format!("{ORIGIN}/oidc"))
            .with_base_path("/oidc")
            .with_firestore(fs.clone())
            .with_store(store.clone());
        World { app: router(p), fs, store }
    }

    impl World {
        async fn session(&self, auth_time: u64) -> String {
            use crate::store::Store;
            let sid = Uuid::new_v4().to_string();
            self.store.save_session(Session { sid: sid.clone(), account_id: "acc-u".into(), auth_time }).await;
            sid
        }

        async fn post(&self, sid: Option<&str>, origin: Option<&str>, name: &str) -> Response {
            let mut req = axum::http::Request::post("/oidc/account/profile").header(header::CONTENT_TYPE, "application/json");
            if let Some(s) = sid {
                req = req.header(header::COOKIE, format!("{SID_COOKIE}={s}"));
            }
            if let Some(o) = origin {
                req = req.header(header::ORIGIN, o);
            }
            let body = serde_json::json!({ "name": name }).to_string();
            self.app.clone().oneshot(req.body(axum::body::Body::from(body)).unwrap()).await.unwrap()
        }

        async fn page(&self, sid: &str) -> String {
            let req = axum::http::Request::get("/oidc/account")
                .header(header::COOKIE, format!("{SID_COOKIE}={sid}"))
                .header(header::ACCEPT_LANGUAGE, "ja");
            let resp = self.app.clone().oneshot(req.body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            body(resp).await
        }

        async fn name(&self) -> Option<String> {
            registration::get_profile(&*self.fs, "acc-u").await.unwrap().remove("name")
        }

        async fn claims(&self) -> HashMap<String, serde_json::Value> {
            crate::store::Store::find_account(&*self.store, "acc-u").await.claims
        }
    }

    async fn body(r: Response) -> String {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(b.to_vec()).unwrap()
    }

    async fn json(r: Response) -> serde_json::Value {
        serde_json::from_str(&body(r).await).unwrap()
    }

    #[tokio::test]
    async fn the_name_is_saved_and_the_page_shows_it() {
        let w = world().await;
        let sid = w.session(now()).await;
        let r = w.post(Some(&sid), Some(ORIGIN), " 山田　太郎 ").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(json(r).await, serde_json::json!({ "ok": true, "name": "山田　太郎" }));
        assert_eq!(w.name().await.as_deref(), Some("山田　太郎"));
        let html = w.page(&sid).await;
        assert!(html.contains(r#"value="山田　太郎""#), "{html}");
        assert!(html.contains(r#"PROFILE="/oidc/account/profile""#), "{html}");
        assert!(html.contains("m.textContent='氏名を保存しました。'"), "{html}");
    }

    /// 空にすると name の field を消し、RP に空の name を渡さない。他の field には触れない。
    #[tokio::test]
    async fn an_empty_name_removes_the_name_and_keeps_the_other_fields() {
        let w = world().await;
        let sid = w.session(now()).await;
        let nick = HashMap::from([("nickname".to_string(), "taro".to_string())]);
        registration::save_profile(&*w.fs, "acc-u", &nick).await.unwrap();
        assert_eq!(w.post(Some(&sid), Some(ORIGIN), "Taro").await.status(), StatusCode::OK);
        let r = w.post(Some(&sid), Some(ORIGIN), "   ").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(json(r).await, serde_json::json!({ "ok": true, "name": "" }));
        let doc = w.fs.get_doc("profiles", "acc-u").await.unwrap().unwrap();
        assert_eq!(crate::firestore::field_str(&doc, "name"), None, "{doc}");
        assert_eq!(crate::firestore::field_str(&doc, "nickname"), Some("taro"), "{doc}");
        let claims = w.claims().await;
        assert!(!claims.contains_key("name"), "{claims:?}");
        assert_eq!(claims["nickname"], "taro");
    }

    /// 前に空のまま保存された name も、RP には渡さない。
    #[tokio::test]
    async fn a_name_saved_empty_before_is_not_a_claim() {
        let w = world().await;
        let doc = serde_json::json!({ "email": crate::firestore::s("acc-u"), "name": crate::firestore::s("") });
        w.fs.set_doc("profiles", "acc-u", doc).await.unwrap();
        let claims = w.claims().await;
        assert!(!claims.contains_key("name"), "{claims:?}");
    }

    #[tokio::test]
    async fn a_post_from_another_origin_or_from_nowhere_is_refused() {
        let w = world().await;
        let sid = w.session(now()).await;
        for origin in [None, Some("https://evil.example"), Some("null")] {
            let r = w.post(Some(&sid), origin, "evil").await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{origin:?}");
        }
        assert_eq!(w.name().await, None);
    }

    /// 確かめが切れていれば 401 の "confirmation required"。画面はこれを見て確かめ直し、打った値のまま送り直す。
    #[tokio::test]
    async fn without_a_session_or_a_recent_confirmation_the_name_is_not_saved() {
        let w = world().await;
        let r = w.post(None, Some(ORIGIN), "x").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(r).await, "sign-in required");
        assert_eq!(w.post(Some("no-such-sid"), Some(ORIGIN), "x").await.status(), StatusCode::UNAUTHORIZED);
        let old = w.session(now() - RECENT_AUTH_SECS - 1).await;
        let r = w.post(Some(&old), Some(ORIGIN), "x").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(r).await, "confirmation required");
        assert_eq!(w.name().await, None);
        let html = w.page(&old).await;
        assert!(html.contains(
            "if(v.status===401){confirmed=false;if(!await signIn())return;v=await post(PROFILE,{name:f.value});}"
        ));
    }

    /// 誤りは errorText が訳せる本文（"invalid name"）で返す。
    #[tokio::test]
    async fn a_name_that_is_too_long_or_has_control_characters_is_not_saved() {
        let w = world().await;
        let sid = w.session(now()).await;
        assert_eq!(w.post(Some(&sid), Some(ORIGIN), "Taro").await.status(), StatusCode::OK);
        let long = "あ".repeat(81);
        for bad in [long.as_str(), "a\u{0007}b", "a\nb", "a\u{202E}b"] {
            let r = w.post(Some(&sid), Some(ORIGIN), bad).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad:?}");
            assert_eq!(body(r).await, "invalid name", "{bad:?}");
            assert_eq!(w.name().await.as_deref(), Some("Taro"), "{bad:?}");
        }
        assert!(w.page(&sid).await.contains("'invalid name':'氏名が長すぎるか、使えない文字が入っています。'"));
        assert_eq!(w.post(Some(&sid), Some(ORIGIN), &"あ".repeat(80)).await.status(), StatusCode::OK);
        assert_eq!(w.name().await.map(|n| n.chars().count()), Some(80));
    }

    /// 名前は HTML として逃がし、画面の文言の印（角括弧 2 つ）や差し込み口（`__…__`）としても読まない。
    #[tokio::test]
    async fn the_name_on_the_page_is_escaped() {
        let w = world().await;
        let sid = w.session(now()).await;
        let evil = r#""><script>alert(1)</script>'[[Passkeys]]__DEL____WEBAUTHN_JS__"#;
        let updates = HashMap::from([("name".to_string(), evil.to_string())]);
        registration::save_profile(&*w.fs, "acc-u", &updates).await.unwrap();
        let html = w.page(&sid).await;
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(
            html.contains(
                r#"value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39;&#91;&#91;Passkeys]]&#95;&#95;DEL&#95;&#95;&#95;&#95;WEBAUTHN&#95;JS&#95;&#95;""#
            ),
            "{html}"
        );
    }
}
