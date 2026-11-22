//! メール送信の概念トレイトと Resend 実装。
//! ローカル用に送らず URL をログに出す LogMailer も用意する。

use crate::web::i18n::{bilingual, localize, Lang};
use async_trait::async_trait;
use serde_json::json;

/// `lang` は送信のきっかけになったブラウザの言語。None（ブラウザの要求が無い）なら日本語と英語の両方で送る。
#[async_trait]
pub trait Mailer: Send + Sync {
    /// 確認 URL 付きのメールを送る。
    async fn send_verification(
        &self,
        to: &str,
        verify_url: &str,
        lang: Option<Lang>,
    ) -> Result<(), String>;
    /// 既登録ユーザーへの案内（メール列挙対策で本文を分岐）。
    async fn send_already_registered(&self, to: &str, lang: Option<Lang>) -> Result<(), String>;
    /// 登録済みの人への案内に、この端末に passkey を足す（復旧の）リンクを添える。
    async fn send_recovery(&self, to: &str, url: &str, lang: Option<Lang>) -> Result<(), String>;
    /// メールで確かめて passkey が足されたことの知らせ。
    async fn send_passkey_added(&self, to: &str, lang: Option<Lang>) -> Result<(), String>;
}

/// (件名, HTML 本文)。両言語のときは本文を日本語、英語の順に並べる。
fn compose(subject: &str, html: &str, lang: Option<Lang>) -> (String, String) {
    match lang {
        Some(lang) => (localize(subject, lang), localize(html, lang)),
        None => (
            bilingual(subject),
            format!(
                "{}<hr style=\"border:0;border-top:1px solid #ddd;margin:0 auto;max-width:560px\">{}",
                localize(html, Lang::Ja),
                localize(html, Lang::En)
            ),
        ),
    }
}

pub(crate) fn verification_mail(verify_url: &str, lang: Option<Lang>) -> (String, String) {
    let html = format!(
        r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">[[Verify your email address]]</h2>
<p>[[To finish signing up, create your passkey with the button below. The link expires in 30 minutes.]]</p>
<p style="margin:24px 0"><a href="{url}" style="display:inline-block;background:#3367d6;color:#fff;padding:14px 24px;border-radius:8px;text-decoration:none;font-weight:600">[[Sign up with a passkey]]</a></p>
<p style="font-size:13px;color:#666">[[If you did not request this, ignore this email.]]</p>
</div>"#,
        url = escape(verify_url)
    );
    compose("[[[rust-idp] Verify your email]]", &html, lang)
}

pub(crate) fn already_registered_mail(to: &str, lang: Option<Lang>) -> (String, String) {
    let html = format!(
        r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">[[Already registered]]</h2>
<p>[[This email address]] (<strong>{email}</strong>) [[is already registered. Please sign in instead of signing up.]]</p>
<p>[[If you cannot use your passkey, contact the administrator.]]</p>
<p style="font-size:13px;color:#666">[[If you did not request this, ignore this email.]]</p>
</div>"#,
        email = escape(to)
    );
    compose("[[[rust-idp] An account already exists]]", &html, lang)
}

pub(crate) fn recovery_mail(to: &str, url: &str, lang: Option<Lang>) -> (String, String) {
    let html = format!(
        r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">[[Add a passkey on this device]]</h2>
<p>[[This email address]] (<strong>{email}</strong>) [[is registered. Sign in with your passkey.]]</p>
<p>[[If you cannot use your passkey, or want to use this device too, add a passkey on this device with the button below. The link expires in 15 minutes.]]</p>
<p style="margin:24px 0"><a href="{url}" style="display:inline-block;background:#3367d6;color:#fff;padding:14px 24px;border-radius:8px;text-decoration:none;font-weight:600">[[Add a passkey on this device]]</a></p>
<p style="font-size:13px;color:#666">[[When you add a passkey this way, you are signed out on your other devices.]] [[If you did not request this, ignore this email.]]</p>
</div>"#,
        email = escape(to),
        url = escape(url)
    );
    compose("[[[rust-idp] Add a passkey on this device]]", &html, lang)
}

pub(crate) fn passkey_added_mail(lang: Option<Lang>) -> (String, String) {
    let html = r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">[[A passkey was added]]</h2>
<p>[[A passkey was added to your account using a link sent to this email address, and you were signed out on your other devices.]]</p>
<p>[[If this was not you, someone may be able to read your email. Secure your email account, then sign in with your own passkey and remove the passkey you do not recognize.]]</p>
</div>"#;
    compose("[[[rust-idp] A passkey was added]]", html, lang)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub struct ResendMailer {
    api_key: String,
    from: String,
    http: reqwest::Client,
}

impl ResendMailer {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            from: "rust-idp <noreply@sonrisa.co.jp>".into(),
            http: crate::http::client(),
        }
    }

    async fn send(&self, to: &str, subject: &str, html: String) -> Result<(), String> {
        let r = self
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.api_key)
            .json(&json!({ "from": self.from, "to": to, "subject": subject, "html": html }))
            .send()
            .await
            .map_err(|e| format!("resend: {e}"))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("resend {} {}", r.status(), r.text().await.unwrap_or_default()))
        }
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send_verification(
        &self,
        to: &str,
        verify_url: &str,
        lang: Option<Lang>,
    ) -> Result<(), String> {
        let (subject, html) = verification_mail(verify_url, lang);
        self.send(to, &subject, html).await
    }

    async fn send_already_registered(&self, to: &str, lang: Option<Lang>) -> Result<(), String> {
        let (subject, html) = already_registered_mail(to, lang);
        self.send(to, &subject, html).await
    }

    async fn send_recovery(&self, to: &str, url: &str, lang: Option<Lang>) -> Result<(), String> {
        let (subject, html) = recovery_mail(to, url, lang);
        self.send(to, &subject, html).await
    }

    async fn send_passkey_added(&self, to: &str, lang: Option<Lang>) -> Result<(), String> {
        let (subject, html) = passkey_added_mail(lang);
        self.send(to, &subject, html).await
    }
}

/// ローカル用。送信せず確認 URL をログに出すだけ。
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send_verification(
        &self,
        to: &str,
        verify_url: &str,
        _lang: Option<Lang>,
    ) -> Result<(), String> {
        tracing::info!("[LogMailer] verify {to}: {verify_url}");
        Ok(())
    }
    async fn send_already_registered(&self, to: &str, _lang: Option<Lang>) -> Result<(), String> {
        tracing::info!("[LogMailer] already-registered notice to {to}");
        Ok(())
    }
    async fn send_recovery(&self, to: &str, url: &str, _lang: Option<Lang>) -> Result<(), String> {
        tracing::info!("[LogMailer] recovery {to}: {url}");
        Ok(())
    }
    async fn send_passkey_added(&self, to: &str, _lang: Option<Lang>) -> Result<(), String> {
        tracing::info!("[LogMailer] passkey-added notice to {to}");
        Ok(())
    }
}
