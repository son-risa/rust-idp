//! メール送信の概念トレイトと Resend 実装。
//! ローカル用に送らず URL をログに出す LogMailer も用意する。

use crate::web::i18n::Lang;
#[cfg(any(feature = "gcp", test))]
use crate::web::i18n::{bilingual, localize};
use async_trait::async_trait;
#[cfg(feature = "gcp")]
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
#[cfg(any(feature = "gcp", test))]
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

#[cfg(any(feature = "gcp", test))]
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

#[cfg(any(feature = "gcp", test))]
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

#[cfg(feature = "gcp")]
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

#[cfg(feature = "gcp")]
pub(crate) fn passkey_added_mail(lang: Option<Lang>) -> (String, String) {
    let html = r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">[[A passkey was added]]</h2>
<p>[[A passkey was added to your account using a link sent to this email address, and you were signed out on your other devices.]]</p>
<p>[[If this was not you, someone may be able to read your email. Secure your email account, then sign in with your own passkey and remove the passkey you do not recognize.]]</p>
</div>"#;
    compose("[[[rust-idp] A passkey was added]]", html, lang)
}

#[cfg(any(feature = "gcp", test))]
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(feature = "gcp")]
pub struct ResendMailer {
    api_key: String,
    from: String,
    endpoint: String,
    http: reqwest::Client,
}

#[cfg(feature = "gcp")]
impl ResendMailer {
    /// from は Resend で確かめ済みの domain の差出人（例 `rust-idp <noreply@example.com>`）。
    pub fn new(api_key: String, from: String) -> Self {
        Self::at(api_key, from, "https://api.resend.com/emails".into())
    }

    fn at(api_key: String, from: String, endpoint: String) -> Self {
        Self {
            api_key,
            from,
            endpoint,
            http: crate::http::client(),
        }
    }

    async fn send(&self, to: &str, subject: &str, html: String) -> Result<(), String> {
        let r = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&json!({ "from": self.from, "to": to, "subject": subject, "html": html }))
            .send()
            .await
            .map_err(|e| format!("resend: {e}"))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "resend {} {}",
                r.status(),
                r.text().await.unwrap_or_default()
            ))
        }
    }
}

#[cfg(feature = "gcp")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailer_contract::{Outbox, Sent};

    mod log {
        use super::*;
        use std::io;
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct VecWriter(Arc<Mutex<Vec<u8>>>);
        impl io::Write for VecWriter {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
            type Writer = VecWriter;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        /// LogMailer が届ける先は記録なので、この thread の記録を受けて読む。
        struct LogOutbox {
            buf: VecWriter,
            _guard: tracing::subscriber::DefaultGuard,
            // 生きている Dispatch が 1 つだけだと、callsite の interest を最初に踏んだ thread の既定の subscriber で
            // 決めて固定する（web/mod.rs の記録の試験と同じ）。2 つ目を生かしておき、ほかの試験に固定されないようにする。
            _second_dispatch: tracing::Dispatch,
        }

        impl Outbox for LogOutbox {
            fn mailer(&self) -> &dyn Mailer {
                &LogMailer
            }
            fn sent(&self) -> Vec<Sent> {
                let out = String::from_utf8(self.buf.0.lock().unwrap().clone()).unwrap();
                out.lines()
                    .filter_map(|line| line.trim().strip_prefix("[LogMailer] "))
                    .map(|rest| {
                        let after = [
                            "verify ",
                            "already-registered notice to ",
                            "recovery ",
                            "passkey-added notice to ",
                        ]
                        .iter()
                        .find_map(|p| rest.strip_prefix(p))
                        .unwrap_or_else(|| panic!("知らない形の行: {rest}"));
                        Sent {
                            to: after.split(':').next().unwrap().to_string(),
                            text: rest.to_string(),
                        }
                    })
                    .collect()
            }
        }

        async fn outbox() -> LogOutbox {
            let _second_dispatch =
                tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            let buf = VecWriter::default();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_level(false)
                .with_target(false)
                .with_ansi(false)
                .with_writer(buf.clone())
                .finish();
            LogOutbox {
                buf,
                _guard: tracing::subscriber::set_default(subscriber),
                _second_dispatch,
            }
        }

        crate::mailer_contract::mailer_contract_tests!(outbox);
    }

    #[cfg(feature = "gcp")]
    mod resend {
        use super::*;
        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::routing::post;
        use axum::{Json, Router};
        use serde_json::Value;
        use std::sync::{Arc, Mutex};

        /// Resend の `POST /emails` を模す。受けた要求を取っておき、`refuse` なら 422 で断る。
        #[derive(Default)]
        struct Fake {
            bodies: Mutex<Vec<Value>>,
            refuse: bool,
        }

        async fn emails(State(f): State<Arc<Fake>>, Json(body): Json<Value>) -> StatusCode {
            if f.refuse {
                return StatusCode::UNPROCESSABLE_ENTITY;
            }
            f.bodies.lock().unwrap().push(body);
            StatusCode::OK
        }

        struct ResendOutbox {
            mailer: ResendMailer,
            fake: Arc<Fake>,
        }

        impl Outbox for ResendOutbox {
            fn mailer(&self) -> &dyn Mailer {
                &self.mailer
            }
            fn sent(&self) -> Vec<Sent> {
                let unescape = |s: &str| {
                    s.replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&amp;", "&")
                };
                self.fake
                    .bodies
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|b| Sent {
                        to: b["to"].as_str().unwrap_or_default().to_string(),
                        text: format!(
                            "{}\n{}",
                            b["subject"].as_str().unwrap_or_default(),
                            unescape(b["html"].as_str().unwrap_or_default())
                        ),
                    })
                    .collect()
            }
        }

        async fn on_fake(refuse: bool) -> ResendOutbox {
            let fake = Arc::new(Fake {
                refuse,
                ..Default::default()
            });
            let app = Router::new()
                .route("/emails", post(emails))
                .with_state(fake.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/emails", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            ResendOutbox {
                mailer: ResendMailer::at(
                    "re_test".into(),
                    "rust-idp <noreply@example.com>".into(),
                    endpoint,
                ),
                fake,
            }
        }

        async fn outbox() -> ResendOutbox {
            on_fake(false).await
        }

        async fn refusing() -> ResendOutbox {
            on_fake(true).await
        }

        crate::mailer_contract::mailer_contract_tests!(outbox, refused: refusing);
    }
}
