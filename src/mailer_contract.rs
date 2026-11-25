//! [`Mailer`] の契約の試験。実装ごとに 1 度 [`mailer_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! 実装が何を届けたかは、実装ごとの [`Outbox`] が受け手の側から読んで返す（送信の API の fake が受けた要求、記録の行など）。
//! 届け損ねうる実装は、届け先が断る [`Outbox`] も渡し、断られたら Err を返すことを確かめる。

use crate::mailer::Mailer;
use crate::web::i18n::Lang;

/// 届いた 1 通。`to` は宛先、`text` は受け手が読む中身（件名と、HTML なら文字参照を戻した本文）。
pub(crate) struct Sent {
    pub to: String,
    pub text: String,
}

/// 試験する実装と、その実装が届けたものを読む口。
pub(crate) trait Outbox {
    fn mailer(&self) -> &dyn Mailer;
    fn sent(&self) -> Vec<Sent>;
}

const TO: &str = "alice@example.com";
/// 呼び手（web/register.rs）が組む形の URL。`&` を含めて、HTML に載せても受け手に同じ URL が届くかを見る。
const URL: &str = "https://op.example/signup/verify?token=T0K-EN_1&lang=ja";

const LANGS: [Option<Lang>; 3] = [None, Some(Lang::Ja), Some(Lang::En)];

/// 送った 1 通を返す。1 度の呼び出しで届くのはちょうど 1 通。
fn one_more(o: &dyn Outbox, before: usize) -> Sent {
    let mut sent = o.sent();
    assert_eq!(sent.len(), before + 1, "1 度の送信で届いたのが 1 通でない");
    sent.pop().unwrap()
}

/// 4 種のメールはどれも、どの言語でも、渡した宛先に 1 通ずつ届き、Ok を返す。
pub(crate) async fn every_mail_reaches_its_recipient_once(o: &dyn Outbox) {
    let m = o.mailer();
    for lang in LANGS {
        let n = o.sent().len();
        m.send_verification(TO, URL, lang).await.unwrap();
        assert_eq!(one_more(o, n).to, TO, "verification {lang:?}");

        let n = o.sent().len();
        m.send_already_registered(TO, lang).await.unwrap();
        assert_eq!(one_more(o, n).to, TO, "already_registered {lang:?}");

        let n = o.sent().len();
        m.send_recovery(TO, URL, lang).await.unwrap();
        assert_eq!(one_more(o, n).to, TO, "recovery {lang:?}");

        let n = o.sent().len();
        m.send_passkey_added(TO, lang).await.unwrap();
        assert_eq!(one_more(o, n).to, TO, "passkey_added {lang:?}");
    }
}

/// 確認と復旧のメールは、呼び手が渡した URL をそのまま受け手に届ける。宛先が違えば別の宛先に届く。
pub(crate) async fn links_reach_the_recipient_unchanged(o: &dyn Outbox) {
    let m = o.mailer();
    for lang in LANGS {
        let n = o.sent().len();
        m.send_verification(TO, URL, lang).await.unwrap();
        let s = one_more(o, n);
        assert!(s.text.contains(URL), "verification {lang:?}: {}", s.text);

        let n = o.sent().len();
        let other = "https://op.example/recover?t=R3C-0V_9&x=1";
        m.send_recovery("bob@example.com", other, lang)
            .await
            .unwrap();
        let s = one_more(o, n);
        assert_eq!(s.to, "bob@example.com");
        assert!(s.text.contains(other), "recovery {lang:?}: {}", s.text);
    }
}

/// 届け先が断ったら、4 種のメールはどれも Err を返す（呼び手はそれを記録に残す）。
// 届け損ねうる今の実装（ResendMailer）は gcp の feature の中にだけ在る。
#[cfg_attr(not(feature = "gcp"), allow(dead_code))]
pub(crate) async fn a_refused_delivery_is_an_err(o: &dyn Outbox) {
    let m = o.mailer();
    assert!(m.send_verification(TO, URL, None).await.is_err());
    assert!(m.send_already_registered(TO, None).await.is_err());
    assert!(m.send_recovery(TO, URL, None).await.is_err());
    assert!(m.send_passkey_added(TO, None).await.is_err());
}

/// `$make` は新しい [`Outbox`] を返す async fn。届け損ねうる実装は `refused: $refused` に、届け先が断る
/// [`Outbox`] を返す async fn を渡す。
macro_rules! mailer_contract_tests {
    ($make:path) => {
        $crate::mailer_contract::mailer_contract_tests!(@mod $make; {});
    };
    ($make:path, refused: $refused:path) => {
        $crate::mailer_contract::mailer_contract_tests!(@mod $make; {
            #[tokio::test]
            async fn a_refused_delivery_is_an_err() {
                c::a_refused_delivery_is_an_err(&$refused().await).await;
            }
        });
    };
    (@mod $make:path; { $($extra:tt)* }) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::mailer_contract as c;

            $crate::mailer_contract::mailer_contract_tests!(@each $make;
                every_mail_reaches_its_recipient_once,
                links_reach_the_recipient_unchanged,
            );
            $($extra)*
        }
    };
    (@each $make:path; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                c::$name(&$make().await).await;
            }
        )*
    };
}
pub(crate) use mailer_contract_tests;
