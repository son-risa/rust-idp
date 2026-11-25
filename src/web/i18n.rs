//! 人に見せる文言の言語切り替え。
//!
//! テンプレートの文言は英語で書き、`[[English text]]` の印で囲む。`localize` が印を
//! 英語ならそのまま、日本語なら `CATALOG` の訳に置き換え、`__LANG__` を言語コードにする。
//! 印の置き換えは `CATALOG` に在る鍵だけに限る（利用者の値に `[[...]]` が紛れても崩さない）。
//! 鍵と訳には HTML・JS の文字列を抜け出せる文字を入れない（`catalog_text_is_safe_everywhere`）。

use axum::http::{header, HeaderMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ja,
}

impl Lang {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ja => "ja",
        }
    }

    pub(crate) fn from_headers(headers: &HeaderMap) -> Lang {
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(Lang::from_accept_language)
            .unwrap_or(Lang::En)
    }

    /// q 値の高い順（同じ q なら書かれた順）に見て、最初に対応している言語を返す。
    /// q=0 は「受け付けない」。対応言語が無ければ英語。
    pub(crate) fn from_accept_language(value: &str) -> Lang {
        let mut ranges: Vec<(u32, Lang)> = value
            .split(',')
            .filter_map(|item| {
                let mut parts = item.split(';');
                let tag = parts.next()?.trim();
                let primary = tag.split('-').next()?.to_ascii_lowercase();
                let lang = match primary.as_str() {
                    "en" => Lang::En,
                    "ja" => Lang::Ja,
                    _ => return None,
                };
                let mut q = 1000;
                for param in parts {
                    if let Some(v) = param.trim().strip_prefix("q=") {
                        q = parse_q(v.trim())?;
                    }
                }
                (q > 0).then_some((q, lang))
            })
            .collect();
        ranges.sort_by_key(|r| std::cmp::Reverse(r.0));
        ranges.first().map(|r| r.1).unwrap_or(Lang::En)
    }
}

/// RFC 9110 の qvalue（0〜1、小数 3 桁まで）を千分率で返す。
fn parse_q(v: &str) -> Option<u32> {
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let milli = match int {
        "0" => format!("{frac:0<3}").parse().ok()?,
        "1" if frac.bytes().all(|b| b == b'0') => 1000,
        _ => return None,
    };
    Some(milli)
}

pub(crate) fn localize(template: &str, lang: Lang) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("[[") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("]]") else {
            rest = &rest[start..];
            break;
        };
        let key = &after[..end];
        match translate(key) {
            Some(ja) => out.push_str(if lang == Lang::Ja { ja } else { key }),
            None => {
                out.push_str("[[");
                rest = after;
                continue;
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out.replace("__LANG__", lang.code())
}

/// 言語が分からない宛先（メール・push）向け。日本語の後に英語を並べる。
pub(crate) fn bilingual(template: &str) -> String {
    format!(
        "{} / {}",
        localize(template, Lang::Ja),
        localize(template, Lang::En)
    )
}

fn translate(key: &str) -> Option<&'static str> {
    CATALOG.iter().find(|(en, _)| *en == key).map(|(_, ja)| *ja)
}

pub(crate) const CATALOG: &[(&str, &str)] = &[
    // login.rs / pages.rs
    ("Sign in", "ログイン"),
    ("Sign in with a passkey", "パスキーでログイン"),
    ("Email address (optional)", "メールアドレス（任意）"),
    ("Sign up with email", "メールアドレスで新規登録"),
    ("Cancel", "キャンセル"),
    (
        "This browser does not support passkeys. Open this page in the standard Safari or Chrome app.",
        "このブラウザは パスキー非対応です（標準の Safari / Chrome アプリで開いてください）。",
    ),
    (
        "Could not start the passkey. Open this page in the standard Safari or Chrome app (in-app browsers are not supported).",
        "パスキーを起動できませんでした。標準の Safari / Chrome アプリで開いてください（アプリ内ブラウザでは使えません）。",
    ),
    ("Signing in…", "ログイン処理中…"),
    ("Male", "男性"),
    ("Female", "女性"),
    ("Other", "その他"),
    ("Not set", "未設定"),
    ("Profile", "プロフィール"),
    ("Name", "氏名"),
    ("Nickname", "ニックネーム"),
    ("Gender", "性別"),
    ("Birthday", "誕生日"),
    ("Time zone", "タイムゾーン"),
    ("Locale", "ロケール"),
    ("Edit", "編集"),
    ("Sign out", "ログアウト"),
    ("Token info (debug)", "トークン情報（デバッグ）"),
    ("Edit profile", "プロフィール編集"),
    ("Gender (male/female/other)", "性別（male/female/other）"),
    ("Birthday (YYYY-MM-DD)", "誕生日（YYYY-MM-DD）"),
    ("Save", "保存"),
    ("Your session has expired", "セッションが切れました"),
    ("Sign-in approval request", "ログイン承認の依頼"),
    ("Approve (passkey)", "承認（パスキー）"),
    ("Reject", "拒否"),
    ("Your session has expired. Please sign in again.", "セッションが切れました。再度ログインしてください。"),
    // register.rs
    ("Sign up", "登録"),
    ("Create an account", "ユーザー登録"),
    ("We will send a confirmation link to your email address.", "メールアドレスに確認リンクを送ります。"),
    ("Send confirmation email", "確認メールを送信"),
    ("Enter a valid email address.", "正しいメールアドレスを入力してください。"),
    ("Too many requests. Please try again later.", "要求が多すぎます。しばらくしてからお試しください。"),
    ("Sent", "送信しました"),
    ("Confirmation email sent", "確認メールを送信しました"),
    (
        "Open the link in the email and create a passkey to finish signing up (the link expires in 30 minutes).",
        "メール内のリンクから パスキーを作成して登録を完了してください（有効期限30分）。",
    ),
    ("Invitation expired", "招待の期限切れ"),
    ("This invitation cannot be used", "この招待は使えません"),
    (
        "It has expired or has already been used. Ask the person who invited you to send it again.",
        "期限が切れたか、既に使われています。招待した方に、もう一度送ってもらってください。",
    ),
    ("Passkey registration", "パスキー登録"),
    ("Create a passkey", "パスキーを作成"),
    ("Name (required)", "氏名（必須）"),
    ("Name (optional)", "氏名（任意）"),
    ("Register securely with the fido2demo app.", "fido2demo アプリで安全に登録します。"),
    ("Open in the app", "アプリで開く"),
    (
        "If the app is installed, it opens automatically. If it does not, continue on the web with the button below.",
        "インストール済みなら自動で開きます。開かない場合は下のボタンから Web で続行できます。",
    ),
    (
        "If you open the app, the name above is not saved. It is saved if you continue on the web.",
        "アプリで開くと、上の氏名は保存されません。Web で登録を続けると保存されます。",
    ),
    ("Continue on the web", "Web で登録を続ける"),
    ("It is created as a synced passkey (for example in iCloud Keychain).", "同期 パスキー（iCloud Keychain 等）として作成されます。"),
    (
        "On iPhone, choose “Passwords” (iCloud) when asked where to save the passkey. A passkey saved in Google Password Manager may ask for a PIN at sign-in.",
        "iPhone では、パスキーの保存先を聞かれたら「パスワード」（iCloud）を選んでください。Google パスワードマネージャーに保存すると、ログインのときに PIN を求められることがあります。",
    ),
    (
        "Create a passkey with this device (for example with biometrics) to finish signing up.",
        "このデバイスの生体認証等で パスキーを作成し、登録を完了します。",
    ),
    ("Create a passkey and sign up", "パスキーを作成して登録"),
    ("Enter your name", "氏名を入力してください"),
    ("Working…", "処理中…"),
    ("Registration complete. Taking you to sign in…", "登録が完了しました。ログイン画面へ移ります…"),
    ("Registration complete.", "登録が完了しました。"),
    // mod.rs（passkey の API の失敗）
    ("This took too long. Please try again.", "時間が経ちすぎました。もう一度お試しください。"),
    ("This passkey is not registered.", "この パスキーは登録されていません。"),
    ("The passkey could not be verified.", "パスキーを確認できませんでした。"),
    ("This account is disabled.", "このアカウントは凍結されています。"),
    ("This account needs to be registered again.", "このアカウントは登録し直す必要があります。"),
    ("This sign-in has expired. Please start again.", "ログインの有効期限が切れました。最初からやり直してください。"),
    ("This sign-in was started in another browser.", "このログインは別のブラウザで始められたものです。"),
    ("Sign in again in this browser", "このブラウザでログインし直す"),
    (
        "This sign-in was started in another browser. Please start again from the app.",
        "このログインは別のブラウザで始められたものです。アプリからもう一度始めてください。",
    ),
    ("This link has expired or has already been used.", "このリンクは期限が切れたか、既に使われています。"),
    (
        "This email address is already registered. Please sign in.",
        "このメールアドレスは既に登録されています。ログインしてください。",
    ),
    ("The passkey could not be created.", "パスキーを作成できませんでした。"),
    (
        "The name is too long or contains characters that cannot be used.",
        "氏名が長すぎるか、使えない文字が入っています。",
    ),
    ("This request was not found or has expired.", "この要求は見つからないか、期限が切れています。"),
    ("No passkey is registered for this account.", "このアカウントには パスキーが登録されていません。"),
    ("This request has already been handled.", "この要求は既に処理されています。"),
    ("Something went wrong. Please try again.", "問題が起きました。もう一度お試しください。"),
    (
        "The passkey was canceled or timed out. If you opened this page inside another app, open it in the standard Safari or Chrome app.",
        "パスキーの操作が取り消されたか、時間切れになりました。ほかのアプリの中で開いている場合は、標準の Safari / Chrome アプリで開いてください。",
    ),
    // oidc.rs
    ("You have signed out", "ログアウトしました"),
    ("Go to sign in", "ログインへ"),
    ("Back to sign in", "ログイン画面に戻る"),
    ("Back to the app", "アプリに戻る"),
    // ciba.rs
    ("You need to sign in to approve.", "承認するにはログインが必要です。"),
    ("CIBA approval", "CIBA 承認"),
    ("There are no pending requests.", "保留中の要求はありません。"),
    ("(no message)", "（メッセージなし）"),
    ("Requested by", "要求元"),
    // admin.rs
    ("Admin console", "管理コンソール"),
    ("Choose an action from the navigation above.", "上のナビゲーションから操作を選んでください。"),
    ("Status", "状態"),
    ("Registered", "登録日"),
    ("Admins cannot be deleted (revoke admin first).", "管理者は削除できません（先に管理者を剥奪）。"),
    (
        "Delete this account permanently? Its passkey, profile, and notification registration are also removed, and this cannot be undone (the CIBA approval history is kept).",
        "このアカウントを完全に削除しますか？パスキー・プロフィール・通知の登録も消え、元に戻せません（CIBA の承認の履歴は残ります）。",
    ),
    ("Delete", "削除（delete）"),
    ("Enable", "凍結解除（enable）"),
    ("You cannot disable yourself (your session would end immediately).", "自分自身は凍結できません（セッションが即座に失効するため）。"),
    ("Disable this account? Its sessions and tokens are also revoked.", "このアカウントを凍結しますか？セッション・トークンも失効します。"),
    ("Disable", "凍結（disable）"),
    ("Revoke your own admin rights?", "自分自身の管理者権限を剥奪しますか？"),
    ("Revoke admin rights?", "管理者権限を剥奪しますか？"),
    ("Revoke admin", "管理者を剥奪"),
    ("Make admin", "管理者に任命"),
    ("No history.", "操作履歴はありません。"),
    ("Time", "日時"),
    ("Actor", "実行者"),
    ("Action", "操作"),
    ("Details", "詳細"),
    ("Target", "対象"),
    ("Role", "権限"),
    ("History", "操作履歴"),
    ("Back to the list", "一覧へ戻る"),
    ("Disabled", "凍結中"),
    ("Active", "有効"),
    ("Admin", "管理者"),
    ("Users", "ユーザー"),
    ("Users ({n})", "ユーザー（{n}）"),
    ("Clients ({n})", "クライアント（{n}）"),
    ("Unused IATs ({n})", "未消費のIAT（{n}）"),
    ("Signature counter", "署名カウンタ"),
    ("Passkeys", "パスキー"),
    ("Authenticator", "保存先"),
    ("Last used", "最後の利用"),
    ("No passkeys. The user can register again with the same account.", "パスキーはありません。同じアカウントのまま登録し直せます。"),
    ("Passkey", "パスキー"),
    ("Not used yet", "まだ使っていません"),
    ("Remove", "削除"),
    ("Continue", "続ける"),
    ("Add a passkey on this device", "この端末のパスキーを追加"),
    ("Add a passkey in Passwords", "「パスワード」にパスキーを追加する"),
    ("Sign in with your passkey to see and add passkeys.", "パスキーを見たり追加したりするには、パスキーでログインしてください。"),
    ("Please sign in again.", "もう一度ログインしてください。"),
    ("Please confirm it is you with a passkey again.", "もう一度パスキーで本人確認をしてください。"),
    ("A passkey for this account is already saved here.", "このアカウントのパスキーは、ここに保存済みです。"),
    ("Can’t use your passkey?", "パスキーを使えないとき"),
    ("If this computer has no passkey, press sign in and scan the QR code that appears with the phone that has your passkey.", "このパソコンにパスキーが無いときは、ログインを押すと出る QR コードを、パスキーのあるスマホで読み取ってください。"),
    ("To continue on your computer, press sign in there and scan the QR code that appears with this phone.", "パソコンで続けるときは、パソコンでログインを押すと出る QR コードを、このスマホで読み取ってください。"),
    ("is registered. Sign in with your passkey.", "は登録済みです。パスキーでログインしてください。"),
    ("[rust-idp] Add a passkey on this device", "【rust-idp】この端末にパスキーを追加する"),
    ("If you cannot use your passkey, contact the administrator.", "パスキーを使えない場合は、管理者に問い合わせてください。"),
    (
        "Passkeys cannot be used in this browser. Open the link in Safari or Chrome.",
        "このブラウザではパスキーを使えません。リンクを Safari か Chrome で開いてください。",
    ),
    (
        "A passkey for this account is already available on this device.",
        "このアカウントのパスキーは、この端末で既に使えます。",
    ),
    ("Sign in with it", "そのパスキーでログインする"),
    (
        "This account has no passkey. Sign up again with the same email address.",
        "このアカウントにはパスキーがありません。同じメールアドレスで登録し直してください。",
    ),
    (
        "This passkey can be removed 24 hours after a passkey was added with email.",
        "このパスキーは、メールでパスキーを追加してから 24 時間たつと削除できます。",
    ),
    (
        "The passkey was added. Go back to the app or service and sign in again.",
        "パスキーを追加しました。アプリやサービスに戻って、もう一度ログインしてください。",
    ),
    (
        "Enter your email address. We will send a link to add a passkey on this device. When you use it, you are signed out on your other devices.",
        "メールアドレスを入れてください。この端末にパスキーを追加するリンクを送ります。使うと、ほかの端末ではログアウトされます。",
    ),
    ("Send email", "メールを送る"),
    ("Email sent", "メールを送りました"),
    (
        "If this address is registered, we sent a link to add a passkey on this device. Open it on the device you want to use (the link expires in 15 minutes).",
        "登録済みのアドレスなら、この端末にパスキーを追加するリンクを送りました。使いたい端末でリンクを開いてください（有効期限15分）。",
    ),
    ("This link cannot be used", "このリンクは使えません"),
    ("Send the email again", "メールを送り直す"),
    (
        "Create a passkey on this device to sign in again. Your other passkeys are kept. When you finish, you are signed out on your other devices.",
        "この端末にパスキーを作って、もう一度ログインできるようにします。ほかのパスキーはそのまま残ります。終わると、ほかの端末ではログアウトされます。",
    ),
    (
        "A passkey cannot be added with email for this account. Contact the administrator.",
        "このアカウントには、メールでパスキーを追加できません。管理者に問い合わせてください。",
    ),
    (
        "If you cannot use your passkey, or want to use this device too, add a passkey on this device with the button below. The link expires in 15 minutes.",
        "パスキーを使えないときや、この端末でも使いたいときは、下のボタンからこの端末にパスキーを追加できます。有効期限は15分です。",
    ),
    (
        "When you add a passkey this way, you are signed out on your other devices.",
        "この方法でパスキーを追加すると、ほかの端末ではログアウトされます。",
    ),
    ("A passkey was added", "パスキーが追加されました"),
    ("[rust-idp] A passkey was added", "【rust-idp】パスキーが追加されました"),
    (
        "A passkey was added to your account using a link sent to this email address, and you were signed out on your other devices.",
        "このメールアドレスに送ったリンクを使って、あなたのアカウントにパスキーが追加されました。ほかの端末ではログアウトしています。",
    ),
    (
        "If this was not you, someone may be able to read your email. Secure your email account, then sign in with your own passkey and remove the passkey you do not recognize.",
        "心当たりが無い場合は、誰かがあなたのメールを読める状態かもしれません。メールのアカウントを守ったうえで、ご自分のパスキーでログインし、覚えの無いパスキーを削除してください。",
    ),
    (
        "A passkey for this account is already saved in the place you chose. Try again and choose “Passwords” (iCloud) as where to save it.",
        "選んだ保存先には、このアカウントのパスキーが既に保存されています。もう一度押して、保存先に「パスワード」（iCloud）を選んでください。",
    ),
    ("This passkey was not found. Please reload the page.", "このパスキーが見つかりません。ページを読み直してください。"),
    ("You cannot remove your only passkey. Add another passkey first.", "パスキーが 1 つだけのときは削除できません。先に別のパスキーを追加してください。"),
    (
        "Remove this passkey? You can no longer sign in with it, and you are signed out on your other devices.",
        "このパスキーを削除しますか？削除すると、このパスキーではログインできなくなり、ほかの端末からもログアウトします。",
    ),
    ("You can add up to 10 passkeys. Remove one first.", "パスキーは 10 個まで追加できます。先に 1 つ削除してください。"),
    (
        "On iPhone, choose “Passwords” (iCloud) when asked where to save the passkey.",
        "iPhone では、パスキーの保存先を聞かれたら「パスワード」（iCloud）を選んでください。",
    ),
    (
        "Your passkey is saved in Google Password Manager, which may ask for a PIN at sign-in on iPhone. Add a passkey and choose “Passwords” (iCloud) as where to save it.",
        "パスキーが Google パスワードマネージャーに保存されています。iPhone ではログインのときに PIN を求められることがあります。パスキーを追加し、保存先に「パスワード」（iCloud）を選んでください。",
    ),
    (
        "Registration complete. This passkey was saved in Google Password Manager, which may ask for a PIN at sign-in. We recommend also saving a passkey in Passwords (iCloud).",
        "登録しました。このパスキーは Google パスワードマネージャーに保存されたため、ログインのときに PIN を求められることがあります。「パスワード」（iCloud）にもパスキーを保存しておくことをおすすめします。",
    ),
    ("Remove passkeys only", "パスキーだけ削除"),
    (
        "Remove all passkeys of this user? The account and profile are kept, and the user can register again as the same person. Sessions and tokens are also revoked.",
        "このユーザーのパスキーをすべて削除しますか？アカウントとプロフィールは残り、同じ人のまま登録し直せます。セッションとトークンも失効します。",
    ),
    ("You cannot remove your own passkeys here.", "自分のパスキーはここでは削除できません。"),
    ("The passkeys of an admin cannot be removed. Revoke admin first.", "管理者のパスキーは削除できません。先に管理者を外してください。"),
    ("Client ID", "クライアント ID"),
    (
        "A return address must use https and must not contain a fragment or user info: {uri}",
        "戻り先は https で、フラグメントやユーザー情報を含まないものにしてください: {uri}",
    ),
    (
        "A return address must be on the host of a redirect_uri of this client: {host}",
        "戻り先は、このクライアントの redirect_uris のいずれかと同じホストにしてください: {host}",
    ),
    (
        "This app is not registered. Please contact the app provider. (error code: {code})",
        "このアプリは登録されていません。アプリの提供元にお問い合わせください。（エラーコード: {code}）",
    ),
    (
        "The request from the app could not be verified. Please start again from the app. (error code: {code})",
        "アプリからの要求を確認できませんでした。アプリからやり直してください。（エラーコード: {code}）",
    ),
    (
        "Something went wrong. Please try again. (error code: {code})",
        "問題が起きました。もう一度お試しください。（エラーコード: {code}）",
    ),
    (
        "The request from the app is invalid. Please contact the app provider. (error code: {code})",
        "アプリからの要求に問題があります。アプリの提供元にお問い合わせください。（エラーコード: {code}）",
    ),
    (
        "The return address after sign-out is not registered for this app. Please contact the app provider.",
        "ログアウト後の戻り先がこのアプリに登録されていません。アプリの提供元にお問い合わせください。",
    ),
    ("Page not found", "ページが見つかりません"),
    (
        "This link is incomplete. Please open the link in the email again.",
        "リンクが途中で切れています。メールのリンクを開き直してください。",
    ),
    (
        "Some of the entered values are invalid. Please check them and try again.",
        "入力内容に誤りがあります。確認してもう一度お試しください。",
    ),
    (
        "The URL of this page is not valid. Please check the link and try again.",
        "このページの URL が正しくありません。リンクを確認してもう一度お試しください。",
    ),
    (
        "Sign-in could not be completed. (error code: {code})",
        "ログインできませんでした。（エラーコード: {code}）",
    ),
    ("Sign-in was canceled.", "ログインをキャンセルしました。"),
    ("Failed to save. Please try again.", "保存に失敗しました。もう一度お試しください。"),
    ("IATs", "IAT"),
    ("Hash", "ハッシュ"),
    ("Redirect hosts", "redirect host"),
    ("Grant types", "grant_type"),
    ("User not found", "ユーザーが見つかりません"),
    ("Client not found", "クライアントが見つかりません"),
    ("Choose a client profile", "プロファイルを選んでください"),
    ("Please sign in.", "ログインしてください。"),
    // mod.rs SWITCH_NOTICE
    ("Switch accounts?", "アカウントを切り替えますか？"),
    ("This browser is signed in as {current}.", "このブラウザは {current} でログインしています。"),
    (
        "If you continue, it will be signed in as {target} instead. Continue only if you expected this email.",
        "続けると {target} に切り替わります。このメールに心当たりがあるときだけ続けてください。",
    ),
    ("Only admins can open this page.", "このページは管理者だけが開けます。"),
    ("The admin console is not available.", "管理コンソールは使えません。"),
    ("User", "ユーザー"),
    ("Clients", "クライアント"),
    ("Client", "クライアント"),
    ("Audit log", "監査ログ"),
    ("Email address", "メールアドレス"),
    ("Regular user", "一般"),
    ("You cannot disable yourself", "自分自身は凍結できません"),
    ("Admins cannot be deleted. Revoke admin first", "管理者は削除できません。先に管理者を剥奪してください"),
    (
        "An account that is not disabled cannot be deleted. Disable it first",
        "凍結していないアカウントは削除できません。先に凍結してください",
    ),
    ("This conflicted with another change. Please try again", "他の書き込みと競合しました。もう一度お試しください"),
    ("You gave up admin rights", "管理者権限を放棄しました"),
    ("You can no longer access the admin console.", "これ以降、管理コンソールにはアクセスできません。"),
    ("The last admin cannot be revoked", "最後の管理者は剥奪できません"),
    ("Audit log (latest {n})", "監査ログ（直近{n}件）"),
    ("Auth method", "認証方式"),
    ("(none)", "（なし）"),
    (
        "(none — this client has no return address after sign-out)",
        "（なし。このクライアントはログアウト後の戻り先を持ちません）",
    ),
    (
        "post_logout_redirect_uris (one per line; leave empty for no return address)",
        "post_logout_redirect_uris（1 行に 1 つ。空にすると戻り先なし）",
    ),
    ("Save return addresses", "戻り先を保存"),
    (
        "initiate_login_uri (where an expired sign-in is sent to start again; leave empty to show the expired message)",
        "initiate_login_uri（期限切れのログイン画面からここへ送り直す。空にすると期限切れの案内を出す）",
    ),
    ("Save sign-in start address", "ログインの入口を保存"),
    (
        "A sign-in start address must use https and must not contain a fragment or user info: {uri}",
        "ログインの入口は https で、フラグメントやユーザー情報を含まないものにしてください: {uri}",
    ),
    (
        "A sign-in start address must be on the host of a redirect_uri of this client: {host}",
        "ログインの入口は、このクライアントの redirect_uris のいずれかと同じホストにしてください: {host}",
    ),
    ("Revoke this client? This cannot be undone.", "このクライアントを失効させますか？取り消せません。"),
    ("Revoke", "失効"),
    ("Set", "設定済み"),
    ("None", "なし"),
    (
        "This client was changed by another update. Reopen it and try again.",
        "このクライアントは別の更新で変わりました。開き直してからやり直してください。",
    ),
    ("Unused IATs", "未消費のIAT"),
    ("New mint", "新規発行"),
    ("Unused", "未消費"),
    ("Reusable", "再利用可"),
    ("Discard", "破棄"),
    ("Discard this IAT?", "このIATを破棄しますか？"),
    ("Mint", "発行"),
    ("Mint a new IAT", "IATを新規発行"),
    ("Client profile", "プロファイル"),
    ("Confidential Key (private_key_jwt, FAPI2 equivalent)", "Confidential Key（private_key_jwt、FAPI2相当）"),
    ("Confidential Secret (client_secret_basic)", "Confidential Secret（client_secret_basic）"),
    ("Public (none)", "Public（none）"),
    (
        "Allowed redirect hosts (one per line or comma-separated; at least one required)",
        "許可する redirect host（改行またはカンマ区切り、1つ以上必須）",
    ),
    ("Allowed grant_type (default: authorization_code, refresh_token)", "許可する grant_type（省略時: authorization_code, refresh_token）"),
    ("Expires in (hours)", "有効期限（時間）"),
    ("Specify at least one redirect host", "redirect host を最低1つ指定してください"),
    ("ttl_hours must be between 1 and {max} (365 days)", "ttl_hours は1〜{max}（365日）の範囲で指定してください"),
    ("ttl_hours is too large", "ttl_hours が大きすぎます"),
    (
        "The IAT was issued (hash={hash}), but the raw token cannot be shown because saving it for display failed.",
        "IATの発行自体は成功しました（hash={hash}）が、表示用の一時保存に失敗したため生トークンは表示できません。",
    ),
    ("Already shown", "表示済みです"),
    ("This token was already shown or has expired. Mint a new one.", "このトークンは既に表示済み、または期限切れです。もう一度発行してください。"),
    ("Expired", "期限切れ"),
    ("It took too long to show it. Mint a new one.", "表示までに時間がかかりすぎました。もう一度発行してください。"),
    ("IAT issued", "IATを発行しました"),
    ("This screen is shown only once. Copy the token now.", "この画面は一度しか表示されません。今すぐコピーしてください。"),
    ("IAT issuance complete", "IAT発行完了"),
    // mailer.rs
    ("[rust-idp] Verify your email", "【rust-idp】メールアドレス確認"),
    ("Verify your email address", "メールアドレス確認"),
    (
        "To finish signing up, create your passkey with the button below. The link expires in 30 minutes.",
        "登録を完了するには、以下のボタンから パスキーを作成してください。有効期限は30分です。",
    ),
    ("Sign up with a passkey", "パスキーを作成して登録"),
    ("If you did not request this, ignore this email.", "心当たりがない場合はこのメールを無視してください。"),
    ("[rust-idp] An account already exists", "【rust-idp】既に登録済みのアカウントがあります"),
    ("Already registered", "既に登録済みです"),
    ("This email address", "このメールアドレス"),
    (
        "is already registered. Please sign in instead of signing up.",
        "は既に登録されています。新規登録ではなくログインをご利用ください。",
    ),
    // fcm.rs
    ("Sign-in approval", "ログインの承認"),
    ("Sign-in request from {client}", "{client} からのログイン要求があります"),
];

#[cfg(test)]
pub(crate) fn has_japanese(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '\u{3040}'..='\u{30FF}' | '\u{4E00}'..='\u{9FFF}'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const OPEN: &str = concat!("[", "[");
    const CLOSE: &str = concat!("]", "]");

    /// 印を探す範囲。人に見せる文言を持つ file は全部ここに並べる。
    const SOURCES: &[(&str, &str)] = &[
        ("web/login.rs", include_str!("login.rs")),
        ("web/pages.rs", include_str!("pages.rs")),
        ("web/register.rs", include_str!("register.rs")),
        ("web/oidc.rs", include_str!("oidc.rs")),
        ("web/ciba.rs", include_str!("ciba.rs")),
        ("web/admin.rs", include_str!("admin.rs")),
        ("web/account.rs", include_str!("account.rs")),
        ("web/recover.rs", include_str!("recover.rs")),
        ("web/mod.rs", include_str!("mod.rs")),
        ("mailer.rs", include_str!("../mailer.rs")),
        ("fcm.rs", include_str!("../fcm.rs")),
    ];

    fn markers_in(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(start) = rest.find(OPEN) {
            let after = &rest[start + 2..];
            let end = after.find(CLOSE).expect("閉じていない印");
            out.push(after[..end].to_string());
            rest = &after[end + 2..];
        }
        out
    }

    #[test]
    fn every_marker_has_a_translation_and_every_translation_is_used() {
        let used: BTreeSet<String> = SOURCES
            .iter()
            .flat_map(|(_, src)| markers_in(src))
            .collect();
        let keys: BTreeSet<String> = CATALOG.iter().map(|(en, _)| en.to_string()).collect();
        let missing: Vec<&String> = used.difference(&keys).collect();
        let unused: Vec<&String> = keys.difference(&used).collect();
        assert!(missing.is_empty(), "訳の無い印: {missing:?}");
        assert!(
            unused.is_empty(),
            "どのテンプレートも使わない訳: {unused:?}"
        );
        assert_eq!(keys.len(), CATALOG.len(), "同じ鍵が二度ある");
    }

    // 英語は sign in / sign out、日本語はログイン / ログアウトに揃える。
    #[test]
    fn sign_in_wording_is_consistent() {
        for (en, ja) in CATALOG {
            // post_logout_redirect_uris・initiate_login_uri は仕様の項目名なので語としては数えない。
            let text = en
                .to_lowercase()
                .replace("post_logout_redirect_uri", "")
                .replace("initiate_login_uri", "");
            for bad in ["log in", "log-in", "login", "log out", "log-out", "logout", "logged", "logon"] {
                assert!(!text.contains(bad), "英語に「{bad}」: {en}");
            }
            for bad in ["サインイン", "サインアウト"] {
                assert!(!ja.contains(bad), "日本語に「{bad}」: {ja}");
            }
        }
    }

    #[test]
    fn catalog_text_is_safe_everywhere() {
        for (en, ja) in CATALOG {
            for s in [en, ja] {
                assert!(!s.is_empty() && s.trim() == *s, "前後の空白: {s:?}");
                assert!(
                    !s.chars()
                        .any(|c| "<>&\"'`\\$".contains(c) || c.is_control()),
                    "HTML の属性や JS の文字列を抜け出せる文字: {s:?}"
                );
                assert!(
                    ![OPEN, CLOSE, "__"].iter().any(|m| s.contains(m)),
                    "印や差し込み口と紛れる: {s:?}"
                );
            }
            let holes = |s: &str| -> BTreeSet<String> {
                s.split('{')
                    .skip(1)
                    .filter_map(|p| p.split_once('}'))
                    .map(|(h, _)| h.to_string())
                    .collect()
            };
            assert_eq!(holes(en), holes(ja), "差し込み口が訳とずれる: {en}");
            assert!(!has_japanese(en), "英語の鍵に日本語: {en}");
        }
    }

    #[test]
    fn localize_replaces_only_known_markers() {
        let t = format!(
            "<html lang=\"__LANG__\">{OPEN}Sign in{CLOSE} {OPEN}not a key{CLOSE} {OPEN}open"
        );
        assert_eq!(
            localize(&t, Lang::En),
            format!("<html lang=\"en\">Sign in {OPEN}not a key{CLOSE} {OPEN}open")
        );
        assert_eq!(
            localize(&t, Lang::Ja),
            format!("<html lang=\"ja\">ログイン {OPEN}not a key{CLOSE} {OPEN}open")
        );
        assert_eq!(
            bilingual(&format!("{OPEN}Sign-in approval{CLOSE}")),
            "ログインの承認 / Sign-in approval"
        );
    }

    #[test]
    fn a_stray_opening_marker_in_a_value_does_not_stop_the_markers_after_it() {
        let t = format!("<td>{OPEN}</td><button>{OPEN}Sign in{CLOSE}</button>");
        assert_eq!(
            localize(&t, Lang::Ja),
            format!("<td>{OPEN}</td><button>ログイン</button>")
        );
        assert_eq!(
            localize(&t, Lang::En),
            format!("<td>{OPEN}</td><button>Sign in</button>")
        );
    }

    #[test]
    fn picks_the_first_supported_language_by_q_value() {
        let cases = [
            ("", Lang::En),
            ("ja", Lang::Ja),
            ("ja-JP", Lang::Ja),
            ("JA-jp", Lang::Ja),
            ("en", Lang::En),
            ("en-US,ja;q=0.5", Lang::En),
            ("ja,en;q=0.8", Lang::Ja),
            ("en;q=0.5,ja;q=0.9", Lang::Ja),
            ("ja;q=0.5,en;q=0.5", Lang::Ja),
            ("fr", Lang::En),
            ("fr-FR,ja;q=0.7,en;q=0.3", Lang::Ja),
            ("de,fr;q=0.9", Lang::En),
            ("ja;q=0,en;q=0.1", Lang::En),
            ("ja;q=0", Lang::En),
            ("*", Lang::En),
            ("ja;q=abc", Lang::En),
            ("ja;q=1.5", Lang::En),
            ("ja;q=0.0001,en;q=0", Lang::En),
            (";;,,,", Lang::En),
            ("日本語", Lang::En),
            ("ja ; q=0.8 , en ; q=0.2", Lang::Ja),
        ];
        for (value, want) in cases {
            assert_eq!(Lang::from_accept_language(value), want, "{value:?}");
        }
        let mut h = HeaderMap::new();
        assert_eq!(Lang::from_headers(&h), Lang::En, "ヘッダが無ければ英語");
        h.insert(header::ACCEPT_LANGUAGE, "ja-JP,ja;q=0.9".parse().unwrap());
        assert_eq!(Lang::from_headers(&h), Lang::Ja);
        h.insert(
            header::ACCEPT_LANGUAGE,
            axum::http::HeaderValue::from_bytes(b"ja\xff").unwrap(),
        );
        assert_eq!(
            Lang::from_headers(&h),
            Lang::En,
            "ASCII でない値は読めないので英語"
        );
        assert_eq!(Lang::En.code(), "en");
        assert_eq!(Lang::Ja.code(), "ja");
    }
}
