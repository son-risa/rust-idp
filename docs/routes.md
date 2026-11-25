# 経路の一覧

rust-idp が受ける HTTP の経路（method と path の組）の届け出。`src/web/routes_tests.rs` の試験が、この表と
`src/web/mod.rs` の `router()` が実際に持つ経路とを突き合わせ、食い違えば `cargo test` を赤にする。
経路を足す・消す・method を変える・管理画面の門の内外を移すときは、この表も同じ PR で直す。

## 表の読み方

- **置き場**: `base` は BASE_PATH（本番は `/roidc` など）の下。path は BASE_PATH からの相対で、`/` は BASE_PATH そのもの。
  `top` は host の直下。`fido` も host の直下だが、`FIDO_CONFORMANCE_ENABLED=1` のときだけ置く（本番では置かない）。
- **method**: GET の経路には axum が HEAD も付ける。表には書かない。
- **path**: axum の書き方のまま。`{uid}` などは path の一部を受ける。`{BASE_PATH}` は BASE_PATH の値に置き換わる。
- **呼び手**: RP（OAuth の client）、RS（access token を受ける側）、ブラウザ（利用者の画面）、アプリ（利用者の端末のアプリ）、
  管理者（管理画面のブラウザ）、試験の道具。
- **認証**: その経路が自分で確かめるもの。「無し」は、誰でも呼べるという意味。
  - client 認証: `client_secret_basic` などの client の認証（`authenticate_client`）。
  - access token: Bearer か DPoP の access token（`authenticate_token`）。DPoP に束縛された token は proof が要る。
  - cookie（sid）: `__Host-sid` の SSO セッション。「確かめ済み」は、最近 passkey で本人と確かめたセッションに限る。
  - cookie（印）: `/authorize` が張る `__Host-ix_{uid}`（ログインを始めたブラウザの印）。
  - メールの token: メールのリンクに載る一度きりの token。
  - 招待の token: RP が `/invites` で発行させた招待のリンクに載る token。
  - Initial Access Token: 管理者が管理画面（`/admin/iats/new`）で発行する、client の登録（`/oauth/register`）に一度だけ使える Bearer の token。
  - 管理者: cookie（sid）に加え、そのアカウントが `admins/{account_id}` に在ること（`require_admin`）。
- **状態を変える**: 保存した値を作る・変える・消す、またはメールを送るなら「はい」。WebAuthn の challenge を保存するだけのものも「はい」。
  読むだけに見える経路でも、ついでに期限切れを掃除して書き込むもの（`/ciba/pending`・`/ciba/history` の `sweep_expired`）は「はい」。
- **門**: `admin_same_origin`（GET と HEAD 以外は、自分の origin から来た要求だけを通す）が掛かっていれば「はい」。

## 一覧

| 置き場 | method | path | 呼び手 | 認証 | 状態を変える | 門 |
|---|---|---|---|---|---|---|
| base | GET | `/.well-known/openid-configuration` | RP | 無し | いいえ | いいえ |
| base | GET | `/jwks` | RP、RS | 無し | いいえ | いいえ |
| base | GET | `/authorize` | ブラウザ（RP から） | 無し（cookie（sid）があれば SSO に使う） | はい | いいえ |
| base | GET | `/authorize/resume` | ブラウザ | cookie（印） | はい | いいえ |
| base | GET | `/login/{uid}` | ブラウザ | cookie（印） | いいえ | いいえ |
| base | GET | `/login/{uid}/cancel` | ブラウザ | cookie（印） | いいえ | いいえ |
| base | POST | `/login/{uid}/passkey/options` | ブラウザ | 無し | はい | いいえ |
| base | POST | `/login/{uid}/passkey/verify` | ブラウザ | passkey、cookie（印） | はい | いいえ |
| base | POST | `/token` | RP | client 認証、DPoP（client が dpop_bound なら必須） | はい | いいえ |
| base | POST | `/introspect` | RS | client 認証 | いいえ | いいえ |
| base | POST | `/oauth/mandate/consume` | RS | client 認証 | はい | いいえ |
| base | POST | `/oauth/register` | RP | Initial Access Token（Bearer、一度きり） | はい | いいえ |
| base | POST | `/revoke` | RP | client 認証 | はい | いいえ |
| base | GET | `/end-session` | ブラウザ（RP から） | id_token_hint（無いか確かめに失敗すれば、確かめの画面を出すだけ） | はい | いいえ |
| base | POST | `/end-session` | ブラウザ（RP から、確かめの画面から） | id_token_hint、または確かめの画面の form（自分の origin に限る） | はい | いいえ |
| base | POST | `/par` | RP | client 認証、DPoP（任意） | はい | いいえ |
| base | GET | `/userinfo` | RP | access token | いいえ | いいえ |
| base | POST | `/userinfo` | RP | access token（body の access_token も可） | いいえ | いいえ |
| base | GET | `/me/profile` | RP | access token | いいえ | いいえ |
| base | PUT | `/me/profile` | RP | access token | はい | いいえ |
| base | POST | `/backchannel-authentication` | RP | client 認証 | はい | いいえ |
| base | GET | `/ciba` | ブラウザ | cookie（sid） | いいえ | いいえ |
| base | GET | `/ciba/pending` | アプリ | access token | はい | いいえ |
| base | GET | `/ciba/history` | アプリ | access token | はい | いいえ |
| base | POST | `/ciba/fcm-tokens` | アプリ | access token | はい | いいえ |
| base | POST | `/ciba/{auth_req_id}/passkey-options` | ブラウザ、アプリ | cookie（sid、自分の origin から）か access token。要求の宛先の利用者に限る | はい | いいえ |
| base | POST | `/ciba/{auth_req_id}/approve` | ブラウザ、アプリ | passkey | はい | いいえ |
| base | POST | `/ciba/{auth_req_id}/reject` | ブラウザ、アプリ | cookie（sid、自分の origin から）か access token。要求の宛先の利用者に限る | はい | いいえ |
| base | GET | `/signup` | ブラウザ | 無し | いいえ | いいえ |
| base | POST | `/signup` | ブラウザ | 無し | はい | いいえ |
| base | GET | `/signup/verify` | ブラウザ | メールの token | いいえ | いいえ |
| base | POST | `/signup/email-challenge` | アプリ | 無し | はい | いいえ |
| base | POST | `/signup/verify-email` | アプリ | メールの token | いいえ | いいえ |
| base | POST | `/signup/passkey/options` | ブラウザ、アプリ | メールの token | はい | いいえ |
| base | POST | `/signup/passkey/verify` | ブラウザ、アプリ | メールの token、passkey | はい | いいえ |
| base | GET | `/account` | ブラウザ | cookie（sid） | いいえ | いいえ |
| base | POST | `/account/signin/options` | ブラウザ | 無し（cookie（sid）があれば passkey を絞る） | はい | いいえ |
| base | POST | `/account/signin/verify` | ブラウザ | passkey | はい | いいえ |
| base | POST | `/account/passkeys/options` | ブラウザ | cookie（sid、確かめ済み） | はい | いいえ |
| base | POST | `/account/passkeys/verify` | ブラウザ | cookie（sid、確かめ済み）、passkey | はい | いいえ |
| base | POST | `/account/passkeys/delete` | ブラウザ | cookie（sid、確かめ済み） | はい | いいえ |
| base | GET | `/recover` | ブラウザ | 無し（`t` があればメールの token） | いいえ | いいえ |
| base | POST | `/recover` | ブラウザ | 無し | はい | いいえ |
| base | POST | `/recover/options` | ブラウザ | メールの token | はい | いいえ |
| base | POST | `/recover/verify` | ブラウザ | メールの token、passkey | はい | いいえ |
| base | POST | `/invites` | RP | client 認証（INVITE_CLIENT_IDS の client） | はい | いいえ |
| base | POST | `/accounts/disable` | RP | client 認証（INVITE_CLIENT_IDS の client） | はい | いいえ |
| base | GET | `/invite` | ブラウザ | 招待の token | いいえ | いいえ |
| base | GET | `/` | ブラウザ | 無し | いいえ | いいえ |
| base | GET | `/callback` | ブラウザ | 無し | いいえ | いいえ |
| base | GET | `/admin/whoami` | 管理者 | 管理者 | いいえ | はい |
| base | GET | `/admin` | 管理者 | 管理者 | いいえ | はい |
| base | GET | `/admin/users` | 管理者 | 管理者 | いいえ | はい |
| base | GET | `/admin/users/{account_id}` | 管理者 | 管理者 | いいえ | はい |
| base | POST | `/admin/users/{account_id}/disable` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/users/{account_id}/enable` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/users/{account_id}/delete` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/users/{account_id}/delete-passkeys` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/users/{account_id}/grant-admin` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/users/{account_id}/revoke-admin` | 管理者 | 管理者 | はい | はい |
| base | GET | `/admin/audit` | 管理者 | 管理者 | いいえ | はい |
| base | GET | `/admin/clients` | 管理者 | 管理者 | いいえ | はい |
| base | GET | `/admin/clients/{client_id}` | 管理者 | 管理者 | いいえ | はい |
| base | POST | `/admin/clients/{client_id}/revoke` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/clients/{client_id}/post-logout` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/clients/{client_id}/initiate-login` | 管理者 | 管理者 | はい | はい |
| base | GET | `/admin/iats` | 管理者 | 管理者 | いいえ | はい |
| base | GET | `/admin/iats/new` | 管理者 | 管理者 | いいえ | はい |
| base | POST | `/admin/iats/new` | 管理者 | 管理者 | はい | はい |
| base | POST | `/admin/iats/{hash}/revoke` | 管理者 | 管理者 | はい | はい |
| base | GET | `/admin/iats/flash/{flash_id}` | 管理者 | 管理者 | はい | はい |
| top | GET | `/` | ブラウザ | 無し | いいえ | いいえ |
| top | GET | `{BASE_PATH}/` | ブラウザ | 無し | いいえ | いいえ |
| top | GET | `/r` | ブラウザ（メールのリンク） | 無し（token は先の画面へ渡すだけ） | いいえ | いいえ |
| top | GET | `/.well-known/apple-app-site-association` | iOS | 無し | いいえ | いいえ |
| fido | POST | `/fido/attestation/options` | 試験の道具 | 無し | はい | いいえ |
| fido | POST | `/fido/attestation/result` | 試験の道具 | 無し | はい | いいえ |
| fido | POST | `/fido/assertion/options` | 試験の道具 | 無し | はい | いいえ |
| fido | POST | `/fido/assertion/result` | 試験の道具 | 無し | はい | いいえ |
| fido | POST | `/fido/mds/_verify` | 試験の道具 | 無し | いいえ | いいえ |
| fido | POST | `/fido/mds/config` | 試験の道具 | 無し | はい | いいえ |

## 注記

- `top` の `/` と `{BASE_PATH}/` は、BASE_PATH が空でないときだけ在り、どちらも BASE_PATH へ送り返すだけ。
  BASE_PATH が空のときは、`base` の `/`（RP のデモ）が host の直下に来る。
- `/admin/iats/flash/{flash_id}` は GET だが、一度見せたら消す。門は GET を通すので、この経路は門で守られていない。
  守りは管理者の確かめと、`flash_id` を知っていること。生の IAT を載せるので、応答には `Cache-Control: no-store` を付ける。
- `/end-session` は OpenID Connect RP-Initiated Logout 1.0 の Logout Endpoint で、GET と POST を受ける。
  id_token_hint が自分の鍵の署名・iss・aud（登録済みの client、client_id があればそれと一致）を満たし、
  sub が今のセッションの利用者なら、確かめずにセッションを消す（exp は見ない）。それ以外でセッションがあれば、
  消す前に確かめの画面を出す。画面の form は `confirm` を付けて同じ path へ POST し、その POST だけは
  `admin_same_origin` と同じ考え方（`from_own_origin`）で自分の origin に限る。RP の POST は他の origin から来るので、門は掛けない。
  確かめに失敗した hint の要求は、post_logout_redirect_uri へ戻さない。
  post_logout_redirect_uri がその client の登録と食い違う要求も、戻り先を捨て、セッションがあれば確かめの画面を出す（誤りで終わらせてセッションを残さない）。
  自分の画面（`/account` と管理画面）のログアウトは、`confirm` を付けた form の POST なので、確かめの画面を出さない。
- `/ciba/{auth_req_id}/passkey-options` と `/reject` は、`auth_req_id` を知っているだけでは呼べない（`auth_req_id` は path に載り、ログに残る）。
  `Authorization` があれば access token（`/ciba/pending` と同じ）、無ければ cookie（sid）で名乗り、要求の宛先の利用者でなければ 404。
  cookie で名乗るときは、管理画面の門と同じ `from_own_origin` で自分の origin からの要求に限る（違えば 403）。
  名乗りが無い（`Authorization` も sid も無い）ときは 401。`auth_req_id` が Firestore の文書 ID にできない形
  （129 文字以上、`__` で始まるなど）なら、引かずに 404。
  期限の切れた要求には、`/passkey-options` は 404（無いのと同じ）、`/reject` は 409（`expired`。拒否として確定させない）を返す。
  `/approve` は今までどおりログインを要らず、passkey の assertion が本人の確かめになる。
- `fido` の経路は CORS の層が OPTIONS（preflight）に答える。表の method には書かない。
- どれにも当たらない要求は、`log_unmatched` が 404 を返す。
- 要求の Host が `LEGACY_HOSTS`（カンマ区切りのホスト名。大文字小文字と port は見ない）のどれかなら、経路を見る前に
  ORIGIN の同じ path と query へ 308 で送る。表に無い path も送る。ただし `/.well-known/apple-app-site-association` は送らずに返す
  （Apple は転送された AASA を読まない）。`LEGACY_HOSTS` が空なら、どの Host でもこの表のとおり。
