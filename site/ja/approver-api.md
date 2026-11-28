---
title: 承認の API
description: 利用者の端末のアプリが、rust-idp の CIBA の要求を一覧し、承認し、拒否するための口。
---

# 承認の API

この頁は、CIBA の要求を利用者の端末で承認するアプリを作る開発者に向けたものです。そのアプリが呼ぶ口と、それぞれの口が求めるものを書きます。

CIBA Core が決めているのは、client が要求を始めて結果を待つ（poll する）手順です。利用者の端末が要求を知る手順と、承認を OP に返す手順は決めていません。この頁の口は、その隙間を埋めます。どれも rust-idp 独自の口で、標準ではありません。汎用の SDK はこの口を扱えません。

アプリが無くても承認できます。ブラウザの画面 `/ciba` は、ログインしている利用者の待ちの要求を並べ、パスキーで承認させます。この画面は、access token ではなくログインの cookie を使います。

## 言葉

- **承認のアプリ**: 利用者の端末で、待ちの要求を見せ、承認か拒否をするアプリ。
- **`ciba:approve`**: 承認の口を呼ぶ access token が持つべき scope。
- **`{i}`**: issuer。例は `https://idp.example/oidc`。下の道は、どれも issuer からの相対です。

## 始める前に

### アプリを登録し、scope を許す

1. アプリを client として登録します。grant は、認可コードと PKCE です。
2. その client に `ciba:approve` を許すよう、運用者に頼みます。client がこの scope を求められるのは、登録の `scope`（RFC 7591 の項目）にこの scope があるときだけです。
    - 動的な client の登録（DCR）では、この scope は付きません。要求に何を書いても、新しい登録の `scope` は空です。
    - Firestore で動かしているなら、運用者は管理コマンドで付けます。

    ```sh
    rust-idp set-client-scope --client <client_id> --scope ciba:approve
    ```

    `--scope ""` で外せます。このコマンドが変えるのは `scope` だけです。登録のほかの項目は変えません。

許されていない client が `ciba:approve` を求めると、`invalid_scope`（"ciba:approve is not allowed for this client"）が返ります。`/authorize`・PAR・`/backchannel-authentication` のどれでも同じです。

### 利用者をログインさせる

認可コードフローと PKCE で、利用者をログインさせます。`scope` には `ciba:approve` を入れます。例は `openid offline_access ciba:approve` です。

- refresh で、後からこの scope を足すことはできません。この scope 無しでログインした利用者は、ログインし直す必要があります。
- 承認の口は、呼ばれるたびに client の登録を見ます。運用者が scope を外すと、その client に出した token は、承認の口では使えなくなります（403）。

### DPoP

access token が DPoP の鍵に束縛されているときは、その token を使う呼び出しのすべてで、`DPoP` の scheme（`Authorization: DPoP <token>`）を使います。呼び出しのたびに、新しい `DPoP` の proof を付けます。proof には次を入れます。

- `htm`: 呼び出しの method
- `htu`: issuer に道を足したもの。例は `https://idp.example/oidc/ciba/pending`
- `ath`: access token の hash

束縛されていない token は、`Authorization: Bearer <token>` で送れます。

### 口の URL を得る

discovery の文書（`{i}/.well-known/openid-configuration`）は、口のうち 3 つを `custom_endpoints` に載せています。アプリは道を書き込まずに済みます。

| 鍵 | URL |
|---|---|
| `ciba_pending` | `{i}/ciba/pending` |
| `ciba_history` | `{i}/ciba/history` |
| `fcm_token` | `{i}/ciba/fcm-tokens` |

要求ごとの口は、`auth_req_id` から組み立てます。`{i}/ciba/{auth_req_id}/passkey-options`・`/approve`・`/reject` です。

## 口

| method | 道 | 認可 |
|---|---|---|
| GET | `/ciba/pending` | `ciba:approve` を持つ access token |
| GET | `/ciba/history` | `ciba:approve` を持つ access token |
| POST | `/ciba/fcm-tokens` | `ciba:approve` を持つ access token |
| POST | `/ciba/{auth_req_id}/passkey-options` | `ciba:approve` を持つ access token か、ブラウザのログインの cookie。要求の宛先の利用者だけ |
| POST | `/ciba/{auth_req_id}/approve` | パスキーの assertion。access token は使わない |
| POST | `/ciba/{auth_req_id}/reject` | `ciba:approve` を持つ access token か、ブラウザのログインの cookie。要求の宛先の利用者だけ |

access token を受ける口に共通の誤り:

| 状態 | 本文 | 意味 |
|---|---|---|
| 401 | `access token required` | `Authorization` の header が無い |
| 401 | `invalid token` | token が無いか、期限が切れている |
| 401 | `DPoP scheme required`・`DPoP proof required`・`DPoP jkt mismatch`・`DPoP: …` | token が DPoP に束縛されているのに、鍵を持つことを示していない |
| 403 | `forbidden` | token に `ciba:approve` が無いか、client の登録がもう許していない |
| 503 | `temporarily unavailable` | token の保存先を読めなかった。token は捨てずに、やり直す |

### GET /ciba/pending

token の利用者に宛てた、待ちの要求を JSON の配列で返します。期限の切れた要求は、先に履歴へ移します。

```json
[
  {
    "auth_req_id": "4f1c…",
    "client_id": "example-rp",
    "scope": "openid",
    "binding_message": "Pay 100",
    "authorization_details": [{ "type": "payment_initiation", "…": "…" }]
  }
]
```

`authorization_details` は、要求の RAR の中身（JSON）か `null` です。これを利用者に見せます。`null` のときは `binding_message` を見せます。利用者が、何を承認するのかを正確に分かるようにするためです。

### GET /ciba/history

token の利用者の、片付いた要求を新しい順に最大 50 件返します。各項目は、上の項目に `outcome`（`approved`・`denied`・`expired`）と `resolved_at`（epoch からの秒）を足したものです。

### POST /ciba/fcm-tokens

端末の Firebase Cloud Messaging の token を登録します。rust-idp は、新しい要求を端末に知らせられるようになります。

```json
{ "token": "<FCM の登録 token>", "platform": "ios" }
```

`platform` は省けます。省くと `ios` になります。204 を返します。push の通知は、Firestore で動かしているときだけ使えます。

### POST /ciba/{auth_req_id}/passkey-options

承認を始めます。WebAuthn の assertion を作るための options を返します。

```json
{
  "challenge": "…",
  "rpId": "idp.example",
  "timeout": 60000,
  "userVerification": "required",
  "allowCredentials": [{ "type": "public-key", "id": "…", "transports": ["internal", "hybrid"] }]
}
```

challenge は、この要求とこの利用者に結び付きます。

| 状態 | 意味 |
|---|---|
| 401 `sign-in required` | access token も、ログインの cookie も無い |
| 403 `forbidden` | cookie でログインしているが、`Origin`（無ければ `Referer`）が OP 自身の origin ではない |
| 404 | 要求が無い、期限が切れている、またはほかの利用者に宛てたもの |
| 400 `no passkey` | 利用者がパスキーを持っていない |

### POST /ciba/{auth_req_id}/approve

上の options で作ったパスキーの assertion を送ります。access token は付けません。本人であることは、assertion が示します。

```json
{
  "id": "<credential の id>",
  "response": {
    "clientDataJSON": "…",
    "authenticatorData": "…",
    "signature": "…",
    "userHandle": "…"
  }
}
```

rust-idp は、次の 3 つを確かめます。

- challenge が、この要求のために出したものであること
- 要求が、同じ利用者のものであること
- assertion が正しく、利用者の確認（user verification）を伴うこと

`clientDataJSON` の `origin` は、OP の origin と完全に一致する必要があります。RP ID は issuer の host です。iOS のアプリ向けに、OP は `/.well-known/apple-app-site-association` を出します。その `webcredentials` には、設定したアプリ（`APPLE_APP_ID`）が入ります。いまの OP は `assetlinks.json` を出しません。`android:apk-key-hash:` の origin も受けません。

| 状態 | 意味 |
|---|---|
| 200 `{"ok": true}` | 承認した。client は次の poll で token を受け取る |
| 400 | challenge が無い・知らない・期限切れ・ほかの要求のもの、または credential が利用者のものではない |
| 401 | assertion を確かめられなかった |
| 403 `account disabled` | アカウントが止められている |
| 404 | 要求が無い、期限が切れている、またはほかの利用者に宛てたもの |
| 409 `already handled` | 要求はもう承認か拒否で片付いている |

### POST /ciba/{auth_req_id}/reject

要求を拒否します。本文もパスキーも要りません。拒否は安全な側に倒れる操作だからです。client は次の poll で `access_denied` を受け取ります。

| 状態 | 意味 |
|---|---|
| 204 | 拒否した |
| 401 `sign-in required` | access token も、ログインの cookie も無い |
| 403 `forbidden` | cookie でログインしているが、`Origin`（無ければ `Referer`）が OP 自身の origin ではない |
| 404 | 要求が無い、またはほかの利用者に宛てたもの |
| 409 `expired` | 要求の期限が切れている。拒否ではなく、期限切れとして記録する |
| 409 `already handled` | 要求はもう承認か拒否で片付いている |

## 出所

- 口: [src/web/ciba.rs](https://github.com/son-risa/rust-idp/blob/main/src/web/ciba.rs)
- token と DPoP の確かめ: [src/web/mod.rs](https://github.com/son-risa/rust-idp/blob/main/src/web/mod.rs) の `authenticate_token`
- discovery: [src/web/oidc.rs](https://github.com/son-risa/rust-idp/blob/main/src/web/oidc.rs) の `custom_endpoints`
- 経路の表: [docs/routes.md](https://github.com/son-risa/rust-idp/blob/main/docs/routes.md)
