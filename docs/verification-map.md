# 検証の地図（client の profile ごと）

どの client の形に、どの Tamarin のモデル（と lemma）が当てはまり、どの適合試験がその形を試し、どの前提に頼っているかを、
client の profile ごとに並べる。「形式検証した」「適合試験を通した」と言うときに、どの client の形の話かを取り違えないための表。

- profile の区分は、コードの `dcr::ClientProfile`（`Public`・`ConfidentialSecret`・`ConfidentialKey`）と、client の記録の旗
  （`token_endpoint_auth_method`・`require_par`・`require_pkce`・`dpop_bound`、`model::Client`）に合わせる。
  旗を個別に決めた組み合わせと CIBA は、`ClientProfile` には無いので別の行に置く。
- 前提の ID は [`formal/premises.json`](../formal/premises.json) の行（ID と model の組）。各モデルの節の
  「表に出た前提 → rust-idp の担保」（[`formal/README.md`](../formal/README.md)）が台帳から作った表。
- 利用者の認証（passkey）は、どの profile にも共通に掛かる。`webauthn.spthy`（`authentication`・`challenge_single_use`、
  前提 P-AKEY・P-ORIGIN・P-CHAL・P-SIG）は下の表では繰り返さない。
- refresh token のローテーションと系列の失効は、どの profile にも共通に掛かる。`refresh.spthy`（前提 P-RSINGLE・P-RFAMILY）も繰り返さない。

## 表

| profile | client 認証 / PAR / PKCE / token | 当てはまる Tamarin のモデルと lemma | その形を試した適合試験の計画 | 置いている前提の ID | 本番の client（2026-11-25 時点） |
|---|---|---|---|---|---|
| `Public` | `none` / なし / 常に必須 / DPoP 束縛 | `oauth_code_pkce_public.spthy`（`code_single_use`・`token_secrecy`）。`composition_public_pkce_dpop.spthy`（#8: `comp_resource_secrecy`・`code_single_use`）。`dpop_binding.spthy`（`dpop_sender_constraining`）。`id_token.spthy`（`idtoken_integrity`）。必要性: `oauth_code_public_NEG_no_pkce`・`composition_public_NEG_no_redirect`・`composition_public_NEG_no_cnf` | 無い | `dpop_binding.spthy`: P-DKEY・P-CNF・P-PROOFSIG・P-JTI。`id_token.spthy`: P-OPKEY・P-AUD・P-NONCE・P-SIG・P-ISS。#8 と `oauth_code_pkce_public` の前提（redirect_uri の完全一致など）は、台帳に ID を持たない（README の文の表だけ） | 試し用の RP 2 件（Web とモバイル） |
| `ConfidentialSecret` | `client_secret_basic` / なし / 必須 / Bearer | `composition_code_bearer_secret.spthy`（#11）: `intercepted_code_unusable`・`token_secrecy`・`no_injection`・`consent_agreement`・`client_auth_sound`・`resource_secrecy`。示せない性質: `limit_bearer_theft_usable`・`limit_secret_leak_impersonation`・`limit_logged_secret_is_reusable`・`limit_secret_leak_resource`。必要性: `composition_bearer_NEG_no_pkce`。`id_token.spthy`（`idtoken_integrity`）。**#6 `composition_code_dpop` は当てはまらない**（DPoP を前提にする） | 無い | `composition_code_bearer_secret.spthy`: P-VERIFIER・P-TLS・P-ENVSEP・P-ATSTORE・P-CSECRET・P-SECRETCMP・P-NOCREDLOG。`id_token.spthy`: P-OPKEY・P-AUD・P-NONCE・P-SIG・P-ISS | **本番の主な RP**（client 2 件）。ほかに開発用の RP 1 件 |
| 旗を個別に決めた `private_key_jwt`（`ClientProfile` に無い組み合わせ） | `private_key_jwt` / なし / 必須 / Bearer | `composition_code_bearer_pkjwt.spthy`（#11）: `intercepted_code_unusable`・`token_secrecy`・`no_injection`・`consent_agreement`・`client_auth_sound`・`resource_secrecy`。示せない性質: `limit_bearer_theft_usable`・`limit_key_leak_impersonation`・`limit_key_leak_resource`。jti の単回を外すと `client_auth_sound` が破れる（CI の時間を超えるおそれがあるので NEG 版は置いていない。README のモデル #11）。`id_token.spthy`（`idtoken_integrity`） | 無い | `composition_code_bearer_pkjwt.spthy`: P-VERIFIER・P-TLS・P-ENVSEP・P-ATSTORE・P-CPRIVKEY・P-AJTI・P-NOLEGACYSECRET。`id_token.spthy`: P-OPKEY・P-AUD・P-NONCE・P-SIG・P-ISS | 0 件。本番の主な RP が移る先 |
| `ConfidentialKey`（FAPI2 相当） | `private_key_jwt` / 必須 / 必須 / DPoP 束縛 | `oauth_code_pkce.spthy`（#1: `code_single_use`・`token_secrecy`）。`dpop_binding.spthy`（#2）。`composition_code_dpop.spthy`（#6: `comp_resource_secrecy`）。`id_token.spthy`（#5）。必要性: `oauth_code_NEG_no_singleuse`・`composition_NEG_no_cnf`・`composition_NEG_no_clientauth`・`dpop_NEG_no_cnf`。PAR はどのモデルにも無い | OIDF の FAPI 2.0 Security Profile の試験計画（suite の alias `rustop-fapi2`）。実装起因の失敗 0、TLS の項目が残る（旧 README の記述。記録は無い）。計画の ID・実施日・suite の版・対象の commit の記録は、リポジトリに無い | `oauth_code_pkce.spthy`: P-SINGLEUSE・P-CODEFRESH・P-VERIFIER・P-CKEY・P-REG・P-TLS。`dpop_binding.spthy`: P-DKEY・P-CNF・P-PROOFSIG・P-JTI。`id_token.spthy`: P-OPKEY・P-AUD・P-NONCE・P-SIG・P-ISS。#6 の前提は台帳に ID を持たない | 0 件（適合試験用の client 2 件は staging だけ） |
| CIBA（grant。`ClientProfile` ではない） | `client_secret_basic` / — / — / Bearer | `ciba_rar.spthy`（#3: `binding_integrity`・`mandate_single_use`）。必要性: `ciba_NEG_no_binding`・`ciba_NEG_no_singleuse`。**#7 `composition_ciba_dpop_rar` は当てはまらない**（private_key_jwt と DPoP を前提にする） | 無い | `ciba_rar.spthy`: P-BIND・P-UREAD・P-MSINGLE・P-CAUTH・P-UAUTH | CIBA の RP 1 件 |

本番の client の数は、2026-11-25 の査読が本番の Firestore の `clients` を読んだ結果による。client を足したり、旗を変えたりしたら、
この欄も直す。

## 前提のうち、いま確かめる手段が無いもの

台帳で `outside`（試験にできない）にしている前提のうち、本番の主な RP の形に効くもの:

| ID | 前提 | 崩れたとき（モデルの lemma） |
|---|---|---|
| P-TLS | token endpoint と RS への通信路はサーバ認証の TLS | 全部の lemma の前提 |
| P-ENVSEP | ID token の署名鍵は本番の版だけが使える（staging と本番で鍵を分ける） | モデルは漏れの規則を置いていない。2026-11-25 の査読は、staging が本番と同じ署名鍵で署名していると指摘した |
| P-CSECRET | client の共有の秘密は client の保管庫から漏れない | `limit_secret_leak_impersonation`・`limit_secret_leak_resource` |
| P-NOCREDLOG | token 要求の `Authorization` の見出しが記録に残らない | `limit_logged_secret_is_reusable` |
| P-CPRIVKEY | client の秘密鍵は client の保管庫から漏れない | `limit_key_leak_impersonation`・`limit_key_leak_resource` |
| P-ATSTORE | Bearer の access token は client の側で漏れない | `limit_bearer_theft_usable` |
| P-NOLEGACYSECRET | private_key_jwt の client は client_secret_basic では通らない | いまのコードは登録された方式を見ず、秘密のハッシュが残っていれば Basic で通す。担保が無い（本番の主な RP の移行の後で直す予定） |

## 本番の主な RP を private_key_jwt に移すと変わること

- 記録から漏れた client 認証の値では、なりすませなくなる（`client_auth_sound` の条件から記録の漏れが消える。P-NOCREDLOG が要らなくなり、
  モデルは代わりに P-AJTI（jti の単回）を置く）。**ただし、移した client に秘密のハッシュが残っていない場合に限る（P-NOLEGACYSECRET）。**
  いまの `ClientSecretBasic::authenticate`（`src/client_auth.rs`）は登録された `token_endpoint_auth_method` を見ないので、ハッシュが
  残っていれば、前に漏れた秘密で Basic のまま通る。移すときに秘密のハッシュを消す。実装（登録された方式だけを受ける）は、
  本番の主な RP の移行の後で直す予定。
- 保管庫から鍵が漏れた場合は、`client_secret_basic` と同じく破れる（`limit_key_leak_*`）。
- Bearer のままなので、access token が盗まれれば使える（`limit_bearer_theft_usable`）ことは変わらない。これを閉じるのは DPoP（#6）。
- いまの `ClientProfile` には、PAR と DPoP を付けない `private_key_jwt` の profile が無い（`ConfidentialKey` は PAR と DPoP を必ず付ける）。
  移すには、profile を足すか、client の記録の旗を個別に決める。
