# formal/ — rust-idp のプロトコルを Tamarin で検証する

[`docs/security-ladder.md`](../docs/security-ladder.md) の「検証アーキテクチャ」の実体。
**プロトコル論理層**を記号的（Dolev-Yao 攻撃者）に検証し、各性質を支える**前提を表に出す**。
前提（抽象）→ rust-idp の担保（具体）への対応づけが、この層の成果物。

## 実行

```sh
brew install tamarin-prover          # maxima/graphviz 等も入る
tamarin-prover --prove formal/oauth_code_pkce.spthy
# 対話GUIで眺める場合:
tamarin-prover interactive formal/oauth_code_pkce.spthy   # → http://127.0.0.1:3001
```

第一版は `sources`/`reuse` 補題が要る場合がある（open-chain や非終了が出たら追加して iterate）。
**「Tamarin が詰まる = 足りない前提が見える」こと自体が収穫**であって、最初から完璧な証明である必要はない。

## CI で回す（`.github/workflows/formal.yml`）

`src/**`・`formal/**`・`Cargo.toml`・`Cargo.lock` を触る PR と main への push で、次の 2 つを回す。

- **Tamarin**: `formal/check.sh` が `formal/*.spthy` を全部 `--prove --auto-sources` にかけ、lemma ごとの結果を
  [`expected.tsv`](./expected.tsv) と突き合わせる。本体のモデルは全 lemma が verified、NEG 版は下の各節に書いた lemma が
  falsified であることを期待する。結果が違う・表に無いモデルや lemma がある・表にあるのに走らなかった・wellformedness が
  通らない、のどれでも赤。モデルを足したり lemma を変えたら、`expected.tsv` も同じ PR で直す（`--auto-sources` が
  足す `AUTO_typing` も表に入れる）。
- **Kani**: `formal/check-kani.sh` が `cargo kani` で全ハーネスを回し、SUCCESSFUL になったハーネスの名前を
  [`kani-harnesses.txt`](./kani-harnesses.txt) と突き合わせる（Kani 0.68.0）。ハーネスが消えた・増えた・名前が変わった・
  失敗した、のどれでも赤。ハーネスを足したり消したりしたら、一覧も同じ PR で直す。

```sh
formal/check.sh      # 手元で Tamarin の期待表を照合
formal/check-kani.sh # 手元で Kani の全ハーネスを一覧と照合
```

下の各節の「表に出た前提 → rust-idp の担保」の表は、[`premises.json`](./premises.json)（担保のコード・試験・Kani ハーネス、
または試験にできない理由を持つ台帳）から作る。`<!-- premises: {model} -->` と `<!-- /premises -->` の間は手で書かず、
`UPDATE_PREMISE_TABLES=1 cargo test formal_ledger` で作り直す。前提の表は範囲の中だけに置き、範囲の外に前提の表を書かない（範囲の外の行は照合しない）。`cargo test` の `formal_ledger_tests` が、その範囲が台帳から
作った表とバイト一致すること、台帳の ID の形と (id, model) の重なり、台帳が指すモデル・関数が在ること、Kani ハーネスが
`kani-harnesses.txt` に在ることを検める。台帳の試験の名前は、CI の test の job で `formal/check-ledger-tests.sh` が
`cargo test -- --list` の一覧と完全一致で照らし、`#[ignore]` の試験も断る。

## モデル #1: 認可コード + PKCE + クライアント認証 → トークン

対象は confidential client（private_key_jwt 相当 = DCR/FAPI クライアント）。フロー:

1. クライアントが `~v`(code_verifier) を生成し、`h(~v)`(code_challenge) を**フロントチャネル**（攻撃者可視）で送る
2. AS が認可コード `~code` を発行し redirect（攻撃者は code を**横取りできる**）
3. クライアントが code + `~v` + 署名(client_assertion) で**トークン要求**
4. AS が **code 単回消費 + クライアント認証 + PKCE(`h(v)=challenge`)** を検査し、トークンを**クライアント鍵へ暗号化(TLS抽象)** して配送

### 検証する性質（lemma）
| lemma | 主張 | 意味 |
|---|---|---|
| `executable` | 正直な実行が完了しうる | モデルが死んでいないことの健全性チェック |
| `code_single_use` | 同じ code から2トークンは出ない | 認可コードの単回性 |
| `token_secrecy` | 攻撃者は honest client のトークンを知り得ない（鍵漏洩がなければ） | 回線支配攻撃者への耐性 |

## 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-06-09 実測）

- `tamarin-prover --prove --auto-sources formal/oauth_code_pkce.spthy`
  → **3 lemma すべて verified**（処理 ~0.6s、wellformedness 全合格、追加 sources 補題は不要）。
  = 前提集合 {P-SINGLEUSE, P-VERIFIER, P-CKEY, P-REG, P-TLS} の下で、回線支配攻撃者に対し性質が**十分**に成り立つ。
  `token_secrecy` の証明は「攻撃者がトークンを知る唯一の道はクライアント鍵の Reveal」を示す＝**P-CKEY の必要性**を裏取り。
- **必要性の実験**: `oauth_code_NEG_no_singleuse.spthy`（`AS_Code` を persistent にして単回消費を外した変種）
  → `code_single_use` が **falsified（攻撃トレース発見）**、`token_secrecy` は verified のまま。
  = **原子的単回消費（P-SINGLEUSE）は“必要”**。外すと同一コードから2トークン（トークン要求のリプレイ）。
    単回性の役割は**コード再利用の阻止に特定**される（token_secrecy には影響しない）。
  = 段0「引換券は一度きり」の、**機械検証された必要十分**。
- **public client 変種** `oauth_code_pkce_public.spthy`（demo-rp / mobile-rp 相当 = `none` + PKCE、クライアント認証なし）
  → 3 lemma すべて verified。**PKCE が唯一の防御**として機能。
- **必要性の実験(PKCE)** `oauth_code_public_NEG_no_pkce.spthy`（public client から PKCE 検査を外す）
  → `token_secrecy` が **falsified（コード横取り攻撃トレース発見）**。
  = public client では **PKCE は“個別に必要”**。外すと攻撃者が横取りした code をそのまま交換しトークンを得る。
- **まとめ（#1 の前提導出が完成、nuance まで機械検証）**:
  - **confidential client**（private_key_jwt = DCR/FAPI）: クライアント認証 と PKCE は**冗長な多層防御**（各々単独で攻撃を阻止）。
  - **public client**（none = demo-rp / mobile-rp）: **PKCE が単独で必要**（外すと code 横取りが成立）。
  - **単回消費**（P-SINGLEUSE）は両者で必要。

## 表に出た前提 → rust-idp の担保（本層の成果物）

<!-- premises: oauth_code_pkce.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-SINGLEUSE | 認可コードは**原子的に単回消費**される（`AS_Code` が linear） | store の code 消費（単回）。回帰テスト `store::code_reuse_revokes_issued_tokens` |
| P-CODEFRESH | 認可コードは**推測不能**（CSPRNG = Fr） | code 生成（乱数） |
| P-VERIFIER | PKCE の verifier は**秘密**で、`h(verifier)=challenge` を AS が検査 | `CheckPkce`（S256 のみ受理、`auth_checks.rs`） |
| P-CKEY | クライアント秘密鍵は**秘匿**（漏れると token_secrecy が破れる） | private_key_jwt（`client_auth.rs`）。rust-idp は**公開鍵のみ保持** |
| P-REG | クライアントは**事前登録**され AS が公開鍵を知る | `with_client` / DCR（`clients` 登録、`resolve_client`） |
| P-TLS | トークン配送路は**機密**で正しいクライアントへ届く（モデルでは鍵への暗号化で抽象化） | TLS（Firebase Hosting / Cloud Run）＋ token endpoint |
<!-- /premises -->

- （攻撃者モデル） In/Out を完全支配する回線攻撃者に耐える（担保: —）

→ 「**`token_secrecy` は、攻撃者X(回線支配)に対し、前提 {P-SINGLEUSE, P-VERIFIER, P-CKEY, P-REG, P-TLS} の下で成り立つ**」。
これが目標「前提の明示」の1行。

## このモデルが示す“設計の洞察”

- **confidential client では、クライアント認証 と PKCE の両方が攻撃を止め、どちらか一方でも交換を阻止できる（多層防御）。**
  PKCE が**主役（必要）になるのは public client（クライアント認証なし）**の場合。→ 次版で public client を別 variant としてモデル化すると「PKCE の必要性」が見える。
- **単回性の必要性**は `token_secrecy` ではなく `code_single_use` に現れる。`AS_Code` を persistent にすると `code_single_use` が破れる（手元で試すと良い）。
- redirect_uri 完全一致は本版では未モデル（code 横取りは前提し、交換を client 認証+PKCE で阻止）。次版で redirect を明示するとコード**配送先**の制御が入る。

## 既知の限界 / 次版（ロードマップ）

- ユーザ認証/同意は抽象化（**WebAuthn は roadmap #4**）。
- public client（client auth 無し・PKCE 主役）は別 variant（次版）。
- TLS は「クライアント鍵への暗号化」で抽象化（実 TLS はサーバ認証）。次版で TLS セッションを明示。
- 第一版の lemma は `sources`/`reuse` 補題が要る場合あり。

ロードマップ（[`docs/security-ladder.md`](../docs/security-ladder.md) の「Tamarin モデリング・ロードマップ」）:
**#1 認可コード+PKCE（本ファイル）→ #2 DPoP 送り主束縛 → #3 CIBA+RAR マンデート → #4 WebAuthn → #5 ID token → #6 合成**。
各モデルが「防げる攻撃＋必要前提」を1セット産み、積むほど rust-idp の前提集合が埋まる。

---

## モデル #2: DPoP 送り主束縛（RFC 9449）

`dpop_binding.spthy` — トークンの**利用フェーズ**（リソースサーバ RS での検証）に焦点。発行は #1 から抽象化。
**「盗まれた bearer アクセストークンは DPoP 秘密鍵なしには使えない」** を検証する。

フロー: AS が token に `cnf.jkt = h(DPoP公開鍵)` を束縛して発行 → クライアントは token + DPoP proof
（DPoP 鍵で署名、htm/htu/jti/ath を含む）を RS に提示 → RS は cnf.jkt 一致・proof 署名・jti 単回 を検査して許可。
攻撃者は token を窃取できる（`Steal_Token`）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
- `dpop_binding.spthy` → `executable` / `dpop_sender_constraining` **verified**（処理 ~0.8s）。
- 必要性の実験 `dpop_NEG_no_cnf.spthy`（cnf.jkt 検査を外す）→ `dpop_sender_constraining` **falsified（攻撃トレース発見）**。
  = **cnf.jkt 束縛検査は必要**。外すと攻撃者が盗んだ token に**自分の鍵の proof** を付けて RS を通せる。

### 表に出た前提 → rust-idp の担保
<!-- premises: dpop_binding.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-DKEY | DPoP 秘密鍵は秘匿（漏れると束縛が無効） | クライアント側保持。rust-idp は proof を検証するだけで**鍵を持たない** |
| P-CNF | RS は「proof の鍵 thumbprint = token の cnf.jkt」を検査 | `authenticate_token`（`at.jkt` と proof の jkt 一致）。introspection が cnf.jkt 公開 |
| P-PROOFSIG | DPoP proof の署名検証（ES256） | `Es256Dpop`（`dpop.rs`） |
| P-JTI | DPoP proof の jti 単回（リプレイ防止） | jti 単回ストア（`NonceStore` / Firestore 分散） |
<!-- /premises -->

→ 導出された運用要件: **RS は token の cnf.jkt と DPoP proof の鍵 thumbprint の一致を検査せよ**（外すと盗難トークンが通る）。

### 限界 / 次版
- トークン発行は #1 から抽象化（**#6 合成**で #1×#2 を繋ぐ）。
- htm/htu は payload に持たせる（厳密一致は部分モデル）。jti 単回は含むが「proof 非リプレイ」の個別 lemma は別途。

---

## モデル #3: CIBA（切り離し承認）+ RAR マンデート

`ciba_rar.spthy` — rust-idp 固有・学術的にも手薄。中心の脅威は**「ユーザが見たものと違う要求を承認させられる」**。
登場人物: クライアント（消費デバイス = ciba-rp）/ AS / ユーザ（認証デバイス, passkey）。
攻撃者は**ユーザへの通知チャネルを操作できる**（表示すり替えの脅威）。

検証する性質: **binding 完全性**（(arid,m) のトークン発行 ⇒ ユーザは“まさにその”(arid,m) を承認していた）と
**マンデート単回**（同じ auth_req_id から2トークンは出ない）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `ciba_rar.spthy` | `executable` / `binding_integrity` / `mandate_single_use` **verified** |
| `ciba_NEG_no_binding.spthy`（承認の mandate 束縛を外す）| `binding_integrity` **falsified（表示すり替え攻撃トレース）** |
| `ciba_NEG_no_singleuse.spthy`（Pending を persistent に）| `mandate_single_use` **falsified（リプレイ）** |

→ **束縛検査が必要**（外すとユーザが承認した mandate と発行 mandate が食い違う＝CIBA 中心の脅威）。
→ **マンデート単回が必要**（外すと同一 auth_req_id から複数トークン）。

### 表に出た前提 → rust-idp の担保
<!-- premises: ciba_rar.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-BIND | ユーザ承認は**具体的 mandate に commit** し、AS は承認された mandate のみ発行 | binding_message + authorization_details を auth_req_id に紐付け表示・承認、token に approved mandate |
| P-UREAD | **ユーザが binding_message を読む**（モデル外の人間前提） | UI で binding_message/mandate を提示（"見たものに commit" を前提） |
| P-MSINGLE | マンデート(auth_req_id) は**単回消費** | `mandate_consumed` CAS（/oauth/mandate/consume）+ CIBA store の単回 |
| P-CAUTH | backchannel と poll で**クライアント認証** | ciba-rp Basic（live e2e で実機確認済） |
| P-UAUTH | 承認は**ユーザ認証**（passkey） | fido2demo アプリで passkey 承認 |
<!-- /premises -->

- （反スパム） 無認証トリガの**レート制限**（担保: `ciba_rate`（**記号的検証の対象外**＝量的性質））

→ 導出された運用要件: **ユーザ承認を具体的 mandate に暗号的に束縛し、AS は承認された mandate のみ発行せよ**（外すと表示すり替え）。**マンデートは単回消費せよ**。

### 限界
- 「ユーザが読む」は記号的に捉えられない人間前提（P-UREAD）。モデルは「ユーザは見た m に commit する」までを表現。
- 反スパム（量的）は Tamarin の対象外（rust-idp は `ciba_rate` で対処）。

---

## モデル #4: WebAuthn / FIDO2 ユーザ認証（passkey）

`webauthn.spthy` — 段1〜3 の「認証」の正体。OAuth/CIBA の中で AS がユーザを認証する所。
攻撃者は**ユーザを任意のオリジンへ誘導できる**（フィッシングを表現）。

検証する性質: **認証**（偽造不能）+ **オリジン束縛**（anti-phishing, passkey の核）+ **challenge 単回**（anti-replay）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `webauthn.spthy` | `executable` / `authentication` / `challenge_single_use` **verified** |
| `webauthn_NEG_no_origin.spthy`（origin 検査を外す）| `authentication` **falsified（フィッシング攻撃トレース）** |
| `webauthn_NEG_no_singleuse.spthy`（Pending を persistent に）| `challenge_single_use` **falsified（リプレイ）** |

→ **オリジン束縛が必要**（外すと偽オリジンのアサーションを本物 RP が受理＝フィッシング）。
→ **challenge 単回が必要**（外すとアサーション再送）。

### 表に出た前提 → rust-idp の担保
<!-- premises: webauthn.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-AKEY | 認証器 credential 鍵は秘匿 | secure enclave。rust-idp は**公開鍵のみ保持** |
| P-ORIGIN | RP は origin/rpId == 自分 を検査 | `webauthn::verify_authentication`（origin + rpIdHash） |
| P-CHAL | challenge 新鮮 + 単回 | `create/consume_webauthn_challenge`（単回。updateTime の CAS 削除 `Firestore::take_doc` で、並行した 2 つの要求の片方だけが通る） |
| P-SIG | 登録公開鍵で署名検証 | `webauthn::verify_authentication` |
<!-- /premises -->

- （anti-clone） signCount 単調増加（担保: signcount 検査（**記号的モデル対象外**＝異常検知））

→ 導出された運用要件: **RP は origin/rpId が自分のものか検査せよ**（外すとフィッシング）／**challenge は単回**。

### 限界
- signCount（anti-clone）は「偽造防止」でなく「クローン異常検知」で、記号的モデルの対象外。
- ブラウザの SOP（rpId=origin 強制）を「認証器は文脈の o に署名」で抽象化。

---

## モデル #5: OIDC ID token（フェデレーションの原子）

`id_token.spthy` — OP がユーザの身元を RP に主張（署名付き）。複数 RP（aud 束縛が効く）。
攻撃者は**悪意 RP として被害 RP の nonce を自分の OP ログインに転送できる**（audience-confusion / cut-and-paste）。

検証する性質: **偽造不能** + **aud 束縛**（RP1 宛 token を RP2 で使えない）+ **nonce 新鮮**（古い token 再送防止）を `idtoken_integrity` に集約。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `id_token.spthy` | `executable` / `idtoken_integrity` **verified** |
| `id_token_NEG_no_aud.spthy`（aud 検査を外す）| `idtoken_integrity` **falsified（audience confusion）** |
| `id_token_NEG_no_nonce.spthy`（nonce 検査を外す）| `idtoken_integrity` **falsified（replay）** |

→ **aud 束縛が必要**（外すと RP1 宛 token を RP2 が受理）／**nonce 新鮮が必要**（外すと古い token 再送）。

### 表に出た前提 → rust-idp の担保
<!-- premises: id_token.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-OPKEY | OP 署名鍵は秘匿 | ES256 / Cloud KMS（鍵をプロセスに展開しない） |
| P-AUD | RP は aud == 自分の client_id を検査 | OP 側: token に aud=client_id。RP 側(fido2demo/oidc): aud 検証 |
| P-NONCE | nonce 新鮮 + RP が一致検査 | OP: 認可要求の nonce を token へ。RP: nonce 検証 |
| P-SIG | RP は OP の JWKS で署名検証 | discovery / JWKS 公開、RP が検証 |
| P-ISS | iss（発行者）確認（IdP mix-up 防止） | token の iss=OP。RP は OP の鍵で検証（モデルは OP 鍵束縛で表現） |
<!-- /premises -->

→ 導出された運用要件: **RP は aud==自分・nonce==自 flow・iss==期待 OP・署名を検査せよ**（外すと audience confusion / replay / mix-up）。

### 限界
- ユーザ認証/同意は #4 で抽象化（**#6 合成**で繋ぐ）。
- iss/mix-up は OP 鍵束縛で部分表現（明示的な mix-up 実験は別途）。

---

## モデル #6: 合成（#1 認可コード+PKCE+クライアント認証 × #2 DPoP × #4 ユーザ同意）

`composition_code_dpop.spthy` — rust-idp の FAPI2 ログイン（confidential client = DCR/FAPI）。
**エンドツーエンドのリソース秘匿**: 正規ユーザの保護リソースは、DPoP 鍵もユーザ鍵も漏れない限り攻撃者に漏れない。

### ★ 合成は一筋縄ではいかなかった（formal verification が隠れた前提を炙り出した）
最初の合成は **2度 falsify** され、抽象化で落としていた前提を Tamarin が強制的に明示させた:
1. **ユーザ同意の束縛が必要**: コードは「ユーザが“その特定クライアント”に同意した」ときだけ出るべき。
   無いと誰のクライアントでもユーザの認可を得られる（1度目の falsify）。→ `U_Consent` を追加。
2. **public client は client_id 詐称で乗っ取れる**（本来 **redirect_uri 完全一致** が防ぐもの）。
   モデルが redirect_uri を抽象化していた（2度目の falsify）。→ confidential client（クライアント認証）に切替。
3. さらに `executable` が falsify（no trace）→ token-use メッセージ形式の不一致という**モデルのバグ**を発見・修正。

これは「個々に安全でも合成は別物」「証明が完成しないと前提を隠せない」の生きた実例。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `composition_code_dpop.spthy` | `executable` / `comp_resource_secrecy` **verified**（空虚でない＝honest flow が通る） |
| `composition_NEG_no_cnf.spthy`（cnf を外す, #2）| `comp_resource_secrecy` **falsified（盗難トークンが RS を通る）** |
| `composition_NEG_no_clientauth.spthy`（クライアント認証を外す, #1）| `comp_resource_secrecy` **falsified（攻撃者が盗んだコードを償還）** |

→ **#2(cnf) と #1(クライアント認証) は各々個別に必要**（外すとエンドツーエンドが破れる）。
→ PKCE・consent は confidential client では**多層防御で冗長**（client auth が償還を守る）。
   これらの個別の必要性は **public client の文脈**で現れる（上記の 2 度の falsify がそれ）。

### 合成の結論
**#1（償還の保護）と #2（盗難トークンの無効化）が重なって初めて、エンドツーエンドの安全性が出る**:
- #1 だけ: トークンは正規クライアントに届くが、盗まれたら使える（#2 が無いと）。
- #2 だけ: 盗難トークンは無効だが、攻撃者が最初から償還できる（#1 が無いと）。
- 両方 + ユーザ同意: 攻撃者は正規ユーザの認可で RS に到達できない。

### 限界
- ID token(#5) の合成は別（本モデルはアクセストークンの送り主束縛に焦点）。
- public client の完全な合成（redirect_uri / プラットフォーム束縛込み）は follow-up。

---

## モデル #7: 合成（#3 CIBA 切り離し承認 × #3 RAR マンデート × #2 DPoP 送り主束縛）

`composition_ciba_dpop_rar.spthy`。rust-idp の CIBA ログイン（confidential client、トークンは DPoP 束縛、
authorization_details = mandate）の end-to-end。#6（認可コード系の合成）と対になる **CIBA 系の合成**。

### 検証する性質（lemma）
- `comp_resource_secrecy`: 正規ユーザ U の保護リソースは、**DPoP 鍵もユーザ鍵も漏れない限り**攻撃者に漏れない。
- `binding_integrity`: (arid, m) のトークン発行 ⇒ ユーザは**まさにその** (arid, m) を承認していた（表示すり替え不可）。
- `mandate_single_use`: 同じ auth_req_id から2トークンは出ない（Pending が linear）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
- `executable` verified (14 steps) / `comp_resource_secrecy` verified (12) / `binding_integrity` verified (8) /
  `mandate_single_use` verified (12)。**一発で verified**（#6 で踏んだ payload 不整合バグを学習し `let` で両側統一）。
- 必要性（NEG）:
  - `composition_ciba_NEG_no_cnf.spthy`: RS の cnf.jkt 検査を外す → `comp_resource_secrecy` **falsified**（盗難トークンを
    攻撃者の鍵で使用しリソース漏洩）＝**DPoP 送り主束縛が必要**。
  - `composition_ciba_NEG_no_binding.spthy`: AS の「承認 mandate = 保存 mandate」検査を外す → `binding_integrity`
    **falsified**（通知すり替えで承認 m′ ≠ 発行 m）＝**CIBA/RAR の mandate 束縛が必要**。

### 表に出た前提 → rust-idp の担保
| 前提（抽象） | rust-idp の担保（具体） |
|---|---|
| ユーザは**見た mandate に commit**して承認（passkey 署名） | CIBA 承認時の passkey 署名（`ciba.rs` / `webauthn.rs`） |
| AS は **承認 mandate = backchannel 要求の mandate** を検査 | CIBA token endpoint の mandate 束縛（`ciba.rs`、authorization_details 照合） |
| トークンは **cnf.jkt で送り主束縛**（盗まれても無効） | DPoP（`dpop.rs`、grants の `dpop_jkt` 一致） |
| auth_req_id は **単回消費** | CIBA `consume_if_approved` の CAS 単回（前提 A1 に依存） |
| クライアント認証（backchannel / poll 両方） | private_key_jwt（`client_auth.rs`） |

### 攻撃者モデルと結論
攻撃者は**ユーザ通知チャネルを操作可（表示すり替え）かつトークン窃取可**。それでも、cnf 束縛（盗難無効化）と
mandate 束縛（すり替え無効化）が**重なって初めて** end-to-end のリソース秘匿が出る。どちらを外しても NEG が falsify する。

### 限界
- ID token(#5) の合成は別。public client（CIBA は通常 confidential なので該当は限定的）は対象外。

---

## モデル #8: 合成（public client 認可コード × redirect_uri 完全一致 × PKCE × #2 DPoP × ユーザ同意）

`composition_public_pkce_dpop.spthy` — rust-idp の **public client**（`token_endpoint_auth_method="none"`、
demo-rp / mobile-rp 型）の end-to-end。#6（confidential = private_key_jwt の合成）と対になる **public 版**。
クライアント認証が無い分、**何がその穴を埋めているか**を炙り出すのが主眼。

### ★ 形式検証が再び隠れた前提を炙り出した（#6 に続く2例目）
最初 redirect_uri 束縛**無し**（code を平文 `Out`）でモデル化すると、`executable` は verified のまま
`comp_resource_secrecy` だけが **falsified（11 steps）**＝モデルは健全で**本物の攻撃**が見つかった:
**攻撃者が自分の verifier `~v_adv` で `authreq(C,U,h(~v_adv))` を作り、ユーザに同意させ、出た code を
自分で償還して自鍵束縛トークンを得る**（public はクライアント認証が無く、PKCE challenge も攻撃者が選べるので
PKCE は素通り）。これを止める唯一の防御が **redirect_uri 完全一致**（code を登録エンドポイントにだけ配送）。
モデルに endpoint 制御（秘密ハンドル `~ep`、never Out）を入れて code をそこへだけ届けると **verified（13 steps）** になる。
→ **修正がそのまま診断の検証**になっている（redirect 束縛を入れて verify したことで、攻撃の原因が redirect 欠如だと確定）。

### 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `composition_public_pkce_dpop.spthy` | `executable` (13) / `comp_resource_secrecy` (13) / `code_single_use` (10) **verified** |
| `composition_public_NEG_no_redirect.spthy`（redirect 束縛を外し `Out(~code)` に戻す）| `comp_resource_secrecy` **falsified（11 steps）** ＝ 上記の自鍵束縛トークン攻撃 |
| `composition_public_NEG_no_cnf.spthy`（RS の cnf.jkt 検査を外す, #2）| `comp_resource_secrecy` **falsified（9 steps）** ＝ 平文配送トークンを窃取し自鍵 proof で使用 |

→ **redirect_uri 完全一致 と cnf 束縛が各々個別に必要**（どちらを外しても end-to-end が破れる）。両 NEG とも
`executable` は verified のまま（モデルが健全な証拠）。

### このモデルが証明すること / しないこと（正直に）
- **証明する**: public client では **redirect_uri 完全一致**（= code の配送先制御）と **cnf 束縛**が load-bearing。
- **証明しない（前提として置く）**: 本モデルは code が登録エンドポイントにだけ届くため、**PKCE は冗長**
  （横取り code が存在しないので `h(v)=challenge` 検査は攻撃を1つも止めていない）。PKCE の**個別の必要性**は
  code 可視（横取り）シナリオの `oauth_code_pkce_public.spthy` + `oauth_code_public_NEG_no_pkce.spthy` で別途証明済み。
  **#8 が PKCE の必要性を示すと主張してはいけない**——#8 が示すのは redirect + cnf の必要性。

### L1 ↔ L3 の層対応が閉じる
#8 の falsify は、**なぜ redirect_uri 完全一致が public client で load-bearing か**をプロトコル論理で示す。
これは L3 Kani の `redirect_uri_match_is_exact`（実コード `auth_checks::redirect_uri_registered` がバイト完全一致で、
正規化の抜け道が無いことをロック）の**プロトコル側の正当化**になる:
- **L1（#8）= なぜ**厳密一致が必要か（外すと自鍵束縛トークン攻撃が成立）。
- **L3（Kani）= 実コードが**その厳密一致を本当に担保しているか（`u==ru` の完全一致、空リストは不一致）。

これで「L1 の前提＝L3 の証明義務」が redirect_uri について両側から閉じる（#6 で「redirect_uri 束縛が public で
load-bearing」と気づいた所を、#8 が記号モデルで明示し、Kani が実コードで固めた）。

### 表に出た前提 → rust-idp の担保
| 前提（抽象） | rust-idp の担保（具体） |
|---|---|
| code は**登録エンドポイントにだけ**配送（redirect_uri 完全一致） | `auth_checks::redirect_uri_registered`（バイト完全一致、Kani `redirect_uri_match_is_exact` でロック） |
| トークンは **cnf.jkt で送り主束縛**（盗まれても無効） | DPoP（`dpop.rs`、grants の `dpop_jkt` 一致） |
| ユーザ同意は**その client への同意**（passkey 署名） | login/consent の passkey 署名（`webauthn.rs`） |
| 認可コードは**単回消費** | store の CAS 単回（前提 A1 に依存、Tamarin `Once` で表現） |
| （PKCE）verifier 秘密 + `h(v)=challenge` | `auth_checks::pkce_method_is_s256`。本合成では冗長だが多層防御として保持 |

### 限界
- フィッシング/同意すり替え（ユーザが偽 client に同意）はスコープ外（client は1つに固定）。redirect 束縛は
  「code の**配送先**が攻撃者に渡らない」ことだけを表現。
- ID token(#5) の合成は別。

---

## モデル #9: 招待の登録リンク（token の単回）

`invite.spthy` — 招待を許した RP が、クライアント認証つきで AS に「E を招待」と頼む。AS は token を作り、TLS の応答で
RP にだけ返す。RP はリンクを E のメール箱へ送り、利用者はその token と自分の passkey 公開鍵を AS に送って登録する。
攻撃者は AS の登録口へ自分で要求を送れ、使い終わったリンクが後から漏れること（転送・メール箱の侵害）も起こせる。

AS の登録は 2 段に分けてある。先に「E がまだ登録済みでない」ことを確かめ（`refuse_invite_for_registered`）、
そのあとで招待を消費して passkey を保存する。2 つの段の間には別の要求が割り込める。

### 検証する性質（lemma）
| lemma | 主張 |
|---|---|
| `executable` | 正直な実行（依頼 → メール → 登録）が完了しうる |
| `invite_single_use` | 1 つの token から登録は 1 回しか起きない |
| `invite_binding` | token で E に登録された鍵は E のメール箱の持ち主の鍵である（リンクの漏れか、招待を頼んだ RP の鍵の漏れを除く） |

### 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-10-18 実測）
| モデル | 結果 |
|---|---|
| `invite.spthy` | `executable` / `invite_single_use` / `invite_binding` **verified** |
| `invite_NEG_no_singleuse.spthy`（`Invite` を persistent にして単回消費を外す）| `invite_single_use` **falsified**、`invite_binding` は verified のまま |

→ **単回消費が必要**。「登録済みなら断る」確認だけでは足りない。確認と消費の間に割り込んだ 2 つ目の要求
（同じ要求の再送や、漏れたリンクを持つ攻撃者の要求）も、確認を通ってしまう。NEG の攻撃の跡はこの競合になっている。
→ 単回の役割は「1 token 1 登録」に限られる。鍵の持ち主の束縛（`invite_binding`）は、単回が無くても崩れない。

### 表に出た前提 → rust-idp の担保
<!-- premises: invite.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-ICLIENT | 招待を頼めるのは、招待を許した confidential client だけ（クライアント認証） | `authorize_invite_client`（`web/register.rs`、許可リストと public client の拒否） |
| P-ITOKEN | token は推測不能（Fr） | `random_token`（OsRng の 32 バイト） |
| P-ISINGLE | 招待は**原子的に単回消費**される（`Invite` が linear） | `consume_email_challenge`（`registration.rs`）。updateTime の CAS 削除で、勝った 1 つの要求だけが通る |
| P-IMAIL | リンクは E のメール箱の持ち主にだけ届く | RP とメールの配送の基盤（モデルの外。漏れは `Leak_Link` で表す） |
<!-- /premises -->

→ 導出された運用要件: **招待の token は、確認とは別に、消費そのものを原子的に行え**（確認だけでは並行した要求を止められない）。

**直す前の版とのずれ（このモデルが見つけたもの）**: このモデルを書いた時点（main d924873）の `consume_email_challenge` と
`consume_webauthn_challenge` は、`get_doc` で読んだあとに `delete_doc(..).ok()` で消すだけで、原子的でなく、削除の失敗も
無視していた。P-ISINGLE は成り立っておらず、NEG 版の攻撃の跡（確認を通った 2 つの要求が両方とも登録する）がコードでも
起きた。fake Firestore で同じ token の消費を 2 つ並べると、5 回とも 2 つが通った。updateTime の CAS 削除
（`Firestore::take_doc`）に直した PR が P-ISINGLE と P-CHAL の担保で、試験
`registration::tests::two_concurrent_consumes_of_one_invite_let_only_one_through` と
`two_concurrent_consumes_of_one_webauthn_challenge_let_only_one_through` が、直しを戻すと赤になる。

### 限界
- 有効期限（7 日）は記号モデルの外。
- 「登録済みなら断る」確認の段（restriction `NotRegisteredAtCheck`）は、モデルでは効いていない。外しても、どの lemma の結果も
  変わらない（2026-10-18 実測）。1 つの E に複数の招待が残る場合を守るのはコードの側で、担保は試験
  `leftover_invite_cannot_replace_a_registered_passkey`。本モデルは 1 token の単回に焦点を当てている。

---

## モデル #10: refresh token のローテーションと系列の失効

`refresh.spthy` — RT を出すたびに使用済みにして同じ系列の新しい RT を返し（ローテーション）、使用済みの RT が
もう一度出されたら（盗難の兆し）系列を丸ごと失効させる（OAuth Security BCP の refresh token rotation と reuse detection）。
盗難を最大に見るため、発行した RT はすべて攻撃者に見える（`Out`）。性質は RT の秘匿に頼らず、AS の状態の遷移だけから出る。
DPoP 束縛・クライアント認証・期限は外してある（DPoP 束縛は grants の試験、系列の walk の停止は Kani が見る）。

### 検証する性質（lemma）
| lemma | 主張 |
|---|---|
| `executable` | 発行 → ローテーション 2 回が起きうる |
| `rt_single_use` | 1 つの RT から 2 回ローテーションは起きない |
| `no_rotation_after_revoke` | 失効した系列でローテーションは起きない（補助。`reuse_stops_the_family` の証明に使う） |
| `reuse_stops_the_family` | ローテーション済みの RT がもう一度出されたら、その後その系列でローテーションは起きない |

### 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-10-18 実測）
| モデル | 結果 |
|---|---|
| `refresh.spthy` | 4 lemma すべて **verified** |
| `refresh_NEG_no_singleuse.spthy`（`Fresh` を persistent にして単回の使用済み化を外す）| `rt_single_use` と `reuse_stops_the_family` が **falsified** |
| `refresh_NEG_no_family_revoke.spthy`（再利用を拒むだけで系列を失効させない）| `reuse_stops_the_family` が **falsified**（`rt_single_use` は verified のまま） |

→ **使用済み化の単回と、系列の失効の両方が要る**。単回が無いと、同じ RT から 2 つの系列の枝が生える。
系列の失効が無いと、盗んだ側が先にローテーションしていた場合、正規の側が古い RT を出して再利用が見つかっても、
盗んだ側は新しい RT で使い続けられる。
→ `refresh_NEG_no_family_revoke.spthy` では `no_rotation_after_revoke` は空虚に verified になる（失効の action が無いため）。
→ 筋書き（盗んだ側が先にローテーションし、正規の側が古い RT を出す）を lemma で表すと、`reuse_stops_the_family` の前件の式
そのものになる。その表し方が正しいことは、`refresh_NEG_no_family_revoke` の反例の跡（Issue → 先に持った側の Rotate → 古い RT の
Present → 新しい RT での Rotate の続き）が示している。

### 表に出た前提 → rust-idp の担保
<!-- premises: refresh.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-RSINGLE | RT の使用済み化は**原子的に単回**（`Fresh` が linear） | `mark_refresh_used`（`store.rs` の Mutex、`firestore_store.rs` の updateTime CAS） |
| P-RFAMILY | 使用済みの RT が出されたら、系列を**丸ごと失効**させ、以後その系列のどの RT も受け付けない | 系列の失効の札（#75）: `RefreshTokenGrant::handle` の `pre.used` 分岐で `revoke_refresh_family` が `refreshFamilyRevocations/{familyId}` に札を書き、ローテーションは読んだ時と書き込みの後に `refresh_family_revoked` で札を見て断る（札を引けなければ断る）。鎖を辿って消すのは後片付けで、消し漏れがあっても札が使わせない。モデルの `Family(F, 'revoked')` が札に当たる。familyId を持たない古い RT はローテーションさせない。札が入る前の版は鎖を辿って消すだけで、上限 64・周の打ち切り・読みの誤り・書き込みの間の失効で使える RT が残った |
<!-- /premises -->

### 限界
- 系列の失効は、コードでは系列の札（#75）で表し、モデルの系列の状態 1 つ（`Family(F, 'revoked')`）とそのまま対応する。
  札の期限（RT の TTL ＋ 2 日）が過ぎた後の振る舞いは、モデルの外（その系列の RT はそれまでに全部切れている）。
- 期限・DPoP 束縛・クライアントの束縛は別のモデルと試験が見る。


---

## モデル #11: 合成（認可コード + PKCE + client 認証 + Bearer。本番の主な RP の形）

#6（`composition_code_dpop.spthy`）の `comp_resource_secrecy` は DPoP の束縛（cnf）を前提にしていて、cnf を外した
`composition_NEG_no_cnf.spthy` は破れる。本番の主な RP は ConfidentialSecret の profile（`client_secret_basic` + PKCE S256、
PAR なし・DPoP なし・Bearer）で動いているので、#6 は当てはまらない。#11 はその形を、そのまま書いたモデル。
client 認証を private_key_jwt に変えた形（PAR と DPoP は入れない）も、同じ骨組みの変種として並べる。

| file | client 認証 | 違う所 |
|---|---|---|
| `composition_code_bearer_secret.spthy` | `client_secret_basic` | client は毎回秘密そのものを TLS の中で送る。AS は秘密のハッシュだけを持つ |
| `composition_code_bearer_pkjwt.spthy` | `private_key_jwt` | client は毎回新しい jti の assertion を送る。AS は公開鍵だけを持ち、jti を 1 回だけ受ける |
| `composition_bearer_NEG_no_pkce.spthy` | `client_secret_basic` | NEG 版。token endpoint の PKCE の検査を外す |

2 つの変種は、client の登録・償還・token endpoint の client 認証の検査・漏れの規則だけが違い、他の規則と lemma の式は同じ。
変種を file で分けたのは、既存のモデルが public と confidential、本体と NEG を file で分けているのに合わせたため。

モデルの作り（#1・#6 との違い）:
- token endpoint と RS の TLS を、AS の公開鍵への暗号化と、client が作る応答用の鍵で表す（サーバ認証の TLS）。
  #1 の「client の鍵への暗号化」より実際の TLS に近く、`client_secret_basic` の秘密を通信路に載せられる。
- 認可コードはフロントチャネルに `Out` する（横取りできる）。redirect_uri の完全一致は効いていない最悪の場合として置く。
- 利用者は、フロントチャネルに来た client C 宛ての要求なら、攻撃者が始めた要求にも passkey で同意する。
- ID token は (iss, aud=C, sub=U, nonce, at_hash) に OP の鍵で署名する。client は署名・aud・nonce を確かめる。
- RS（`/userinfo` などの token で守る口）は Bearer。token を持って来た者に、その者の TLS の鍵でリソースを返す。
- 漏れの規則を 4 つ置く: client の秘密（鍵）の漏れ、処理を終えた token 要求の記録の漏れ、client が持つ Bearer token の漏れ、
  利用者の passkey の漏れ。lemma の条件にどれが出てくるかが、その性質が何に頼っているかを表す。

### 示す性質（lemma。両方の変種で verified）
| lemma | 主張 | 条件（漏れてもよいもの / 漏れてはいけないもの） |
|---|---|---|
| `executable` | 正直な流れ（同意 → code → token → RS）が最後まで通る | 漏れなし |
| `intercepted_code_unusable` | 正直な client の要求から出た code を横取りしても、その code の token を攻撃者は知らない（PKCE） | client の秘密（鍵）が漏れていても成り立つ。Bearer token の漏れだけを除く |
| `token_secrecy` | 正直な client が受け取った access token と ID token を、攻撃者は知らない | 同上 |
| `no_injection` | 正直な client が要求 (v, n) で受け取った token は、AS がこの client に、challenge h(v) と nonce n に結び付いた code に対して出したもの。別の要求の code・token・ID token を混ぜられない | 条件なし（どの漏れの下でも） |
| `consent_agreement` | その token の利用者 U は、まさにこの要求 (C, h(v), n) に同意している | U の passkey の漏れを除く |
| `client_auth_sound` | AS が C として認めた token 要求は、C 自身が送ったもの（なりすましへの耐性）。pkjwt では assertion 単位で、「AS が受けた (jti, code) の組は、C 自身がその code の償還のために作ったもの」 | secret: 秘密が保管庫からも記録からも漏れない限り。pkjwt: 秘密鍵が漏れない限り（記録の漏れは条件に無い） |
| `resource_secrecy` | 利用者のリソースは攻撃者に漏れない | 利用者の passkey、client の秘密（鍵）、記録、Bearer token のどれも漏れない限り |

### 示せない性質（exists-trace の lemma。verified = 攻撃の跡が在る = その性質は成り立たない）
| lemma | 変種 | 示すこと |
|---|---|---|
| `limit_bearer_theft_usable` | 両方 | 漏れた Bearer token は、client の秘密も passkey も無事なまま、そのまま使える（DPoP が無いため） |
| `limit_secret_leak_impersonation` | secret | 共有の秘密が漏れると、C になりすまして token endpoint を通れる |
| `limit_logged_secret_is_reusable` | secret | 処理を終えた token 要求の記録が漏れると、攻撃者は秘密そのものを知る（毎回同じ値を送るため）。あとは上と同じ |
| `limit_secret_leak_resource` | secret | 秘密が漏れ、攻撃者が始めた要求に利用者が同意すると、利用者のリソースが漏れる（PKCE は攻撃者自身の verifier なので止めない） |
| `limit_key_leak_impersonation` | pkjwt | 秘密鍵が漏れると、C になりすまして token endpoint を通れる |
| `limit_key_leak_resource` | pkjwt | 秘密鍵が漏れ、利用者が攻撃者の要求に同意すると、利用者のリソースが漏れる |

`limit_logged_secret_is_reusable` は、はじめ「記録の漏れ → C 以外が token endpoint を通る」を 1 つの exists-trace に書いたが、
手元で 2 分を超えても跡が出なかったので、「記録から秘密そのものを知る」に分けた。なりすましへのつながりは
`limit_secret_leak_impersonation` が示す。

### 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-11-25 実測。手元の Apple Silicon で 1 つずつ）
| モデル | 結果 | 時間 |
|---|---|---|
| `composition_code_bearer_secret.spthy` | 示す性質 7 つ（`executable` を含む）と示せない性質 4 つが、すべて **verified** | 約 45 秒 |
| `composition_code_bearer_pkjwt.spthy` | 示す性質 7 つと示せない性質 3 つが、すべて **verified** | 約 40 秒 |
| `composition_bearer_NEG_no_pkce.spthy` | `intercepted_code_unusable`（16 steps）と `no_injection`（10 steps）が **falsified**。`executable` は verified | 約 12 秒 |

派生の検査（wellformedness の 1 つ）が手元でも 3〜4 秒かかり、既定の 5 秒の打ち切りに近いので、`check.sh` は
`--derivcheck-timeout=60` で走らせる。

jti の単回（`OnceJti`）を外した NEG 版（記録から漏れた assertion を、攻撃者が自分の要求で得た別の code に使い回す）では、
`client_auth_sound` が **falsified（29 steps）** になる。つまり pkjwt の `client_auth_sound` は jti の単回（P-AJTI）に頼っている。
ただし、全 lemma（`executable` と `client_auth_sound`）を証明すると手元で約 670 秒かかり、CI の tamarin の job の上限（15 分）を超えるおそれがあるので、
NEG 版は formal/ に置いていない（`--prove=client_auth_sound` に絞ると約 265 秒）。作り方は、`composition_code_bearer_pkjwt.spthy` から
`OnceJti` の action と restriction を外すだけ。コードの側の jti の単回は試験 `client_auth::tests::pkjwt_rejects_jti_replay` が見る。

→ **PKCE は、client の秘密が漏れた場合の横取りと注入を止める**。NEG 版で外すと `intercepted_code_unusable` と `no_injection`
が破れる。#1 では「confidential client では client 認証と PKCE は冗長な多層防御」としたが、秘密の漏れを入れると、
PKCE が個別に効く場面がはっきりする。
→ **2 つの client 認証の差は、送った値が後から漏れた場合に出る**。`client_secret_basic` は毎回同じ秘密を送るので、
記録（前段のログ、RP の側の記録）に残れば秘密が漏れたのと同じになる。`private_key_jwt` は jti を 1 回だけ受けるので、
記録から漏れた assertion では通れない（`client_auth_sound` の条件に記録の漏れが無い）。保管庫から鍵が漏れた場合は、どちらも同じく破れる。
ただしこれは、private_key_jwt の client が Basic では通らないこと（P-NOLEGACYSECRET）を前提にしている。いまのコードの
`ClientSecretBasic::authenticate`（`src/client_auth.rs`）は登録された方式を見ないので、移した client に秘密のハッシュが残っていれば、
漏れた秘密で Basic のまま通る。実装は本番の主な RP の移行の後で直す予定。
→ **Bearer は盗まれれば使える**。これは仕様どおりで、防ぐのは DPoP（#6）の役目。この形では、access token の寿命（900 秒）と、
RP の側の保管が守りになる。

### 表に出た前提 → rust-idp の担保

client_secret_basic の変種:
<!-- premises: composition_code_bearer_secret.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-VERIFIER | PKCE の verifier は**秘密**で、token endpoint が `h(verifier)=challenge` を検査（横取りした code を償還させず、別の要求の code を差し込ませない） | `CheckPkce`（S256 のみ受理）。client の旗 `require_pkce=true`（ConfidentialSecret の profile は必ず立てる） |
| P-TLS | token endpoint と RS への通信路は**サーバ認証の TLS**（モデルでは AS の公開鍵への暗号化と、client が作る応答の鍵） | TLS（Cloud Run のドメインのマッピング）。HSTS |
| P-ENVSEP | ID token の署名鍵は**本番の版だけ**が使える（staging と本番で鍵を分ける）。モデルは署名鍵の漏れの規則を置かない | Cloud KMS の鍵（`KMS_ES256_KEY`・`KMS_RS256_KEY`）と実行 SA。staging の鍵と SA を分けるのは配備の仕事 |
| P-ATSTORE | Bearer の access token は client の側で**漏れない**（漏れれば使える: `limit_bearer_theft_usable`） | RP の実装（token を記録やブラウザへ出さない）。rust-idp の側は寿命を 900 秒にし、失効（`/revoke`）を受ける |
| P-CSECRET | client の共有の秘密は client の保管庫から**漏れない**（漏れればなりすませる: `limit_secret_leak_impersonation`） | RP の秘密の保管（Secret Manager など）。rust-idp は秘密のハッシュだけを持つ（`dcr::hash_token`） |
| P-SECRETCMP | AS は提示された秘密の**ハッシュ**を、登録したハッシュと比べる（`h(cs) = hs`） | `ClientSecretBasic::authenticate`（`hash_token` を定数時間で比べる。平文は保存しない） |
| P-NOCREDLOG | token 要求の `Authorization` の見出し（秘密そのもの）が、処理の後も**記録に残らない**（残れば秘密が漏れたのと同じ: `limit_logged_secret_is_reusable`） | rust-idp は見出しを記録しない。前段（Cloud Run のリクエストログ）と RP の側の記録の設定に依る |
<!-- /premises -->

private_key_jwt の変種:
<!-- premises: composition_code_bearer_pkjwt.spthy -->
| ID | 前提（抽象） | rust-idp の担保 |
|---|---|---|
| P-VERIFIER | PKCE の verifier は**秘密**で、token endpoint が `h(verifier)=challenge` を検査（横取りした code を償還させず、別の要求の code を差し込ませない） | `CheckPkce`（S256 のみ受理）。client の旗 `require_pkce=true`（ConfidentialSecret の profile は必ず立てる） |
| P-TLS | token endpoint と RS への通信路は**サーバ認証の TLS**（モデルでは AS の公開鍵への暗号化と、client が作る応答の鍵） | TLS（Cloud Run のドメインのマッピング）。HSTS |
| P-ENVSEP | ID token の署名鍵は**本番の版だけ**が使える（staging と本番で鍵を分ける）。モデルは署名鍵の漏れの規則を置かない | Cloud KMS の鍵（`KMS_ES256_KEY`・`KMS_RS256_KEY`）と実行 SA。staging の鍵と SA を分けるのは配備の仕事 |
| P-ATSTORE | Bearer の access token は client の側で**漏れない**（漏れれば使える: `limit_bearer_theft_usable`） | RP の実装（token を記録やブラウザへ出さない）。rust-idp の側は寿命を 900 秒にし、失効（`/revoke`）を受ける |
| P-CPRIVKEY | client の秘密鍵は client の保管庫から**漏れない**（漏れればなりすませる: `limit_key_leak_impersonation`） | RP の鍵の保管。rust-idp は公開鍵（jwks / jwks_uri）だけを持つ |
| P-AJTI | client_assertion の jti は **1 回だけ**受ける（記録から漏れた assertion を使い回させない） | `PrivateKeyJwt::authenticate` が `NonceStore::claim` で jti を exp まで覚える。aud は issuer の文字列だけ |
| P-NOLEGACYSECRET | private_key_jwt の client は **client_secret_basic では通らない**（モデルの client は秘密を持たない） | **いまは担保が無い**。`ClientSecretBasic::authenticate` は登録された `token_endpoint_auth_method` を見ず、`client_secret` のハッシュが残っていれば Basic で通す。private_key_jwt に移した client にハッシュが残ると、漏れた秘密でなりすませる。本番の主な RP の移行の後で、登録された方式だけを受けるように直す予定 |
<!-- /premises -->

- （攻撃者モデル）フロントチャネルを完全に支配し、認可コードを横取りできる（担保: —。redirect_uri の完全一致は効いていない場合として置く）
- 認可コードの単回（P-SINGLEUSE）は、#11 のどの lemma も頼っていないので、#11 の前提の表に置かない（#1 が見る）。
- 利用者の同意は passkey の署名（#4 の前提）。ID token の検査（署名・aud・nonce）は RP の側の実装で、このモデルでは TLS と PKCE が先に
  注入を止めるため、単独では効いていない（ID token の署名の効き目は #5 `id_token.spthy` が見る）

### 限界
- 時刻（code の 60 秒、assertion の exp、token の 900 秒）は記号モデルの外。assertion の exp の窓は Kani の `exp_in_window_spec` が見る。
- 記録の漏れ（`Leak_TokenRequestLog`）は、AS が要求を処理して token を出した後だけを置いている。処理の前の漏れ（前段で記録され、
  AS に届く前に読まれる）と、断られた要求の記録の漏れは置いていない。
- 同意は、モデルでは要求ごとの passkey の署名（`U_Consent`）で表す。実装では、ログイン済みの session（SSO）が要求ごとの passkey の
  代わりをする。session の盗難や、session がある間に攻撃者の要求へ黙って同意が出る場合は、モデルの外。
- 利用者の同意の画面のすり替え（利用者が偽の client に同意する）は外。client は登録された名前だけで区別する。
- refresh token は外（ローテーションと系列の失効は #10 が見る）。
- private_key_jwt の変種（PAR・DPoP なし）は、いまの DCR の profile には無い組み合わせ（ConfidentialKey は PAR と DPoP を必ず付ける）。
  移すときは、profile を足すか、client の記録の旗を個別に決める。

---

## ロードマップ達成状況
**#1 ✅ #2 ✅ #3 ✅ #4 ✅ #5 ✅ #6 ✅ #7 ✅ #8 ✅** — 全モデルが Tamarin 1.12.0 で verified、各前提の必要性も
NEG 変種の falsify で実証。各モデルが「防げる攻撃 ＋ 必要前提（→ rust-idp の運用要件）」を1セット産んだ。
合成 #6（confidential 認可コード系）・#7（CIBA 系）・#8（public 認可コード系）は、複数防御が**重なって初めて**
end-to-end の安全性が出ることを示す。#6 と #8 は形式検証が隠れた前提（consent 束縛・redirect_uri 完全一致）を
炙り出した実例でもある（#8 は redirect 束縛の load-bearing 性を記号モデルで明示し、L3 Kani の redirect ロックと層対応が閉じた）。

---

## L3: コード↔モデル橋（Kani 0.68.0 / CBMC）

Tamarin（L1）は記号モデル上で前提が成り立てば性質が成り立つことを示す。が、**その前提を実コードが本当に担保しているか**、また
**記号モデルが見ない実装固有の落とし穴（整数オーバーフロー等）が無いか**は L1 では分からない。これを埋めるのが Kani による
有界モデル検査（L3）。`#[cfg(kani)] mod kani_harness`（`src/kani_harness.rs`）に置き、通常ビルド・テストからは除外される。

```sh
cargo install --locked kani-verifier && cargo kani setup
cargo kani                       # 全ハーネス
cargo kani --harness exp_in_window_spec
```

### 検証結果（Kani 0.67.0 / CBMC, 2026-06-09 実測）

| ハーネス | 検証した命題 | 結果 |
|---|---|---|
| `exp_in_window_spec` | `exp_in_window(exp,now,max)` は全 i64 で **panic せず**（saturating_add でオーバーフロー無し）、定義どおり `ok ⇔ now<exp≤now+max` | ✅ 4/4 checks |
| `jti_ttl_is_bounded` | 受理された exp に対し jti TTL = `exp-now` が **(0, 3600] に有界・溢れない** | ✅ SUCCESSFUL |

### 橋の意味（Tamarin の前提 → Kani が機械検証した実コード述語）

| Tamarin 側 | Kani 側の担保 |
|---|---|
| #1 の client_assertion 新鮮性の **時間有効性**の半分（リプレイ不能の半分は jti 単回ストアが担い、本ハーネス対象外） | `exp_in_window`（`client_auth.rs`）が窓検査を一点に集約し、Kani が全 i64 でオーバーフロー非発生＋定義一致を証明 |
| jti を覚える窓が有界であること（さもなくば保持無限肥大／TTL オーバーフロー） | `jti_ttl_is_bounded` が `exp-now ∈ (0,3600]` を機械保証。**exp_in_window は jti 単回防御を健全かつ有界にする load-bearing な前提**だと位置づく |

→ **記号モデルが算術を見ない死角（遠未来 exp による TTL オーバーフロー／jti 保持の無限肥大）を、Kani が実コード上で閉じた**。
これが「L1 の前提＝L3 の証明義務」を1つ履行した形。

### 追加の橋 #1〜#4（2026-06-09）— 階層を正直に分ける

候補4つを実コードに当たって精査すると、**Tamarin の前提が「比較(`==`)」か「変換/パース」か**で Kani の効き方が分かれた。
比較は言語意味論で厳密ゆえ Kani は**回帰ロック**止まり（恒真寄り）、変換は panic/正当性の**本物の検証面**になる。
4つを同列の「verified」と並べず、効能を正直に区別する。

**正直な結論: 4つのうち潜在バグを実際に発見したものは無い**。#1/#2/#4 は「既に安全なものを固定する回帰ロック」、#3 は層の割当（Kani 射程外）。
特に #4 は当初「本物のバグ狩り」と見積もったが**過大評価だった**: `strip_query_fragment` は `str::find` を使っており、`str::find` は
**文字境界を返す**契約ゆえ `&u[..end]` は構造的に panic しえない（クラッシュ事例は作ろうにも作れない）。安全イディオムが既に
適用済みで、Kani は「やはり起きない」を確認しただけ。**この見積もり違いのせいで、起こりえないクラッシュの記号探索に
状態爆発で時間を浪費した**（教訓として残す）。→ Kani が本当にバグ狩りになるのは、安全 API を使わず生バイト index 演算や
`unsafe`・ビット操作をする**変換コード**（`b64url`／thumbprint）であって、strip_query_fragment はそこではなかった。

| 橋 | 実コード | Kani の効能 | ハーネス / 結果 |
|---|---|---|---|
| #1 redirect_uri 完全一致 | `auth_checks::redirect_uri_registered`（`iter().any(\|u\| u==ru)`） | **回帰ロック**: 照合がバイト完全一致で正規化の抜け道が無いことを固定（`match ⟺ a==b`、空リストは不一致）。将来正規化が紛れ込むと破れる | `redirect_uri_match_is_exact` ✅ |
| #2 PKCE S256 | `auth_checks::pkce_method_is_s256`（`method.unwrap_or("plain")=="S256"`） | **回帰ロック**: `m`が`Some("S256")`ちょうどのみ受理＝None/plain/大小違いへのダウングレード不可を固定 | `pkce_method_no_downgrade` ✅ |
| #3 認可コード単回 | store の CAS 単回消費（Firestore `take_code`） | **Kani 射程外**（下記） | — |
| #4 DPoP htu 正規化 | `dpop::strip_query_fragment`（`&u[..u.find(['?','#'])..]`） | **回帰ロック**（当初「バグ狩り」と誤見積）: `str::find` が文字境界を返すゆえ `&u[..end]` は元から panic しえない。安全イディオム（`str::find`+slice）が保たれることを固定し、生 index 化等の危険な refactor を検出（入力は下記の通り有界化） | `strip_query_fragment_safe` ✅ |

**#3 は「スキップ」ではなく層の割当**: 認可コード単回は **Firestore の分散 CAS 原子性**に依存する。Kani は**単一プロセスの有界モデル検査器**で、
分散ストアの原子性は射程外（見えない）。この義務は **L1（Tamarin の `Once` ＝ #1 で verified 済）** と **L4（回帰テスト
`store::code_reuse_revokes_issued_tokens`）** で履行済み。「どの前提がどの層の責務か」を明示するのが、この演習の狙いそのもの。

**なぜ panic しえないか（#4 の核心）**: `strip_query_fragment` は `end = u.find(['?','#']).unwrap_or(u.len())` を使う。
`str::find` は **文字単位**で走査しマッチ文字の**先頭バイト位置**を返す契約なので、`end` は**常に文字境界**（`u.len()` も境界）。
ゆえに `&u[..end]` は構造的に文字の途中を割らず panic しえない。「区切りが多バイト文字を割る」クラッシュ事例は
`str::find` 経由では**構成不能**。Kani の役割はこの安全性の再確認＝**ロック**であって、潜在バグの発見ではない。

**カバレッジ境界（silent cap を作らない）**: それでも記号文字列で `find` を走らせるとパターンマッチャの UTF-8 デコードが
状態爆発する（この 8GB 環境では全 UTF-8 シンボリック化は収束しない）。そこで入力を `"é<tail>"`（先頭 2 バイト文字 `é` を
具体値固定、`tail` は ASCII 全域の記号バイト）に有界化し、`tail` が `?`/`#` のとき `&u[..2]`（`é` 直後＝多バイト境界）で切れることを
検証した。**任意の先頭文字長・任意長文字列の全証明ではない**点を明示する（そもそも上記契約より全入力で安全なので、ここは確認）。

### 次に橋を架ける候補
JWK thumbprint（RFC 7638 正準化＝**変換**ゆえ本物の Kani 面）、`b64url`（ビット操作・アルファベット/パディング＝変換）、
id_token `aud`/`nonce` 照合（比較＝ロック）。比較系はロック、変換/パース系は panic/正当性。新しい橋もこの判別則で仕分ける。
