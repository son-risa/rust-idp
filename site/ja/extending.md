# 拡張のしかた

この頁は、rust-idp を自分の環境に合わせて変えたい開発者に向けて書いている。どこを差し替えられるか、どこはまだ差し替えられないか、どう変えれば安全かを書く。

## 言葉

- **差し替え口**: 自分の実装を差し込める所。多くは trait で、`Provider` の `with_*` の関数で差し込む。
- **契約の試験**: trait の約束を確かめる試験の組。どの実装にも同じ試験を当てる。`src/*_contract.rs` にあり、macro を 1 行呼ぶと、その実装に全部の試験が当たる。
- **口はまだ無い**: 差し替える所が今のコードに無い。足すには、まず口の形（trait の関数と約束）を決める。

## 結び方

rust-idp は 1 つの組織だけを扱う（シングルテナント）。1 つの rust-idp は 1 つの issuer。複数の組織を扱いたい RP は、組織ごとに別の rust-idp と結ぶ。

使い方は 3 つある。どの型にも、それぞれの差し替え口を持たせる方針。今動くのは型 A だけで、型 B と型 C は予定で、まだ書いていない。

| 型 | rust-idp が持つ物 | 今の状態 |
|---|---|---|
| A. Cloud Run と Firestore の無料枠ですぐ使う | 利用者と、ログインの材料（パスキーなど） | 今ある。1 台で足りる小さな組織は、SQLite でもよい（実例 1） |
| B. 自前の system の横に置き、既存の認証と結ぶ | token だけ。ログインの画面と本人の確かめは、自前の system に任せる | 予定。まだ無い |
| C. RDB（PostgreSQL）に置き、既存の利用者の表を読む | ログインの材料だけ。利用者は既存の表から引く | 予定。まだ無い。PostgreSQL は使う人が出てから |

型 B は Ory Hydra の形をとる。端点は rust-idp に残し、ログインを challenge で自前の system に渡し、結果を受け取る。Authlete のように端点を自前の側に置く形にはしない。

### 型ごとの差し替え口

| 差し替え口 | 使う型 | 今の状態 |
|---|---|---|
| 保存先: `DocumentStore`。キーで引く（`get_doc`）・CAS（`create_if_absent`・`set_doc_if_unchanged`・`delete_doc_if_unchanged`）・1 つの値で絞る（`query_eq`）・新しい順に並べる（`list_recent_ordered`）・期限の過ぎた物を消す（`sweep_expired`） | どの型も | 今ある。実装はメモリ・Firestore・SQLite |
| ログインの委任 | 型 B | 予定。まだ無い |
| 利用者の引き当て | 型 C | 予定。まだ無い。今の名簿は `DocumentStore` の `accounts` の集まり |
| 環境: 署名鍵・メール・秘密 | どの型も | 一部ある。署名鍵は Cloud KMS（だめなら Secret Manager）があり、鍵 file は予定。メールは Resend があり、SMTP は予定。秘密は Secret Manager と環境変数から読み、差し替え口はまだ無い |

予定の口は、ログインの委任、利用者の引き当て、PostgreSQL の順に作る。

### 規模の目安

Cloud Run では、最小 0 台（常駐しない）・最大 3 台で動かす。同時にログインする 30 人を 1 台でさばく想定。Firestore では、回数の上限の数と、一度きりの記録（認可コードや jti など）を共有の保存先に置く。このため、上限も一度きりの記録も台の全体で 1 つになり、台が増えても効く。

## 拡張の軸

| 軸 | 例 | 差し替え口 | 契約の試験 |
|---|---|---|---|
| 動かす場所 | Cloud Run・VPS・k8s | 組み立ての場所。binary は `src/main.rs` と `src/gcp.rs` で組む。ライブラリとして使うなら、自分の `main` で `Provider` を組む | なし |
| 保存先 | メモリ・Firestore・SQLite → PostgreSQL | `DocumentStore`（`with_document_store`）・`Store`（`with_store`）・`CibaStore`（`with_ciba`）・`FidoStore`（`FidoState::from_env` の中で選ぶ。`with_*` は無い） | あり。`document_store_contract.rs`・`store_contract.rs`・`ciba_store_contract.rs`・`fido_store_contract.rs` |
| 鍵と署名 | Cloud KMS → 鍵 file・Vault・他の KMS・HSM | `JwsSigner`（`with_signer`・`add_signer`） | あり。`jws_signer_contract.rs` |
| 利用者の確かめ方 | パスキー → 既存のパスワード DB・LDAP/AD・上流の IdP | 口はまだ無い。パスキーの確かめは `src/webauthn.rs` と登録の流れに直に書いてある | なし |
| 利用者の出どころ | 自前の登録 → 既存の利用者 DB・SCIM | 口はまだ無い。名簿は `DocumentStore` の `accounts` の集まりにある。登録・無効化・token の発行が、そこを直に読む。id_token などの claim は `Store::find_account` が返す | なし。`find_account` は `Store` の契約の試験に入っていない |
| 知らせの手段 | Resend → SMTP・SES | `Mailer`（`with_mailer`） | あり。`mailer_contract.rs` |
| 連携先の形 | OIDC の RP・API の introspection → 既存の Basic 認証のサイトの前に置く forward-auth・SAML | 口はまだ無い。経路は `rust_idp::router` が組む | なし |
| 認可の型 | grant の種類・確かめの規則 | `GrantHandler`（`with_grant`）・`AuthorizationCheck`（`with_check`）・`ResponseMode`（`with_response_mode`） | あり。`grant_handler_contract.rs`・`authorization_check_contract.rs`・`response_mode_contract.rs` |
| client の認証の方式 | private_key_jwt・Basic → mTLS | `ClientAuthMethod`（`with_client_auth`）・`DpopVerifier`（`with_dpop`）。mTLS は、入力の `ClientAuthInput` に client の証明書の欄が無い。入力を広げるところから始める | あり。`client_auth_contract.rs`・`dpop_verifier_contract.rs` |
| 見張り | OpenTelemetry など | 口はまだ無い。rust-idp は `tracing` で記録を出す。ライブラリとして使うなら、組む側が `tracing` の subscriber を選べる。binary は `src/main.rs` で subscriber を決めている | なし |
| 多テナント | 1 つの process で複数の issuer | 持たない（決めた方針）。rust-idp は 1 つの組織だけを扱い、1 つの `Provider` は issuer を 1 つだけ持つ。複数の組織には、組織ごとに rust-idp を立てる | なし |

契約の試験の module は `#[cfg(test)]` で、macro は crate の中にだけ公開している。このため、契約の試験を当てたい実装は、この crate の中に足す。たとえば SQLite の実装（`src/sqlite.rs`）は、その試験の mod から macro を呼んでいる。

## gcp の feature なしで、今どこまで動くか

`gcp` の feature を付けずに build した binary は、次のように組む（`src/main.rs`）。

- 保存先: `MemoryDocumentStore` と、それを読む `MemoryStore`。CIBA は `MemoryCibaStore`。どれも process を止めると消える。`sqlite` の feature を付けて build し、`SQLITE_PATH` を渡すと、SQLite の file に置く（実例 1）。
- 署名鍵: 起動のたびに新しい ES256 の鍵を作る。RS256 の鍵は無い。
- メール: `LogMailer`。メールは送らず、リンクを記録に出す。
- パスキーの登録とログイン: メモリの上で動く。
- 動かない物: 管理者用のサブコマンド（Firestore を使う）。CIBA の push 通知（FCM）。
- 待ち受け: `127.0.0.1` と `[::1]` だけ。外から受けるには、前に reverse proxy を置く。
- `K_SERVICE` があると（Cloud Run の上だと）、起動しない。

ライブラリとして `Provider::new` だけで組むと、`DocumentStore` が無い。この形では、パスキーの登録とログイン・PAR・動的な client 登録・管理画面が 503 などで断る。`with_document_store` を呼ぶと動く。

メモリだけの形は、試しに動かす用途に限る。再起動すると、登録した利用者とパスキーが消える。

## 実例 1: VPS で、DB サーバを立てずに動かす

SQLite の file 1 つを保存先にする。`gcp` の feature は付けない。

SQLite の実装はある。`sqlite` の feature を付けて build し、環境変数 `SQLITE_PATH` に file の道を渡す。

```sh
cargo build --release --features sqlite
SQLITE_PATH=/var/lib/rust-idp/idp.sqlite ./target/release/rust-idp
```

- `SQLITE_PATH` があると、利用者・パスキー・登録の token・PAR・DCR など（`DocumentStore`）、セッション・認可コード・token（`Store`）、CIBA の要求（`CibaStore`）を、その file 1 つに置く。file が無ければ、持ち主だけが読み書きできる形（0600）で作る。開けなければ起動しない。
- `SQLITE_PATH` が無ければ、今までどおりメモリに置く。`sqlite` の feature なしで build した binary に `SQLITE_PATH` を渡すと、起動しない。メモリで動いて、止めたときに利用者が消えるのを避けるため。
- 1 つの process だけが file を開く前提で、WAL と `synchronous=FULL` で開く。同じ file を複数の process で分け合わない。
- file と、それを置く directory は、rust-idp を動かす利用者だけが読めるようにする（file は 600、directory は 700）。token や session の id が文書の id に入るため。
- 写しは `sqlite3` の `.backup` か `VACUUM INTO` で取る。動いている最中に file だけを `cp` すると、`-wal` にある commit が写しから欠ける。
- そのため台数は増やせない。1 台で足りる小さな組織向けで、その 1 台が止まればログインも止まる。台数を増やすなら、Firestore のような、複数の台から共有できる保存先を使う。
- 実装は `src/sqlite.rs`。SQLite で書いたのは `DocumentStore` だけ。`Store` と `CibaStore` は、Firestore でも使っている「`DocumentStore` の上の実装」をそのまま載せる。`document_store_contract_tests!`・`store_contract_tests!`・`ciba_store_contract_tests!` を、一時 directory に作った file に当てている。
- `FidoStore`（FIDO2 の適合試験の面 `/fido/*` の保存先）には、SQLite の実装が無い。この面は `FIDO_CONFORMANCE_ENABLED` のときだけ載り、メモリに置く。本番のパスキーのログインは `DocumentStore` を使う。
- `rusqlite` の crate が SQLite 本体（C）を同梱して build する。build する機械に C の compiler が要る。

まだ無いもの:

- **署名鍵を file から読む部分。** `gcp` なしの binary は、起動のたびに新しい ES256 の鍵を作る。再起動すると鍵が変わり、JWKS も変わる。`Es256Signer::from_scalar_b64` と `Rs256Signer::from_pkcs8_pem` はあり、どちらの型にも `jws_signer_contract_tests!` が当たっている。file から読んで `with_signer`・`add_signer` で差し込む部分を足す。
- **SMTP でメールを送る `Mailer`。** `gcp` なしの binary は `LogMailer` で、メールは送らず、リンクを記録に出す。`Mailer` を SMTP で実装し、`mailer_contract_tests!` を呼ぶ。この macro には、届いた中身を受け手の側から読む `Outbox` を渡す。送り損ねうる実装は、届け先が断る `Outbox` も渡す。

知っておくこと:

- rust-idp が禁じているのは、自分の crate の中の `unsafe` だけ（`#![forbid(unsafe_code)]`）。C を含む依存は禁じていない。`sqlite` の feature を付けると、SQLite 本体の C が binary に入る。
- JAR・DPoP・`private_key_jwt` の jti を 1 度だけ通す記録（`NonceStore`）は、trait でない。メモリか Firestore の 2 つから選ぶ。1 台で動かすならメモリでよい。ただし再起動すると、jti の記録が消える。

## 実例 2: PostgreSQL と動かす

`src/sqlite.rs` のように `DocumentStore` だけを PostgreSQL で書けば、`Store` と `CibaStore` は `DocumentStore` の上の実装（`FirestoreStore`・`FirestoreCibaStore`）を流用できる。この 2 つは `#[cfg(any(feature = "gcp", feature = "sqlite"))]` の中にあるので、その cfg に PostgreSQL の feature を足す。通す試験は、`document_store_contract_tests!`・`store_contract_tests!`・`ciba_store_contract_tests!`（`/fido/*` を出すなら `fido_store_contract_tests!` も）を呼んで緑にする。

PostgreSQL では、次の点を確かめる。

- 1 度だけ通す操作（`take_doc`・`take_code`・`mark_refresh_used` など）が、同時に来ても 1 つだけ通る。契約の試験には、同時に呼ぶ試験（`racing_*`）がある。行の lock か、条件つきの `UPDATE ... RETURNING` で書く。
- `*_if_unchanged` は、読んだときの版と同じときだけ書く。版の列を持つ。
- 複数の process で動かすと、メモリにある物は process ごとに分かれる。回数の上限（rate limit）の数は `DocumentStore` の `rateLimits` に置くので、同じ保存先を使う process の全体で 1 つの上限になる。jti の記録（`NonceStore`）は、Firestore の配線のほかはメモリにある。jti の記録を PostgreSQL に置くには、`NonceStore` を trait にするところから始める。private_key_jwt の公開鍵の cache（5 分）も process ごとで、鍵の入れ替えの反映が最大 5 分遅れる。

## 実例 3: 既存の利用者 DB があり、Basic 認証をしているサイトと連携する

この例は 3 つの軸にまたがる。どの軸も、口はまだ無い。口の形の案と、先に決める約束の例を書く。

### 既存のパスワードで確かめ、後でパスキーへ移す（利用者の確かめ方）

口の形の案:

```rust
#[async_trait]
pub trait PasswordVerifier: Send + Sync {
    /// 合えば account_id を返す。合わなければ None。
    async fn verify(&self, login: &str, password: &str) -> Result<Option<String>, String>;
}
```

ログインの画面に、パスワードの欄と、確かめた後にパスキーを登録する流れを足す。

先に決める約束の例:

- パスワードは定数時間で比べる（`subtle` は既に依存にある）。
- 失敗の回数に上限を持つ。利用者ごとと、送り元の IP ごとに数える。
- パスワードを記録（log）に出さない。誤りの文にも入れない。
- 利用者が居ないときと、パスワードが違うときで、同じ応答を返す。
- パスキーを登録した利用者は、パスワードでログインできなくする。

### 名簿を既存 DB から引く（利用者の出どころ）

口の形の案:

```rust
#[async_trait]
pub trait AccountDirectory: Send + Sync {
    async fn find(&self, account_id: &str) -> Result<Option<Account>, String>;
    async fn is_active(&self, account_id: &str) -> Result<bool, String>;
}
```

今は、登録・無効化・token の発行が `accounts` の集まりを直に読む。この読み方を、口を通す形に替える。

先に決める約束の例:

- 既存 DB で無効にした利用者には、新しい token を出さない。
- 既存 DB の id と、id_token の `sub` の対応を変えない。
- 既存 DB が答えないときは、token を出さずに断る。

### そのサイトを rust-idp の後ろに置く（連携先の形）

2 つの形がある。

- **forward-auth**: reverse proxy が、要求のたびに rust-idp に「この cookie のセッションは有効か」を聞く。有効なら、利用者の id を header に載せてサイトへ渡す。サイトは Basic 認証をやめ、その header を読む。rust-idp 側には、セッションを確かめて header を返す経路を足す。
- **OIDC の RP**: サイトに OIDC の RP の部品を入れ、ログインを rust-idp に任せる。rust-idp 側の変更は要らない。サイト側の変更が大きい。

forward-auth で先に決める約束の例:

- 利用者の id の header は、proxy が毎回上書きする。外から来た同じ名の header は捨てる。
- サイトには、proxy を通った要求だけが届く。
- セッションの確かめに失敗したら、通さない。

## 安全に拡張する流れ

AI に実装させる前提で書く。

1. **約束を文にする。** 人が決める。「パスワードを記録に出さない」のように、守れたか守れないかを決められる文にする。
2. **試験にする。** 約束 1 つにつき、試験を 1 つ以上書く。この時点では、試験は赤になる。
3. **実装する。** 終わる条件は 2 つある。新しい試験が緑になること。前からの試験が全部緑のままであること。
4. **わざとコードを壊して、試験が赤になるかを確かめる。** 約束を守る行を消したり、条件を逆にしたりする。壊しても緑なら、試験に穴がある。試験を直して、もう一度壊す。
5. **契約の試験がある口は、macro を 1 行呼ぶ。** すると、前の実装に当ててきた約束が、新しい実装にも同じく当たる。

## 関連

- [使い始める](get-started.md)
- [検証](verification.md)
- [設計の文書](design-docs.md)
