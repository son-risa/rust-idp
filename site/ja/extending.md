# 拡張のしかた

この頁は、rust-idp を自分の環境に合わせて変えたい開発者に向けて書いている。どこを差し替えられるか、どこはまだ差し替えられないか、どう変えれば安全かを書く。

## 言葉

- **差し替え口**: 自分の実装を差し込める所。多くは trait で、`Provider` の `with_*` の関数で差し込む。
- **契約の試験**: trait の約束を確かめる試験の組。どの実装にも同じ試験を当てる。`src/*_contract.rs` にあり、macro を 1 行呼ぶと、その実装に全部の試験が当たる。
- **口はまだ無い**: 差し替える所が今のコードに無い。足すには、まず口の形（trait の関数と約束）を決める。

## 拡張の軸

| 軸 | 例 | 差し替え口 | 契約の試験 |
|---|---|---|---|
| 動かす場所 | Cloud Run・VPS・k8s | 組み立ての場所。binary は `src/main.rs` と `src/gcp.rs` で組む。ライブラリとして使うなら、自分の `main` で `Provider` を組む | なし |
| 保存先 | メモリ・Firestore → PostgreSQL・SQLite | `DocumentStore`（`with_document_store`）・`Store`（`with_store`）・`CibaStore`（`with_ciba`）・`FidoStore`（`FidoState::from_env` の中で選ぶ。`with_*` は無い） | あり。`document_store_contract.rs`・`store_contract.rs`・`ciba_store_contract.rs`・`fido_store_contract.rs` |
| 鍵と署名 | Cloud KMS → 鍵 file・Vault・他の KMS・HSM | `JwsSigner`（`with_signer`・`add_signer`） | あり。`jws_signer_contract.rs` |
| 利用者の確かめ方 | パスキー → 既存のパスワード DB・LDAP/AD・上流の IdP | 口はまだ無い。パスキーの確かめは `src/webauthn.rs` と登録の流れに直に書いてある | なし |
| 利用者の出どころ | 自前の登録 → 既存の利用者 DB・SCIM | 口はまだ無い。名簿は `DocumentStore` の `accounts` の集まりにある。登録・無効化・token の発行が、そこを直に読む。id_token などの claim は `Store::find_account` が返す | なし。`find_account` は `Store` の契約の試験に入っていない |
| 知らせの手段 | Resend → SMTP・SES | `Mailer`（`with_mailer`） | あり。`mailer_contract.rs` |
| 連携先の形 | OIDC の RP・API の introspection → 既存の Basic 認証のサイトの前に置く forward-auth・SAML | 口はまだ無い。経路は `rust_idp::router` が組む | なし |
| 認可の型 | grant の種類・確かめの規則 | `GrantHandler`（`with_grant`）・`AuthorizationCheck`（`with_check`）・`ResponseMode`（`with_response_mode`） | なし |
| client の認証の方式 | private_key_jwt・Basic → mTLS | `ClientAuthMethod`（`with_client_auth`）・`DpopVerifier`（`with_dpop`）。mTLS は、入力の `ClientAuthInput` に client の証明書の欄が無い。入力を広げるところから始める | なし |
| 見張り | OpenTelemetry など | 口はまだ無い。rust-idp は `tracing` で記録を出す。ライブラリとして使うなら、組む側が `tracing` の subscriber を選べる。binary は `src/main.rs` で subscriber を決めている | なし |
| 多テナント | 1 つの process で複数の issuer | 口はまだ無い。1 つの `Provider` は issuer を 1 つだけ持つ | なし |

契約の試験の module は `#[cfg(test)]` で、macro は crate の中にだけ公開している。このため、契約の試験を当てたい実装は、この crate の中に足す。たとえば `src/sqlite_store.rs` を作り、その試験の mod から macro を呼ぶ。

## gcp の feature なしで、今どこまで動くか

`gcp` の feature を付けずに build した binary は、次のように組む（`src/main.rs`）。

- 保存先: `MemoryDocumentStore` と、それを読む `MemoryStore`。CIBA は `MemoryCibaStore`。どれも process を止めると消える。
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

SQLite の実装は、まだ無い。足す物は次のとおり。

1. **保存先の実装を 3 つか 4 つ書く。**
    - `DocumentStore`: 利用者・パスキー・登録の token・PAR・DCR など。文書の中身は Firestore の REST の値の形の JSON で来る。表 1 つ（集まりの名・id・JSON・版）で持てる。
    - `Store`: セッション・認可コード・token。`find_account` は、`MemoryStore` と同じく、同じ `DocumentStore` から利用者を引く。
    - `CibaStore`: CIBA の要求。
    - `FidoStore`: FIDO2 の適合試験の面（`/fido/*`）の保存先。この面は `FIDO_CONFORMANCE_ENABLED` のときだけ載る。本番のパスキーのログインは `DocumentStore` を使う。この面を出さないなら、`FidoStore` は要らない。
2. **契約の試験を呼ぶ。** 実装ごとに macro を 1 行呼び、緑にする。

    ```rust
    #[cfg(test)]
    mod tests {
        async fn store() -> super::SqliteDocumentStore {
            super::SqliteDocumentStore::open_in_memory().unwrap()
        }
        crate::document_store_contract::document_store_contract_tests!(store);
    }
    ```

    `Store` は `store_contract_tests!`、`CibaStore` は `ciba_store_contract_tests!`、`FidoStore` は `fido_store_contract_tests!` を呼ぶ。`SqliteDocumentStore` は、これから作る実装の名の例。
3. **鍵を file から読む。** `Es256Signer::from_scalar_b64` と `Rs256Signer::from_pkcs8_pem` がある。file から読んで `with_signer`・`add_signer` で差し込む。どちらの型も `jws_signer_contract_tests!` が当たっている。file を読む部分は、まだ無い。
4. **メールを SMTP で送る。** `Mailer` を SMTP で実装し、`mailer_contract_tests!` を呼ぶ。この macro には、届いた中身を受け手の側から読む `Outbox` を渡す。送り損ねうる実装は、届け先が断る `Outbox` も渡す。
5. **起動を組む。** 今の `src/main.rs` は、`gcp` なしだとメモリの保存先を固定で組む。SQLite を使う組み立て（feature を 1 つ足すか、自分の `main` を書く）が要る。

先に決めること:

- SQLite の crate の多くは C の SQLite を含む。rust-idp は Rust だけで書く方針なので、どの crate を使うかを先に決める。
- JAR・DPoP・`private_key_jwt` の jti を 1 度だけ通す記録（`NonceStore`）は、trait でない。メモリか Firestore の 2 つから選ぶ。1 台で動かすならメモリでよい。ただし再起動すると、jti の記録が消える。

## 実例 2: PostgreSQL と動かす

実例 1 と同じ口を、PostgreSQL で実装する。通す試験も同じで、`document_store_contract_tests!`・`store_contract_tests!`・`ciba_store_contract_tests!`（`/fido/*` を出すなら `fido_store_contract_tests!` も）を呼んで緑にする。

PostgreSQL では、次の点を確かめる。

- 1 度だけ通す操作（`take_doc`・`take_code`・`mark_refresh_used` など）が、同時に来ても 1 つだけ通る。契約の試験には、同時に呼ぶ試験（`racing_*`）がある。行の lock か、条件つきの `UPDATE ... RETURNING` で書く。
- `*_if_unchanged` は、読んだときの版と同じときだけ書く。版の列を持つ。
- 複数の process で動かすと、メモリにある物は process ごとに分かれる。jti の記録（`NonceStore`）と、回数の上限（rate limit）がそうなる。jti の記録を PostgreSQL に置くには、`NonceStore` を trait にするところから始める。

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
