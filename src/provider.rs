//! Provider 本体。差し替え可能な実装をレジストリに保持する。
//! 新機能 = 新しい trait impl を register するだけ、が拡張の基本方針。

use crate::auth_checks::*;
use crate::ciba::{CibaRateLimiter, CibaStore, MemoryCibaStore};
use crate::client_auth::*;
use crate::dpop::{DpopVerifier, Es256Dpop};
use crate::error::OAuthError;
use crate::document_store::DocumentStore;
#[cfg(feature = "gcp")]
use crate::firestore::Firestore;
use crate::grants::*;
use crate::jws::{Es256Signer, JwsSigner};
use crate::mailer::{LogMailer, Mailer};
use crate::model::Client;
use crate::response_mode::*;
use crate::store::{MemoryStore, Store};
use std::collections::HashMap;
use std::sync::Arc;

pub struct Provider {
    pub(crate) issuer: String,
    /// 外部 URL のパス接頭辞（例 "/rust-oidc"）。Hosting rewrite はパスを保持して
    /// 転送するので、内部リダイレクトの Location もこの接頭辞を付ける必要がある。
    pub(crate) base_path: String,
    pub(crate) store: Arc<dyn Store>,
    /// store が new() の MemoryStore のまま（with_store を呼んでいない）か。with_document_store が見る。
    store_is_default: bool,
    /// 既定の署名鍵（ES256）。client が alg を指定しない場合に使う。
    pub(crate) signer: Arc<dyn JwsSigner>,
    /// 追加の署名鍵（RS256 等）。jwks 公開と alg 選択に使う。
    pub(crate) extra_signers: Vec<Arc<dyn JwsSigner>>,
    /// パスキーの登録とログイン・復旧・管理画面・PAR・DCR・CIBA の承認などの保存先。
    /// None ならそれらの経路は 503 などで断る（既定）。本番（Cloud Run）は Firestore。
    pub(crate) docs: Option<Arc<dyn DocumentStore>>,
    /// FCM の push の送り先（project とアクセストークン）。本番の Firestore と同じもの。
    #[cfg(feature = "gcp")]
    pub(crate) fcm: Option<Arc<Firestore>>,
    /// CIBA バックチャネル要求の永続化。既定は In-memory、本番は Firestore 実装を注入する。
    pub(crate) ciba: Arc<dyn CibaStore>,
    /// CIBA の (client_id, account) ごとレート制限。push スパム抑止のバックストップ。
    pub(crate) ciba_rate: Arc<CibaRateLimiter>,
    /// 登録メール送信のレート制限（email / IP ごと）。無認証メール乱用のバックストップ。
    pub(crate) register_rate: Arc<CibaRateLimiter>,
    pub(crate) mailer: Arc<dyn Mailer>,
    pub(crate) dpop: Arc<dyn DpopVerifier>,
    /// JAR (request object) の jti 単回ストア。本番は Firestore（with_firestore で注入）。
    pub(crate) jar_jti: crate::nonce::NonceStore,
    pub(crate) clients: HashMap<String, Client>,
    /// Phase 1（client 解決 + redirect 検証後）のポリシーチェック群。相互に可換なので
    /// 順序は自由。client 解決と redirect 検証は auth_checks::resolve_addressee に固定。
    pub(crate) checks: Vec<Arc<dyn AuthorizationCheck>>,
    pub(crate) grants: HashMap<String, Arc<dyn GrantHandler>>,
    pub(crate) client_auth: HashMap<String, Arc<dyn ClientAuthMethod>>,
    pub(crate) response_modes: HashMap<String, Arc<dyn ResponseMode>>,
    /// private_key_jwt クライアントの jwks_uri から鍵を取得・キャッシュする（鍵ローテーション）。
    pub(crate) jwks_resolver: crate::jwks_resolver::JwksResolver,
    /// 招待の登録リンク（POST /invites）の発行を許す confidential client の client_id。空なら誰にも許さない。
    pub(crate) invite_clients: Vec<String>,
    /// メールのリンクから passkey の登録を渡すネイティブのアプリ。None ならアプリへの誘導と AASA を出さない。
    pub(crate) mobile_app: Option<MobileApp>,
}

/// 登録の画面からアプリを開く誘導（iOS の custom scheme・Android の intent）と、
/// `/.well-known/apple-app-site-association` に出すアプリ。
#[derive(Clone, Debug)]
pub struct MobileApp {
    /// 登録の画面に出すアプリの名前。
    pub name: String,
    /// アプリの custom scheme（`{scheme}://magic?t=...` で開く）。
    pub scheme: String,
    pub android_package: String,
    /// AASA の appID（`TEAMID.bundle.id`）。
    pub apple_app_id: String,
}

impl Provider {
    pub fn new(issuer: impl Into<String>) -> Self {
        let checks: Vec<Arc<dyn AuthorizationCheck>> = vec![
            Arc::new(CheckResponseType),
            Arc::new(CheckScope),
            Arc::new(CheckPkce),
        ];

        let mut grants: HashMap<String, Arc<dyn GrantHandler>> = HashMap::new();
        register_grant(&mut grants, Arc::new(AuthorizationCodeGrant));
        register_grant(&mut grants, Arc::new(RefreshTokenGrant));
        register_grant(&mut grants, Arc::new(CibaGrant));

        let mut client_auth: HashMap<String, Arc<dyn ClientAuthMethod>> = HashMap::new();
        register_auth(&mut client_auth, Arc::new(NoneAuth));
        register_auth(&mut client_auth, Arc::new(ClientSecretBasic));
        register_auth(&mut client_auth, Arc::new(PrivateKeyJwt::default()));

        let mut response_modes: HashMap<String, Arc<dyn ResponseMode>> = HashMap::new();
        let q: Arc<dyn ResponseMode> = Arc::new(QueryMode);
        response_modes.insert(q.name().to_string(), q);

        Self {
            issuer: issuer.into(),
            base_path: String::new(),
            store: Arc::new(MemoryStore::default()),
            store_is_default: true,
            signer: Arc::new(Es256Signer::generate()),
            extra_signers: Vec::new(),
            docs: None,
            #[cfg(feature = "gcp")]
            fcm: None,
            mailer: Arc::new(LogMailer),
            ciba: Arc::new(MemoryCibaStore::default()),
            ciba_rate: Arc::new(CibaRateLimiter::default()),
            // 1 時間に 5 通まで（同一 email / 同一 IP）。正常な登録では超えない。
            register_rate: Arc::new(CibaRateLimiter::new(std::time::Duration::from_secs(3600), 5)),
            dpop: Arc::new(Es256Dpop::default()),
            jar_jti: crate::nonce::NonceStore::memory(),
            clients: HashMap::new(),
            checks,
            grants,
            client_auth,
            response_modes,
            jwks_resolver: crate::jwks_resolver::JwksResolver::new(),
            invite_clients: Vec::new(),
            mobile_app: None,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// `/authorize` の検証ステップを足す（既定は response_type・scope・PKCE）。
    pub fn with_check(mut self, check: Arc<dyn AuthorizationCheck>) -> Self {
        self.checks.push(check);
        self
    }

    /// grant_type の処理を足す。同じ grant_type の既存の処理は置き換わる。
    pub fn with_grant(mut self, grant: Arc<dyn GrantHandler>) -> Self {
        register_grant(&mut self.grants, grant);
        self
    }

    /// token endpoint のクライアント認証方式を足す。同じ名前の既存の方式は置き換わる。
    pub fn with_client_auth(mut self, auth: Arc<dyn ClientAuthMethod>) -> Self {
        register_auth(&mut self.client_auth, auth);
        self
    }

    /// 認可レスポンスの返し方を足す。同じ名前の既存の返し方は置き換わる。
    pub fn with_response_mode(mut self, mode: Arc<dyn ResponseMode>) -> Self {
        self.response_modes.insert(mode.name().to_string(), mode);
        self
    }

    pub fn with_client(mut self, c: Client) -> Self {
        self.clients.insert(c.client_id.clone(), c);
        self
    }

    /// 期限切れストアエントリの定期一掃タスクを起動する(active sweep)。
    /// In-memory ストアが無制限に成長する DoS/資源枯渇を防ぐ。取得時の lazy 失効と
    /// 二段構えで、参照されないまま溜まるエントリもこのタスクが物理削除する。
    /// Firestore など TTL 自己管理のストアでは sweep_expired が no-op なので無害。
    /// 返した JoinHandle は破棄してよい(プロセス終了まで走り続ける)。
    pub(crate) fn spawn_store_sweeper(self: &Arc<Self>, period: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let p = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // 初回即時 tick を消費(起動直後の無駄掃除を避ける)
            loop {
                tick.tick().await;
                p.store.sweep_expired().await;
                p.ciba_rate.sweep();
                p.register_rate.sweep();
            }
        })
    }

    /// client_id を解決する。静的登録(HashMap)を先に見て、無ければ Firestore の
    /// DCR 登録クライアントへフォールバックする。未知なら None。
    ///
    /// 注意: 静的クライアントは HashMap で即解決されるが、未知 id は Firestore への
    /// 1 read を引く。/authorize・/end_session など無認証面でも引かれるため、
    /// 未知 id の point-read 増は許容する前提（攻撃面メモは PR 説明参照）。
    pub async fn resolve_client(&self, id: &str) -> Option<Client> {
        if let Some(c) = self.clients.get(id) {
            return Some(c.clone());
        }
        let docs = self.docs.as_deref()?;
        crate::dcr_store::load_client(docs, id).await
    }

    pub fn with_base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = base_path.into();
        self
    }

    #[cfg(feature = "gcp")]
    pub(crate) fn with_firestore(mut self, fs: Arc<Firestore>) -> Self {
        // JAR jti もインスタンス跨ぎで単回化する（DPoP / client_assertion と同様）。
        self.jar_jti = crate::nonce::NonceStore::firestore(fs.clone());
        self.docs = Some(fs.clone());
        self.fcm = Some(fs);
        self
    }

    /// パスキーの登録とログイン・復旧・管理画面・PAR・DCR・CIBA の承認などの保存先を差し込む。
    /// 差し込まなければ、それらの経路は 503 などで断る。1 つの process で試すなら
    /// [`MemoryDocumentStore`](crate::MemoryDocumentStore)。
    ///
    /// userinfo などの claim は [`Store::find_account`] が返し、この保存先は見ない。
    /// [`MemoryStore`] の find_account は、[`MemoryStore::with_documents`] で同じ保存先を渡さないと、
    /// 登録とは無関係の試し用の claim（`<sub>@example.com`、`email_verified: true` など）を返す。
    /// そこで with_store をまだ呼んでいなければ、ここで store を `MemoryStore::with_documents(docs)` に替える。
    /// 後から with_store で別の Store を差し込むときは、その find_account が同じ保存先を引くようにすること
    /// （例 `.with_store(Arc::new(MemoryStore::with_documents(docs.clone())))`）。
    pub fn with_document_store(mut self, docs: Arc<dyn DocumentStore>) -> Self {
        if self.store_is_default {
            self.store = Arc::new(MemoryStore::with_documents(docs.clone()));
        }
        self.docs = Some(docs);
        self
    }

    pub fn with_ciba(mut self, ciba: Arc<dyn CibaStore>) -> Self {
        self.ciba = ciba;
        self
    }

    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = store;
        self.store_is_default = false;
        self
    }

    /// DPoP 検証器を差し替える（本番は Firestore 連携で jti を分散単回化）。
    pub fn with_dpop(mut self, dpop: Arc<dyn DpopVerifier>) -> Self {
        self.dpop = dpop;
        self
    }

    /// 追加の署名鍵（RS256 等）を登録する。
    pub fn add_signer(mut self, signer: Arc<dyn JwsSigner>) -> Self {
        self.extra_signers.push(signer);
        self
    }

    /// alg に対応する署名鍵を返す。None（未指定）は既定（ES256）。
    /// 未対応の alg は既定へ黙ってフォールバックせずエラーにする。フォールバックは
    /// switch の default が新種を吸い込むのと同型の暗黙バグで、RP 側の検証失敗として
    /// 遅れて表面化する。登録値と実際の署名 alg の不一致はここで即座に落とす。
    pub fn signer_for(&self, alg: Option<&str>) -> Result<&Arc<dyn JwsSigner>, OAuthError> {
        match alg {
            None => Ok(&self.signer),
            Some(a) if a == self.signer.alg() => Ok(&self.signer),
            Some(a) => self
                .extra_signers
                .iter()
                .find(|s| s.alg() == a)
                .ok_or_else(|| {
                    OAuthError::ServerError(format!("no signer registered for alg {a}"))
                }),
        }
    }

    /// jwks / discovery 用に全署名鍵を列挙する。
    pub fn all_signers(&self) -> impl Iterator<Item = &Arc<dyn JwsSigner>> {
        std::iter::once(&self.signer).chain(self.extra_signers.iter())
    }

    pub fn with_signer(mut self, signer: Arc<dyn JwsSigner>) -> Self {
        self.signer = signer;
        self
    }

    pub fn with_invite_clients(mut self, ids: Vec<String>) -> Self {
        self.invite_clients = ids;
        self
    }

    pub fn with_mobile_app(mut self, app: MobileApp) -> Self {
        self.mobile_app = Some(app);
        self
    }

    pub fn with_mailer(mut self, m: Arc<dyn Mailer>) -> Self {
        self.mailer = m;
        self
    }

    /// base_path を付けた内部リダイレクト用パス。
    pub(crate) fn path(&self, suffix: &str) -> String {
        format!("{}{}", self.base_path, suffix)
    }

    /// WebAuthn origin（scheme://host[:port]、パスなし）。
    pub(crate) fn origin(&self) -> String {
        let scheme = self.issuer.split("://").next().unwrap_or("https");
        let after = self.issuer.split("://").nth(1).unwrap_or(&self.issuer);
        let host_port = after.split('/').next().unwrap_or(after);
        format!("{scheme}://{host_port}")
    }

    /// WebAuthn rp_id（ホスト名のみ、ポートなし）。
    pub(crate) fn rp_id(&self) -> String {
        let after = self.issuer.split("://").nth(1).unwrap_or(&self.issuer);
        let host_port = after.split('/').next().unwrap_or(after);
        host_port.split(':').next().unwrap_or(host_port).to_string()
    }
}

fn register_grant(m: &mut HashMap<String, Arc<dyn GrantHandler>>, g: Arc<dyn GrantHandler>) {
    m.insert(g.grant_type().to_string(), g);
}
fn register_auth(m: &mut HashMap<String, Arc<dyn ClientAuthMethod>>, a: Arc<dyn ClientAuthMethod>) {
    m.insert(a.method().to_string(), a);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_for_rejects_unregistered_alg_instead_of_fallback() {
        let p = Provider::new("https://op");
        // None / 既定 alg は既定署名鍵。
        assert!(p.signer_for(None).is_ok());
        assert!(p.signer_for(Some("ES256")).is_ok());
        // 未登録 alg は黙って ES256 にフォールバックせずエラー。
        assert!(matches!(
            p.signer_for(Some("PS256")),
            Err(crate::error::OAuthError::ServerError(_))
        ));
    }

    /// with_document_store だけでも、find_account は試し用の claim を返さない。with_store が先なら替えない。
    #[tokio::test]
    async fn document_store_alone_does_not_make_up_claims() {
        let docs: Arc<dyn DocumentStore> = Arc::new(crate::document_store::MemoryDocumentStore::default());
        let p = Provider::new("https://op").with_document_store(docs.clone());
        let a = p.store.find_account("not-registered").await;
        assert_eq!(a.claims.get("email"), None);
        assert_eq!(a.claims.get("email_verified"), None);

        let p = Provider::new("https://op").with_store(Arc::new(MemoryStore::default())).with_document_store(docs);
        let a = p.store.find_account("not-registered").await;
        assert_eq!(a.claims.get("email_verified"), Some(&serde_json::json!(true)));
    }
}
