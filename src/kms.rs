//! Cloud KMS による JWS 署名（非対称署名鍵、ソフトウェア保護）。
//! 秘密鍵がプロセスに展開されない（侵害ホストから抜けない）。alg は ES256 / RS256。
//! 公開鍵は起動時に 1 回取得して JWK 化・キャッシュ（/jwks は KMS を叩かない）。

use crate::firestore::Firestore;
use crate::jws::{JwsSigner, b64url};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::Digest;
use std::sync::Arc;

const KMS_BASE: &str = "https://cloudkms.googleapis.com";

#[derive(Clone, Copy)]
enum KmsKind {
    Es256,
    Rs256,
}

pub struct KmsSigner {
    kind: KmsKind,
    fs: Arc<Firestore>, // metadata server のアクセストークン取得に使う
    http: reqwest::Client,
    base: String,
    version: String, // cryptoKeyVersion のフル resource path
    kid: String,
    jwk: serde_json::Value,
}

impl KmsSigner {
    pub async fn es256(fs: Arc<Firestore>, key_path: &str) -> Result<Self, String> {
        Self::new(KmsKind::Es256, fs, key_path).await
    }
    pub async fn rs256(fs: Arc<Firestore>, key_path: &str) -> Result<Self, String> {
        Self::new(KmsKind::Rs256, fs, key_path).await
    }

    async fn new(kind: KmsKind, fs: Arc<Firestore>, key_path: &str) -> Result<Self, String> {
        Self::at(kind, fs, key_path, KMS_BASE.into()).await
    }

    async fn at(
        kind: KmsKind,
        fs: Arc<Firestore>,
        key_path: &str,
        base: String,
    ) -> Result<Self, String> {
        let version = version_path(key_path);
        let http = crate::http::client();
        let (jwk, kid) = public_jwk(kind, &fs, &http, &base, &version).await?;
        Ok(Self {
            kind,
            fs,
            http,
            base,
            version,
            kid,
            jwk,
        })
    }

    /// digest(SHA-256) を KMS で署名し、JOSE 形式の署名(b64url)を返す。
    async fn kms_sign(&self, digest: &[u8]) -> Result<String, String> {
        let tok = self.fs.token().await?;
        let url = format!("{}/v1/{}:asymmetricSign", self.base, self.version);
        let body = serde_json::json!({ "digest": { "sha256": B64.encode(digest) } });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&tok)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("kms sign: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "kms sign {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        let j: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("kms sign json: {e}"))?;
        let sig_b64 = j
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or("kms sign: no signature")?;
        let sig = B64
            .decode(sig_b64)
            .map_err(|e| format!("kms sig b64: {e}"))?;
        let raw = match self.kind {
            // KMS は ES256 を DER で返す。JWS は raw r||s なので変換する。
            KmsKind::Es256 => p256::ecdsa::Signature::from_der(&sig)
                .map_err(|e| format!("es256 der: {e}"))?
                .to_bytes()
                .to_vec(),
            // RS256(PKCS1v15) は raw 署名そのまま。
            KmsKind::Rs256 => sig,
        };
        Ok(b64url(raw))
    }
}

/// env の値（鍵の道、または版までの道）を cryptoKeyVersion の道にする。
/// 鍵の道だけなら版 1（版を書けるようにする前からの振る舞い）。
fn version_path(path: &str) -> String {
    let p = path.trim().trim_end_matches('/');
    if p.contains("/cryptoKeyVersions/") {
        p.to_string()
    } else {
        format!("{p}/cryptoKeyVersions/1")
    }
}

/// 版の公開鍵 PEM を取得し、JWK と kid を作る（jws.rs と同じ kid の付け方）。
async fn public_jwk(
    kind: KmsKind,
    fs: &Firestore,
    http: &reqwest::Client,
    base: &str,
    version: &str,
) -> Result<(serde_json::Value, String), String> {
    let tok = fs.token().await?;
    let url = format!("{base}/v1/{version}/publicKey");
    let resp = http
        .get(&url)
        .bearer_auth(&tok)
        .send()
        .await
        .map_err(|e| format!("kms publicKey: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "kms publicKey {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let j: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("kms publicKey json: {e}"))?;
    let pem = j
        .get("pem")
        .and_then(|v| v.as_str())
        .ok_or("kms publicKey: no pem")?;
    Ok(match kind {
        KmsKind::Es256 => {
            use p256::elliptic_curve::sec1::ToSec1Point;
            use p256::pkcs8::DecodePublicKey;
            let pk = p256::PublicKey::from_public_key_pem(pem)
                .map_err(|e| format!("es256 spki: {e}"))?;
            let pt = pk.to_sec1_point(false);
            let x = b64url(pt.x().ok_or("no x")?);
            let y = b64url(pt.y().ok_or("no y")?);
            let kid = crate::es256::jwk_thumbprint_p256(&x, &y);
            let jwk = serde_json::json!({
                "kty":"EC","crv":"P-256","x":x,"y":y,"alg":"ES256","use":"sig","kid":kid
            });
            (jwk, kid)
        }
        KmsKind::Rs256 => {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::traits::PublicKeyParts;
            let pk =
                rsa::PublicKey::from_public_key_pem(pem).map_err(|e| format!("rs256 spki: {e}"))?;
            let n = b64url(pk.n().to_be_bytes_trimmed_vartime().into_vec());
            let e = b64url(pk.e().to_be_bytes_trimmed_vartime().into_vec());
            let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
            let kid = b64url(sha2::Sha256::digest(canonical.as_bytes()));
            let jwk = serde_json::json!({
                "kty":"RSA","n":n,"e":e,"alg":"RS256","use":"sig","kid":kid
            });
            (jwk, kid)
        }
    })
}

/// 署名には使わない版の公開 JWK（jwks と確かめにだけ載せる）。`path` は版までの道。
pub async fn verify_only_es256(fs: &Firestore, path: &str) -> Result<serde_json::Value, String> {
    verify_only_at(KmsKind::Es256, fs, path, KMS_BASE).await
}
pub async fn verify_only_rs256(fs: &Firestore, path: &str) -> Result<serde_json::Value, String> {
    verify_only_at(KmsKind::Rs256, fs, path, KMS_BASE).await
}

async fn verify_only_at(
    kind: KmsKind,
    fs: &Firestore,
    path: &str,
    base: &str,
) -> Result<serde_json::Value, String> {
    // 版を書かずに鍵の道だけを渡すと版 1 になり、入れ替え後の新しい版と取り違えやすい。版を必ず書かせる。
    if !path.contains("/cryptoKeyVersions/") {
        return Err(format!(
            "verify-only key needs a cryptoKeyVersions path: {path}"
        ));
    }
    let version = version_path(path);
    let (jwk, _) = public_jwk(kind, fs, &crate::http::client(), base, &version).await?;
    Ok(jwk)
}

#[async_trait]
impl JwsSigner for KmsSigner {
    fn alg(&self) -> &str {
        match self.kind {
            KmsKind::Es256 => "ES256",
            KmsKind::Rs256 => "RS256",
        }
    }

    async fn sign(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": self.alg(), "typ": "JWT", "kid": self.kid });
        let signing_input = format!(
            "{}.{}",
            b64url(header.to_string()),
            b64url(claims.to_string())
        );
        let digest = sha2::Sha256::digest(signing_input.as_bytes());
        match self.kms_sign(&digest).await {
            Ok(sig) => format!("{signing_input}.{sig}"),
            Err(e) => {
                // 署名不能は致命的。誤った署名で発行するより、検証で確実に落ちる空署名にする。
                tracing::error!(event = "kms_sign_failed", "{e}");
                format!("{signing_input}.")
            }
        }
    }

    fn public_jwk(&self) -> serde_json::Value {
        self.jwk.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::{Value, json};

    /// Cloud KMS の publicKey と asymmetricSign だけを模す。鍵はこの fake の中に持ち、渡された digest をそのまま署名して、
    /// 本物と同じく ES256 は DER、RS256 は生の署名を base64 で返す。
    enum FakeKey {
        Es256(p256::ecdsa::SigningKey),
        Rs256(Box<rsa::PrivateKey>),
    }

    impl FakeKey {
        fn pem(&self) -> String {
            use p256::pkcs8::{EncodePublicKey, LineEnding};
            match self {
                FakeKey::Es256(k) => k.verifying_key().to_public_key_pem(LineEnding::LF).unwrap(),
                FakeKey::Rs256(k) => k.to_public_key().to_public_key_pem(LineEnding::LF).unwrap(),
            }
        }
        fn sign(&self, digest: &[u8]) -> Vec<u8> {
            match self {
                FakeKey::Es256(k) => {
                    use p256::ecdsa::signature::hazmat::PrehashSigner;
                    let sig: p256::ecdsa::Signature = k.sign_prehash(digest).unwrap();
                    sig.to_der().as_bytes().to_vec()
                }
                FakeKey::Rs256(k) => k
                    .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), digest)
                    .unwrap(),
            }
        }
    }

    /// 版の番号（1 から）で fake の鍵を選ぶ。
    fn key_of<'a>(keys: &'a [FakeKey], rest: &str, suffix: &str) -> &'a FakeKey {
        let n: usize = rest
            .strip_suffix(suffix)
            .and_then(|r| r.rsplit_once("/cryptoKeyVersions/"))
            .and_then(|(_, n)| n.parse().ok())
            .unwrap_or_else(|| panic!("{rest}"));
        &keys[n - 1]
    }

    async fn public_key(
        State(keys): State<Arc<Vec<FakeKey>>>,
        Path(rest): Path<String>,
    ) -> Json<Value> {
        Json(json!({ "pem": key_of(&keys, &rest, "/publicKey").pem() }))
    }

    async fn asymmetric_sign(
        State(keys): State<Arc<Vec<FakeKey>>>,
        Path(rest): Path<String>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let digest = B64
            .decode(body["digest"]["sha256"].as_str().unwrap())
            .unwrap();
        let sig = key_of(&keys, &rest, ":asymmetricSign").sign(&digest);
        Json(json!({ "signature": B64.encode(sig) }))
    }

    const KEY: &str = "projects/p/locations/global/keyRings/r/cryptoKeys/k";

    /// 版 1, 2, ... に keys を順に置いた fake の KMS。返すのは base の URL。
    async fn fake_kms(keys: Vec<FakeKey>) -> String {
        let app = Router::new()
            .route("/v1/{*rest}", get(public_key).post(asymmetric_sign))
            .with_state(Arc::new(keys));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    /// new_for_test の Firestore は metadata server へ行かずに token を返す。宛先は使わない。
    fn fs() -> Arc<Firestore> {
        Arc::new(Firestore::new_for_test("proj", "127.0.0.1:9"))
    }

    async fn signer_on_fake(kind: KmsKind, key: FakeKey) -> KmsSigner {
        let base = fake_kms(vec![key]).await;
        KmsSigner::at(kind, fs(), KEY, base).await.unwrap()
    }

    fn es256_key() -> FakeKey {
        use p256::elliptic_curve::Generate;
        FakeKey::Es256(p256::ecdsa::SigningKey::generate())
    }

    #[test]
    fn a_key_path_means_version_1_and_a_version_path_is_kept() {
        assert_eq!(version_path(KEY), format!("{KEY}/cryptoKeyVersions/1"));
        assert_eq!(
            version_path(&format!("{KEY}/")),
            format!("{KEY}/cryptoKeyVersions/1")
        );
        let v2 = format!("{KEY}/cryptoKeyVersions/2");
        assert_eq!(version_path(&v2), v2);
    }

    /// 入れ替えの後: 版 2 で署名し、版 1 は検証用に載せる。版 1 の JWK は、入れ替え前に
    /// 版 1 で署名していたときの JWK と同じ（前に出した ID Token の kid と合う）。
    #[tokio::test]
    async fn a_version_path_signs_with_that_version_and_the_old_one_stays_publishable() {
        let base = fake_kms(vec![es256_key(), es256_key()]).await;
        let before = KmsSigner::at(KmsKind::Es256, fs(), KEY, base.clone())
            .await
            .unwrap();
        let v2 = format!("{KEY}/cryptoKeyVersions/2");
        let after = KmsSigner::at(KmsKind::Es256, fs(), &v2, base.clone())
            .await
            .unwrap();
        assert_ne!(before.kid, after.kid);

        let v1 = format!("{KEY}/cryptoKeyVersions/1");
        let old = verify_only_at(KmsKind::Es256, &fs(), &v1, &base)
            .await
            .unwrap();
        assert_eq!(old, before.public_jwk());

        let jwt = after.sign(&json!({"sub": "alice"})).await;
        let header: Value = serde_json::from_slice(
            &crate::es256::b64url_decode(jwt.split('.').next().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], after.kid);
    }

    #[tokio::test]
    async fn a_verify_only_key_must_name_its_version() {
        let base = fake_kms(vec![es256_key()]).await;
        let e = verify_only_at(KmsKind::Es256, &fs(), KEY, &base)
            .await
            .unwrap_err();
        assert!(e.contains("cryptoKeyVersions"), "{e}");
    }

    mod es256 {
        use super::*;

        async fn signer() -> KmsSigner {
            signer_on_fake(KmsKind::Es256, es256_key()).await
        }
        crate::jws_signer_contract::jws_signer_contract_tests!(signer);
    }

    mod rs256 {
        use super::*;

        async fn signer() -> KmsSigner {
            let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
            signer_on_fake(KmsKind::Rs256, FakeKey::Rs256(Box::new(key))).await
        }
        crate::jws_signer_contract::jws_signer_contract_tests!(signer);
    }
}
