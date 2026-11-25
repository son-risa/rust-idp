//! JWS 署名の概念トレイトと、ES256(P-256) のピュア Rust 実装。
//! 後で RS256/PS256/EdDSA を足す時はこのトレイトに impl を増やすだけ。

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;

/// base64url(no-pad) エンコード。実体は es256 に集約。
pub fn b64url(bytes: impl AsRef<[u8]>) -> String {
    crate::es256::b64url_encode(bytes)
}

/// 署名鍵の概念。alg / 署名 / 公開 JWK を提供する。
/// sign は async（Cloud KMS 実装がネットワーク署名するため）。ローカル鍵実装は即時 return。
#[async_trait]
pub trait JwsSigner: Send + Sync {
    fn alg(&self) -> &str;
    /// claims を JWS Compact Serialization (header.payload.signature) で署名する。
    async fn sign(&self, claims: &serde_json::Value) -> String;
    /// /jwks で公開する 1 鍵分の JWK。
    fn public_jwk(&self) -> serde_json::Value;
}

pub struct Es256Signer {
    key: SigningKey,
    kid: String,
    x: String,
    y: String,
}

impl Es256Signer {
    pub fn generate() -> Self {
        let key = SigningKey::generate();
        Self::from_key(key)
    }

    /// 秘密スカラー(P-256, 32byte)の b64url から再構成する。
    /// Secret Manager 保存鍵の読込に使う。
    pub fn from_scalar_b64(s: &str) -> Result<Self, String> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|e| format!("scalar b64: {e}"))?;
        let key = SigningKey::from_slice(&bytes).map_err(|e| format!("scalar key: {e}"))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: SigningKey) -> Self {
        let vk = key.verifying_key();
        let point = vk.to_sec1_point(false);
        let x = b64url(point.x().expect("P-256 has x"));
        let y = b64url(point.y().expect("P-256 has y"));
        let kid = thumbprint(&x, &y);
        Self { key, kid, x, y }
    }
}

/// RFC 7638 JWK Thumbprint (EC) は es256 に集約。
fn thumbprint(x: &str, y: &str) -> String {
    crate::es256::jwk_thumbprint_p256(x, y)
}

#[async_trait]
impl JwsSigner for Es256Signer {
    fn alg(&self) -> &str {
        "ES256"
    }
    async fn sign(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let header_b64 = b64url(header.to_string());
        let payload_b64 = b64url(claims.to_string());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig_b64 = b64url(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }
    fn public_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": self.x,
            "y": self.y,
            "alg": "ES256",
            "use": "sig",
            "kid": self.kid,
        })
    }
}

/// RS256 (RSASSA-PKCS1-v1.5 / SHA-256)。OIDC Core §15.1 は OP に RS256 を要求する。
pub struct Rs256Signer {
    key: rsa::PrivateKey,
    kid: String,
    n: String,
    e: String,
}

impl Rs256Signer {
    /// テスト専用の一時鍵生成。本番経路から参照できないよう cfg(test) で隔離する。
    #[cfg(test)]
    pub fn generate() -> Self {
        let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).expect("rsa keygen");
        Self::from_key(key)
    }

    /// PKCS#8 PEM から読み込む（Secret Manager 保存鍵の読込に使う）。
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, String> {
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::PrivateKey::from_pkcs8_pem(pem.trim())
            .map_err(|e| format!("rsa pkcs8 pem: {e}"))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: rsa::PrivateKey) -> Self {
        use rsa::traits::PublicKeyParts;
        let n = b64url(key.n().to_be_bytes_trimmed_vartime().into_vec());
        let e = b64url(key.e().to_be_bytes_trimmed_vartime().into_vec());
        // RFC 7638 RSA Thumbprint: canonical JSON はキー昇順 e,kty,n。
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = b64url(<sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes()));
        Self { key, kid, n, e }
    }
}

#[async_trait]
impl JwsSigner for Rs256Signer {
    fn alg(&self) -> &str {
        "RS256"
    }
    async fn sign(&self, claims: &serde_json::Value) -> String {
        use sha2::Digest;
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid });
        let signing_input = format!(
            "{}.{}",
            b64url(header.to_string()),
            b64url(claims.to_string())
        );
        let hashed = sha2::Sha256::digest(signing_input.as_bytes());
        let sig = self
            .key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed)
            .expect("rsa sign");
        format!("{signing_input}.{}", b64url(sig))
    }
    fn public_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "n": self.n,
            "e": self.e,
            "alg": "RS256",
            "use": "sig",
            "kid": self.kid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod es256 {
        async fn signer() -> super::Es256Signer {
            super::Es256Signer::generate()
        }
        crate::jws_signer_contract::jws_signer_contract_tests!(signer);
    }

    mod rs256 {
        async fn signer() -> super::Rs256Signer {
            super::Rs256Signer::generate()
        }
        crate::jws_signer_contract::jws_signer_contract_tests!(signer);
    }

    /// Secret Manager に置いた秘密スカラーから読んだ鍵。
    mod es256_scalar {
        async fn signer() -> super::Es256Signer {
            use p256::elliptic_curve::Generate;
            let key = p256::ecdsa::SigningKey::generate();
            super::Es256Signer::from_scalar_b64(&super::b64url(key.to_bytes())).unwrap()
        }
        crate::jws_signer_contract::jws_signer_contract_tests!(signer);
    }

    /// Secret Manager に置いた PKCS#8 PEM から読んだ鍵。
    mod rs256_pem {
        async fn signer() -> super::Rs256Signer {
            use rsa::pkcs8::{EncodePrivateKey, LineEnding};
            let key = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
            super::Rs256Signer::from_pkcs8_pem(&key.to_pkcs8_pem(LineEnding::LF).unwrap()).unwrap()
        }
        crate::jws_signer_contract::jws_signer_contract_tests!(signer);
    }

    #[test]
    fn from_scalar_b64_reconstructs_same_key() {
        let signer = Es256Signer::generate();
        let scalar = b64url(signer.key.to_bytes());
        let restored = Es256Signer::from_scalar_b64(&scalar).unwrap();
        // 同じ鍵 → 同じ kid / 公開鍵。
        assert_eq!(restored.kid, signer.kid);
        assert_eq!(restored.public_jwk(), signer.public_jwk());
    }

    #[test]
    fn from_scalar_b64_rejects_garbage() {
        assert!(Es256Signer::from_scalar_b64("!!!notb64!!!").is_err());
    }
}
