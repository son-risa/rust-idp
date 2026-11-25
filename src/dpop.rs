//! DPoP (RFC 9449) proof 検証。概念トレイト + ES256 実装（ピュア Rust）。
//! proof は JWS Compact（ES256, 署名は raw r||s 64byte）。WebAuthn の DER とは別。

use crate::es256;
use crate::nonce::NonceStore;
use async_trait::async_trait;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
#[cfg(feature = "gcp")]
use std::sync::Arc;
use std::time::Duration;

const IAT_SKEW_SECS: i64 = 60;
const JTI_TTL: Duration = Duration::from_secs(300);

#[async_trait]
pub trait DpopVerifier: Send + Sync {
    /// proof を検証し、成功時に jkt (JWK SHA-256 Thumbprint) を返す。
    /// expected_ath は resource(userinfo) 検証時のみ Some。
    async fn verify(
        &self,
        proof: &str,
        htm: &str,
        htu: &str,
        expected_ath: Option<&str>,
    ) -> Result<String, String>;
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// access_token の ath（RFC 9449 §4.3）= base64url(SHA-256(token ascii))。全長。
pub fn ath(access_token: &str) -> String {
    es256::b64url_encode(Sha256::digest(access_token.as_bytes()))
}

/// htu 正規化: query(?) と fragment(#) を除去（RFC 9449 §4.3）。
/// `str::find` は文字境界を返す契約ゆえ `end` は常に境界 → `&u[..end]` は panic しえない
/// （安全イディオム）。kani_harness.rs でこの安全性をロックとして確認する（生 index 化等の
/// 危険な refactor を検出）。記号 find が状態爆発するため代表的な境界ケースに有界化。
pub(crate) fn strip_query_fragment(u: &str) -> &str {
    let end = u.find(['?', '#']).unwrap_or(u.len());
    &u[..end]
}

#[derive(Default)]
pub struct Es256Dpop {
    jti: NonceStore,
}

#[cfg(feature = "gcp")]
impl Es256Dpop {
    /// 本番: Firestore 連携で jti をインスタンス跨ぎで単回化する。
    pub fn with_store(fs: Arc<crate::firestore::Firestore>) -> Self {
        Self {
            jti: NonceStore::firestore(fs),
        }
    }
}

#[async_trait]
impl DpopVerifier for Es256Dpop {
    async fn verify(
        &self,
        proof: &str,
        htm: &str,
        htu: &str,
        expected_ath: Option<&str>,
    ) -> Result<String, String> {
        let parts: Vec<&str> = proof.split('.').collect();
        if parts.len() != 3 {
            return Err("proof not a compact JWS".into());
        }
        let header: serde_json::Value = serde_json::from_slice(&es256::b64url_decode(parts[0])?)
            .map_err(|e| format!("header json: {e}"))?;
        if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
            return Err("typ != dpop+jwt".into());
        }
        if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
            return Err("alg != ES256".into());
        }
        let jwk = header.get("jwk").ok_or("header.jwk missing")?;
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
            || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
        {
            return Err("jwk not EC/P-256".into());
        }
        if jwk.get("d").is_some() {
            return Err("jwk contains private key".into());
        }
        let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("jwk.x")?;
        let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("jwk.y")?;

        // 署名検証（埋め込み公開鍵で）。JWS の ES256 署名は raw r||s。
        let vk =
            es256::verifying_key_from_xy(&es256::b64url_decode(x)?, &es256::b64url_decode(y)?)?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&es256::b64url_decode(parts[2])?)
            .map_err(|e| format!("sig: {e}"))?;
        vk.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| "invalid proof signature".to_string())?;

        // payload クレーム。
        let payload: serde_json::Value = serde_json::from_slice(&es256::b64url_decode(parts[1])?)
            .map_err(|e| format!("payload json: {e}"))?;
        if payload.get("htm").and_then(|v| v.as_str()) != Some(htm) {
            return Err("htm mismatch".into());
        }
        // RFC 9449 §4.3: htu 比較では query と fragment を無視する。
        let proof_htu = payload.get("htu").and_then(|v| v.as_str()).unwrap_or("");
        if strip_query_fragment(proof_htu) != strip_query_fragment(htu) {
            return Err(format!("htu mismatch (got {proof_htu:?}, want {htu})"));
        }
        let iat = payload
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or("iat missing")?;
        if now_secs().abs_diff(iat) > IAT_SKEW_SECS as u64 {
            return Err("iat out of window".into());
        }
        if let Some(want) = expected_ath
            && payload.get("ath").and_then(|v| v.as_str()) != Some(want)
        {
            return Err("ath mismatch".into());
        }
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or("jti missing")?;
        // DPoP と client_assertion で名前空間を分け、jti 文字列の偶発衝突を避ける。
        if !self.jti.claim(&format!("dpop:{jti}"), JTI_TTL).await {
            return Err("jti replay".into());
        }

        Ok(es256::jwk_thumbprint_p256(x, y))
    }
}

#[cfg(test)]
mod tests {
    mod memory {
        async fn verifier() -> super::super::Es256Dpop {
            super::super::Es256Dpop::default()
        }
        crate::dpop_verifier_contract::dpop_verifier_contract_tests!(verifier);
    }

    #[cfg(feature = "gcp")]
    mod firestore {
        async fn verifier() -> super::super::Es256Dpop {
            let (host, _state) = crate::firestore::fake_firestore::spawn().await;
            super::super::Es256Dpop::with_store(std::sync::Arc::new(
                crate::firestore::Firestore::new_for_test("proj", host),
            ))
        }
        crate::dpop_verifier_contract::dpop_verifier_contract_tests!(verifier);
    }
}
