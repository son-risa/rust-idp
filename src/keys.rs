use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::{Value, json};

const KID: &str = "default";

#[derive(Serialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// id_token署名用のRSA鍵ペア。起動時にプロセス内でのみ生成し、秘密鍵はプロセス外に出さない。
/// 署名処理は `sign_bytes` という境界に閉じており、本番でCloud KMSの `asymmetricSign` に
/// 委譲する際もこの内部だけ差し替えればよい(DESIGN_NOTES.md参照)。
pub struct SigningKeys {
    signing_key: SigningKey<Sha256>,
    n_b64: String,
    e_b64: String,
}

impl SigningKeys {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generation failed");
        let public_key = RsaPublicKey::from(&private_key);
        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        SigningKeys {
            signing_key: SigningKey::<Sha256>::new(private_key),
            n_b64,
            e_b64,
        }
    }

    /// 署名対象バイト列(signing input)を渡すと署名済みバイト列を返す境界。
    /// 今はローカルのRSA秘密鍵で署名しているが、本番ではCloud KMSへの委譲に差し替える。
    fn sign_bytes(&self, signing_input: &[u8]) -> Vec<u8> {
        self.signing_key.sign(signing_input).to_vec()
    }

    pub fn sign_id_token(&self, claims: &IdTokenClaims) -> serde_json::Result<String> {
        let header = json!({ "alg": "RS256", "typ": "JWT", "kid": KID });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signature = self.sign_bytes(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        Ok(format!("{signing_input}.{signature_b64}"))
    }

    pub fn jwks_document(&self) -> Value {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": self.n_b64,
                "e": self.e_b64,
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::BigUint;
    use rsa::sha2::{Digest, Sha256};

    fn sample_claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://idp.example".to_string(),
            sub: "user-001".to_string(),
            aud: "demo-client".to_string(),
            exp: 1_000_000,
            iat: 999_000,
            nonce: Some("nonce-1".to_string()),
        }
    }

    /// 手組みJWS生成が実際に検証可能な署名を作れているかの確認。
    /// jwks_document()が公開するn/eから鍵を再構成し、署名対象(header.claims)を
    /// SHA-256でハッシュしてPKCS1v15で検証する(RS256の定義通り)。
    #[test]
    fn sign_id_token_produces_verifiable_jws() {
        let keys = SigningKeys::generate();
        let jwt = keys.sign_id_token(&sample_claims()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS compact serialization must have 3 segments");

        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], KID);

        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["sub"], "user-001");

        let jwk = &keys.jwks_document()["keys"][0];
        let n = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap());
        let e = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap()).unwrap());
        let public_key = RsaPublicKey::new(n, e).unwrap();

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let hashed = Sha256::digest(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        public_key
            .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, &signature)
            .expect("signature must verify against the published JWK");
    }

    #[test]
    fn tampered_claims_fail_verification() {
        let keys = SigningKeys::generate();
        let jwt = keys.sign_id_token(&sample_claims()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();

        let jwk = &keys.jwks_document()["keys"][0];
        let n = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap());
        let e = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap()).unwrap());
        let public_key = RsaPublicKey::new(n, e).unwrap();

        // payloadだけ別のsubに差し替えるとsigning_inputが変わり検証が失敗するはず。
        let mut forged = sample_claims();
        forged.sub = "attacker".to_string();
        let forged_claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        let signing_input = format!("{}.{}", parts[0], forged_claims_b64);
        let hashed = Sha256::digest(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let result = public_key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, &signature);
        assert!(result.is_err(), "forged claims must not verify with the original signature");
    }
}
