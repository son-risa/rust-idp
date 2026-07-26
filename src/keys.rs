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
