//! OpenID Provider（FAPI 2.0・パスキー・CIBA）を axum の Router として組み立てるライブラリ。
//!
//! node-oidc-provider と同じく crate は 1 つで、保存先や署名鍵などは trait の実装を
//! [`Provider`] に差し込んで替える。既定はメモリ上の保存先と起動ごとの鍵（ephemeral）。
//!
//! ```no_run
//! # async fn run() {
//! let provider = rust_idp::Provider::new("http://localhost:8080");
//! let app = rust_idp::router(provider);
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
//! axum::serve(listener, app).await.unwrap();
//! # }
//! ```

// ピュア Rust 方針の明文化: 本番・テストビルドでは unsafe を全面禁止する。
// 例外は Kani 証明ハーネス（kani_harness.rs）のみ——シンボリック入力のモデル化に
// from_utf8_unchecked を使うため、cargo kani 時だけ forbid を外す。
#![cfg_attr(not(kani), forbid(unsafe_code))]

mod account_admin;
mod admin_store;
mod audit_log;
mod auth_checks;
mod ciba;
mod claims;
mod client_auth;
mod context;
mod dcr;
mod dcr_store;
#[cfg(test)]
mod diff_tests;
mod dpop;
mod error;
mod es256;
#[cfg(test)]
mod formal_ledger_tests;
#[cfg(test)]
mod fuzz_tests;
mod fcm;
mod fido;
mod firestore;
mod firestore_store;
pub mod gcp;
mod grants;
mod http;
mod interaction_policy;
mod jwks_resolver;
mod jws;
#[cfg(kani)]
mod kani_harness;
mod kms;
mod mailer;
mod model;
mod nonce;
mod par;
mod provider;
mod registration;
mod request_object;
mod response_mode;
mod sig;
mod step_up;
mod store;
mod web;
mod webauthn;

pub use auth_checks::AuthorizationCheck;
pub use ciba::{AuthReqId, BackchannelAuthRequest, CibaHistoryEntry, CibaStatus, CibaStore, MemoryCibaStore};
pub use client_auth::{ClientAuthInput, ClientAuthMethod};
pub use context::AddressedRequest;
pub use dpop::{DpopVerifier, Es256Dpop};
pub use error::OAuthError;
pub use grants::GrantHandler;
pub use jws::{Es256Signer, JwsSigner, Rs256Signer};
pub use mailer::{LogMailer, Mailer};
pub use model::{
    AccessToken, Account, AuthParams, AuthorizationCode, Client, Interaction, JwkPub, RefreshToken, Session,
    TokenResponse,
};
pub use provider::Provider;
pub use response_mode::ResponseMode;
pub use store::{CodeTake, MemoryStore, Store, StoreError, StoreResult};
pub use web::i18n::Lang;
pub use web::router;
