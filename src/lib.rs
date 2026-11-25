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
mod admin_command;
mod admin_store;
mod audit_log;
mod auth_checks;
mod ciba;
#[cfg(test)]
mod ciba_store_contract;
mod claims;
mod client_auth;
mod context;
mod dcr;
mod dcr_store;
#[cfg(test)]
mod diff_tests;
mod document_store;
#[cfg(test)]
mod document_store_contract;
mod dpop;
mod error;
mod es256;
mod fcm;
mod fido;
#[cfg(test)]
mod fido_store_contract;
mod firestore;
#[cfg(feature = "gcp")]
mod firestore_store;
#[cfg(test)]
mod formal_ledger_tests;
#[cfg(test)]
mod fuzz_tests;
#[cfg(feature = "gcp")]
pub mod gcp;
mod grants;
mod http;
mod interaction_policy;
mod jwks_resolver;
mod jws;
#[cfg(test)]
mod jws_signer_contract;
#[cfg(kani)]
mod kani_harness;
#[cfg(feature = "gcp")]
mod kms;
mod mailer;
#[cfg(test)]
mod mailer_contract;
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
#[cfg(test)]
mod store_contract;
mod web;
mod webauthn;

#[doc(hidden)]
pub use admin_command::AdminCommand;
pub use auth_checks::AuthorizationCheck;
pub use ciba::{
    AuthReqId, BackchannelAuthRequest, CibaHistoryEntry, CibaStatus, CibaStore, MemoryCibaStore,
};
pub use client_auth::{ClientAuthInput, ClientAuthMethod};
pub use context::AddressedRequest;
pub use dcr::hash_token;
pub use document_store::{DocumentStore, MemoryDocumentStore};
pub use dpop::{DpopVerifier, Es256Dpop};
pub use error::OAuthError;
pub use grants::GrantHandler;
pub use jws::{Es256Signer, JwsSigner, Rs256Signer};
pub use mailer::{LogMailer, Mailer};
pub use model::{
    AccessToken, Account, AuthParams, AuthorizationCode, Client, Interaction, JwkPub, RefreshToken,
    Session, TokenResponse,
};
pub use provider::{MobileApp, Provider};
pub use response_mode::ResponseMode;
pub use store::{CodeTake, MemoryStore, Store, StoreError, StoreResult};
pub use web::i18n::Lang;
pub use web::router;
