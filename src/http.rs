//! 外へ出る HTTP のクライアント。reqwest 0.13 は TLS の provider を自分では選ばない（Cargo.toml の注記）。

/// rustls の provider に ring を入れてから builder を返す。provider は process に一つで、
/// 入っていれば何もしない（試験は main を通らないので、ここで入れる）。
pub fn builder() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
}

#[cfg(any(feature = "gcp", test))]
pub fn client() -> reqwest::Client {
    builder().build().expect("reqwest client")
}
