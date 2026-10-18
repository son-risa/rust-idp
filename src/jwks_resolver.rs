//! private_key_jwt クライアントの `jwks_uri` から公開鍵を取得し TTL キャッシュする
//! （RFC 7591 / 鍵ローテーション対応）。inline jwks に kid が無い時のフォールバック。

use crate::model::JwkPub;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// キャッシュ TTL。鍵ローテーションの反映遅延の上限であり、jwks_uri への取得頻度の下限。
const TTL_SECS: u64 = 300;

struct Cached {
    keys: Vec<JwkPub>,
    expires_at: u64,
}

pub struct JwksResolver {
    cache: Mutex<HashMap<String, Cached>>,
}

impl Default for JwksResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksResolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// `jwks_uri` から kid に一致する公開鍵を返す。キャッシュが有効ならその中から探し、
    /// 期限切れ/未取得なら取得し直す。kid が見つからなければ None。
    pub async fn resolve(&self, jwks_uri: &str, kid: &str) -> Option<JwkPub> {
        let now = now();
        {
            let cache = self.cache.lock().unwrap();
            if let Some(c) = cache.get(jwks_uri) {
                if c.expires_at > now {
                    return c.keys.iter().find(|k| k.kid == kid).cloned();
                }
            }
        }
        let keys = self.fetch(jwks_uri).await?;
        let found = keys.iter().find(|k| k.kid == kid).cloned();
        self.cache.lock().unwrap().insert(
            jwks_uri.to_string(),
            Cached { keys, expires_at: now + TTL_SECS },
        );
        found
    }

    async fn fetch(&self, jwks_uri: &str) -> Option<Vec<JwkPub>> {
        let (client, url) = request_for(jwks_uri).await?;
        let resp = client
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let keys = crate::dcr::jwks_from_jwk_set(Some(&v));
        if keys.is_empty() {
            None
        } else {
            Some(keys)
        }
    }
}

/// jwks_uri を取りに行ってよいなら、判定したアドレスに留めたクライアントと URL を返す。
/// jwks_uri は DCR(IAT 必須)で登録された半信頼値なので、https に限り、内向きのアドレスを断る（SSRF 緩和）。
async fn request_for(jwks_uri: &str) -> Option<(reqwest::Client, reqwest::Url)> {
    if !jwks_uri.starts_with("https://") {
        return None;
    }
    let url = reqwest::Url::parse(jwks_uri).ok()?;
    let addrs = public_addrs(&url).await?;
    let client = pinned_client(&addrs).ok()?;
    Some((client, url))
}

/// 内向き（loopback・private・link-local・メタデータ・ULA など）のアドレス。
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let [o0, o1, o2, _] = a.octets();
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || o0 == 0
                || o0 >= 240
                || (o0 == 100 && (o1 & 0xc0) == 64)
                || (o0 == 192 && o1 == 0 && o2 == 0)
                || (o0 == 198 && (o1 & 0xfe) == 18)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            let embedded = |hi: u16, lo: u16| is_internal(IpAddr::V4(std::net::Ipv4Addr::from(((hi as u32) << 16) | lo as u32)));
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                // IPv4 互換（::a.b.c.d）と IPv4 写像（::ffff:a.b.c.d）は中の IPv4 で判定する。
                || a.to_ipv4().is_some_and(|v4| is_internal(IpAddr::V4(v4)))
                // NAT64（64:ff9b::/96 と 64:ff9b:1::/48）と Teredo（2001::/32）は、先が IPv4 の内側へ届きうるので断る。
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0])
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                || (s[0] == 0x2001 && s[1] == 0)
                // 6to4（2002::/16）は埋め込みの IPv4 で判定する。
                || (s[0] == 0x2002 && embedded(s[1], s[2]))
        }
    }
}

/// 名前を解いた後のアドレスで判定する。1 つでも内向きなら全体を断る（DNS の応答に混ぜる手を塞ぐ）。
async fn public_addrs(url: &reqwest::Url) -> Option<Vec<SocketAddr>> {
    let port = url.port_or_known_default()?;
    let host = url.host_str()?;
    let addrs: Vec<SocketAddr> = match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::net::lookup_host((host, port)).await.ok()?.collect(),
    };
    if addrs.is_empty() || addrs.iter().any(|a| is_internal(a.ip())) {
        return None;
    }
    Some(addrs)
}

/// 名前を問わず、判定したアドレスだけを返す resolver。`resolve_to_addrs` の上書きは名前の鍵で引くので、
/// 大文字や末尾の点で引き損ねると reqwest は黙って名前を解き直す。これを 1 つのクライアントの全ての名前に当てる。
struct PinnedResolver(Vec<SocketAddr>);

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addrs = self.0.clone();
        Box::pin(async move { Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs) })
    }
}

/// 判定したアドレスにだけ接続し（取得の間に名前を解き直させない）、redirect は追わない。
fn pinned_client(addrs: &[SocketAddr]) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .dns_resolver(std::sync::Arc::new(PinnedResolver(addrs.to_vec())))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_https_schemes_are_rejected_for_ssrf() {
        let r = JwksResolver::new();
        // https 以外は一切ネットワークに出さない（SSRF 緩和）。大文字 HTTPS も
        // starts_with は大小区別＝拒否（err on the safe side）。
        for bad in [
            "http://example.com/jwks",
            "file:///etc/passwd",
            "ftp://host/jwks",
            "gopher://host/",
            "javascript:alert(1)",
            "HTTPS://Example.com/jwks",
            "https:/missing-slash",
            "//evil.com/jwks",
            "",
            " https://leading-space/jwks",
        ] {
            assert!(r.fetch(bad).await.is_none(), "{bad:?} を取得してはならない");
        }
    }

    async fn allowed(u: &str) -> bool {
        request_for(u).await.is_some()
    }

    #[tokio::test]
    async fn internal_addresses_are_refused_after_resolution() {
        for bad in [
            "https://127.0.0.1/jwks",
            "https://localhost/jwks",
            "https://10.1.2.3/jwks",
            "https://172.16.0.1/jwks",
            "https://192.168.1.1/jwks",
            "https://169.254.169.254/computeMetadata/v1/",
            "https://100.64.0.1/jwks",
            "https://0.0.0.0/jwks",
            "https://[::1]/jwks",
            "https://[fd00:ec2::254]/jwks",
            "https://[fe80::1]/jwks",
            "https://[::ffff:169.254.169.254]/jwks",
            "https://[::7f00:1]/jwks",
            "https://[64:ff9b::a9fe:a9fe]/jwks",
            "https://[64:ff9b:1::1]/jwks",
            "https://[2002:a9fe:a9fe::1]/jwks",
            "https://[2001::1]/jwks",
            "https://192.0.0.1/jwks",
            "https://198.18.0.1/jwks",
            "https://240.0.0.1/jwks",
        ] {
            assert!(!allowed(bad).await, "{bad} を通してはならない");
        }
        assert!(allowed("https://93.184.215.14/jwks").await);
        assert!(allowed("https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/jwks").await);
        assert!(allowed("https://[2002:5db8:d70e::1]/jwks").await, "6to4 は埋め込みの IPv4 が公開なら通す");
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use axum::response::Redirect;
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/jwks", get(|| async { Redirect::temporary("/inside") }))
            .route("/inside", get(|| async { "inside" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = pinned_client(&[addr]).unwrap();
        let resp = client.get(format!("http://jwks.example:{}/jwks", addr.port())).send().await.unwrap();
        assert!(resp.status().is_redirection(), "redirect の先へ行ってはならない");
    }

    #[tokio::test]
    async fn the_pinned_client_never_resolves_names_on_its_own() {
        let app = axum::Router::new().route("/jwks", axum::routing::get(|| async { "pinned" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = pinned_client(&[addr]).unwrap();
        // .invalid は DNS で決して解けない（RFC 6761）。大文字・末尾の点でも、留めた先にだけ届く。
        for host in ["jwks.invalid", "JWKS.INVALID", "jwks.invalid."] {
            let resp = client.get(format!("http://{host}:{}/jwks", addr.port())).send().await;
            let body = resp.unwrap_or_else(|e| panic!("{host}: {e}")).text().await.unwrap();
            assert_eq!(body, "pinned", "{host}");
        }
    }
}
