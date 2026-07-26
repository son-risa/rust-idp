/// クライアントは今回のスコープでは1つだけ埋め込みで持つ(Dynamic Client Registration不要)。
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
}

pub struct Config {
    pub issuer: String,
    pub client: ClientConfig,
}

impl Config {
    pub fn load() -> Self {
        let issuer =
            std::env::var("ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_string());

        Config {
            issuer,
            client: ClientConfig {
                client_id: "demo-client".to_string(),
                client_secret: "demo-secret".to_string(),
                redirect_uris: vec!["http://localhost:8080/callback".to_string()],
            },
        }
    }
}
