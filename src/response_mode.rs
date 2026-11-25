//! 認可レスポンスの返し方。node-oidc-provider の `response_modes/*` 相当。
//! form_post / fragment / jwt を足す時はこの trait に impl を増やす。

use axum::response::{IntoResponse, Redirect, Response};

pub trait ResponseMode: Send + Sync {
    fn name(&self) -> &'static str;
    /// redirect_uri に params を載せて返す Response を組み立てる。
    fn build(&self, redirect_uri: &str, params: &[(String, String)]) -> Response;
}

/// response_mode = query（authorization code flow の既定）。
pub struct QueryMode;
impl ResponseMode for QueryMode {
    fn name(&self) -> &'static str {
        "query"
    }
    fn build(&self, redirect_uri: &str, params: &[(String, String)]) -> Response {
        let qs = serde_urlencoded::to_string(params).unwrap_or_default();
        let sep = if redirect_uri.contains('?') { '&' } else { '?' };
        Redirect::to(&format!("{redirect_uri}{sep}{qs}")).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response_mode_contract::{Arrival, Arrived};

    /// 3xx の Location を、RP の側の URI として読む。
    struct FromLocation(QueryMode);
    impl Arrival for FromLocation {
        fn mode(&self) -> &dyn ResponseMode {
            &self.0
        }
        fn read(&self, resp: Response) -> Arrived {
            assert!(resp.status().is_redirection(), "{}", resp.status());
            let loc = resp.headers()["location"].to_str().unwrap().to_string();
            let (rest, fragment) = loc.split_once('#').unwrap_or((&loc, ""));
            let (uri, query) = rest.split_once('?').unwrap_or((rest, ""));
            Arrived {
                uri: uri.to_string(),
                query: serde_urlencoded::from_str(query).unwrap(),
                elsewhere: serde_urlencoded::from_str(fragment).unwrap(),
            }
        }
    }

    fn query() -> FromLocation {
        FromLocation(QueryMode)
    }
    crate::response_mode_contract::response_mode_contract_tests!(query);
}
