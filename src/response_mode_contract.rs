//! [`ResponseMode`] の契約の試験。実装ごとに 1 度 [`response_mode_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! 認可の応答（code・state・iss、誤りなら error と error_description）は、検証を済ませた redirect_uri へ、この口が組んだ
//! Response で返る。RP が何を受け取るかは、実装ごとの [`Arrival`] が Response から RP の側の見え方で読んで返す
//! （query なら Location の query、fragment なら Location の fragment、form_post なら form の input）。

use crate::response_mode::ResponseMode;
use axum::response::Response;

/// RP の側に届いたもの。`uri` は届け先（query と fragment を除いた URI）、`query` は届け先の URI の query の組
/// （並びのまま）、`elsewhere` は query の外（fragment・form の本文など）で届いた組（並びのまま）。
pub(crate) struct Arrived {
    pub uri: String,
    pub query: Vec<(String, String)>,
    pub elsewhere: Vec<(String, String)>,
}

impl Arrived {
    /// redirect_uri がもともと持っていた query `kept` を頭に残しているか確かめ、その後に届いた組を返す。
    fn after(&self, kept: &[(String, String)]) -> Vec<(String, String)> {
        assert!(
            self.query.starts_with(kept),
            "redirect_uri の query {kept:?} が残っていない: {:?}",
            self.query
        );
        self.query[kept.len()..]
            .iter()
            .chain(&self.elsewhere)
            .cloned()
            .collect()
    }
}

/// 試験する実装と、その実装が組んだ Response を RP の側から読む口。
pub(crate) trait Arrival {
    fn mode(&self) -> &dyn ResponseMode;
    fn read(&self, resp: Response) -> Arrived;
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// 呼び手が載せる値は、どれもそのまま、redirect_uri に届く。値に区切りの文字（`&`・`=`・`#`・`?`・`+`・空白・`%`）や
/// 非 ASCII があっても、値は変わらず、ほかの名の値を作り出さない。
pub(crate) fn delivers_every_param_unchanged(a: &dyn Arrival) {
    let sent = pairs(&[
        ("code", "c0de-1_2.3~"),
        ("state", "a&code=injected#frag?x=1+2 %41 状態"),
        ("iss", "https://op.example.com/oidc"),
    ]);
    let got = a.read(a.mode().build("https://rp.example/cb", &sent));
    assert_eq!(got.uri, "https://rp.example/cb");
    assert_eq!(got.after(&[]), sent);

    let error = pairs(&[
        ("error", "access_denied"),
        ("error_description", "end-user denied the request"),
        ("iss", "https://op.example.com"),
    ]);
    let got = a.read(a.mode().build("https://rp.example/cb", &error));
    assert_eq!(got.after(&[]), error);
}

/// redirect_uri がもともと持つ query は残す（RFC 6749 §3.1.2）。載せる値と混ざらない。
pub(crate) fn keeps_the_query_of_the_redirect_uri(a: &dyn Arrival) {
    let sent = pairs(&[("code", "C1"), ("state", "S1")]);
    let got = a.read(
        a.mode()
            .build("https://rp.example/cb?tenant=a&lang=ja", &sent),
    );
    assert_eq!(got.uri, "https://rp.example/cb");
    assert_eq!(got.after(&pairs(&[("tenant", "a"), ("lang", "ja")])), sent);
}

/// 届け先は渡した redirect_uri だけ。port・path・末尾の `/` も変えない。
pub(crate) fn sends_to_the_given_redirect_uri_only(a: &dyn Arrival) {
    for ru in [
        "https://rp.example/cb",
        "https://rp.example:8443/a/b/",
        "http://localhost:3000/callback",
        "com.example.app:/oauth2redirect",
    ] {
        let got = a.read(a.mode().build(ru, &pairs(&[("code", "C1")])));
        assert_eq!(got.uri, ru);
        assert_eq!(got.after(&[]), pairs(&[("code", "C1")]));
    }
}

/// `$make` は [`Arrival`] を返す fn。
macro_rules! response_mode_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::response_mode_contract as c;

            $crate::response_mode_contract::response_mode_contract_tests!(@each $make;
                delivers_every_param_unchanged,
                keeps_the_query_of_the_redirect_uri,
                sends_to_the_given_redirect_uri_only,
            );
        }
    };
    (@each $make:path; $($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                c::$name(&$make());
            }
        )*
    };
}
pub(crate) use response_mode_contract_tests;
