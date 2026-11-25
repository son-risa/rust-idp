//! docs/routes.md の経路の一覧と、router() が実際に持つ経路との突き合わせ。
//!
//! axum は経路を列挙できないので、2 つの向きから挟む。
//! - 表 → 実際: 表の path ごとに、どの経路も受けない method（PROBE）で叩く。path が在れば axum は 405 と
//!   Allow（その path が受ける method の全部）を返す。Allow が表の method と一致するかを見る。
//!   Origin 無しで叩いたときに 403 なら、管理画面の門が掛かっている。
//! - 実際 → 表: src の本番のコードにある `.route(` の path を拾い、表の path と一致するかを見る。

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use tower::ServiceExt;

const ORIGIN: &str = "https://idp.example";
const BASE: &str = "/oidc";

/// router() が `base` の経路を BASE_PATH の下へ置く nest。
const KNOWN_NEST: &str = ".nest(&base_path, inner)";

/// 文字列でない path を `.route(` に渡している箇所と、表での書き方。
const NON_LITERAL_PATHS: &[(&str, &str)] = &[("&format!(\"{base_path}/\")", "{BASE_PATH}/")];

#[derive(Debug)]
struct Row {
    place: String,
    method: String,
    path: String,
    gate: bool,
}

fn manifest_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// crates.io の package には docs/ を入れない。package から取り出した crate（`.cargo_vcs_info.json` が在る）で
/// cargo test を回したときだけ、表との照合を飛ばす。repo の中で docs/routes.md が消えたときは飛ばさずに落とす。
fn skipped_in_package() -> bool {
    let skip = !manifest_path("docs/routes.md").is_file() && manifest_path(".cargo_vcs_info.json").is_file();
    if skip {
        eprintln!("skip: docs/routes.md は package に入らない");
    }
    skip
}

fn documented() -> Vec<Row> {
    let doc = std::fs::read_to_string(manifest_path("docs/routes.md")).expect("docs/routes.md");
    let after = doc.split("## 一覧").nth(1).expect("docs/routes.md に「## 一覧」が無い");
    let table = after.split("## 注記").next().unwrap().trim();
    // 表の途中の空行や地の文で、後ろの行を黙って捨てないよう、「## 注記」まで表の行だけが続くことを求める。
    let lines: Vec<&str> = table.lines().collect();
    if let Some(bad) = lines.iter().find(|l| !l.starts_with('|')) {
        panic!("docs/routes.md の表が「## 注記」の前で途切れている: {bad:?}");
    }
    let mut rows = Vec::new();
    for line in lines.into_iter().skip(2) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 7, "列の数が違う: {line}");
        assert!(["base", "top", "fido"].contains(&cells[0]), "置き場が分からない: {line}");
        assert!(["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&cells[1]), "method が分からない: {line}");
        for c in [cells[5], cells[6]] {
            assert!(c == "はい" || c == "いいえ", "「はい」か「いいえ」で書く: {line}");
        }
        assert!(cells[3..5].iter().all(|c| !c.is_empty()), "呼び手と認証を書く: {line}");
        rows.push(Row {
            place: cells[0].to_string(),
            method: cells[1].to_string(),
            path: cells[2].trim_matches('`').to_string(),
            gate: cells[6] == "はい",
        });
    }
    assert!(!rows.is_empty(), "docs/routes.md の表が読めない");
    rows
}

/// 表の (置き場, path) ごとの method と門。同じ組に門の値が食い違って書かれていれば止める。
fn by_path(rows: &[Row]) -> BTreeMap<(String, String), (BTreeSet<String>, bool)> {
    let mut m: BTreeMap<(String, String), (BTreeSet<String>, bool)> = BTreeMap::new();
    for r in rows {
        let e = m.entry((r.place.clone(), r.path.clone())).or_insert_with(|| (BTreeSet::new(), r.gate));
        assert!(e.0.insert(r.method.clone()), "同じ行が 2 つある: {r:?}");
        assert_eq!(e.1, r.gate, "同じ path で門の欄が食い違う: {r:?}");
    }
    m
}

fn concrete(place: &str, path: &str) -> String {
    // `{uid}` などは、その名前をそのまま値にする。
    let out = path.replace("{BASE_PATH}", BASE).replace(['{', '}'], "");
    match place {
        "base" if out == "/" => BASE.to_string(),
        "base" => format!("{BASE}{out}"),
        _ => out,
    }
}

async fn probe(app: &Router, url: &str, origin: Option<&str>) -> (StatusCode, BTreeSet<String>) {
    let mut req = axum::http::Request::builder().method(axum::http::Method::from_bytes(b"PROBE").unwrap()).uri(url);
    if let Some(o) = origin {
        req = req.header(header::ORIGIN, o);
    }
    let resp = app.clone().oneshot(req.body(axum::body::Body::empty()).unwrap()).await.unwrap();
    let allow = resp
        .headers()
        .get(header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(',')
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty() && m != "HEAD")
        .collect();
    (resp.status(), allow)
}

/// 表の path を全部叩き、受ける method の全部と門の有無が表と一致するかを見る。
#[tokio::test]
async fn every_documented_route_is_served_with_exactly_the_documented_methods_and_gate() {
    if skipped_in_package() {
        return;
    }
    let app = router(Provider::new(format!("{ORIGIN}{BASE}")).with_base_path(BASE));
    // fido は FIDO_CONFORMANCE_ENABLED のときだけ router() が host の直下へ merge する。環境変数を触らずに同じものを組む。
    let fido = crate::fido::router(Arc::new(crate::fido::FidoState::from_env()));
    let mut errors = Vec::new();
    for ((place, path), (methods, gate)) in by_path(&documented()) {
        let app = if place == "fido" { &fido } else { &app };
        let url = concrete(&place, &path);
        let (status, allow) = probe(app, &url, Some(ORIGIN)).await;
        if status != StatusCode::METHOD_NOT_ALLOWED {
            errors.push(format!("{place} {path}（{url}）: 経路が無い（{status}）"));
            continue;
        }
        if allow != methods {
            errors.push(format!("{place} {path}: 表は {methods:?}、実際は {allow:?}"));
        }
        let (status, _) = probe(app, &url, None).await;
        let actual_gate = status == StatusCode::FORBIDDEN;
        if actual_gate != gate {
            errors.push(format!("{place} {path}: 門の欄は {gate}、実際は {actual_gate}（{status}）"));
        }
    }
    assert!(errors.is_empty(), "docs/routes.md と router() が食い違う:\n{}", errors.join("\n"));
}

/// src の本番のコード（`#[cfg(test)]` の mod と `*_tests.rs` を除く）から、`.route(` の第 1 引数を拾う。
fn routes_in_source() -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stack = vec![manifest_path("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let shown = p.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap().display().to_string();
            let code = without_test_mods(&src);
            for bad in ["route_service(", "nest_service(", "fallback_service("] {
                assert!(!code.contains(bad), "{shown} の {bad} は、この試験では経路を拾えない。拾い方を足す");
            }
            // 経路の前に接頭辞を付ける nest は、BASE_PATH の下へ置くこの 1 つだけを知っている。
            for (i, _) in code.match_indices(".nest(") {
                assert!(
                    code[i..].starts_with(KNOWN_NEST),
                    "{shown}: 知らない `.nest(` が在る。この試験は接頭辞の付いた path を拾えない。拾い方を足す"
                );
            }
            for (i, _) in code.match_indices(".route(") {
                let arg = code[i + ".route(".len()..].trim_start();
                let path = match arg.strip_prefix('"') {
                    Some(rest) => rest[..rest.find('"').unwrap()].to_string(),
                    None => {
                        let expr = arg[..arg.find(',').unwrap()].trim();
                        match NON_LITERAL_PATHS.iter().find(|(e, _)| *e == expr) {
                            Some((_, doc)) => doc.to_string(),
                            None => panic!("{shown}: 文字列でない path `{expr}` を NON_LITERAL_PATHS に足す"),
                        }
                    }
                };
                found.entry(path).or_default().push(shown.clone());
            }
        }
    }
    found
}

/// 行頭の `#[cfg(test)]` に続く `mod … {` から、行頭の `}` までを落とす（rustfmt の形を前提にする）。
fn without_test_mods(src: &str) -> String {
    let mut out = String::new();
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        if line == "#[cfg(test)]" && lines.peek().is_some_and(|n| n.contains("mod ") && n.ends_with('{')) {
            for l in lines.by_ref() {
                if l == "}" {
                    break;
                }
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// 表に無い経路を src に足したら（または表に在る経路を src から消したら）止める。
/// path が同じでも、置き場（base・top・fido）や門の内外が違えば `.route(` は別に要る。
/// path ごとに、src に現れる数と、表でその path を持つ置き場の数とを比べる。
/// 門の内と外は同じ置き場なので、表では 1 つ。門の外に同じ path を足すと src の数だけが増えて止まる。
#[test]
fn every_route_in_the_source_is_documented() {
    if skipped_in_package() {
        return;
    }
    let in_source = routes_in_source();
    let mut in_doc: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in documented() {
        in_doc.entry(r.path).or_default().insert(r.place);
    }
    let mut errors = Vec::new();
    for (path, files) in &in_source {
        let places = in_doc.get(path).map_or(0, BTreeSet::len);
        if files.len() != places {
            errors.push(format!(
                "{path}: src に {} 回（{}）、表の置き場は {places} つ（{:?}）",
                files.len(),
                files.join(", "),
                in_doc.get(path).cloned().unwrap_or_default()
            ));
        }
    }
    for (path, places) in &in_doc {
        if !in_source.contains_key(path) {
            errors.push(format!("{path}: 表の置き場は {places:?}、src に無い"));
        }
    }
    assert!(errors.is_empty(), "docs/routes.md と src の `.route(` が食い違う:\n{}", errors.join("\n"));
}
