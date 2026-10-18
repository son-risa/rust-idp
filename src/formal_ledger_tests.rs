//! `formal/premises.json`（Tamarin のモデルが表に出した前提 P-* → rust-op の担保）が
//! 実在するものだけを指していることを検める門。
//!
//! - README の前提の表に出る P-* と台帳の行が過不足なく対応する（同じ ID が複数モデルに出るときは数も合わせる）
//! - 行が指すモデル（formal/*.spthy）と担保のコード（`fn`）が在る
//! - 行が指す Kani ハーネスが formal/kani-harnesses.txt に在る（一覧と実際に走ったハーネスの照合は formal/check-kani.sh）
//! - 各行は試験か Kani ハーネスを 1 つ以上持つか、持てない理由（outside）を書く
//!
//! 台帳の試験の名前が cargo test に実際に登録された試験と一致するかは、ここでなく
//! formal/check-ledger-tests.sh が `cargo test -- --list` と照らして見る（文字列の照合ではコメントや cfg で外した試験を見分けられない）。

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Premise {
    id: String,
    model: String,
    premise: String,
    #[serde(default)]
    guard: Vec<String>,
    #[serde(default)]
    tests: Vec<String>,
    #[serde(default)]
    kani: Vec<String>,
    #[serde(default)]
    outside: Option<String>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn ledger() -> Vec<Premise> {
    serde_json::from_str(&read("formal/premises.json")).expect("formal/premises.json が読めない")
}

fn premise_id_in(cell: &str) -> Option<String> {
    let at = cell.find("P-")?;
    let tail: String = cell[at + 2..].chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit()).collect();
    (!tail.is_empty()).then(|| format!("P-{tail}"))
}

/// README の表の行の最初のセルから P-* を数える。見出しの最初のセルが ID の表（前提の表）の行で
/// ID を取れないものは誤りとして返す（「（攻撃者モデル）」のように全角の括弧で囲んだ注記の行は除く）。
/// 本文の中の P-* の言及（表の行でないもの）は数えない。
fn readme_ids() -> Result<BTreeMap<String, usize>, Vec<String>> {
    let mut ids = BTreeMap::new();
    let mut errors = Vec::new();
    let mut in_id_table = false;
    for (n, line) in read("formal/README.md").lines().enumerate() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_id_table = false;
            continue;
        }
        let first = t.trim_start_matches('|').split('|').next().unwrap_or("");
        let bare = first.trim_matches(|c: char| c == '*' || c == '`' || c.is_whitespace());
        if bare == "ID" {
            in_id_table = true;
            continue;
        }
        if !bare.is_empty() && bare.chars().all(|c| c == '-' || c == ':') {
            continue;
        }
        match premise_id_in(first) {
            Some(id) => *ids.entry(id).or_insert(0) += 1,
            None if in_id_table && !(bare.starts_with('（') && bare.ends_with('）')) => {
                errors.push(format!("README {} 行目: 前提の表の行なのに ID が取れない: {t}", n + 1))
            }
            None => {}
        }
    }
    if errors.is_empty() {
        Ok(ids)
    } else {
        Err(errors)
    }
}

/// `src/x.rs: Type::method` か `src/x.rs: function`。Type を書いたときは impl も在ることを見る。
fn guard_exists(guard: &str) -> Result<(), String> {
    let (file, sym) = guard.split_once(": ").ok_or_else(|| format!("{guard}: `file: 名前` の形でない"))?;
    let text = std::fs::read_to_string(root().join(file)).map_err(|e| format!("{guard}: {e}"))?;
    let (ty, f) = match sym.rsplit_once("::") {
        Some((t, f)) => (Some(t), f),
        None => (None, sym),
    };
    if !text.contains(&format!("fn {f}(")) && !text.contains(&format!("fn {f}<")) {
        return Err(format!("{guard}: fn {f} が無い"));
    }
    if let Some(t) = ty {
        if !text.contains(&format!("for {t} {{")) && !text.contains(&format!("impl {t} {{")) {
            return Err(format!("{guard}: impl {t} が無い"));
        }
    }
    Ok(())
}

#[test]
fn ledger_rows_match_the_readme_premise_tables() {
    let mut in_ledger = BTreeMap::new();
    for p in ledger() {
        *in_ledger.entry(p.id).or_insert(0usize) += 1;
    }
    let in_readme = readme_ids().unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert_eq!(in_ledger, in_readme, "formal/README.md の P-* と formal/premises.json の行が合わない");
}

#[test]
fn every_ledger_row_points_at_things_that_exist() {
    let harnesses: Vec<String> =
        read("formal/kani-harnesses.txt").lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect();
    let mut errors = Vec::new();
    for p in ledger() {
        let row = format!("{} ({})", p.id, p.model);
        if p.premise.trim().is_empty() {
            errors.push(format!("{row}: premise が空"));
        }
        if !Path::new(&root().join("formal").join(&p.model)).is_file() {
            errors.push(format!("{row}: formal/{} が無い", p.model));
        }
        let outside = p.outside.as_deref().map(str::trim).filter(|s| !s.is_empty());
        if p.tests.is_empty() && p.kani.is_empty() && outside.is_none() {
            errors.push(format!("{row}: 試験も Kani ハーネスも無く、outside の理由も無い"));
        }
        if outside.is_none() && p.guard.is_empty() {
            errors.push(format!("{row}: 担保のコード（guard）が無い"));
        }
        for g in &p.guard {
            if let Err(e) = guard_exists(g) {
                errors.push(format!("{row}: {e}"));
            }
        }
        for k in &p.kani {
            if !harnesses.contains(k) {
                errors.push(format!("{row}: Kani ハーネス {k} が formal/kani-harnesses.txt に無い"));
            }
        }
    }
    assert!(errors.is_empty(), "formal/premises.json が実在しないものを指している:\n{}", errors.join("\n"));
}
