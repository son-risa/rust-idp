//! `formal/premises.json`（Tamarin のモデルが表に出した前提 P-* → rust-op の担保）が
//! 実在するものだけを指していることを検める門。
//!
//! - README の前提の表は台帳から作る。`<!-- premises: {model} -->` と `<!-- /premises -->` の間が、台帳の
//!   その model の行から作った表とバイト一致する（README の文字を読み解かない）。作り直すときは
//!   `UPDATE_PREMISE_TABLES=1 cargo test formal_ledger` で README の範囲を書き換える。
//! - 台帳の ID は P-[A-Z][A-Z0-9]* の形で、(id, model) の組は重ならない
//! - 行が指すモデル（formal/*.spthy）と担保のコード（`fn`）が在る
//! - 行が指す Kani ハーネスが formal/kani-harnesses.txt に在る（一覧と実際に走ったハーネスの照合は formal/check-kani.sh）
//! - 各行は試験か Kani ハーネスを 1 つ以上持つか、持てない理由（outside）を書く
//!
//! 台帳の試験の名前が cargo test に実際に登録された試験と一致するかは、ここでなく
//! formal/check-ledger-tests.sh が `cargo test -- --list` と照らして見る（文字列の照合ではコメントや cfg で外した試験を見分けられない）。

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Premise {
    id: String,
    model: String,
    premise: String,
    assurance: String,
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

const REGION_END: &str = "<!-- /premises -->";

fn region_start(model: &str) -> String {
    format!("<!-- premises: {model} -->")
}

fn is_premise_id(id: &str) -> bool {
    id.strip_prefix("P-").is_some_and(|t| {
        t.starts_with(|c: char| c.is_ascii_uppercase()) && t.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    })
}

/// 台帳から model ごとの前提の表（README の範囲の中身）を作る。行の順は台帳の順。
fn premise_tables(rows: &[Premise]) -> Result<BTreeMap<String, String>, Vec<String>> {
    let mut tables: BTreeMap<String, String> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    for p in rows {
        let row = format!("{} ({})", p.id, p.model);
        if !is_premise_id(&p.id) {
            errors.push(format!("{row}: ID が P-[A-Z][A-Z0-9]* の形でない"));
        }
        if !seen.insert((p.id.clone(), p.model.clone())) {
            errors.push(format!("{row}: 同じ (id, model) の行が 2 つある"));
        }
        for (name, cell) in [("premise", &p.premise), ("assurance", &p.assurance)] {
            if cell.trim().is_empty() || cell.contains(['|', '\n', '\r']) {
                errors.push(format!("{row}: {name} が空か、表を壊す文字（| や改行）を含む"));
            }
        }
        tables
            .entry(p.model.clone())
            .or_insert_with(|| "| ID | 前提（抽象） | rust-op の担保 |\n|---|---|---|\n".to_string())
            .push_str(&format!("| {} | {} | {} |\n", p.id, p.premise, p.assurance));
    }
    if errors.is_empty() {
        Ok(tables)
    } else {
        Err(errors)
    }
}

/// README の各範囲の中身を作った表に差し替えた README を返す。範囲の欠け・重なり・閉じ忘れ・台帳に無い model の
/// 範囲は誤り。
fn readme_with_tables(readme: &str, tables: &BTreeMap<String, String>) -> Result<String, Vec<String>> {
    let mut out = String::new();
    let mut errors = Vec::new();
    let mut placed = BTreeSet::new();
    let mut lines = readme.split_inclusive('\n');
    while let Some(line) = lines.next() {
        out.push_str(line);
        let Some(model) = line.trim_end_matches(['\n', '\r']).strip_prefix("<!-- premises: ").and_then(|r| r.strip_suffix(" -->")) else {
            continue;
        };
        if !placed.insert(model.to_string()) {
            errors.push(format!("{model} の範囲が 2 つある"));
        }
        match tables.get(model) {
            Some(t) => out.push_str(t),
            None => errors.push(format!("台帳に行の無い model の範囲: {model}")),
        }
        loop {
            match lines.next() {
                Some(l) if l.trim_end_matches(['\n', '\r']) == REGION_END => {
                    out.push_str(l);
                    break;
                }
                Some(l) if l.starts_with("<!-- premises: ") => {
                    errors.push(format!("{model} の範囲が閉じる前に別の範囲が始まる"));
                    out.push_str(l);
                    break;
                }
                Some(_) => {}
                None => {
                    errors.push(format!("{model} の範囲が閉じていない"));
                    break;
                }
            }
        }
    }
    for model in tables.keys().filter(|m| !placed.contains(*m)) {
        errors.push(format!("README に {} の範囲が無い", region_start(model)));
    }
    if errors.is_empty() {
        Ok(out)
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
fn readme_premise_tables_are_generated_from_the_ledger() {
    let tables = premise_tables(&ledger()).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    let readme = read("formal/README.md");
    let expected = readme_with_tables(&readme, &tables).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    if std::env::var_os("UPDATE_PREMISE_TABLES").is_some() {
        std::fs::write(root().join("formal/README.md"), &expected).unwrap();
        return;
    }
    assert!(
        readme == expected,
        "formal/README.md の前提の表が台帳から作った表と一致しない（UPDATE_PREMISE_TABLES=1 cargo test formal_ledger で作り直す）"
    );
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
