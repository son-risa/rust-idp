//! `formal/premises.json`（Tamarin のモデルが表に出した前提 P-* → rust-op の担保）が
//! 実在するものだけを指していることを検める門。
//!
//! - README の前提の表に出る P-* と台帳の行が過不足なく対応する（同じ ID が複数モデルに出るときは数も合わせる）
//! - 行が指すモデル（formal/*.spthy）・担保のコード（`fn`）・試験・Kani ハーネスが実在する
//! - 各行は試験か Kani ハーネスを 1 つ以上持つか、持てない理由（outside）を書く
//!
//! 名前を変えたり消したりして台帳が古くなると、ここが赤になる。

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

fn readme_ids() -> BTreeMap<String, usize> {
    let mut ids = BTreeMap::new();
    for line in read("formal/README.md").lines() {
        let Some(rest) = line.strip_prefix("| P-") else { continue };
        let id = format!("P-{}", rest.split('|').next().unwrap().trim());
        *ids.entry(id).or_insert(0) += 1;
    }
    ids
}

/// `a::b::tests::name` を src/a/b.rs（または src/a/b/mod.rs、src/a.rs の中の `mod b`）に解決し、
/// 残りの段が `mod` として、最後の段が試験の `fn` として在るかを見る。
fn test_exists(path: &str) -> Result<(), String> {
    let segs: Vec<&str> = path.split("::").collect();
    let (name, mods) = segs.split_last().ok_or("空の名前")?;
    let src = root().join("src");
    let mut file = None;
    for k in (1..=mods.len()).rev() {
        let dir: PathBuf = mods[..k].iter().collect();
        for cand in [src.join(&dir).with_extension("rs"), src.join(&dir).join("mod.rs")] {
            if cand.is_file() {
                file = Some((cand, &mods[k..]));
                break;
            }
        }
        if file.is_some() {
            break;
        }
    }
    let (file, inner) = file.ok_or_else(|| format!("{path}: モジュールの file が無い"))?;
    let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
    for m in inner {
        if !text.contains(&format!("mod {m} {{")) {
            return Err(format!("{path}: {} に mod {m} が無い", file.display()));
        }
    }
    let lines: Vec<&str> = text.lines().collect();
    let sig = [format!("fn {name}("), format!("fn {name}<")];
    for (i, l) in lines.iter().enumerate() {
        if !sig.iter().any(|s| l.contains(s.as_str())) {
            continue;
        }
        let attrs = &lines[i.saturating_sub(4)..i];
        if attrs.iter().any(|a| a.trim_start().starts_with("#[test]") || a.contains("#[tokio::test")) {
            return Ok(());
        }
    }
    Err(format!("{path}: {} に試験の fn {name} が無い", file.display()))
}

fn kani_exists(name: &str, harness: &str) -> bool {
    let lines: Vec<&str> = harness.lines().collect();
    lines.iter().enumerate().any(|(i, l)| {
        l.trim_start().starts_with(&format!("fn {name}("))
            && lines[i.saturating_sub(3)..i].iter().any(|a| a.contains("#[kani::proof]"))
    })
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
    assert_eq!(in_ledger, readme_ids(), "formal/README.md の P-* と formal/premises.json の行が合わない");
}

#[test]
fn every_ledger_row_points_at_things_that_exist() {
    let harness = read("src/kani_harness.rs");
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
        for t in &p.tests {
            if let Err(e) = test_exists(t) {
                errors.push(format!("{row}: {e}"));
            }
        }
        for k in &p.kani {
            if !kani_exists(k, &harness) {
                errors.push(format!("{row}: Kani ハーネス {k} が src/kani_harness.rs に無い"));
            }
        }
    }
    assert!(errors.is_empty(), "formal/premises.json が実在しないものを指している:\n{}", errors.join("\n"));
}
