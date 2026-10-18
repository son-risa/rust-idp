//! `formal/premises.json`（Tamarin のモデルが表に出した前提 P-* → rust-op の担保）が
//! 実在するものだけを指していることを検める門。
//!
//! - README の各モデルの節に出る (P-*, モデル) の組と、台帳の (id, model) の組が一致する
//!   （README は表の形に依らず、節の全文から拾う。節とモデルの file の対応は MODEL_SECTIONS の一覧で引く）
//! - 行が指すモデル（formal/*.spthy）と担保のコード（`fn`）が在る
//! - 行が指す Kani ハーネスが formal/kani-harnesses.txt に在る（一覧と実際に走ったハーネスの照合は formal/check-kani.sh）
//! - 各行は試験か Kani ハーネスを 1 つ以上持つか、持てない理由（outside）を書く
//!
//! 台帳の試験の名前が cargo test に実際に登録された試験と一致するかは、ここでなく
//! formal/check-ledger-tests.sh が `cargo test -- --list` と照らして見る（文字列の照合ではコメントや cfg で外した試験を見分けられない）。

use serde::Deserialize;
use std::collections::BTreeSet;
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

/// README のモデルの節の見出し（行全体）と、その節が扱うモデルの file の一覧。節は見出しの行から次の `---` の行まで。
/// 見出しの番号から file を推さず、この一覧で引く。
const MODEL_SECTIONS: &[(&str, &str)] = &[
    ("## モデル #1: 認可コード + PKCE + クライアント認証 → トークン", "oauth_code_pkce.spthy"),
    ("## モデル #2: DPoP 送り主束縛（RFC 9449）", "dpop_binding.spthy"),
    ("## モデル #3: CIBA（切り離し承認）+ RAR マンデート", "ciba_rar.spthy"),
    ("## モデル #4: WebAuthn / FIDO2 ユーザ認証（passkey）", "webauthn.spthy"),
    ("## モデル #5: OIDC ID token（フェデレーションの原子）", "id_token.spthy"),
    ("## モデル #6: 合成（#1 認可コード+PKCE+クライアント認証 × #2 DPoP × #4 ユーザ同意）", "composition_code_dpop.spthy"),
    ("## モデル #7: 合成（#3 CIBA 切り離し承認 × #3 RAR マンデート × #2 DPoP 送り主束縛）", "composition_ciba_dpop_rar.spthy"),
    ("## モデル #8: 合成（public client 認可コード × redirect_uri 完全一致 × PKCE × #2 DPoP × ユーザ同意）", "composition_public_pkce_dpop.spthy"),
];

/// README の各モデルの節の全文（表・本文を問わない）から P-[A-Z][A-Z0-9]* を拾い、(ID, モデルの file) の組にする。
/// 次は誤りとして返す: 一覧に無い「## モデル」の見出し、一覧の見出しが README に無い・2 度ある、
/// モデルの節の外にある P-*、ASCII でないハイフンで書いた ID（P‐CKEY など。拾われずに照合をすり抜ける）。
fn readme_pairs() -> Result<BTreeSet<(String, String)>, Vec<String>> {
    const LOOKALIKE_DASHES: &[char] = &['‐', '‑', '‒', '–', '—', '―', '−', '－', 'ー'];
    let text = read("formal/README.md");
    let mut pairs = BTreeSet::new();
    let mut errors = Vec::new();
    let mut seen_headings = BTreeSet::new();
    let mut model: Option<&str> = None;
    for (n, line) in text.lines().enumerate() {
        if line.starts_with("## モデル") {
            match MODEL_SECTIONS.iter().find(|(h, _)| *h == line) {
                Some((h, m)) => {
                    if !seen_headings.insert(*h) {
                        errors.push(format!("README {} 行目: 同じモデルの見出しが 2 度ある: {line}", n + 1));
                    }
                    model = Some(m);
                }
                None => {
                    errors.push(format!("README {} 行目: MODEL_SECTIONS に無いモデルの見出し: {line}", n + 1));
                    model = None;
                }
            }
            continue;
        }
        if line.trim() == "---" {
            model = None;
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        for (k, w) in chars.windows(3).enumerate() {
            if w[0] != 'P' || (k > 0 && chars[k - 1].is_ascii_alphanumeric()) || !w[2].is_ascii_uppercase() {
                continue;
            }
            if w[1] == '-' {
                let tail: String =
                    chars[k + 2..].iter().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit()).collect();
                match model {
                    Some(m) => {
                        pairs.insert((format!("P-{tail}"), m.to_string()));
                    }
                    None => errors.push(format!("README {} 行目: モデルの節の外の P-{tail}: {line}", n + 1)),
                }
            } else if LOOKALIKE_DASHES.contains(&w[1]) {
                errors.push(format!("README {} 行目: ASCII でないハイフンの ID: {line}", n + 1));
            }
        }
    }
    for (h, m) in MODEL_SECTIONS {
        if !seen_headings.contains(h) {
            errors.push(format!("MODEL_SECTIONS の見出しが README に無い: {h}"));
        }
        if !root().join("formal").join(m).is_file() {
            errors.push(format!("MODEL_SECTIONS の formal/{m} が無い"));
        }
    }
    if errors.is_empty() {
        Ok(pairs)
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
    let in_ledger: BTreeSet<(String, String)> = ledger().into_iter().map(|p| (p.id, p.model)).collect();
    let in_readme = readme_pairs().unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert_eq!(in_ledger, in_readme, "formal/README.md の (P-*, モデル) と formal/premises.json の (id, model) が合わない");
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
