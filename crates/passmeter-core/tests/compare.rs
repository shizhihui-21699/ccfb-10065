//! 对比测试：把本实现的强度排序与「真实泄露频次」做相关性检查。
//!
//! 这是本项目的质量护栏。评估器的任何参数改动（词典名次、权重、
//! 模式估值）都应当看这里的数字，而不是凭感觉调。
//!
//! 数据依赖：
//! - `tests/data/compare_set.txt`   待评估口令（含 3000 条真实 rockyou 样本）
//! - `tests/data/truth.tsv`         每行 `<rockyou 频次名次>\t<口令>`
//!
//! 两组数据都由 `tools/gen_compare_set.py` 生成，可复现。
//!
//! 通过标准见各测试的断言；数值来自 docs/COMPARISON.md 的实测基线。

use passmeter_core::Evaluator;
use std::collections::HashMap;

fn load_ours() -> (Vec<String>, HashMap<String, f64>) {
    let e = Evaluator::with_embedded_full().expect("数据表损坏");
    let set = include_str!("data/compare_set.txt");
    let mut words = Vec::new();
    let mut log10 = HashMap::new();
    for line in set.lines() {
        let w = line.trim();
        if w.is_empty() {
            continue;
        }
        let r = e.evaluate(w);
        words.push(w.to_string());
        log10.insert(w.to_string(), r.guesses_log10);
    }
    (words, log10)
}

fn load_truth() -> HashMap<String, u32> {
    let mut m = HashMap::new();
    for line in include_str!("data/truth.tsv").lines() {
        let mut it = line.split('\t');
        let (Some(rank), Some(word)) = (it.next(), it.next()) else {
            continue;
        };
        if let Ok(r) = rank.parse() {
            m.insert(word.to_string(), r);
        }
    }
    m
}

/// Spearman 秩相关（并列取平均秩）。
fn spearman(xs: &[f64], ys: &[f64]) -> f64 {
    fn ranks(v: &[f64]) -> Vec<f64> {
        let mut idx: Vec<usize> = (0..v.len()).collect();
        idx.sort_by(|&a, &b| v[a].partial_cmp(&v[b]).unwrap_or(std::cmp::Ordering::Equal));
        let mut r = vec![0.0; v.len()];
        let mut i = 0;
        while i < idx.len() {
            let mut j = i;
            while j + 1 < idx.len() && v[idx[j + 1]] == v[idx[i]] {
                j += 1;
            }
            let avg = (i + j) as f64 / 2.0 + 1.0;
            for k in i..=j {
                r[idx[k]] = avg;
            }
            i = j + 1;
        }
        r
    }
    let rx = ranks(xs);
    let ry = ranks(ys);
    let n = xs.len() as f64;
    let mx = rx.iter().sum::<f64>() / n;
    let my = ry.iter().sum::<f64>() / n;
    let num: f64 = rx.iter().zip(&ry).map(|(a, b)| (a - mx) * (b - my)).sum();
    let dx: f64 = rx.iter().map(|a| (a - mx).powi(2)).sum::<f64>().sqrt();
    let dy: f64 = ry.iter().map(|b| (b - my).powi(2)).sum::<f64>().sqrt();
    if dx == 0.0 || dy == 0.0 {
        0.0
    } else {
        num / (dx * dy)
    }
}

/// 与真实泄露频次的整体相关性。
///
/// 基线（2851 条长度 ≥6 的样本）：ρ ≈ 0.63。
/// 阈值取 0.55，留出算法微调的余量，但拦住结构性退化。
#[test]
fn correlates_with_real_breach_rank() {
    let (words, ours) = load_ours();
    let truth = load_truth();
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for w in &words {
        if w.chars().count() < 6 {
            continue;
        }
        if let Some(&rank) = truth.get(w) {
            xs.push(ours[w]);
            ys.push((rank as f64).log10());
        }
    }
    assert!(xs.len() > 2000, "样本量不足：{}", xs.len());
    let rho = spearman(&xs, &ys);
    assert!(
        rho >= 0.55,
        "与真实泄露频次的 Spearman ρ = {rho:.3}，低于基线 0.55；\
         检查词典名次或估算参数是否被改坏"
    );
}

/// 分档一致率：把真实名次也按 1e3/1e6/1e8/1e10 分档后比对。
///
/// 基线：97% 完全一致，100% 相差 ≤1 档。阈值取 90% / 99%。
#[test]
fn score_bins_agree_with_truth() {
    let (words, ours) = load_ours();
    let truth = load_truth();
    let bin = |log10: f64| -> u8 {
        let g = 10f64.powf(log10);
        if g < 1e3 + 5.0 {
            0
        } else if g < 1e6 + 5.0 {
            1
        } else if g < 1e8 + 5.0 {
            2
        } else if g < 1e10 + 5.0 {
            3
        } else {
            4
        }
    };
    let mut total = 0usize;
    let mut exact = 0usize;
    let mut within1 = 0usize;
    for w in &words {
        if w.chars().count() < 6 {
            continue;
        }
        let Some(&rank) = truth.get(w) else {
            continue;
        };
        let truth_bin = bin((rank as f64).log10());
        let ours_bin = bin(ours[w]);
        total += 1;
        if ours_bin == truth_bin {
            exact += 1;
        }
        if ours_bin.abs_diff(truth_bin) <= 1 {
            within1 += 1;
        }
    }
    let exact_rate = exact as f64 / total as f64;
    let within1_rate = within1 as f64 / total as f64;
    assert!(
        exact_rate >= 0.90,
        "分档完全一致率 {:.1}%，低于 90% 基线",
        exact_rate * 100.0
    );
    assert!(
        within1_rate >= 0.99,
        "分档差 ≤1 档的比例 {:.1}%，低于 99% 基线",
        within1_rate * 100.0
    );
}

/// 高频口令区间的相关性必须显著高于长尾。
///
/// rockyou 名次 5 万以后基本是长尾噪声：那些口令彼此的「真实强度」
/// 差异已经淹没在语料偏差里。真正有意义的检验是前 1 万名。
#[test]
fn top_rank_correlation_is_strong() {
    let (words, ours) = load_ours();
    let truth = load_truth();
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for w in &words {
        if let Some(&rank) = truth.get(w) {
            if rank <= 10_000 {
                xs.push(ours[w]);
                ys.push((rank as f64).log10());
            }
        }
    }
    assert!(xs.len() > 100, "前 1 万名样本不足：{}", xs.len());
    let rho = spearman(&xs, &ys);
    assert!(
        rho >= 0.70,
        "前 1 万名区间 ρ = {rho:.3}，低于 0.70 基线"
    );
}

/// 两份测试数据必须一致：`tests/data/`（脚本与文档用）与
/// `crates/passmeter-core/tests/data/`（`include_str!` 用）。
/// 用 `make compare` 会同步；若有人只改了一份，这里会失败。
#[test]
fn test_data_copies_are_in_sync() {
    let crate_set = include_str!("data/compare_set.txt");
    let crate_truth = include_str!("data/truth.tsv");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data");
    if root.join("compare_set.txt").exists() {
        let root_set = std::fs::read_to_string(root.join("compare_set.txt")).unwrap();
        assert_eq!(
            crate_set, root_set,
            "tests/data/compare_set.txt 与 crate 内副本不一致，运行 make compare 同步"
        );
        let root_truth = std::fs::read_to_string(root.join("truth.tsv")).unwrap();
        assert_eq!(crate_truth, root_truth, "tests/data/truth.tsv 与 crate 内副本不一致");
    }
}

/// 中英文口令都必须在样本里出现，避免「只对英文有效」的虚假通过。
#[test]
fn comparison_set_covers_chinese() {
    let set = include_str!("data/compare_set.txt");
    let has_cjk = set.chars().any(|c| {
        let cp = c as u32;
        (0x4E00..=0x9FFF).contains(&cp)
    });
    assert!(has_cjk, "对比集里应包含中文样本");
    assert!(set.contains("woaini1314"), "对比集应含拼音样本");
    assert!(set.contains("P@ssw0rd"), "对比集应含 l33t 样本");
}
