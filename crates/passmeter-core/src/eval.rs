//! 评估入口：把归一化、各匹配器、评分、反馈串起来。

use crate::breach::{PasswordHash, PREFIX_HEX_LEN};

/// 前缀的字节数（十六进制长度的一半）。
pub const PREFIX_BYTES: usize = PREFIX_HEX_LEN / 2;
use crate::date::match_date;
use crate::dictionary::{match_dictionary, match_l33t, match_pinyin, match_reversed_dictionary, Dictionaries};
use crate::feedback::{build_feedback, Advice};
use crate::norm::{classify, normalize};
use crate::repeat::{match_repeat, match_sequence};
use crate::scoring::apply_min_guesses;
use crate::spatial::{graphs, match_graph};
use crate::types::{Evaluation, Match, Pattern, SCENARIOS};

/// 评估器。持有词典与音节表。
pub struct Evaluator {
    dicts: Dictionaries,
}

/// 评估结果的完整形态（含反馈与原文区间映射）。
pub struct FullResult {
    /// 面向 UI 的匹配序列，区间已映射回原文
    pub sequence: Vec<Match>,
    pub guesses: f64,
    pub guesses_log10: f64,
    pub score: u8,
    pub crack_seconds: [f64; 4],
    pub breach: Option<crate::types::BreachInfo>,
    pub feedback: Vec<Advice>,
    /// 口令的 SHA-1 前缀（供前端发查询），长度 = `breach::PREFIX_HEX_LEN / 2` 字节
    pub sha1_prefix: [u8; PREFIX_BYTES],
    /// 口令长度（字符数）
    pub char_count: usize,
    /// 字符类别
    pub classes: crate::norm::CharClasses,
}

impl Evaluator {
    /// 用内嵌的一级词典构造。
    pub fn with_embedded() -> Result<Self, String> {
        let tier1 = crate::index::Index::parse(include_bytes!("../../../data/generated/dict1.bin"))?;
        let syllables = crate::index::Syllables::parse(include_bytes!(
            "../../../data/generated/syllables.bin"
        ))
        .ok();
        Ok(Evaluator {
            dicts: Dictionaries {
                tier1,
                tier2: None,
                syllables,
            },
        })
    }

    /// 用内嵌的一级 + 二级词典构造。
    ///
    /// WASM 下二级词典（60 万条、7.8 MB）由前端按需 fetch 后注入，
    /// 以避免首屏加载体积；原生侧（服务端、基准测试、对比脚本）
    /// 直接全部内嵌，保证两种环境行为一致。
    pub fn with_embedded_full() -> Result<Self, String> {
        let mut ev = Self::with_embedded()?;
        let tier2 = crate::index::Index::parse(include_bytes!(
            "../../../data/generated/dict2.bin"
        ))?;
        ev.dicts.tier2 = Some(tier2);
        Ok(ev)
    }

    /// 注入二级词典（WASM 里从 fetch 结果调用）。
    pub fn load_tier2(&mut self, bytes: &'static [u8]) -> Result<(), String> {
        self.dicts.tier2 = Some(crate::index::Index::parse(bytes)?);
        Ok(())
    }

    /// 二级词典是否已加载。
    pub fn has_tier2(&self) -> bool {
        self.dicts.tier2.is_some()
    }

    /// 从外部字节构造（WASM 里由 JS 传入 tier2，或测试里注入小词典）。
    pub fn new(tier1: &'static [u8], tier2: Option<&'static [u8]>, syllables: Option<&'static [u8]>) -> Result<Self, String> {
        let tier1 = crate::index::Index::parse(tier1)?;
        let tier2 = match tier2 {
            Some(b) => Some(crate::index::Index::parse(b)?),
            None => None,
        };
        let syllables = match syllables {
            Some(b) => Some(crate::index::Syllables::parse(b)?),
            None => None,
        };
        Ok(Evaluator {
            dicts: Dictionaries {
                tier1,
                tier2,
                syllables,
            },
        })
    }

    /// 评估一条口令（不含泄露查询）。
    pub fn evaluate(&self, password: &str) -> FullResult {
        let norm = normalize(password);
        let text = &norm.text;
        let classes = classify(text);

        // 超长输入截断，保证耗时上界；口令场景几乎不会超过 256 字节。
        let truncated;
        let text = if text.len() > crate::dictionary::MAX_INPUT_BYTES {
            truncated = truncate_on_char_boundary(text, crate::dictionary::MAX_INPUT_BYTES);
            truncated
        } else {
            text.as_str()
        };

        let mut matches: Vec<Match> = Vec::with_capacity(64);
        // 各匹配器
        match_dictionary(text, &self.dicts, &mut matches);
        match_reversed_dictionary(text, &self.dicts, &mut matches);
        match_l33t(text, &self.dicts, &mut matches);
        match_pinyin(text, &self.dicts, &mut matches);
        for g in graphs() {
            match_graph(text, &g, &mut matches);
        }
        matches.extend(match_repeat(text));
        matches.extend(match_sequence(text));
        matches.extend(match_date(text));
        matches.extend(crate::chinese::match_chinese_run(text));

        // 词典命中要按原文大小写加权：攻击者会同时尝试全小写与常见的
        // 大小写变体。归一化串与原文区间一一对应（见 norm 的偏移表），
        // 因此可以直接用归一化区间去原文里数大写字母。
        apply_case_variations(password, &norm, &mut matches);

        // 重复片段需要递归估值：其猜测数 = 循环节估值 × 重复次数
        resolve_repeats(text, &mut matches, &self.dicts);

        // 排序、去重、应用下限。
        //
        // 去重键是 (区间, 模式)：同一区间可能被普通词典、l33t、反转各命中一次，
        // 只需保留猜测数最小的那个。注意区间不同（`ann` 与 `anniversary`）
        // 绝不能合并——它们是不同的候选，交给 DP 竞争。
        matches.sort_by(|a, b| {
            (a.start, a.end, a.pattern)
                .cmp(&(b.start, b.end, b.pattern))
                .then(
                    a.guesses
                        .partial_cmp(&b.guesses)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
        });
        matches.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.pattern == b.pattern);
        apply_min_guesses(&mut matches, text.len());

        // 暴力段的字符集：用整条口令覆盖的字符类别的并集大小。
        // 对纯中文口令，这会把暴力段从 10^n 提升到 2500^n，
        // 从而让词典命中（哪怕名次数万）成为更优选择。
        let cardinality = classes.cardinality();
        let (mut seq, guesses) =
            crate::scoring::most_guessable_sequence_with_cardinality(text.len(), &matches, cardinality);

        // 把区间从归一化串映射回原文
        for m in seq.iter_mut() {
            let (s, e) = norm.map_span(m.start, m.end);
            m.start = s;
            m.end = e;
        }
        // 原文里的暴力段也需要映射
        for m in seq.iter_mut() {
            if m.pattern == Pattern::Bruteforce && m.start == m.end {
                // 空暴力段不应存在
                m.end = m.start;
            }
        }

        let guesses_log10 = if guesses > 0.0 {
            guesses.log10()
        } else {
            0.0
        };
        let score = Evaluation::score_for(guesses);
        let mut crack_seconds = [0.0f64; 4];
        for (i, s) in SCENARIOS.iter().enumerate() {
            crack_seconds[i] = guesses / s.rate;
        }

        // 反馈基于归一化前的原文长度
        let eval_for_fb = Evaluation {
            sequence: seq.clone(),
            guesses,
            guesses_log10,
            score,
            crack_seconds,
            breach: None,
        };
        let feedback = build_feedback(&eval_for_fb, text.chars().count());

        let hash = PasswordHash::compute(password);
        let mut sha1_prefix = [0u8; PREFIX_BYTES];
        sha1_prefix.copy_from_slice(&hash.digest[..PREFIX_BYTES]);

        FullResult {
            sequence: seq,
            guesses,
            guesses_log10,
            score,
            crack_seconds,
            breach: None,
            feedback,
            sha1_prefix,
            char_count: text.chars().count(),
            classes,
        }
    }

    /// 只算 k-匿名查询所需的前缀（前端用）。
    pub fn hash_prefix(password: &str) -> [u8; PREFIX_BYTES] {
        let h = PasswordHash::compute(password);
        let mut p = [0u8; PREFIX_BYTES];
        p.copy_from_slice(&h.digest[..PREFIX_BYTES]);
        p
    }

    /// 用服务端返回的区间数据填充泄露信息。
    pub fn apply_breach(result: &mut FullResult, password: &str, resp: &crate::breach::RangeResponse) {
        let h = PasswordHash::compute(password);
        if let Some(count) = resp.lookup(&h) {
            if count > 0 {
                let info = crate::types::BreachInfo {
                    count,
                    prefix_matched: true,
                };
                // 泄露命中意味着攻击者可能已直接拿到口令，
                // 猜测数至少等于「在泄露库里枚举到它」的位置。
                result.breach = Some(info);
                let floor = (count.max(1) as f64) * 10.0;
                if result.guesses < floor {
                    result.guesses = floor;
                    result.guesses_log10 = result.guesses.log10();
                    result.score = Evaluation::score_for(result.guesses);
                    for (i, s) in SCENARIOS.iter().enumerate() {
                        result.crack_seconds[i] = result.guesses / s.rate;
                    }
                }
            }
        }
    }
}

fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// 给每个词典命中乘上大小写变体数。
///
/// 归一化会把 `ASD` 折成 `asd`，但攻击者并不知道用户是否全大写——
/// 他必须把「全小写 / 首字母大写 / 全大写 / 混杂」这些变体都试一遍。
/// 不做这一步会显著低估 `Password`、`PASSWORD` 这类口令。
fn apply_case_variations(original: &str, norm: &crate::norm::Normalized, matches: &mut [Match]) {
    for m in matches.iter_mut() {
        if m.pattern != Pattern::Dictionary || m.l33t {
            // l33t 的变体在 l33t 匹配里已经乘过；不必叠加
            continue;
        }
        let (os, oe) = norm.map_span(m.start, m.end);
        if oe <= original.len() && os < oe {
            m.guesses *= crate::dictionary::case_variations(original, os, oe);
        }
    }
}

/// 重复片段：用循环节自身的强度作为基础，再乘重复次数。
///
/// 攻击者的做法是先猜「循环节」，再试它的各种重复长度。因此
/// 基础猜测数应当是「猜中这个循环节」的代价：
/// - 循环节是词典词（如 `password`）→ 用词典名次；
/// - 否则按字符空间完整枚举 `cardinality^len`（不是 `^len/2`，
///   那会严重低估 `34343434` 这类纯数字重复）。
fn resolve_repeats(text: &str, matches: &mut [Match], dicts: &Dictionaries) {
    for m in matches.iter_mut() {
        if m.pattern != Pattern::Repeat {
            continue;
        }
        let base_bytes = m.repeat_base_len as usize;
        if base_bytes == 0 || base_bytes >= m.len_bytes() {
            continue;
        }
        let base = &text[m.start..m.start + base_bytes];
        let repeat_count = (m.len_bytes() / base_bytes) as f64;

        // 先看循环节本身是否是词典词
        let mut base_matches = Vec::new();
        match_dictionary(base, dicts, &mut base_matches);
        let base_guesses = if let Some(best) = base_matches.iter().min_by(|a, b| {
            a.guesses.partial_cmp(&b.guesses).unwrap_or(std::cmp::Ordering::Equal)
        }) {
            best.guesses
        } else {
            let classes = classify(base);
            classes
                .cardinality()
                .powf(base.chars().count() as f64)
        };
        m.guesses = (base_guesses * repeat_count).max(1.0);
        m.repeat_base_len = base_bytes as u32;
    }
}

/// 便捷函数：评估 + 生成哈希前缀。
pub fn evaluate_quick(password: &str) -> (f64, u8, [u8; PREFIX_BYTES]) {
    let ev = Evaluator::with_embedded().expect("内嵌词典损坏");
    let r = ev.evaluate(password);
    (r.guesses, r.score, r.sha1_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_password_is_weak() {
        let ev = Evaluator::with_embedded_full().unwrap();
        let r = ev.evaluate("123qweASD");
        assert!(r.score <= 2, "123qweASD 得分应 ≤2，实际 {}", r.score);
        // 整串在泄露库里排第 1 万名，因此「整串命中」优于「123+asd+走位」的分解；
        // 关键是它被识别为可预测素材，而不是判成强口令。
        assert!(r.guesses < 1e6, "猜测数不应超过百万，实际 {}", r.guesses);
    }

    #[test]
    fn strong_passphrase() {
        let ev = Evaluator::with_embedded_full().unwrap();
        let r = ev.evaluate("木星斑马图书馆风铃");
        assert!(r.guesses > 1e8, "长中文短语应很强，实际 {}", r.guesses);
    }

    #[test]
    fn sequence_offsets_are_contiguous() {
        let ev = Evaluator::with_embedded_full().unwrap();
        for pw in ["abc123def", "password1991", "woaini520"] {
            let r = ev.evaluate(pw);
            let mut pos = 0;
            for m in &r.sequence {
                assert_eq!(m.start, pos, "口令 {pw} 片段不连续: {m:?}");
                pos = m.end;
            }
            assert_eq!(pos, pw.len(), "口令 {pw} 片段未覆盖全串");
        }
    }
}
