//! 中文字符段匹配。
//!
//! 纯中文口令是英文模式（走位、l33t、英文词）覆盖不到的盲区，
//! 若完全交给暴力段，猜测数会按 `2500^字数` 爆炸，得到一个
//! 「强得离谱」的结论。但现实是：中文口令的素材池并不大，
//! 常用字 3500、常用词数万，攻击者会优先用工整的中文词表。
//!
//! 因此这里把连续中文段建模成「按字数增长的字典式枚举」：
//! - 每个字的位置有 `CHINESE_SYLLABLE_SPACE`（常用汉字数）种选择；
//! - 但真实口令不是随机汉字串，而是词的组合，故按 `CHINESE_WORD_BASE^(字数/2)`
//!   估计——两个字大致对应「一个词」的空间。
//!
//! 这个估计器只在**没有任何词典命中**时参与竞争，词典命中永远优先
//! （它的名次来自真实语料，比这个粗估可靠）。

use crate::types::{Match, Pattern};

/// 常用汉字数（GB2312 一级字库 3755，取保守的 3000）
const CHINESE_SYLLABLE_SPACE: f64 = 3000.0;

/// 对每个连续中文段生成一个估计匹配。
pub fn match_chinese_run(text: &str) -> Vec<Match> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        if !crate::norm::is_cjk(chars[i].1) {
            i += 1;
            continue;
        }
        let start_idx = i;
        while i < chars.len() && crate::norm::is_cjk(chars[i].1) {
            i += 1;
        }
        let char_count = i - start_idx;
        if char_count == 0 {
            continue;
        }
        let start = chars[start_idx].0;
        let end = if i < chars.len() {
            chars[i].0
        } else {
            text.len()
        };
        let mut m = Match::new(Pattern::ChineseRun, start, end, 1.0);
        m.guesses = chinese_run_guesses(char_count);
        // 不标 source：这不是真实词典命中，反馈里会走通用「常见词」分支
        m.rank = 0;
        out.push(m);
    }
    out
}

/// 中文段的猜测次数。
///
/// 单字：按常用字空间估计（`3000`）。
/// 多字：假设是「词的组合」，每两个字算一个词，词表规模取 3 万——
/// 即 `30000^(字数/2)`。9 个汉字 → 30000^4.5 ≈ 1.3e20，
/// 仍远低于暴力段 2500^9 ≈ 3.8e30 的荒谬值。
pub fn chinese_run_guesses(char_count: usize) -> f64 {
    if char_count == 0 {
        return 1.0;
    }
    if char_count == 1 {
        return CHINESE_SYLLABLE_SPACE;
    }
    const WORD_SPACE: f64 = 30_000.0;
    let word_units = char_count as f64 / 2.0;
    WORD_SPACE.powf(word_units).max(CHINESE_SYLLABLE_SPACE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_runs() {
        let m = match_chinese_run("abc密码def");
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].start, m[0].end), (3, 9));
    }

    #[test]
    fn guesses_grow_with_length() {
        assert!(chinese_run_guesses(2) < chinese_run_guesses(4));
        assert!(chinese_run_guesses(4) < chinese_run_guesses(9));
    }

    #[test]
    fn single_char() {
        assert_eq!(chinese_run_guesses(1), CHINESE_SYLLABLE_SPACE);
    }
}
