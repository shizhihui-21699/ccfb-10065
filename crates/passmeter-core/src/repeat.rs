//! 重复与序列匹配。
//!
//! 两者都是「结构型」模式，不依赖词典：
//! - 重复：`aaa`、`abcabcabc`、`aabaab`。识别最短循环节，按循环节内容
//!   递归估值，再乘以重复次数。
//! - 序列：`abcd`、`13579`、`zyx`、`9753`。按码点差值的稳定性识别，
//!   允许步长 1..5（因此 `9753` 也算序列）。

use crate::types::{Match, Pattern};

/// 重复匹配。
///
/// 只有在「基串真的重复了至少两次」时才算重复。判定写成
/// `text[i..i+base] == text[i+base..i+2base]`，而不是只看长度——
/// 早期版本漏了这个比较，导致任意长串都被当成重复，并把真实
/// 词典命中挤出最优序列。
pub fn match_repeat(text: &str) -> Vec<Match> {
    let chars: Vec<char> = text.chars().collect();
    let byte_offsets: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut start = 0usize;

    while start < n {
        // 对每个可能的基串长度，向前贪心扩展重复次数
        let mut best: Option<(usize, usize)> = None; // (base_len, total_len)
        for base_len in 1..=(n - start) / 2 {
            if !region_equals(&chars, start, start + base_len, base_len) {
                continue;
            }
            let mut total = base_len * 2;
            while start + total + base_len <= n
                && region_equals(&chars, start, start + total, base_len)
            {
                total += base_len;
            }
            // 取「覆盖最长」的方案；同长时取更短的基串（aaa 的基串是 a 而不是 aa）
            if best.map_or(true, |(bl, t)| total > t || (total == t && base_len < bl)) {
                best = Some((base_len, total));
            }
        }
        match best {
            Some((base_len, total)) => {
                // total 已经是 base_len 的整数倍且 ≥ 2 倍
                let mut m = Match::new(
                    Pattern::Repeat,
                    byte_offsets[start],
                    byte_offsets[start + total],
                    1.0,
                );
                m.repeat_base_len =
                    (byte_offsets[start + base_len] - byte_offsets[start]) as u32;
                out.push(m);
                start += total;
            }
            None => start += 1,
        }
    }
    out
}

/// `chars[a..a+len]` 是否等于 `chars[b..b+len]`。越界返回 false。
fn region_equals(chars: &[char], a: usize, b: usize, len: usize) -> bool {
    if a + len > chars.len() || b + len > chars.len() {
        return false;
    }
    chars[a..a + len] == chars[b..b + len]
}

/// 序列匹配：连续字符的码点差恒定为 `delta`，且 `1 <= |delta| <= 5`。
pub fn match_sequence(text: &str) -> Vec<Match> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < 2 {
        return Vec::new();
    }
    let byte_offsets: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();

    let mut out = Vec::new();
    let mut i = 0usize;
    let mut last_delta: i64 = i64::MIN;

    for k in 1..chars.len() {
        let delta = chars[k] as i64 - chars[k - 1] as i64;
        if last_delta == i64::MIN {
            last_delta = delta;
        }
        if delta == last_delta {
            continue;
        }
        // 序列在此中断，结算 [i, k-1]
        push_sequence(&mut out, &chars, &byte_offsets, i, k - 1, last_delta);
        i = k - 1;
        last_delta = delta;
    }
    push_sequence(&mut out, &chars, &byte_offsets, i, chars.len() - 1, last_delta);
    out
}

fn push_sequence(
    out: &mut Vec<Match>,
    chars: &[char],
    byte_offsets: &[usize],
    i: usize,
    j: usize,
    delta: i64,
) {
    let len = j - i + 1;
    // 长度 2 且步长为 1 的（ab、12）噪声太大；长度 ≥ 3 才收
    if len < 3 || delta == 0 || delta.abs() > 5 {
        return;
    }
    // 只接受同类字符（全数字、全小写字母、全大写字母）
    let all_digit = chars[i..=j].iter().all(|c| c.is_ascii_digit());
    let all_lower = chars[i..=j].iter().all(|c| c.is_ascii_lowercase());
    let all_upper = chars[i..=j].iter().all(|c| c.is_ascii_uppercase());
    if !(all_digit || all_lower || all_upper) {
        return;
    }
    let start = byte_offsets[i];
    let end = byte_offsets[j + 1];
    let ascending = delta > 0;
    let first = chars[i];
    out.push(
        Match::new(Pattern::Sequence, start, end, 1.0)
            .with_sequence(ascending, len, all_digit, first),
    );
}

impl Match {
    fn with_sequence(mut self, ascending: bool, len: usize, all_digit: bool, first: char) -> Self {
        // 与 zxcvbn 一致：常见起点（a/A/z/Z/0/1/9）只算 4 种，
        // 数字起点 10 种，字母 26 种。降序再乘 2。
        let base = if matches!(first, 'a' | 'A' | 'z' | 'Z' | '0' | '1' | '9') {
            4.0
        } else if all_digit {
            10.0
        } else {
            26.0
        };
        let direction = if ascending { 1.0 } else { 2.0 };
        self.guesses = (base * direction * len as f64).max(1.0);
        self.turns = if ascending { 1 } else { 0 };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_aaa() {
        let m = match_repeat("aaa");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].len_bytes(), 3);
        assert_eq!(m[0].repeat_base_len, 1);
    }

    #[test]
    fn repeat_abcabcabc_base_is_abc() {
        let m = match_repeat("abcabcabc");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].repeat_base_len, 3);
    }

    #[test]
    fn repeat_aabaab_greedy() {
        // aabaab：基串 aab，重复 2 次
        let m = match_repeat("aabaab");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].repeat_base_len, 3);
    }

    #[test]
    fn sequence_ascending() {
        let m = match_sequence("abcdef");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].len_bytes(), 6);
    }

    #[test]
    fn sequence_step2() {
        let m = match_sequence("13579");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn sequence_rejects_mixed_classes() {
        assert!(match_sequence("ab12cd").is_empty());
    }
}
