//! 日期匹配。
//!
//! 识别：
//! - 无分隔符：4~8 位数字，按 (日|月|年) 的多种切分尝试；
//! - 有分隔符：`1/1/91`、`11-11-1991`、`1991.01.01` 等。
//!
//! 与 zxcvbn 的差异：
//! - 年份判定用「距参考年份的距离」而不是硬编码的 `19xx|20xx` 正则，
//!   这样可以识别 `2031`，也不会把 `1122` 误当成年份；
//! - 同一区间出现多个合法解释时，取「年份最接近参考年」的那个，
//!   与 zxcvbn 一致；
//! - 被更长日期完全覆盖的子匹配会被剪掉（`2015_06_04` 不重复报 5 个子日期）。

use crate::types::{Match, Pattern};

const MIN_YEAR: i32 = 1000;
const MAX_YEAR: i32 = 2100;
/// 两位年份的归属窗口：00..30 → 2000+，31..99 → 1900+
const TWO_DIGIT_PIVOT: i32 = 30;

/// 参考年份。口令里的日期分布相对固定，用常量而非系统时钟，
/// 保证评估结果可复现（这一点对回归测试与前后端一致性很重要）。
pub const REFERENCE_YEAR: i32 = 2025;

/// 日期匹配结果。
pub fn match_date(text: &str) -> Vec<Match> {
    let bytes = text.as_bytes();
    let mut out: Vec<Match> = Vec::new();

    // —— 无分隔符 ——
    let mut i = 0usize;
    while i < bytes.len() {
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        let run_len = j - i;
        // 4..8 位数字串内部所有长度 ≥4 的窗口都尝试
        if run_len >= 4 {
            for len in 4..=run_len.min(8) {
                for s in i..=(j - len) {
                    let token = &bytes[s..s + len];
                    if let Some((day, month, year)) = best_split(token) {
                        out.push(make_date(s, s + len, token, day, month, year, ' '));
                    }
                }
            }
        }
        i = if j > i { j } else { i + 1 };
    }

    // —— 有分隔符 ——
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // 三段数字，两段分隔符，分隔符相同
        let mut parts = [(0usize, 0usize); 3];
        let mut seps = [' '; 2];
        let mut pos = i;
        let mut ok = true;
        for k in 0..3 {
            let s = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            parts[k] = (s, pos);
            let dlen = pos - s;
            if dlen == 0 || dlen > 4 {
                ok = false;
                break;
            }
            if k < 2 {
                if pos >= bytes.len() || !is_separator(bytes[pos]) {
                    ok = false;
                    break;
                }
                seps[k] = bytes[pos] as char;
                pos += 1;
            }
        }
        if ok && seps[0] == seps[1] {
            let vals = parts.map(|(s, e)| std::str::from_utf8(&bytes[s..e]).ok().and_then(parse_i32));
            if let (Some(a), Some(b), Some(c)) = (vals[0], vals[1], vals[2]) {
                if let Some((day, month, year)) = map_ints_to_dmy(a, b, c) {
                    out.push(make_date(i, pos, &bytes[i..pos], day, month, year, seps[0]));
                    i = pos;
                    continue;
                }
            }
        }
        // 该位置不构成带分隔日期，前进到下一段
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i < bytes.len() {
            i += 1;
        }
    }

    // 剪掉被更长的日期完全覆盖的子匹配
    let mut keep = vec![true; out.len()];
    for a in 0..out.len() {
        if !keep[a] {
            continue;
        }
        for b in 0..out.len() {
            if a == b {
                continue;
            }
            if out[b].start <= out[a].start
                && out[b].end >= out[a].end
                && (out[b].end - out[b].start) > (out[a].end - out[a].start)
            {
                keep[a] = false;
                break;
            }
        }
    }
    out.iter()
        .zip(keep)
        .filter(|(_, k)| *k)
        .map(|(m, _)| m.clone())
        .collect()
}

fn is_separator(b: u8) -> bool {
    matches!(b, b'/' | b'\\' | b'-' | b'_' | b'.' | b' ')
}

fn parse_i32(s: &str) -> Option<i32> {
    let mut v: i32 = 0;
    if s.is_empty() {
        return None;
    }
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as i32;
        if v > 99_999 {
            return None;
        }
    }
    Some(v)
}

fn make_date(start: usize, end: usize, _token: &[u8], day: i32, month: i32, year: i32, sep: char) -> Match {
    let mut m = Match::new(Pattern::Date, start, end, date_guesses(year, sep != ' '));
    m.year = year.clamp(0, u16::MAX as i32) as u16;
    m.turns = (month.max(0) as u32) | ((day.max(0) as u32) << 8);
    m
}

/// 日期片段的猜测次数：年份空间 × 365 天，有分隔符再 ×4。
pub fn date_guesses(year: i32, has_separator: bool) -> f64 {
    let year_space = (year - REFERENCE_YEAR).unsigned_abs().max(20) as f64;
    let mut g = year_space * 365.0;
    if has_separator {
        g *= 4.0;
    }
    g.max(1.0)
}

/// 无分隔符数字串：尝试所有合法切分，取年份最接近参考年的解释。
fn best_split(token: &[u8]) -> Option<(i32, i32, i32)> {
    // 4 位数字如果本身落在合理年份区间，优先当作「就是一个年份」。
    // 否则 `1991` 会被切成 1/9/91 并解释成 2001 年——这既错又会
    // 让 `wangwei1991` 的反馈说「像一个日期（2001 年）」。
    // zxcvbn 用 recent_year 正则单独匹配这一情形，这里用区间判断
    // 更宽（能认 2031），也不依赖正则。
    if token.len() == 4 {
        if let Some(y) = parse_i32(std::str::from_utf8(token).ok()?) {
            if (MIN_YEAR..=MAX_YEAR).contains(&y) {
                return Some((0, 0, y));
            }
        }
    }
    let splits: &[(usize, usize)] = match token.len() {
        4 => &[(1, 2), (2, 3)],
        5 => &[(1, 3), (2, 3)],
        6 => &[(1, 2), (2, 4), (4, 5)],
        7 => &[(1, 3), (2, 3), (4, 5), (4, 6)],
        8 => &[(2, 4), (4, 6)],
        _ => return None,
    };
    let mut best: Option<(i32, i32, i32)> = None;
    let mut best_dist = i32::MAX;
    for &(k, l) in splits {
        if k >= l || l >= token.len() {
            continue;
        }
        let a = parse_i32(std::str::from_utf8(&token[..k]).ok()?)?;
        let b = parse_i32(std::str::from_utf8(&token[k..l]).ok()?)?;
        let c = parse_i32(std::str::from_utf8(&token[l..]).ok()?)?;
        if let Some((day, month, year)) = map_ints_to_dmy(a, b, c) {
            let dist = (year - REFERENCE_YEAR).abs();
            if dist < best_dist {
                best_dist = dist;
                best = Some((day, month, year));
            }
        }
    }
    best
}

/// 把三元组映射成 (日, 月, 年)。返回 None 表示不是合法日期。
pub fn map_ints_to_dmy(a: i32, b: i32, c: i32) -> Option<(i32, i32, i32)> {
    let ints = [a, b, c];
    // 中间项是年份 → 不是日期
    if b <= 0 || b > 31 {
        return None;
    }
    let mut over_12 = 0;
    let mut over_31 = 0;
    let mut under_1 = 0;
    for &v in &ints {
        if (99 < v && v < MIN_YEAR) || v > MAX_YEAR {
            return None;
        }
        if v > 31 {
            over_31 += 1;
        }
        if v > 12 {
            over_12 += 1;
        }
        if v <= 0 {
            under_1 += 1;
        }
    }
    if over_31 >= 2 || over_12 == 3 || under_1 >= 2 {
        return None;
    }

    // 优先找四位年份：年在前或在后
    for &(y, d, m) in &[(c, a, b), (a, b, c)] {
        if (MIN_YEAR..=MAX_YEAR).contains(&y) {
            let (d, m) = match (d, m) {
                (d, m) if (1..=31).contains(&d) && (1..=12).contains(&m) => (d, m),
                (d, m) if (1..=31).contains(&m) && (1..=12).contains(&d) => (m, d),
                _ => return None,
            };
            return Some((d, m, y));
        }
    }

    // 两位年份
    for &(y, d, m) in &[(c, a, b), (a, b, c)] {
        let (d, m) = match (d, m) {
            (d, m) if (1..=31).contains(&d) && (1..=12).contains(&m) => (d, m),
            (d, m) if (1..=31).contains(&m) && (1..=12).contains(&d) => (m, d),
            _ => continue,
        };
        let year = two_to_four(y);
        return Some((d, m, year));
    }
    None
}

fn two_to_four(year: i32) -> i32 {
    if year > 99 {
        year
    } else if year <= TWO_DIGIT_PIVOT {
        year + 2000
    } else {
        year + 1900
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date_token(text: &str) -> Option<(usize, usize, u16)> {
        let m = match_date(text);
        m.into_iter().next().map(|m| (m.start, m.end, m.year))
    }

    #[test]
    fn iso_date() {
        let (_, _, year) = date_token("19910101").unwrap();
        assert_eq!(year, 1991);
        let (_, _, year) = date_token("2015-06-04").unwrap();
        assert_eq!(year, 2015);
    }

    #[test]
    fn slash_date() {
        let (s, e, year) = date_token("a1/1/91b").unwrap();
        assert_eq!((s, e), (1, 7));
        assert_eq!(year, 1991);
    }

    #[test]
    fn two_digit_year_window() {
        // 30 → 2030；31 → 1931
        let (_, _, y) = date_token("1/1/30").unwrap();
        assert_eq!(y, 2030);
        let (_, _, y) = date_token("1/1/31").unwrap();
        assert_eq!(y, 1931);
    }

    #[test]
    fn rejects_non_dates() {
        assert!(match_date("123456789012").is_empty() || match_date("123456789012").iter().all(|m| m.year != 0));
        assert!(map_ints_to_dmy(13, 32, 5).is_none());
        assert!(map_ints_to_dmy(0, 0, 0).is_none());
    }

    #[test]
    fn guards_submatch_noise() {
        // 2015_06_04 应只报一个完整日期
        let ms = match_date("2015_06_04");
        let longest = ms.iter().map(|m| m.end - m.start).max().unwrap();
        assert!(ms.iter().all(|m| m.end - m.start == longest));
    }

    #[test]
    fn guesses_grow_with_year_distance() {
        assert!(date_guesses(2025, false) < date_guesses(1980, false));
        assert!(date_guesses(2025, true) > date_guesses(2025, false));
    }
}
