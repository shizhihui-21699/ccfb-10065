//! 输入归一化与字符分类。
//!
//! 归一化必须在**字节级**保持「归一化文本 ↔ 原始文本」的位置映射，
//! 因为所有匹配结果都要回指用户在输入框里看到的原文。
//!
//! 做法：只做逐字符的、不改变字节长度语义的折叠——
//! - ASCII 大写 → 小写（1 字节 → 1 字节）
//! - 全角 ASCII（U+FF01..U+FF5E）→ 半角（3 字节 → 1 字节，需要映射表）
//!   实际实现里全角折叠会改变字节数，因此单独维护一份 `orig_offsets`。
//!
//! 为了保持简单且不引入 O(n²)，这里采用「归一化串 + 字节偏移映射表」：
//! `orig_offsets[i]` 是归一化串第 i 字节在原串中对应的字节起点。

/// 归一化结果：折叠后的文本，以及回指原文的偏移表。
#[derive(Debug, Clone)]
pub struct Normalized {
    /// 归一化后的 UTF-8 文本（小写、全角折叠）
    pub text: String,
    /// `orig_offsets[i]` = 归一化串第 i 字节对应原文的字节偏移。
    /// 长度 = `text.len() + 1`，最后一项 = 原文长度。
    pub orig_offsets: Vec<u32>,
}

impl Normalized {
    /// 把归一化串里的区间 [start, end) 映射回原文区间。
    #[inline]
    pub fn map_span(&self, start: usize, end: usize) -> (usize, usize) {
        let s = self.orig_offsets[start.min(self.orig_offsets.len() - 1)] as usize;
        let e = self.orig_offsets[end.min(self.orig_offsets.len() - 1)] as usize;
        (s, e)
    }
}

/// 全角 ASCII 标点/字母数字 → 半角的映射；返回 `None` 表示保持原样。
#[inline]
fn fold_wide(c: char) -> Option<char> {
    let cp = c as u32;
    // 全角 ！ 到 ～ ：U+FF01..U+FF5E 映射到 U+0021..U+007E
    if (0xFF01..=0xFF5E).contains(&cp) {
        return char::from_u32(cp - 0xFF01 + 0x21);
    }
    // 全角空格
    if cp == 0x3000 {
        return Some(' ');
    }
    None
}

/// 归一化：NFKC 的实用子集 + 小写。
///
/// 不做完整 NFKC：完整的 Unicode 归一化会引入很大的表（CJK 兼容汉字的
/// 分解尤其庞大），而口令场景里真正需要折叠的只有全角 ASCII 和大小写。
/// 归一化是「安全检查」的一部分，宁可少折叠也不要把不同字节的两串误判为同一串。
pub fn normalize(input: &str) -> Normalized {
    let mut text = String::with_capacity(input.len());
    let mut offsets = Vec::with_capacity(input.len() + 1);

    for (idx, ch) in input.char_indices() {
        let folded = fold_wide(ch).unwrap_or(ch);
        // 折叠后再统一小写：全角 Ａ 折叠成 'A'，仍需再变 'a'。
        let mapped = if folded.is_ascii_uppercase() {
            folded.to_ascii_lowercase()
        } else {
            folded
        };

        let mut buf = [0u8; 4];
        let s = mapped.encode_utf8(&mut buf);
        for _ in 0..s.len() {
            offsets.push(idx as u32);
        }
        text.push_str(s);
    }
    offsets.push(input.len() as u32);
    Normalized {
        text,
        orig_offsets: offsets,
    }
}

/// 字符类别，用于暴力段的字符空间估计。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CharClasses {
    pub has_lower: bool,
    pub has_upper: bool,
    pub has_digit: bool,
    pub has_symbol: bool,
    pub has_cjk: bool,
}

impl CharClasses {
    /// 该字符集合对应的暴力搜索空间大小（每次尝试的候选数）。
    pub fn cardinality(&self) -> f64 {
        let mut n = 0.0;
        if self.has_lower {
            n += 26.0;
        }
        if self.has_upper {
            n += 26.0;
        }
        if self.has_digit {
            n += 10.0;
        }
        if self.has_symbol {
            n += 33.0;
        }
        if self.has_cjk {
            // 常用汉字约 3500，取保守的 2500；不含生僻字。
            n += 2500.0;
        }
        // 至少要有一个非空类别；纯控制字符等极端情况按 10 处理。
        if n == 0.0 {
            n = 10.0;
        }
        n
    }
}

/// 统计一段文本覆盖的字符类别。`text` 应已归一化。
pub fn classify(text: &str) -> CharClasses {
    let mut c = CharClasses::default();
    for ch in text.chars() {
        if ch.is_ascii_lowercase() {
            c.has_lower = true;
        } else if ch.is_ascii_uppercase() {
            // 归一化后不应出现，但保留以防调用方传入未归一化文本
            c.has_upper = true;
        } else if ch.is_ascii_digit() {
            c.has_digit = true;
        } else if is_cjk(ch) {
            c.has_cjk = true;
        } else {
            c.has_symbol = true;
        }
    }
    c
}

/// 是否为 CJK 统一表意文字（含扩展 A、基本区、兼容区）。
#[inline]
pub fn is_cjk(ch: char) -> bool {
    let cp = ch as u32;
    (0x3400..=0x4DBF).contains(&cp)      // 扩展 A
        || (0x4E00..=0x9FFF).contains(&cp)  // 基本区
        || (0xF900..=0xFAFF).contains(&cp)  // 兼容表意文字
        || (0x20000..=0x2FA1F).contains(&cp) // 扩展 B..F + 兼容补充
}

/// 是否为拼音音节允许的 ASCII 字母。
#[inline]
pub fn is_ascii_alpha(b: u8) -> bool {
    b.is_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_lowercase_keeps_offsets() {
        let n = normalize("AbC");
        assert_eq!(n.text, "abc");
        assert_eq!(n.map_span(0, 3), (0, 3));
    }

    #[test]
    fn wide_chars_fold_and_map_back() {
        // 全角 Ａ（3 字节）→ a（1 字节）
        let n = normalize("Ａb");
        assert_eq!(n.text, "ab");
        // 归一化 [0,1) 应回指原文 [0,3)
        assert_eq!(n.map_span(0, 1), (0, 3));
        assert_eq!(n.map_span(1, 2), (3, 4));
    }

    #[test]
    fn cjk_offsets_are_byte_accurate() {
        let n = normalize("密码abc");
        assert_eq!(n.text, "密码abc");
        // 「密」是 3 字节
        assert_eq!(n.map_span(0, 3), (0, 3));
        assert_eq!(n.map_span(3, 6), (3, 6));
        assert_eq!(n.map_span(6, 9), (6, 9));
    }

    #[test]
    fn classify_mixed() {
        let c = classify("abc123!密码");
        assert!(c.has_lower && c.has_digit && c.has_symbol && c.has_cjk);
        assert!(!c.has_upper);
        assert!((c.cardinality() - (26.0 + 10.0 + 33.0 + 2500.0)).abs() < 1e-9);
    }

    #[test]
    fn empty_input() {
        let n = normalize("");
        assert_eq!(n.text, "");
        assert_eq!(n.map_span(0, 0), (0, 0));
    }
}
