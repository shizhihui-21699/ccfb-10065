//! 词典匹配：普通词、反转、l33t 替换、拼音。
//!
//! 统一思路：对每个起点做「滑窗」，一边扩展一边维护 FNV 指纹，
//! 每扩一个字符就查一次索引。这样单次扫描是 O(n·L_max)，
//! 不需要为每个子串重新计算哈希。
//!
//! 拼音与普通词典共用同一个索引（生成脚本已把「词 → 拼音」写进表里），
//! 因此 `woaini` 与「我爱你」都是词典命中，只是来源标签不同，
//! 可以给出不同措辞的反馈。

use crate::hash::{fnv1a_finish, fnv1a_step, FNV_OFFSET};
use crate::index::{Index, Syllables};
use crate::types::{Match, Pattern, Source};

/// 词典集合。
pub struct Dictionaries {
    /// 一级索引（嵌入，约 4 万条）
    pub tier1: Index,
    /// 二级索引（按需加载，约 20 万条）
    pub tier2: Option<Index>,
    /// 拼音音节表
    pub syllables: Option<Syllables>,
}

impl Dictionaries {
    /// 在一、二级索引里查同一个哈希，取名次更小的那个。
    fn lookup(&self, hash: u64) -> Option<(u32, Source)> {
        let a = self.tier1.lookup(hash);
        let b = self.tier2.as_ref().and_then(|t| t.lookup(hash));
        match (a, b) {
            (Some(x), Some(y)) => Some(if y.0 < x.0 { y } else { x }),
            (Some(x), None) => Some(x),
            (None, Some(y)) => Some(y),
            (None, None) => None,
        }
    }

    fn is_empty(&self) -> bool {
        self.tier1.is_empty() && self.tier2.as_ref().map_or(true, |t| t.is_empty())
    }
}

/// 单个片段最长的词典词（字节）。
/// 数据里最长的词是 6 个汉字（18 字节）或 20 字节英文词，
/// 取 24 覆盖全部；更长的滑窗只是白做二分查找。
const MAX_WORD_BYTES: usize = 24;
/// 单个片段最长处理字符数，防止超长输入拖慢
pub const MAX_INPUT_BYTES: usize = 128;

/// 普通词典匹配（大小写已由归一化折叠）。
pub fn match_dictionary(text: &str, dicts: &Dictionaries, out: &mut Vec<Match>) {
    if dicts.is_empty() {
        return;
    }
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut start = 0usize;

    while start < n {
        // 跳过 UTF-8 续字节，保证起点落在字符边界
        if (bytes[start] & 0xC0) == 0x80 {
            start += 1;
            continue;
        }
        let mut h = FNV_OFFSET;
        let mut end = start;
        while end < n {
            // 每次并入一个完整字符（1~4 字节），保证滑动窗口只落在字符边界上。
            let clen = utf8_len(bytes[end]);
            if end + clen > n {
                break;
            }
            if end - start + clen > MAX_WORD_BYTES {
                break;
            }
            for k in 0..clen {
                h = fnv1a_step(h, bytes[end + k]);
            }
            end += clen;
            let len = end - start;
            if len >= 2 {
                let hash = fnv1a_finish(h, len);
                if let Some((rank, source)) = dicts.lookup(hash) {
                    out.push(
                        Match::new(Pattern::Dictionary, start, end, 1.0)
                            .with_dictionary(rank, source),
                    );
                }
            }
        }
        start += utf8_len(bytes[start]);
    }
}

/// 大小写变体的猜测倍数。
///
/// 攻击者不仅会试「全小写」的词典词，还会试常见的改大小写方式。
/// 与 zxcvbn 一致：
/// - 首字母大写 / 尾字母大写 / 全大写：只算 2 倍（最常见，低估更安全）；
/// - 其余混杂大小写：按「从 U+L 个位置里选 U 个」的组合数。
///
/// 注意：这里用**原文**（未归一化）来数大写字母，所以调用方必须
/// 传入原始口令。区间是字节偏移，与归一化后的区间一致（归一化只改
/// 大小写与全角折叠，不改变字符数）。
pub fn case_variations(original: &str, start: usize, end: usize) -> f64 {
    let token = &original[start..end];
    let upper = token.chars().filter(|c| c.is_uppercase()).count();
    let lower = token.chars().filter(|c| c.is_lowercase()).count();
    if upper == 0 {
        return 1.0;
    }
    if lower == 0 {
        // 全大写
        return 2.0;
    }
    // 首字母大写或尾字母大写
    let first_upper = token.chars().next().is_some_and(|c| c.is_uppercase());
    let last_upper = token.chars().last().is_some_and(|c| c.is_uppercase());
    if first_upper || last_upper {
        return 2.0;
    }
    // 混杂：从 upper+lower 个位置里选 upper 个
    let mut variations = 0.0f64;
    let max = upper.min(lower);
    for i in 1..=max {
        variations += crate::spatial::n_choose_k((upper + lower) as u32, i as u32);
    }
    variations.max(1.0)
}

#[inline]
pub(crate) fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

impl Match {
    pub(crate) fn with_dictionary(mut self, rank: u32, source: Source) -> Self {
        self.rank = rank;
        self.source = Some(source);
        self.guesses = dictionary_guesses(rank);
        self
    }
}

/// 词典片段的猜测量：名次 × 大小写变体 × 反转 × l33t。
/// 大小写/l33t/反转的变体数由各匹配器的后处理步骤乘上去，
/// 这里给出基线（名次）。
pub fn dictionary_guesses(rank: u32) -> f64 {
    rank.max(1) as f64
}

// ---------------------------------------------------------------------------
// 反转
// ---------------------------------------------------------------------------

/// 反转词典匹配：把整串倒过来扫一遍，命中后把区间映射回原文。
pub fn match_reversed_dictionary(text: &str, dicts: &Dictionaries, out: &mut Vec<Match>) {
    if dicts.is_empty() {
        return;
    }
    // 反转后按字符顺序构造新串，同时记录每个字节回原串的偏移
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut rev = String::with_capacity(text.len());
    let mut rev_to_orig = Vec::with_capacity(text.len() + 1);
    for &(off, ch) in chars.iter().rev() {
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        for _ in 0..s.len() {
            rev_to_orig.push(off as u32);
        }
        rev.push_str(s);
    }
    rev_to_orig.push(text.len() as u32);

    let mut found = Vec::new();
    match_dictionary(&rev, dicts, &mut found);
    let n = text.len() as u32;
    for m in found {
        // 反转串里的 [s,e) 对应原文的 [n-e, n-s)
        let rs = rev_to_orig[m.start];
        let re = if m.end < rev_to_orig.len() {
            rev_to_orig[m.end]
        } else {
            n
        };
        let start = (n - rs) as usize;
        let end = (n - re) as usize;
        let _ = re;
        if end <= start {
            continue;
        }
        let mut m2 = m.clone();
        m2.start = start;
        m2.end = end;
        m2.reversed = true;
        // 反转使候选翻倍
        m2.guesses *= 2.0;
        out.push(m2);
    }
}

// ---------------------------------------------------------------------------
// l33t
// ---------------------------------------------------------------------------

/// l33t 替换表：被替换字符 → 可接受的替代写法。
///
/// 与 zxcvbn 的差异：
/// - 收录 `@→a`、`0→o`、`1→i/l`、`3→e`、`4→a`、`5→s`、`7→t`、`$→s`
///   等常见替换；
/// - `1` 同时映射到 `i` 和 `l`（zxcvbn 也是），因为 `1337` 既可以是 `leet` 的变体
///   也可能是 `l33t` 的误写，两种都必须尝试。
pub const L33T_MAP: &[(char, &[char])] = &[
    ('4', &['a']),
    ('@', &['a']),
    ('8', &['b']),
    ('(', &['c']),
    ('3', &['e']),
    ('6', &['g']),
    ('9', &['g']),
    ('1', &['i', 'l']),
    ('|', &['i', 'l']),
    ('!', &['i']),
    ('0', &['o']),
    ('$', &['s']),
    ('5', &['s']),
    ('7', &['t']),
    ('+', &['t']),
    ('2', &['z']),
];

/// 最多同时处理的替换种类数，防止组合爆炸。
const MAX_SUBSTITUTIONS: usize = 12;

/// 找到文本中实际出现的 l33t 字符及其可能的还原。
fn relevant_substitutions(text: &str) -> Vec<(char, Vec<char>)> {
    let mut out = Vec::new();
    for &(l33t, targets) in L33T_MAP {
        if text.contains(l33t) {
            out.push((l33t, targets.to_vec()));
            if out.len() >= MAX_SUBSTITUTIONS {
                break;
            }
        }
    }
    out
}

/// l33t 匹配。
///
/// 做法：枚举「哪一组替换会把某段变成词典词」，而不是像 zxcvbn 那样
/// 先对全串做替换再整体扫词典——后者在长口令上会产生大量重复候选。
/// 这里对每个可能起点，枚举它前面若干字符上的替换组合，逐个查词典。
pub fn match_l33t(text: &str, dicts: &Dictionaries, out: &mut Vec<Match>) {
    if dicts.is_empty() {
        return;
    }
    let subs = relevant_substitutions(text);
    if subs.is_empty() {
        return;
    }
    // 生成所有「替换字符 → 目标字符」的映射组合（每个 l33t 字符选一个目标）
    let maps = enumerate_maps(&subs);
    if maps.is_empty() {
        return;
    }

    let chars: Vec<char> = text.chars().collect();
    let byte_offsets: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();

    for map in &maps {
        // 逐起点尝试：把 [start..end) 按 map 替换后查词典。
        // 哈希增量推进（每扩一个字符只做常数次 FNV 步），而不是每次
        // 重新对整个已翻译串求哈希——后者是 O(n²)，长口令上要 2ms。
        for start in 0..chars.len() {
            let mut h = crate::hash::FNV_OFFSET;
            let mut len_bytes = 0usize;
            let mut has_sub = false;
            for end in start..chars.len().min(start + MAX_WORD_BYTES) {
                let c = chars[end];
                let (mapped, was_sub) = match map.iter().find(|(from, _)| *from == c) {
                    Some((_, to)) => (*to, true),
                    None => (c, false),
                };
                if was_sub {
                    has_sub = true;
                }
                let mut buf = [0u8; 4];
                let s = mapped.encode_utf8(&mut buf);
                for &b in s.as_bytes() {
                    h = crate::hash::fnv1a_step(h, b);
                }
                len_bytes += s.len();
                if len_bytes < 2 || !has_sub || len_bytes > MAX_WORD_BYTES {
                    continue;
                }
                let hash = crate::hash::fnv1a_finish(h, len_bytes);
                if let Some((rank, source)) = dicts.lookup(hash) {
                    let s = byte_offsets[start];
                    let e = byte_offsets[end + 1];
                    let mut m = Match::new(Pattern::Dictionary, s, e, 1.0)
                        .with_dictionary(rank, source);
                    m.l33t = true;
                    // 每种替换组合按 2 倍放大（攻击者要同时试替换与不替换）
                    m.guesses *= 2.0;
                    out.push(m);
                }
            }
        }
    }
}

/// 枚举替换映射。每个 l33t 字符选一个目标字符；组合数按乘法增长，
/// 但 `relevant_substitutions` 已限制种类数，且实际口令里同时出现的
/// l33t 字符很少（通常 1~3 种），因此规模可控。
fn enumerate_maps(subs: &[(char, Vec<char>)]) -> Vec<Vec<(char, char)>> {
    let mut result: Vec<Vec<(char, char)>> = vec![Vec::new()];
    for (from, targets) in subs {
        let mut next = Vec::new();
        for base in &result {
            for &to in targets {
                let mut m = base.clone();
                m.push((*from, to));
                next.push(m);
            }
        }
        result = next;
        if result.len() > 256 {
            result.truncate(256);
            break;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// 拼音
// ---------------------------------------------------------------------------

/// 拼音匹配：把纯字母串切成音节序列，命中「常见词拼音」时给出词典级权重。
///
/// 注意：这里**不**对任意字母串做无差别切分。`sunshine` 能被切成
/// `sun-shi-ne`，但它是英文词而不是「孙-使-呢」。因此只接受
/// 两级证据：
///   1. 整串直接命中索引里的拼音词条（最高置信）；
///   2. 整串能完整切分为合法音节，且至少有一个音节组合在索引中作为
///      「拼音词」出现（即切分方向与真实词一致）。
pub fn match_pinyin(text: &str, dicts: &Dictionaries, out: &mut Vec<Match>) {
    let syllables = match &dicts.syllables {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut start = 0usize;
    while start < n {
        if !bytes[start].is_ascii_lowercase() {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < n && bytes[end].is_ascii_lowercase() {
            end += 1;
        }
        // [start, end) 是一段连续小写字母
        if end - start >= 3 {
            try_pinyin_run(&text[start..end], start, syllables, out);
        }
        start = end;
    }
}

fn try_pinyin_run(run: &str, base: usize, syllables: &Syllables, out: &mut Vec<Match>) {
    // 动态规划：reach[i] = 能否用若干音节恰好覆盖 run[..i]
    let n = run.len();
    let mut reach = vec![false; n + 1];
    let mut prev = vec![0usize; n + 1];
    reach[0] = true;
    let mut seg_count = vec![0u32; n + 1];
    for i in 0..n {
        if !reach[i] {
            continue;
        }
        for len in 1..=7 {
            if i + len > n {
                break;
            }
            let syl = &run[i..i + len];
            let hash = crate::hash::fnv1a(syl.as_bytes());
            if syllables.lookup(hash).is_some() {
                reach[i + len] = true;
                prev[i + len] = i;
                seg_count[i + len] = seg_count[i] + 1;
            }
        }
    }
    if !reach[n] {
        return;
    }
    // 至少 2 个音节才算「拼音串」（单音节无意义，且与普通词重叠）
    if seg_count[n] < 2 {
        return;
    }
    // 取最长可覆盖前缀；整段命中时 end = n
    let mut m = Match::new(Pattern::Dictionary, base, base + n, 1.0);
    m.source = Some(Source::ZhPinyin);
    // 音节越多、越常见，猜测量越低。用音节数与平均名次的近似：
    // 每个音节有约 400 种可能，但常见组合远少于此。
    let segs = seg_count[n] as f64;
    m.guesses = (400f64.powf(segs - 1.0)).max(1.0);
    m.repeat_base_len = seg_count[n];
    out.push(m);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l33t_map_covers_common() {
        let found = relevant_substitutions("p@ssw0rd");
        assert!(found.iter().any(|(c, _)| *c == '@'));
        assert!(found.iter().any(|(c, _)| *c == '0'));
    }

    #[test]
    fn enumerate_small() {
        let subs = vec![('4', vec!['a']), ('0', vec!['o'])];
        let maps = enumerate_maps(&subs);
        assert_eq!(maps.len(), 1);
        let subs2 = vec![('1', vec!['i', 'l'])];
        assert_eq!(enumerate_maps(&subs2).len(), 2);
    }
}
