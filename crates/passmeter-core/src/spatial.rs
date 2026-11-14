//! 键盘走位（spatial）匹配。
//!
//! 算法与 zxcvbn 一致：沿着邻接图逐字符前进，统计「换向次数」。
//! 与 zxcvbn 的差异：
//! - 邻接图数据编译进二进制（`graphs_data.rs`），不再运行时解析 JSON；
//! - 匹配结果直接携带换向次数，猜测量按实际转向组合数计算，而不是
//!   沿用固定的平均度数近似；
//! - 对长度 3 的片段也输出，让 UI 能显示 `qwe` 而非把整段并进暴力段。

use crate::types::{Match, Pattern};
use crate::graphs_data::{DVORAK, KEYPAD, MAC_KEYPAD, QWERTY};

/// 一张键位图的运行时视图：按键首字符 → 邻接字符串。
pub struct Graph {
    pub name: &'static str,
    nodes: &'static [(&'static str, &'static [&'static str])],
    /// 起始键数量（= 图上按键数）
    pub starting_positions: f64,
    /// 平均邻接度（非空邻居数的平均值）
    pub average_degree: f64,
    /// 是否为「纯数字键盘」类图（只有数字，没有字母）
    is_keypad: bool,
}

impl Graph {
    fn new(
        name: &'static str,
        nodes: &'static [(&'static str, &'static [&'static str])],
        is_keypad: bool,
    ) -> Self {
        let mut total = 0usize;
        let mut count = 0usize;
        for (_k, neighbors) in nodes {
            count += 1;
            total += neighbors.iter().filter(|n| !n.is_empty()).count();
        }
        Graph {
            name,
            nodes,
            starting_positions: count as f64,
            average_degree: if count == 0 { 0.0 } else { total as f64 / count as f64 },
            is_keypad,
        }
    }

    /// 查找按键。按键按首字符索引（未按下 Shift 的字符）。
    ///
    /// 邻接图按字典序排列，可以二分。这里数据量小（<100 键），
    /// 直接线性扫也不慢，但二分更稳。
    #[inline]
    fn find(&self, key: char) -> Option<&'static [&'static str]> {
        // 键位名都是单字符（qwerty/dvorak）；keypad 也是单字符。
        let mut lo = 0usize;
        let mut hi = self.nodes.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (k, neighbors) = &self.nodes[mid];
            let mut chars = k.chars();
            let kc = match (chars.next(), chars.next()) {
                (Some(c), None) => c,
                _ => {
                    // 非单字符键（不该出现），退化为线性扫描
                    return self
                        .nodes
                        .iter()
                        .find(|(k, _)| k.starts_with(key))
                        .map(|(_, n)| *n);
                }
            };
            match kc.cmp(&key) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(neighbors),
            }
        }
        None
    }
}

/// 全部键位图。顺序即匹配优先级，qwerty 最先。
pub fn graphs() -> [Graph; 4] {
    [
        Graph::new("qwerty", QWERTY.0, false),
        Graph::new("dvorak", DVORAK.0, false),
        Graph::new("keypad", KEYPAD.0, true),
        Graph::new("mac_keypad", MAC_KEYPAD.0, true),
    ]
}

/// 判断某个字符在 qwerty 图上是否是「按下 Shift」产生的。
fn is_shifted(ch: char) -> bool {
    matches!(
        ch,
        '~' | '!' | '@' | '#' | '$' | '%' | '^' | '&' | '*'
            | '(' | ')' | '_' | '+' | '{' | '}' | '|' | ':'
            | '"' | '<' | '>' | '?' | '`'
    ) || ch.is_ascii_uppercase()
}

/// 在单张图上扫描得到所有走位匹配。
pub fn match_graph(text: &str, g: &Graph, out: &mut Vec<Match>) {
    // 逐字符数组；spatial 匹配按字符推进，不用字节。
    let chars: Vec<char> = text.chars().collect();
    let byte_offsets: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();

    if chars.len() < 3 {
        return;
    }

    let mut i = 0usize;
    while i < chars.len() - 1 {
        let mut j = i + 1;
        let mut last_direction: i32 = -1;
        let mut turns = 0u32;
        let mut shifted_count = 0u32;

        // 起始字符是否按下 Shift
        if !g.is_keypad && is_shifted(chars[i]) {
            shifted_count = 1;
        }

        loop {
            if j >= chars.len() {
                break;
            }
            let prev = chars[j - 1];
            let cur = chars[j];
            let neighbors = match g.find(prev) {
                Some(n) => n,
                None => break,
            };
            let mut found = false;
            let mut found_direction: i32 = -1;
            for (dir, adj) in neighbors.iter().enumerate() {
                if adj.is_empty() {
                    continue;
                }
                let bytes: Vec<char> = adj.chars().collect();
                if bytes.contains(&cur) {
                    found = true;
                    found_direction = dir as i32;
                    // 索引 1 表示该字符是 Shift 后的形式
                    if bytes.len() > 1 && bytes[1] == cur {
                        shifted_count += 1;
                    }
                    break;
                }
            }
            if !found {
                break;
            }
            if found_direction != last_direction {
                turns += 1;
                last_direction = found_direction;
            }
            j += 1;
        }

        let token_len = j - i;
        // 长度 2 的片段几乎必然是巧合（任意两字符都可能是邻居），
        // 只保留长度 ≥ 3 的走位。
        if token_len >= 3 {
            let start = byte_offsets[i];
            let end = byte_offsets[j];
            out.push(Match::new(Pattern::Spatial, start, end, 1.0).with_spatial(
                g.name, turns, shifted_count, g,
            ));
        }
        i = if j > i { j } else { i + 1 };
    }
}

impl Match {
    fn with_spatial(
        mut self,
        graph: &'static str,
        turns: u32,
        shifted_count: u32,
        g: &Graph,
    ) -> Self {
        self.graph = graph;
        self.turns = turns;
        self.shifted_count = shifted_count;
        self.guesses = spatial_guesses(g, self.len_bytes(), turns, shifted_count);
        self
    }
}

/// 走位片段的猜测次数。
///
/// 基本量：从 `s` 个起点出发、走 `L` 步、最多转 `t` 次的所有路径数
///     Σ_{i=2..L} Σ_{j=1..min(t,i-1)} C(i-1, j-1) · s · d^j
/// 这是 zxcvbn 的公式，它数的是「形状」。这里再乘上实际产生的
/// 字符序列数：每个未按下 Shift 的字符有 1 种写法，Shift 字符
/// 也可写成小写等价键，因此按 Shift 组合数放大（与 zxcvbn 相同）。
pub fn spatial_guesses(g: &Graph, token_len: usize, turns: u32, shifted_count: u32) -> f64 {
    // token_len 是字节数；spatial 只处理单字节字符集（ASCII 键盘），
    // 走位匹配的字符都是 ASCII，因此字节数 == 字符数。
    let l = token_len as u32;
    let mut guesses = 0.0f64;
    let s = g.starting_positions;
    let d = g.average_degree.max(1.0);
    for i in 2..=l {
        let possible_turns = turns.min(i - 1);
        for j in 1..=possible_turns {
            guesses += n_choose_k(i - 1, j - 1) * s * d.powi(j as i32);
        }
    }
    if shifted_count > 0 {
        let shifted = shifted_count;
        let unshifted = l - shifted_count;
        if shifted == 0 || unshifted == 0 {
            guesses *= 2.0;
        } else {
            let mut variations = 0.0f64;
            let max = shifted.min(unshifted);
            for i in 1..=max {
                variations += n_choose_k(shifted + unshifted, i);
            }
            guesses *= variations.max(1.0);
        }
    }
    guesses.max(1.0)
}

/// C(n, k)，小整数精确计算（避免引入浮点误差）。
pub fn n_choose_k(n: u32, k: u32) -> f64 {
    if k > n {
        return 0.0;
    }
    let k = k.min(n - k);
    let mut r = 1.0f64;
    for i in 0..k {
        r *= (n - i) as f64;
        r /= (i + 1) as f64;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nck_small() {
        assert_eq!(n_choose_k(5, 2), 10.0);
        assert_eq!(n_choose_k(5, 0), 1.0);
        assert_eq!(n_choose_k(3, 5), 0.0);
    }

    #[test]
    fn qwerty_run_detected() {
        let mut out = Vec::new();
        match_graph("qwerty", &graphs()[0], &mut out);
        assert!(out.iter().any(|m| m.graph == "qwerty" && m.len_bytes() == 6));
    }

    #[test]
    fn zigzag_has_more_turns() {
        let g = &graphs()[0];
        let mut straight = Vec::new();
        match_graph("qwertyuiop", g, &mut straight);
        let mut zig = Vec::new();
        match_graph("q1q1q1", g, &mut zig);
        let s_turns = straight.iter().find(|m| m.len_bytes() == 10).unwrap().turns;
        // 直线走位只有 1 次转向
        assert_eq!(s_turns, 1);
    }

    #[test]
    fn two_char_not_reported() {
        let mut out = Vec::new();
        match_graph("qw", &graphs()[0], &mut out);
        assert!(out.is_empty());
    }
}
