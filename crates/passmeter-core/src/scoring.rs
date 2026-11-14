//! 最优匹配序列的搜索与总猜测数估计。
//!
//! 这是 zxcvbn 的核心算法：在「覆盖整串、互不重叠」的所有匹配序列里，
//! 找使下列目标函数最小的那一个
//!
//! ```text
//! g = l! · Π guesses_i + D^(l-1)
//! ```
//!
//! 其中 `l` 是序列长度，`D = 10000`。
//! - `l!` 表示攻击者要枚举这 l 个模式的排列顺序；
//! - `D^(l-1)` 表示攻击者会先试完所有长度 < l 的组合。
//!
//! 实现上与 zxcvbn 的差别：
//! - 用扁平 `Vec` 代替对象字典，避免 WASM 里的 HashMap 分配；
//! - 每个状态记录前驱，回溯不再是启发式搜索；
//! - 暴力段用「悬空区间」表示（`last_match == NONE`），
//!   与 zxcvbn 的 bruteforce match 等价但不需要为每个 (i,j) 造对象。

use crate::types::{Match, Pattern};

/// 序列长度每 +1 的附加代价底数
const MIN_GUESSES_BEFORE_GROWING_SEQUENCE: f64 = 10000.0;
/// 单个字符的暴力猜测下限
const MIN_SUBMATCH_GUESSES_SINGLE_CHAR: f64 = 10.0;
/// 多字符片段的暴力猜测下限
const MIN_SUBMATCH_GUESSES_MULTI_CHAR: f64 = 50.0;

/// 最长序列长度上限。口令中极少出现超过 8 段的结构。
const MAX_SEQUENCE_LEN: usize = 8;

/// 暴力段回看窗口（字节）。
/// 超过这个长度的暴力段在最优序列里没有意义：
/// 它意味着「前面若干个模式 + 一大段无模式内容」，而那一大段本身就
/// 等价于整段暴力，且序列更短（少了阶乘与 D^(l-1) 惩罚）。
/// 取 16 足以覆盖「短词 + 长尾」这类真实结构。
const BRUTEFORCE_LOOKBACK: usize = 16;

/// 表示「本状态以暴力段结尾」的哨兵。
const NONE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct State {
    /// 目标函数值 g
    g: f64,
    /// 乘积项 Π guesses
    product: f64,
    /// 末段对应的匹配下标；NONE 表示暴力段
    last_match: u32,
    /// 前驱状态：已覆盖到的字节数 k
    prev_k: u32,
    /// 前驱状态：序列长度 l
    prev_l: u8,
}

/// 搜索最优序列。返回 (最优序列, 总猜测数)。
///
/// `matches` 必须已按 start 升序、且区间落在字符边界上。
pub fn most_guessable_sequence(password_len: usize, matches: &[Match]) -> (Vec<Match>, f64) {
    most_guessable_sequence_with_cardinality(password_len, matches, 10.0)
}

/// 同 [`most_guessable_sequence`]，但暴力段使用给定的字符集大小。
///
/// zxcvbn 固定用 10 作为暴力段基数，这假设「攻击者会优先试词典」。
/// 对中文口令这个假设不成立：常用汉字约 2500~3500 个，纯中文片段的
/// 暴力空间远大于英文。传入真实字符集大小能让 `mima`（词典第 1.8 万名）
/// 这类片段被正确判为「比暴力更可猜」。
pub fn most_guessable_sequence_with_cardinality(
    password_len: usize,
    matches: &[Match],
    cardinality: f64,
) -> (Vec<Match>, f64) {
    let bf = |len: f64| bruteforce_guesses_with_cardinality(len, cardinality);
    if password_len == 0 {
        return (Vec::new(), 1.0);
    }

    // 按结束位置分组
    let mut by_end: Vec<Vec<u32>> = vec![Vec::new(); password_len + 1];
    for (idx, m) in matches.iter().enumerate() {
        if m.end <= password_len && m.start < m.end {
            by_end[m.end].push(idx as u32);
        }
    }

    // states[k][l]：已覆盖 [0,k) 的、长度为 l 的最优序列
    let mut states: Vec<[Option<State>; MAX_SEQUENCE_LEN + 1]> =
        vec![[None; MAX_SEQUENCE_LEN + 1]; password_len + 1];

    for k in 1..=password_len {
        // ——— 暴力段：覆盖 [i, k) ———
        // i = 0：整段暴力
        let bf_all = bf(k as f64);
        consider(
            &mut states,
            k,
            1,
            State {
                g: bf_all,
                product: bf_all,
                last_match: NONE,
                prev_k: 0,
                prev_l: 0,
            },
        );
        for i in 1..k {
            // 剪枝：只需回看有限长度的暴力段。设当前位置 k 之前的某个
            // 状态在 i 处结束，暴力段长度 k-i。当 k-i 超过 BRUTEFORCE_LOOKBACK
            // 时，把这整段当作单段暴力（已在 i=0 处考虑过）总是优于
            // 前面再接更多片段——因为 `bf(len)` 对长段已经足够大，
            // 多段序列还要乘阶乘与 D^(l-1) 惩罚。
            if k - i > BRUTEFORCE_LOOKBACK {
                break;
            }
            let bf_g = bf((k - i) as f64);
            for l in 1..MAX_SEQUENCE_LEN {
                if let Some(prev) = states[i][l] {
                    // 相邻两段暴力可合并，跳过
                    if prev.last_match == NONE {
                        continue;
                    }
                    let product = prev.product * bf_g;
                    let new_l = l + 1;
                    let g = factorial(new_l) * product
                        + MIN_GUESSES_BEFORE_GROWING_SEQUENCE.powi((new_l - 1) as i32);
                    consider(
                        &mut states,
                        k,
                        new_l,
                        State {
                            g,
                            product,
                            last_match: NONE,
                            prev_k: i as u32,
                            prev_l: l as u8,
                        },
                    );
                }
            }
        }

        // ——— 真实匹配 ———
        let ends = by_end[k].clone();
        for idx in ends {
            let m = &matches[idx as usize];
            if m.start == 0 {
                let product = m.guesses;
                consider(
                    &mut states,
                    k,
                    1,
                    State {
                        g: product,
                        product,
                        last_match: idx,
                        prev_k: 0,
                        prev_l: 0,
                    },
                );
            } else {
                for l in 1..MAX_SEQUENCE_LEN {
                    if let Some(prev) = states[m.start][l] {
                        let product = prev.product * m.guesses;
                        let new_l = l + 1;
                        let g = factorial(new_l) * product
                            + MIN_GUESSES_BEFORE_GROWING_SEQUENCE.powi((new_l - 1) as i32);
                        consider(
                            &mut states,
                            k,
                            new_l,
                            State {
                                g,
                                product,
                                last_match: idx,
                                prev_k: m.start as u32,
                                prev_l: l as u8,
                            },
                        );
                    }
                }
            }
        }
    }

    // 终局：取终点处最优
    let mut best_l = 0usize;
    let mut best_g = f64::INFINITY;
    for l in 1..=MAX_SEQUENCE_LEN {
        if let Some(s) = states[password_len][l] {
            if s.g < best_g {
                best_g = s.g;
                best_l = l;
            }
        }
    }
    if best_l == 0 {
        return (Vec::new(), bf(password_len as f64));
    }

    // 回溯
    let mut seq: Vec<Match> = Vec::with_capacity(best_l);
    let mut k = password_len;
    let mut l = best_l;
    while l > 0 {
        let st = match states[k][l] {
            Some(s) => s,
            None => break,
        };
        if st.last_match == NONE {
            let start = st.prev_k as usize;
            seq.push(Match::new(
                Pattern::Bruteforce,
                start,
                k,
                bf((k - start) as f64),
            ));
        } else {
            seq.push(matches[st.last_match as usize].clone());
        }
        k = st.prev_k as usize;
        l = st.prev_l as usize;
    }
    seq.reverse();
    (seq, best_g.max(1.0))
}


fn consider(
    states: &mut [[Option<State>; MAX_SEQUENCE_LEN + 1]],
    k: usize,
    l: usize,
    cand: State,
) {
    if l == 0 || l > MAX_SEQUENCE_LEN || k >= states.len() {
        return;
    }
    // 更短序列若已用更少猜测覆盖同一前缀，当前候选不可能成为全局最优
    for shorter in 1..l {
        if let Some(s) = states[k][shorter] {
            if s.g <= cand.g {
                return;
            }
        }
    }
    match states[k][l] {
        Some(s) if s.g <= cand.g => {}
        _ => states[k][l] = Some(cand),
    }
}

/// 暴力段的猜测次数：10^长度，并按片段长度设下限。
pub fn bruteforce_guesses(token_len: f64) -> f64 {
    bruteforce_guesses_with_cardinality(token_len, 10.0)
}

/// 暴力段猜测次数，使用指定字符集大小作为基数。
pub fn bruteforce_guesses_with_cardinality(token_len: f64, cardinality: f64) -> f64 {
    let card = if cardinality.is_finite() && cardinality >= 2.0 {
        cardinality
    } else {
        10.0
    };
    let mut g = card.powf(token_len);
    if !g.is_finite() {
        g = f64::MAX;
    }
    let min = if token_len <= 1.0 {
        MIN_SUBMATCH_GUESSES_SINGLE_CHAR + 1.0
    } else {
        MIN_SUBMATCH_GUESSES_MULTI_CHAR + 1.0
    };
    g.max(min)
}

/// 对每个匹配应用「最小猜测下限」。
pub fn apply_min_guesses(matches: &mut [Match], password_len: usize) {
    for m in matches.iter_mut() {
        if m.len_bytes() < password_len {
            let min = if m.len_bytes() <= 1 {
                MIN_SUBMATCH_GUESSES_SINGLE_CHAR
            } else {
                MIN_SUBMATCH_GUESSES_MULTI_CHAR
            };
            if m.guesses < min {
                m.guesses = min;
            }
        }
    }
}

/// 阶乘（小整数）。
pub fn factorial(n: usize) -> f64 {
    let mut r = 1.0f64;
    for i in 2..=n {
        r *= i as f64;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password() {
        let (seq, g) = most_guessable_sequence(0, &[]);
        assert!(seq.is_empty());
        assert_eq!(g, 1.0);
    }

    #[test]
    fn pure_bruteforce() {
        let (seq, g) = most_guessable_sequence(5, &[]);
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].pattern, Pattern::Bruteforce);
        assert!((g - 1e5).abs() < 1e-6);
    }

    #[test]
    fn single_match_preferred() {
        let m = Match::new(Pattern::Dictionary, 0, 6, 100.0);
        let (seq, g) = most_guessable_sequence(6, &[m]);
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].pattern, Pattern::Dictionary);
        assert!((g - 100.0).abs() < 1e-9);
    }

    #[test]
    fn two_matches_compose() {
        let a = Match::new(Pattern::Dictionary, 0, 3, 100.0);
        let b = Match::new(Pattern::Date, 3, 7, 365.0);
        let (seq, g) = most_guessable_sequence(7, &[a, b]);
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[0].start, 0);
        assert_eq!(seq[1].end, 7);
        // 2! * 100 * 365 + 10000
        assert!((g - (2.0 * 100.0 * 365.0 + 10000.0)).abs() < 1e-6);
    }

    #[test]
    fn bruteforce_fills_gap() {
        let a = Match::new(Pattern::Dictionary, 0, 2, 100.0);
        let b = Match::new(Pattern::Dictionary, 5, 7, 100.0);
        let (seq, _) = most_guessable_sequence(7, &[a, b]);
        // 中间 [2,5) 应由暴力段填充
        assert!(seq.iter().any(|m| m.pattern == Pattern::Bruteforce));
        let covered: usize = seq.iter().map(|m| m.end - m.start).sum();
        assert_eq!(covered, 7);
    }

    #[test]
    fn factorial_values() {
        assert_eq!(factorial(0), 1.0);
        assert_eq!(factorial(4), 24.0);
    }
}
