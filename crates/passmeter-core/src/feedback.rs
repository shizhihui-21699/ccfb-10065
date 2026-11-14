//! 反馈文案。
//!
//! 输出分两类：
//! - 总体判断（一两条）：基于总分与最强/最弱片段；
//! - 针对每个片段的改进建议：告诉用户具体哪一段可预测、为什么、怎么改。
//!
//! 文案刻意给出「具体动作」（加两个字、换成语义无关的组合），
//! 而不是泛泛的「请使用更复杂的密码」，因为后者对用户没有信息量。

use crate::types::{Evaluation, Match, Pattern, Source};

/// 一条反馈。
#[derive(Debug, Clone)]
pub struct Advice {
    /// 指向的片段区间；`None` 表示针对整条口令
    pub span: Option<(usize, usize)>,
    /// 简短结论（≤ 30 字）
    pub message: String,
    /// 可执行建议（≤ 60 字）
    pub action: String,
}

/// 生成反馈。
pub fn build_feedback(eval: &Evaluation, password_len: usize) -> Vec<Advice> {
    let mut out = Vec::new();

    // —— 泄露库命中优先级最高 ——
    if let Some(b) = &eval.breach {
        if b.count > 0 {
            out.push(Advice {
                span: None,
                message: format!(
                    "已在公开泄露库中出现 {} 次{}",
                    format_count(b.count),
                    if b.prefix_matched { "（哈希前缀命中）" } else { "" }
                ),
                action: "这条口令必须立刻更换，且任何站点都不要再用".to_string(),
            });
        }
    }

    // —— 逐片段 ——
    for m in &eval.sequence {
        if let Some(a) = advice_for_match(m) {
            out.push(a);
        }
    }

    // —— 总体 ——
    if password_len == 0 {
        out.push(Advice {
            span: None,
            message: "尚未输入口令".to_string(),
            action: "建议使用至少 4 个随机词的短语，例如「木星-斑马-7-图书馆」".to_string(),
        });
        return out;
    }

    match eval.score {
        0 => out.push(Advice {
            span: None,
            message: "整体过弱，几乎立刻会被猜中".to_string(),
            action: "改成攻击者猜不到的短语：4 个互不相关的词 + 1 个符号".to_string(),
        }),
        1 => out.push(Advice {
            span: None,
            message: "整体很弱，可被离线快速破解".to_string(),
            action: "加长到 12 字符以上，并避免用个人信息的变体".to_string(),
        }),
        2 => out.push(Advice {
            span: None,
            message: "中等强度，能挡住不限速的在线猜测".to_string(),
            action: "再加一个词，或把某个词换成不常见但好记的同义词".to_string(),
        }),
        3 => out.push(Advice {
            span: None,
            message: "较强，能挡住常见离线攻击".to_string(),
            action: "若用于重要账号，建议再长两个字符或改用密码管理器".to_string(),
        }),
        _ => out.push(Advice {
            span: None,
            message: "很强".to_string(),
            action: "无需修改；记得为每个站点使用不同口令".to_string(),
        }),
    }

    // 同一片段区间只留一条
    dedupe(&mut out);
    out
}

fn format_count(n: u32) -> String {
    if n >= 1_000_000 {
        format!("{:.1} 百万", n as f64 / 1e6)
    } else if n >= 10_000 {
        format!("{} 万", n / 10_000)
    } else {
        n.to_string()
    }
}

fn advice_for_match(m: &Match) -> Option<Advice> {
    let span = Some((m.start, m.end));
    match m.pattern {
        Pattern::Dictionary => {
            let source = m.source?;
            let (message, action) = match source {
                Source::Pwned => (
                    if m.l33t {
                        "这是把常见口令做了字符替换".to_string()
                    } else if m.reversed {
                        "这是常见口令倒过来写".to_string()
                    } else {
                        format!("这是排行第 {} 的常见口令片段", format_count(m.rank))
                    },
                    "字符替换和倒写都在破解工具的规则里，换成和原词无关的内容".to_string(),
                ),
                Source::ZhPinyin => (
                    if m.reversed {
                        "这是把常用汉语词的拼音倒过来".to_string()
                    } else {
                        "这是常用汉语词的拼音".to_string()
                    },
                    "拼音是最先被尝试的中文素材，换成不含完整词句的组合".to_string(),
                ),
                Source::ZhNames | Source::ZhPinyinName => (
                    "这像是一个中文姓名（或其拼音）".to_string(),
                    "姓名（含拼音）在中文口令里排在最前面，不要用自己和家人的名字".to_string(),
                ),
                Source::ZhWords => (
                    "这是常见中文词汇".to_string(),
                    "常见词会被中文专用词表覆盖，加两个无关的字或换成语短语".to_string(),
                ),
                _ => (
                    format!("这是常见词（{}）", source_label(source)),
                    "常见词容易被字典攻击覆盖，改用不常见但好记的词".to_string(),
                ),
            };
            Some(Advice {
                span,
                message,
                action,
            })
        }
        Pattern::Spatial => Some(Advice {
            span,
            message: format!("这是键盘上的连续走位（换向 {} 次）", m.turns),
            action: "沿着键盘画形状很容易被还原，换成不相邻的键".to_string(),
        }),
        Pattern::Repeat => Some(Advice {
            span,
            message: "这是重复片段".to_string(),
            action: "重复不会增加多少强度，用一个新词替换整段".to_string(),
        }),
        Pattern::Sequence => Some(Advice {
            span,
            message: "这是顺序或等差的字符序列".to_string(),
            action: "序列是最早被尝试的模式之一，改成无序组合".to_string(),
        }),
        Pattern::Date => Some(Advice {
            span,
            message: format!("这像一个日期（年份约 {}）", m.year),
            action: "生日、纪念日是优先猜测目标，换掉或不要单独使用".to_string(),
        }),
        Pattern::ChineseRun => Some(Advice {
            span,
            message: "这段汉字没有命中常见词表，但汉字组合的可猜性高于英文".to_string(),
            action: "换成不含完整词语的短语，或与数字、符号混合".to_string(),
        }),
        Pattern::Bruteforce => None,
    }
}

fn source_label(s: Source) -> &'static str {
    match s {
        Source::EnCommon => "常见英文口令",
        Source::EnWiki => "英文常用词",
        Source::EnNames => "英文人名",
        Source::EnTv => "影视常用词",
        Source::EnZipf => "英文常用词",
        _ => "常见词",
    }
}

fn dedupe(items: &mut Vec<Advice>) {
    let mut seen = std::collections::HashSet::new();
    items.retain(|a| seen.insert((a.span, a.message.clone())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BreachInfo, Match, Pattern};

    fn eval_with(seq: Vec<Match>, score: u8) -> Evaluation {
        Evaluation {
            sequence: seq,
            guesses: 1000.0,
            guesses_log10: 3.0,
            score,
            crack_seconds: [0.0; 4],
            breach: None,
        }
    }

    #[test]
    fn breach_first() {
        let mut e = eval_with(vec![], 2);
        e.breach = Some(BreachInfo {
            count: 12345,
            prefix_matched: true,
        });
        let fb = build_feedback(&e, 8);
        assert!(fb[0].message.contains("泄露库"));
        assert!(fb[0].message.contains("万") || fb[0].message.contains("1.2"));
    }

    #[test]
    fn pinyin_advice() {
        let mut m = Match::new(Pattern::Dictionary, 0, 6, 100.0);
        m.source = Some(Source::ZhPinyin);
        let fb = build_feedback(&eval_with(vec![m], 1), 6);
        assert!(fb.iter().any(|a| a.message.contains("拼音")));
    }

    #[test]
    fn empty_password() {
        let fb = build_feedback(&eval_with(vec![], 0), 0);
        assert!(fb.iter().any(|a| a.message.contains("尚未输入")));
    }
}
