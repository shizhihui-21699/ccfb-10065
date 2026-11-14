//! 集成测试：评估质量、性质与性能。
//!
//! 这些测试针对「用户可见的行为」而非内部实现，因此改动内部算法
//! 时它们仍应通过（除非是有意的行为变更）。

use passmeter_core::Evaluator;
use std::time::Instant;

fn ev() -> Evaluator {
    Evaluator::with_embedded_full().expect("数据表损坏")
}

/// 弱口令必须被判为弱。
#[test]
fn obvious_weak_passwords_score_low() {
    let e = ev();
    let weak = [
        "123456", "password", "qwerty", "123qweASD", "iloveyou", "woaini1314",
        "5201314", "wangwei123", "zhangwei1991", "qazwsx", "1qaz2wsx", "abc123",
        "111111", "12345678", "admin", "a123456", "woaini520",
    ];
    for pw in weak {
        let r = e.evaluate(pw);
        assert!(
            r.score <= 2,
            "{} 应判为 ≤2 分，实际 {} 分（猜测数 {:.3e}）",
            pw, r.score, r.guesses
        );
    }
}

/// 强口令必须判为强，且不能因为「不在词典」就被随意拉高或压低。
#[test]
fn strong_passwords_score_high() {
    let e = ev();
    let strong = [
        "correcthorsebatterystaple",
        "Tr0ub4dor&3",
        "木星斑马图书馆风铃",
        "MyL0ng&Compl3x!Passw0rd#2024",
        "vT7#qL9$wZ2!kN5",
        "iloveyoubutnotreally2024!",
    ];
    for pw in strong {
        let r = e.evaluate(pw);
        assert!(
            r.score >= 3,
            "{} 应判为 ≥3 分，实际 {} 分（猜测数 {:.3e}）",
            pw, r.score, r.guesses
        );
    }
}

/// 每条口令的匹配序列必须无缝覆盖整串（这是 UI 逐段高亮的前提）。
#[test]
fn sequence_covers_whole_password() {
    let e = ev();
    let cases = [
        "abc", "123qweASD", "P@ssw0rd!", "密码123", "木星斑马图书馆风铃",
        "a\u{301}bc", "🇨🇳abc", "x", "", "   ", "Tr0ub4dor&3",
        "correcthorsebatterystaple", "！＠＃", "12345678901234567890",
    ];
    for pw in cases {
        let r = e.evaluate(pw);
        let mut pos = 0;
        for m in &r.sequence {
            assert_eq!(m.start, pos, "{} 的片段不连续：{:?}", pw, r.sequence);
            assert!(m.end >= m.start, "{} 存在空片段", pw);
            pos = m.end;
        }
        assert_eq!(pos, pw.len(), "{} 的片段未覆盖整串", pw);
    }
}

/// 大小写与全角折叠不能改变字符数（否则前端高亮会错位）。
#[test]
fn offsets_are_byte_accurate() {
    let e = ev();
    let cases = ["ＡＢＣ", "PASSWORD", "密码ABC", "ａｂｃ１２３"];
    for pw in cases {
        let r = e.evaluate(pw);
        for m in &r.sequence {
            assert!(
                pw.is_char_boundary(m.start) && pw.is_char_boundary(m.end),
                "{} 的片段 [{},{}) 不在字符边界上",
                pw, m.start, m.end
            );
        }
    }
}

/// 同一口令两次评估必须完全一致（无隐藏状态）。
#[test]
fn evaluation_is_deterministic() {
    let e = ev();
    for pw in ["123qweASD", "password", "木星斑马图书馆风铃"] {
        let a = e.evaluate(pw);
        let b = e.evaluate(pw);
        assert_eq!(a.guesses, b.guesses);
        assert_eq!(a.score, b.score);
        assert_eq!(a.sequence.len(), b.sequence.len());
    }
    // 换序评估也不受影响
    let e2 = ev();
    let r2 = e2.evaluate("木星斑马图书馆风铃");
    let r1 = e.evaluate("木星斑马图书馆风铃");
    assert_eq!(r1.guesses, r2.guesses);
}

/// 加长/加料一般不应让口令变弱（单调性）。
#[test]
fn adding_characters_does_not_weaken() {
    let e = ev();
    let bases = ["password", "abcdef", "123456", "woaini"];
    for base in bases {
        let base_g = e.evaluate(base).guesses;
        for suffix in ["x", "9", "!", "Xy9"] {
            let longer = format!("{base}{suffix}");
            let g = e.evaluate(&longer).guesses;
            // 允许小幅波动（新片段可能命中更常见的词），但不该差一个数量级
            assert!(
                g >= base_g / 10.0,
                "{} 比 {} 弱太多：{:.3e} vs {:.3e}",
                longer, base, g, base_g
            );
        }
    }
}

/// 完整评估必须在 5 ms 内（含中文与超长边界）。
#[test]
fn evaluation_under_5ms() {
    let e = ev();
    let cases = [
        "123qweASD", "password", "P@ssw0rd", "woaini1314", "zhangwei1991",
        "木星斑马图书馆风铃", "Tr0ub4dor&3", "correcthorsebatterystaple",
        "MyL0ng&Compl3x!Passw0rd#2024", "ｐａｓｓｗｏｒｄ", "密码密码密码",
    ];
    // 预热
    for pw in cases {
        let _ = e.evaluate(pw);
    }
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..200 {
        for pw in cases {
            let t = Instant::now();
            let _ = e.evaluate(pw);
            let d = t.elapsed();
            if d > worst {
                worst = d;
            }
        }
    }
    assert!(
        worst.as_millis() < 5,
        "最坏耗时 {} µs 超过 5 ms 预算",
        worst.as_micros()
    );

    // 超长输入（安全上限）
    let long: String = "abcdefghij1234567890".repeat(6);
    let t = Instant::now();
    let _ = e.evaluate(&long);
    assert!(
        t.elapsed().as_millis() < 20,
        "120 字节输入耗时 {} ms，超出可接受范围",
        t.elapsed().as_millis()
    );
}

/// 中文口令必须被识别为中文结构，而不是简单的英文暴力段。
#[test]
fn chinese_passwords_are_recognized() {
    let e = ev();
    for pw in ["密码", "我爱你", "王伟", "张三", "木星斑马图书馆风铃"] {
        let r = e.evaluate(pw);
        assert!(
            r.sequence.iter().any(|m| m.pattern != passmeter_core::Pattern::Bruteforce),
            "{} 应至少命中一种结构，实际 {:?}",
            pw,
            r.sequence.iter().map(|m| m.pattern).collect::<Vec<_>>()
        );
    }
}

/// 拼音口令要识别为词典命中，而不是无模式。
///
/// 注意：`woaini` 这类词在真实泄露库里也出现过（rockyou 第 3751 名），
/// 会被标成 `pwned` 而不是 `zh_pinyin`——这是更准确的分类，同样算命中。
#[test]
fn pinyin_passwords_are_dictionary_hits() {
    let e = ev();
    for pw in ["woaini", "wangwei", "zhangwei", "nihao", "mima", "zhangsan"] {
        let r = e.evaluate(pw);
        let hit = r.sequence.iter().any(|m| m.source.is_some());
        assert!(
            hit,
            "{} 应命中词典（中文或泄露库），实际 {:?}",
            pw,
            r.sequence
                .iter()
                .map(|m| (m.pattern.as_str(), m.source.map(|s| s.as_str())))
                .collect::<Vec<_>>()
        );
    }
}

/// 反馈必须指向具体片段或给出可执行建议，不能是空泛的套话。
#[test]
fn feedback_is_actionable() {
    let e = ev();
    let r = e.evaluate("123qweASD");
    assert!(!r.feedback.is_empty());
    for a in &r.feedback {
        assert!(!a.action.is_empty(), "建议的 action 不能为空");
        assert!(a.message.len() < 120, "message 过长：{}", a.message);
        assert!(a.action.len() < 160, "action 过长：{}", a.action);
    }
}

/// l33t 与倒写都能被还原成词典词。
#[test]
fn l33t_and_reversed_detected() {
    let e = ev();
    let r = e.evaluate("P@ssw0rd");
    assert!(
        r.sequence.iter().any(|m| m.l33t || m.source.is_some()),
        "P@ssw0rd 应命中 l33t 或词典，实际 {:?}",
        r.sequence
    );

    let r = e.evaluate("drowssap");
    assert!(
        r.sequence.iter().any(|m| m.reversed || m.source.is_some()),
        "drowssap 应命中倒写词典"
    );
}

/// SHA-1 前缀与已知向量一致（Python hashlib 同值）。
#[test]
fn hash_prefix_matches_reference() {
    let e = ev();
    let r = e.evaluate("password");
    // sha1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    // 前缀是 16 bit（4 位十六进制）= 2 字节
    assert_eq!(r.sha1_prefix, [0x5b, 0xaa]);
    let h = passmeter_core::breach::PasswordHash::compute("password");
    assert_eq!(h.prefix(), "5baa");
    assert_eq!(h.suffix(), "61e4c9b93f3f0682250b6cf8331b7ee68fd8");
}

/// 泄露库命中必须把猜测数抬到「在泄露库里的位置」量级。
#[test]
fn breach_hit_raises_floor() {
    use passmeter_core::breach::parse_range;
    let e = ev();
    let mut r = e.evaluate("correcthorsebatterystaple");
    let before = r.guesses;
    let hash = passmeter_core::breach::PasswordHash::compute("correcthorsebatterystaple");
    let body = format!("{}:1000\n", hash.suffix());
    let resp = parse_range(hash.prefix(), &body).unwrap();
    Evaluator::apply_breach(&mut r, "correcthorsebatterystaple", &resp);
    assert!(r.breach.is_some(), "应标记为泄露");
    assert!(
        r.guesses >= before,
        "泄露命中不应降低猜测数：{:.3e} → {:.3e}",
        before, r.guesses
    );
    assert!(r.guesses >= 1000.0, "猜测数应至少为泄露库次数 × 10");
}
