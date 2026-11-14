use passmeter_core::Evaluator;
fn main() {
    let ev = Evaluator::with_embedded().unwrap();
    let cases = [
        "123qweASD", "123qwe", "password", "P@ssw0rd", "woaini1314", "woaini520",
        "wangwei123", "zhangwei1991", "5201314", "qwertyuiop", "qazwsx",
        "abcdef", "aaa111", "iloveyou", "p@ssw0rd!", "mima123",
        "woshizhangsan", "123456789", "1qaz2wsx", "qwedcxza",
        "correcthorsebatterystaple", "木星斑马图书馆风铃", "Tr0ub4dor&3",
        "password1991", "wangwei1991", "abcdefg123456",
    ];
    for pw in cases {
        let r = ev.evaluate(pw);
        let seq: Vec<String> = r.sequence.iter().map(|m| {
            let tok = &pw[m.start..m.end];
            format!("{}({tok:?} g={:.0} src={:?})", m.pattern.as_str(), m.guesses, m.source.map(|s| s.as_str()))
        }).collect();
        println!("{pw:28} score={} guesses={:12.3e} log10={:5.2} | {}", r.score, r.guesses, r.guesses_log10, seq.join(" + "));
    }
}
