use passmeter_core::Evaluator;
fn main() {
    let ev = Evaluator::with_embedded_full().unwrap();
    for pw in ["wangwei1991","wangwei123","zhangwei","王伟","woaini1314","P@ssw0rd"] {
        let r = ev.evaluate(pw);
        println!("{pw:14} score={} fb={:?}", r.score,
            r.feedback.iter().map(|a| a.message.as_str()).collect::<Vec<_>>());
    }
}
