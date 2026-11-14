use passmeter_core::Evaluator;
use std::io::{self, Read, Write};

fn esc(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn main() {
    let ev = Evaluator::with_embedded_full().unwrap();
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::stdout().lock();
    let mut first = true;
    write!(out, "[").unwrap();
    for line in input.lines() {
        if line.is_empty() { continue; }
        let r = ev.evaluate(line);
        let patterns: Vec<String> = r.sequence.iter()
            .map(|m| format!("\"{}\"", m.pattern.as_str())).collect();
        if !first { write!(out, ",").unwrap(); }
        first = false;
        write!(out, "{{\"password\":\"{}\",\"guesses\":{:e},\"log10\":{:e},\"score\":{},\"patterns\":[{}]}}",
            esc(line), r.guesses, r.guesses_log10, r.score, patterns.join(",")).unwrap();
    }
    write!(out, "]").unwrap();
}
