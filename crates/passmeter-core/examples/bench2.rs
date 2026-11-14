use passmeter_core::norm::normalize;
use passmeter_core::dictionary::{match_dictionary, match_l33t, match_reversed_dictionary, match_pinyin, Dictionaries};
use passmeter_core::index::{Index, Syllables};
use passmeter_core::repeat::{match_repeat, match_sequence};
use passmeter_core::spatial::{graphs, match_graph};
use passmeter_core::date::match_date;
use std::time::Instant;

fn main() {
    let tier1 = Index::parse(include_bytes!("../../../data/generated/dict1.bin")).unwrap();
    let tier2 = Index::parse(include_bytes!("../../../data/generated/dict2.bin")).unwrap();
    let syl = Syllables::parse(include_bytes!("../../../data/generated/syllables.bin")).unwrap();
    let d = Dictionaries { tier1, tier2: Some(tier2), syllables: Some(syl) };
    let long: String = "abcdefghij1234567890".repeat(10);
    let t = &normalize(&long).text;

    macro_rules! timeit {
        ($name:expr, $body:expr) => {{
            let start = Instant::now();
            let n = 20;
            for _ in 0..n { let _ = $body; }
            println!("{:24} {:>10.2} ms/次", $name, start.elapsed().as_millis() as f64 / n as f64);
        }};
    }
    timeit!("match_dictionary", { let mut o = Vec::new(); match_dictionary(t, &d, &mut o); o.len() });
    timeit!("match_reversed", { let mut o = Vec::new(); match_reversed_dictionary(t, &d, &mut o); o.len() });
    timeit!("match_l33t", { let mut o = Vec::new(); match_l33t(t, &d, &mut o); o.len() });
    timeit!("match_pinyin", { let mut o = Vec::new(); match_pinyin(t, &d, &mut o); o.len() });
    timeit!("spatial", { let mut o = Vec::new(); for g in graphs() { match_graph(t, &g, &mut o); } o.len() });
    timeit!("repeat", { match_repeat(t).len() });
    timeit!("sequence", { match_sequence(t).len() });
    timeit!("date", { match_date(t).len() });
}
