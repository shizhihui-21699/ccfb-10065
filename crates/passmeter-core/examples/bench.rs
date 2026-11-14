use passmeter_core::Evaluator;
use std::time::Instant;
fn main() {
    let ev = Evaluator::with_embedded_full().unwrap();
    let cases = ["123qweASD","password","P@ssw0rd","woaini1314","zhangwei1991",
        "correcthorsebatterystaple","木星斑马图书馆风铃","Tr0ub4dor&3","qwertyuiop",
        "woshizhangsan","a1b2c3d4e5f6","MyL0ng&Compl3x!Passw0rd#2024","x","a",
        "aaaaaaaaaaaaaaa","2024-01-01T12:00:00","ｐａｓｓｗｏｒｄ","密码密码密码"];
    for pw in cases { let _ = ev.evaluate(pw); }
    let mut total = std::time::Duration::ZERO;
    let n = 3000;
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..n {
        for pw in cases {
            let t = Instant::now();
            let _ = ev.evaluate(pw);
            let e = t.elapsed();
            total += e;
            if e > worst { worst = e; }
        }
    }
    let count = n * cases.len();
    println!("平均 {:.1} µs | 最坏 {:.2} ms | 次数 {}", total.as_micros() as f64 / count as f64, worst.as_secs_f64()*1000.0, count);
    let long: String = "abcdefghij1234567890".repeat(7);
    let t = Instant::now(); let _ = ev.evaluate(&long);
    println!("{} 字节: {:.2} ms", long.len(), t.elapsed().as_secs_f64()*1000.0);
}
