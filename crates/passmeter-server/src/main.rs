//! k-匿名泄露库查询服务。
//!
//! 协议与 HIBP Pwned Passwords 相同：
//!   GET /range/{5位十六进制前缀}
//!   → 200 text/plain，每行 `<35 位后缀>:<出现次数>`
//!
//! 服务端只收到 20 bit 的前缀（约 104 万分之一的口令空间），
//! 单个前缀下通常聚集数百到数千条记录，因此无法据此反推具体口令。
//!
//! 数据来源：rockyou（1430 万条真实泄露口令）经 SHA-1 处理后，
//! 按前缀分桶写入磁盘。构建方式见 `tools/build_breach_db.py`。


use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod routes;
mod timefmt;

use routes::{handle_range, HealthStats};

/// 服务配置。
pub struct Config {
    /// 监听地址
    pub addr: String,
    /// 泄露库目录（含 `bucket_XX/` 子目录）
    pub db_dir: PathBuf,
    /// 静态站点目录（可选）
    pub static_dir: Option<PathBuf>,
    /// 每个前缀返回的最大记录数（防止超大桶拖慢响应）
    pub max_entries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            addr: "127.0.0.1:8787".to_string(),
            db_dir: PathBuf::from("data/generated/breach"),
            static_dir: Some(PathBuf::from("web")),
            max_entries: 5000,
        }
    }
}

fn main() {
    let mut cfg = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => cfg.addr = args.next().expect("--addr 需要一个值"),
            "--db" => cfg.db_dir = PathBuf::from(args.next().expect("--db 需要一个值")),
            "--static" => cfg.static_dir = Some(PathBuf::from(args.next().expect("--static 需要一个值"))),
            "--no-static" => cfg.static_dir = None,
            "--max-entries" => {
                cfg.max_entries = args
                    .next()
                    .expect("--max-entries 需要一个值")
                    .parse()
                    .expect("--max-entries 必须是整数")
            }
            "--help" | "-h" => {
                println!("用法: passmeter-server [--addr 127.0.0.1:8787] [--db 目录] [--static 目录] [--no-static]");
                return;
            }
            other => {
                eprintln!("未知参数: {other}");
                std::process::exit(2);
            }
        }
    }

    if !cfg.db_dir.exists() {
        eprintln!(
            "泄露库目录不存在: {}\n先运行 tools/build_breach_db.py 生成",
            cfg.db_dir.display()
        );
        std::process::exit(1);
    }

    let db = match BreachDb::open(&cfg.db_dir) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("加载泄露库失败（{}）: {e}", cfg.db_dir.display());
            std::process::exit(1);
        }
    };
    let stats = Arc::new(HealthStats::default());
    let listener = match TcpListener::bind(&cfg.addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("无法监听 {}: {e}", cfg.addr);
            std::process::exit(1);
        }
    };
    println!("passmeter 查询服务已启动: http://{}", cfg.addr);
    println!("泄露库: {}", cfg.db_dir.display());
    if let Some(s) = &cfg.static_dir {
        println!("静态站点: {}", s.display());
    }

    let cfg = Arc::new(cfg);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&cfg);
                let stats = Arc::clone(&stats);
                let db = Arc::clone(&db);
                // 简单的每连接一线程：查询服务是 IO 密集且请求极短，
                // 线程池在这里并不划算（引入依赖得不偿失）。
                std::thread::spawn(move || {
                    let _ = serve(stream, &cfg, &stats, &db);
                });
            }
            Err(e) => eprintln!("接受连接失败: {e}"),
        }
    }
}

fn serve(
    mut stream: TcpStream,
    cfg: &Config,
    stats: &HealthStats,
    db: &BreachDb,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let started = Instant::now();

    // 读掉头部，避免客户端因未读完而 reset
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 0 {
        let mut sink = vec![0u8; content_length.min(64 * 1024)];
        let _ = reader.read_exact(&mut sink);
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_response(&mut stream, 400, "text/plain; charset=utf-8", "bad request");
    }
    let method = parts[0];
    let path = parts[1];
    if method != "GET" && method != "HEAD" {
        return write_response(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            "method not allowed",
        );
    }

    let (status, ctype, body, cache) = dispatch(path, cfg, stats, db);
    let _ = timefmt::humanize(0.0); // 保持模块被使用
    stats.record(status, started.elapsed());
    let is_head = method == "HEAD";
    write_response_full(&mut stream, status, ctype, &body, cache, is_head)
}

fn dispatch(
    path: &str,
    cfg: &Config,
    stats: &HealthStats,
    db: &BreachDb,
) -> (u16, &'static str, Vec<u8>, Option<&'static str>) {
    let path = path.split('?').next().unwrap_or(path);
    if path == "/healthz" {
        let body = stats.health_json();
        return (200, "application/json; charset=utf-8", body.into_bytes(), Some("no-store"));
    }
    if path == "/metrics" {
        let body = stats.metrics_text();
        return (200, "text/plain; charset=utf-8", body.into_bytes(), Some("no-store"));
    }
    if let Some(prefix) = path.strip_prefix("/range/") {
        return handle_range(prefix, db, cfg.max_entries);
    }
    // 静态资源
    if let Some(dir) = &cfg.static_dir {
        if let Some((ctype, bytes)) = routes::serve_static(dir, path) {
            return (200, ctype, bytes, Some("no-cache"));
        }
    }
    (404, "text/plain; charset=utf-8", b"not found".to_vec(), None)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &str,
) -> std::io::Result<()> {
    write_response_full(stream, status, ctype, body.as_bytes(), None, false)
}

fn write_response_full(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
    cache: Option<&str>,
    head_only: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(c) = cache {
        head.push_str(&format!("Cache-Control: {c}\r\n"));
    }
    // 查询接口一定不要被中间缓存：响应本身就是敏感信息的聚合
    if ctype.starts_with("text/plain") {
        head.push_str("X-Content-Type-Options: nosniff\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

/// 泄露库的分片文件布局。
///
/// `breach.idx`:  "PMB1" + u32 桶数 + u32 前缀十六进制位数 + 每桶 (u64 offset, u32 len)
/// `breach.bin`:  所有桶按前缀值升序首尾相接
///
/// 之所以不用「一前缀一文件」：实测 95 万个小文件占用 3.6 GB 块空间，
/// 而拼接成单文件后只有 92 MB，且查询只需一次 seek。
pub(crate) struct BreachDb {
    bin: Vec<u8>,
    /// 每桶 (offset, len)，下标即前缀值
    index: Vec<(u64, u32)>,
    hex_len: usize,
}

impl BreachDb {
    pub(crate) fn open(dir: &Path) -> std::io::Result<Self> {
        let mut bin = Vec::new();
        std::fs::File::open(dir.join("breach.bin"))?.read_to_end(&mut bin)?;
        let idx_bytes = std::fs::read(dir.join("breach.idx"))?;
        if idx_bytes.len() < 12 || &idx_bytes[0..4] != b"PMB1" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "breach.idx 魔数不符",
            ));
        }
        let n = u32::from_le_bytes([idx_bytes[4], idx_bytes[5], idx_bytes[6], idx_bytes[7]]) as usize;
        let hex_len = u32::from_le_bytes([idx_bytes[8], idx_bytes[9], idx_bytes[10], idx_bytes[11]]) as usize;
        let need = 12 + n * 12;
        if idx_bytes.len() < need {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "breach.idx 长度不足",
            ));
        }
        let mut index = Vec::with_capacity(n);
        for i in 0..n {
            let off = 12 + i * 12;
            let offset = u64::from_le_bytes(idx_bytes[off..off + 8].try_into().unwrap());
            let len = u32::from_le_bytes(idx_bytes[off + 8..off + 12].try_into().unwrap());
            index.push((offset, len));
        }
        Ok(BreachDb { bin, index, hex_len })
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(bin: Vec<u8>, index: Vec<(u64, u32)>, hex_len: usize) -> Self {
        BreachDb { bin, index, hex_len }
    }

    /// 按前缀（十六进制字符串）取该桶的全部记录文本。
    pub(crate) fn lookup(&self, prefix: &str, max_entries: usize) -> Option<String> {
        if prefix.len() != self.hex_len {
            return None;
        }
        // 大小写不敏感：from_str_radix 对大小写都接受
        let p = usize::from_str_radix(prefix, 16).ok()?;
        let (offset, len) = *self.index.get(p)?;
        let start = offset as usize;
        let end = start.checked_add(len as usize)?;
        if end > self.bin.len() {
            return None;
        }
        let slice = &self.bin[start..end];
        let mut out = String::with_capacity(slice.len());
        let mut count = 0;
        for line in std::str::from_utf8(slice).ok()?.lines() {
            if count >= max_entries {
                break;
            }
            out.push_str(line);
            out.push('\n');
            count += 1;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_path_layout() {
        let dir = Path::new("/tmp/x");
        let p = dir.join("bucket_ab").join("abcde.txt");
        assert!(p.to_string_lossy().ends_with("bucket_ab/abcde.txt"));
    }
}
