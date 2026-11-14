//! 路由处理：`/range/{prefix}` 与静态资源。

use crate::BreachDb;
use passmeter_core::breach::validate_prefix;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// 运行统计，供 /healthz 与 /metrics 使用。
#[derive(Default)]
pub struct HealthStats {
    pub requests: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub errors: AtomicU64,
    pub total_micros: AtomicU64,
}

impl HealthStats {
    pub fn record(&self, status: u16, elapsed: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        match status {
            200 => {
                self.hits.fetch_add(1, Ordering::Relaxed);
            }
            404 => {
                self.misses.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {}
            _ => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn health_json(&self) -> String {
        let req = self.requests.load(Ordering::Relaxed);
        let avg_us = self
            .total_micros
            .load(Ordering::Relaxed)
            .checked_div(req)
            .unwrap_or(0);
        format!(
            "{{\"status\":\"ok\",\"requests\":{req},\"hits\":{},\"misses\":{},\"errors\":{},\"avg_micros\":{avg_us}}}",
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }

    pub fn metrics_text(&self) -> String {
        format!(
            "# HELP passmeter_requests_total 查询请求总数\n\
             # TYPE passmeter_requests_total counter\n\
             passmeter_requests_total {}\n\
             # TYPE passmeter_hits_total counter\n\
             passmeter_hits_total {}\n\
             # TYPE passmeter_misses_total counter\n\
             passmeter_misses_total {}\n\
             # TYPE passmeter_errors_total counter\n\
             passmeter_errors_total {}\n",
            self.requests.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}

/// 处理 `/range/{prefix}`。
pub fn handle_range(
    prefix: &str,
    db: &BreachDb,
    max_entries: usize,
) -> (u16, &'static str, Vec<u8>, Option<&'static str>) {
    if let Err(msg) = validate_prefix(prefix) {
        return (
            400,
            "text/plain; charset=utf-8",
            format!("{msg}\n").into_bytes(),
            Some("no-store"),
        );
    }
    match db.lookup(prefix, max_entries) {
        Some(body) => (
            200,
            "text/plain; charset=utf-8",
            body.into_bytes(),
            // 桶内容基本不变，允许短缓存以减轻重复查询
            Some("public, max-age=300"),
        ),
        None => (
            200,
            "text/plain; charset=utf-8",
            Vec::new(),
            Some("public, max-age=300"),
        ),
    }
}

/// 静态资源。返回 (Content-Type, 内容)。
pub fn serve_static(dir: &Path, path: &str) -> Option<(&'static str, Vec<u8>)> {
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() || rel == "index.html" {
        "index.html"
    } else {
        rel
    };
    // 防目录穿越：拒绝 `..` 与绝对路径
    if rel.contains("..") || rel.starts_with('/') || rel.contains('\\') {
        return None;
    }
    let full: PathBuf = dir.join(rel);
    let bytes = std::fs::read(&full).ok()?;
    let ctype = match full.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json; charset=utf-8",
        Some("bin") => "application/octet-stream",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    Some((ctype, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal() {
        let dir = Path::new("/tmp");
        assert!(serve_static(dir, "/../etc/passwd").is_none());
        assert!(serve_static(dir, "/a/../../etc/passwd").is_none());
    }

    fn build_test_db() -> std::sync::Arc<BreachDb> {
        // 4 位前缀（16 bit）。index[p] = (该桶起点 offset, 该桶字节数)
        // '0000' → "AAAA:7\n"（7 字节）
        // '0001' → "BBBB:1\nCCCC:2\n"（16 字节）
        // 其余前缀 → 空桶
        let p0 = b"AAAA:7\n";
        let p1 = b"BBBB:1\nCCCC:2\n";
        let mut bin = Vec::new();
        bin.extend_from_slice(p0);
        bin.extend_from_slice(p1);
        let mut index = Vec::new();
        index.push((0u64, p0.len() as u32)); // '0000'
        index.push((p0.len() as u64, p1.len() as u32)); // '0001'
        std::sync::Arc::new(BreachDb::from_test_parts(bin, index, 4))
    }

    #[test]
    fn range_rejects_bad_prefix() {
        let db = build_test_db();
        assert_eq!(handle_range("XYZ", &db, 100).0, 400);
        assert_eq!(handle_range("ABCDE", &db, 100).0, 400);
        assert_eq!(handle_range("abc", &db, 100).0, 400);
        // 大写是合法的：HTTP 路径大小写常被中间件改写。
        // 该前缀没有数据，但请求本身有效 → 200 空响应。
        assert_eq!(handle_range("ABCD", &db, 100).0, 200);
    }

    #[test]
    fn range_rejects_short_prefix() {
        let db = build_test_db();
        assert_eq!(handle_range("1", &db, 100).0, 400);
    }

    #[test]
    fn range_reads_bucket() {
        let db = build_test_db();
        let (status, _ct, body, _cache) = handle_range("0001", &db, 100);
        assert_eq!(status, 200);
        assert!(String::from_utf8_lossy(&body).contains(":2"));
        let (status, _ct, body, _cache) = handle_range("0000", &db, 100);
        assert_eq!(status, 200);
        assert!(String::from_utf8_lossy(&body).contains(":7"));
        // 无数据但合法的前缀（索引里没有这一项）
        let (status, _ct, body, _cache) = handle_range("0002", &db, 100);
        assert_eq!(status, 200);
        assert!(body.is_empty());
        let (status, _ct, body, _cache) = handle_range("ffff", &db, 100);
        assert_eq!(status, 200);
        assert!(body.is_empty());
    }

    #[test]
    fn metrics_format() {
        let s = HealthStats::default();
        s.record(200, Duration::from_micros(10));
        let t = s.metrics_text();
        assert!(t.contains("passmeter_requests_total 1"));
        assert!(t.contains("passmeter_hits_total 1"));
    }
}
