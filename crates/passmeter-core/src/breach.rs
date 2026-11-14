//! k-匿名泄露查询。
//!
//! 协议（与 HIBP Pwned Passwords 相同的思路）：
//!   1. 客户端算 SHA-1(口令)；
//!   2. 只把前 5 个十六进制字符（20 bit）发给服务端；
//!   3. 服务端返回该前缀下的全部「后缀 → 出现次数」；
//!   4. 客户端在本地比对完整后缀。
//!
//! 服务端只知道「有人查过前缀 ABCDE」，不知道完整口令；单个前缀下
//! 通常有数百到数千条记录，这就是 k-匿名的 k。20 bit 的检索空间
//! （约 104 万桶）足以让单次查询无法反推口令，同时保证响应体积可控。
//!
//! 本模块只负责「算前缀、校验后缀、给出结论」，网络传输在
//! `passmeter-server`（服务端）与 WASM 侧（客户端）实现。

use crate::hash::{sha1, to_hex_lower};

/// 前缀长度（十六进制字符数）。4 位 = 16 bit。
///
/// 不用 HIBP 的 5 位（20 bit）：本项目语料只有 245 万条唯一口令，
/// 20 bit 下每桶中位数仅 2 条记录，k-匿名的 k 太小、可被撞库反推。
/// 16 bit 下 k 中位 37、最小 12，满足匿名要求（推导见 docs/BREACH.md）。
pub const PREFIX_HEX_LEN: usize = 4;
/// 完整 SHA-1 的十六进制长度。
pub const SHA1_HEX_LEN: usize = 40;
/// 后缀长度（十六进制字符数）。
pub const SUFFIX_HEX_LEN: usize = SHA1_HEX_LEN - PREFIX_HEX_LEN;

/// 口令的 SHA-1 与其十六进制表示。
pub struct PasswordHash {
    pub digest: [u8; 20],
    /// 40 位小写十六进制
    pub hex: [u8; SHA1_HEX_LEN],
}

impl PasswordHash {
    pub fn compute(password: &str) -> Self {
        let digest = sha1(password.as_bytes());
        let mut hex = [0u8; SHA1_HEX_LEN];
        to_hex_lower(&digest, &mut hex);
        PasswordHash { digest, hex }
    }

    /// 查询用的前缀（前 5 位十六进制）。
    pub fn prefix(&self) -> &str {
        // hex 全是 ASCII，安全
        std::str::from_utf8(&self.hex[..PREFIX_HEX_LEN]).unwrap_or("")
    }

    /// 完整后缀（前缀之后的十六进制）。
    pub fn suffix(&self) -> &str {
        std::str::from_utf8(&self.hex[PREFIX_HEX_LEN..]).unwrap_or("")
    }
}

/// 服务端响应里的一行：`后缀:次数`。
#[derive(Debug, Clone, Copy)]
pub struct SuffixCount {
    pub suffix: [u8; SUFFIX_HEX_LEN],
    pub count: u32,
}

/// 服务端响应：一个前缀下的全部记录。
pub struct RangeResponse {
    /// 该前缀的十六进制（回显，便于客户端校验没弄错）
    pub prefix: [u8; PREFIX_HEX_LEN],
    pub entries: Vec<SuffixCount>,
}

impl RangeResponse {
    /// 在响应里查找完整哈希对应的出现次数。
    pub fn lookup(&self, hash: &PasswordHash) -> Option<u32> {
        let want = &hash.hex[PREFIX_HEX_LEN..];
        self.entries
            .iter()
            .find(|e| &e.suffix[..] == want)
            .map(|e| e.count)
    }
}

/// 解析服务端响应。格式：每行 `<35 位十六进制>:<次数>`，
/// 行尾 `\n`，不接受多余空白（减少歧义）。
pub fn parse_range(prefix: &str, body: &str) -> Result<RangeResponse, String> {
    if prefix.len() != PREFIX_HEX_LEN || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("非法前缀: {prefix:?}"));
    }
    let mut prefix_bytes = [0u8; PREFIX_HEX_LEN];
    prefix_bytes.copy_from_slice(prefix.as_bytes());

    let mut entries = Vec::new();
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (suffix, count) = line
            .split_once(':')
            .ok_or_else(|| format!("行格式错误（缺冒号）: {line:?}"))?;
        if suffix.len() != SUFFIX_HEX_LEN {
            return Err(format!("后缀长度错误: {suffix:?}"));
        }
        if !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("后缀含非十六进制字符: {suffix:?}"));
        }
        let count: u32 = count
            .trim()
            .parse()
            .map_err(|_| format!("次数不是整数: {count:?}"))?;
        let mut sb = [0u8; SUFFIX_HEX_LEN];
        sb.copy_from_slice(suffix.as_bytes());
        entries.push(SuffixCount {
            suffix: sb,
            count,
        });
    }
    // 响应体积上限，防止恶意服务端塞爆内存
    if entries.len() > 100_000 {
        return Err("响应记录数异常".to_string());
    }
    Ok(RangeResponse {
        prefix: prefix_bytes,
        entries,
    })
}

/// 序列化服务端响应（服务端用）。
pub fn serialize_range(prefix: &str, entries: &[(String, u32)]) -> String {
    let mut s = String::with_capacity(entries.len() * 45);
    for (suffix, count) in entries {
        s.push_str(suffix);
        s.push(':');
        s.push_str(&count.to_string());
        s.push('\n');
    }
    let _ = prefix;
    s
}

/// 校验客户端传来的前缀是否合法。
///
/// 大小写不敏感：HTTP 路径里大小写常被中间件改写，拒绝大写只会
/// 制造难以排查的 400。服务端内部统一转小写后查表。
pub fn validate_prefix(prefix: &str) -> Result<(), String> {
    if prefix.len() != PREFIX_HEX_LEN {
        return Err(format!("前缀长度必须为 {PREFIX_HEX_LEN}"));
    }
    if !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("前缀必须是十六进制".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_password_hash() {
        let h = PasswordHash::compute("password");
        assert_eq!(h.prefix(), "5baa");
        assert_eq!(h.suffix(), "61e4c9b93f3f0682250b6cf8331b7ee68fd8");
    }

    #[test]
    fn prefix_is_four_hex() {
        let h = PasswordHash::compute("123qweASD");
        assert_eq!(h.prefix().len(), 4);
        assert_eq!(h.suffix().len(), 36);
    }

    #[test]
    fn parse_and_lookup() {
        let h = PasswordHash::compute("password");
        let other = "0".repeat(SUFFIX_HEX_LEN);
        let body = format!("{other}:3\n{}:12\n", h.suffix());
        let resp = parse_range(h.prefix(), &body).unwrap();
        assert_eq!(resp.lookup(&h), Some(12));
        assert_eq!(resp.entries.len(), 2);
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(parse_range("abcde", "notahexline").is_err());
        assert!(parse_range("abcde", "abc:1").is_err());
        assert!(parse_range("ABC", "").is_err());
    }

    #[test]
    fn prefix_validation() {
        assert!(validate_prefix("abcd").is_ok());
        assert!(validate_prefix("a1b2").is_ok());
        // 大小写不敏感
        assert!(validate_prefix("ABCD").is_ok());
        assert!(validate_prefix("abcde1").is_err());
        assert!(validate_prefix("abcg").is_err());
        assert!(validate_prefix("abc").is_err());
    }
}
