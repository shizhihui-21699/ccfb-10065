//! 词典索引的运行时表示。
//!
//! 数据由 `tools/build_data.py` 生成，格式见该脚本头部注释。
//! 一篇 13 字节：u64 哈希 | u32 名次 | u8 来源。按哈希升序，二分查找。

use crate::types::Source;

/// 一条词典记录。
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub hash: u64,
    pub rank: u32,
    pub source: Source,
}

const HEADER_LEN: usize = 8;
const RECORD_LEN: usize = 13;

/// 一个已解析的词典索引。
#[derive(Clone)]
pub struct Index {
    /// 原始字节（`dict1.bin` / `dict2.bin` 的内容）
    bytes: &'static [u8],
    /// 记录条数
    len: usize,
}

impl Index {
    /// 解析索引。格式错误返回 `Err`，带上足够的诊断信息。
    pub fn parse(bytes: &'static [u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_LEN {
            return Err("词典索引过短".into());
        }
        if &bytes[0..4] != b"PMD1" {
            return Err(format!("词典索引魔数不符: {:?}", &bytes[0..4]));
        }
        let n = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let expect = HEADER_LEN + n * RECORD_LEN;
        if bytes.len() != expect {
            return Err(format!(
                "词典索引长度不符: 声明 {n} 条应为 {expect} 字节，实际 {}",
                bytes.len()
            ));
        }
        Ok(Index { bytes, len: n })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn record(&self, i: usize) -> (u64, u32, u8) {
        let off = HEADER_LEN + i * RECORD_LEN;
        let b = &self.bytes[off..off + RECORD_LEN];
        let hash = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let rank = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        (hash, rank, b[12])
    }

    /// 查找哈希对应的记录。二分。
    pub fn lookup(&self, hash: u64) -> Option<(u32, Source)> {
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (h, rank, src) = self.record(mid);
            match h.cmp(&hash) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    // 理论上无重复哈希；万一有，取名次更小的
                    let mut best = (rank, src);
                    let mut i = mid;
                    while i > 0 {
                        i -= 1;
                        let (h2, r2, s2) = self.record(i);
                        if h2 != hash {
                            break;
                        }
                        if r2 < best.0 {
                            best = (r2, s2);
                        }
                    }
                    let mut i = mid + 1;
                    while i < self.len {
                        let (h2, r2, s2) = self.record(i);
                        if h2 != hash {
                            break;
                        }
                        if r2 < best.0 {
                            best = (r2, s2);
                        }
                        i += 1;
                    }
                    return Some((best.0, Source::from_u8(best.1)?));
                }
            }
        }
        None
    }
}

/// 拼音音节表。哈希升序，名次表示该音节的常见度。
#[derive(Clone)]
pub struct Syllables {
    bytes: &'static [u8],
    len: usize,
}

impl Syllables {
    pub fn parse(bytes: &'static [u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_LEN || &bytes[0..4] != b"PMS1" {
            return Err("音节表格式错误".into());
        }
        let n = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let expect = HEADER_LEN + n * 12;
        if bytes.len() != expect {
            return Err(format!("音节表长度不符: 应为 {expect}，实际 {}", bytes.len()));
        }
        Ok(Syllables { bytes, len: n })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 查找音节，返回常见度名次。
    pub fn lookup(&self, hash: u64) -> Option<u32> {
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = HEADER_LEN + mid * 12;
            let b = &self.bytes[off..off + 12];
            let h = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            match h.cmp(&hash) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    return Some(u32::from_le_bytes([b[8], b[9], b[10], b[11]]))
                }
            }
        }
        None
    }
}
