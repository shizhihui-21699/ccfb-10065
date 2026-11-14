//! 哈希工具：FNV-1a（词典滑窗查找）+ SHA-1（k-匿名泄露查询）。
//!
//! 两者都手写实现，不引入外部依赖：
//! - FNV-1a 用于把每个子串映射成 64 位指纹，词典以「排序后的 u64 数组」存储，
//!   查找走二分，缓存友好且无需构建哈希表（WASM 里省内存、省启动时间）。
//! - SHA-1 仅用于生成泄露查询的 k-匿名前缀，属于协议要求而非安全边界。

/// FNV-1a 64 位偏移基准。
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 位质数。
pub const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 逐字节推进 FNV-1a。
#[inline(always)]
pub fn fnv1a_step(h: u64, byte: u8) -> u64 {
    (h ^ byte as u64).wrapping_mul(FNV_PRIME)
}

/// 计算一段字节的 FNV-1a。长度也混入，避免 "ab" 与 "ab\0" 一类前缀歧义。
#[inline]
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h = fnv1a_step(h, b);
    }
    h = fnv1a_step(h, bytes.len() as u8);
    h = fnv1a_step(h, (bytes.len() >> 8) as u8);
    h
}

/// 词典匹配时使用的长度截断：把长度折叠进指纹，和 [`fnv1a`] 保持一致。
/// 调用方在滑窗扩展过程中只维护内容哈希，命中后再调用本函数。
#[inline(always)]
pub fn fnv1a_finish(h: u64, len: usize) -> u64 {
    let h = fnv1a_step(h, len as u8);
    fnv1a_step(h, (len >> 8) as u8)
}

// ---------------------------------------------------------------------------
// SHA-1
// ---------------------------------------------------------------------------

/// 计算 SHA-1 摘要。
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

    let mut chunks = data.chunks_exact(64);
    for block in &mut chunks {
        sha1_compress(&mut state, block);
    }
    let rem = chunks.remainder();

    // 填充：0x80 + 若干 0 + 64 位大端比特长度。
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let tail_len = if rem.len() < 56 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(64) {
        sha1_compress(&mut state, block);
    }

    let mut out = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[inline(always)]
fn sha1_compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// 小写十六进制编码。`out` 长度须为 `bytes.len() * 2`。
pub fn to_hex_lower(bytes: &[u8], out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_assert_eq!(out.len(), bytes.len() * 2);
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xf) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vectors() {
        let mut hex = [0u8; 40];
        to_hex_lower(&sha1(b""), &mut hex);
        assert_eq!(&hex[..], b"da39a3ee5e6b4b0d3255bfef95601890afd80709");

        to_hex_lower(&sha1(b"abc"), &mut hex);
        assert_eq!(&hex[..], b"a9993e364706816aba3e25717850c26c9cd0d89d");

        // 跨多个分块 + 需要两次填充块的长输入。
        to_hex_lower(
            &sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            &mut hex,
        );
        assert_eq!(&hex[..], b"84983e441c3bd26ebaae4aa1f95129e5e54670f1");

        let million = vec![b'a'; 1_000_000];
        to_hex_lower(&sha1(&million), &mut hex);
        assert_eq!(&hex[..], b"34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    #[test]
    fn fnv_incremental_matches_whole() {
        let s = b"correct horse";
        let whole = fnv1a(&s[..5]);
        let mut h = FNV_OFFSET;
        for &b in &s[..5] {
            h = fnv1a_step(h, b);
        }
        assert_eq!(fnv1a_finish(h, 5), whole);
    }
}
