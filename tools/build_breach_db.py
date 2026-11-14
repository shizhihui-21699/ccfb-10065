#!/usr/bin/env python3
"""构建 k-匿名泄露库：把泄露口令转成「哈希前缀 → 后缀列表」的分片。

## 为什么是 16 bit 而不是 HIBP 的 20 bit

k-匿名的 k 是「单次查询落到的桶里有几条记录」。实测（见 docs/BREACH.md）：

    前缀位宽  桶数       k 最小 / 中位 / p90
    20 bit   947 976     1 / 2 / 4        ← 本语料下匿名性不足
    16 bit    65 536     12 / 37 / 45     ← 可用
    12 bit     4 096    510 / 601 / 632   ← 桶太大，响应体积不可接受

HIBP 用 20 bit 是因为它有 6 亿条口令，每个前缀仍有数十条记录。
本项目的语料是 245 万条（≥2 次的唯一口令），20 bit 下每桶只剩 2 条，
攻击者拿响应去撞库的成本太低。**16 bit 是这份数据下匿名性与
响应体积的平衡点**：k ≥ 12，单桶响应 < 2 KB。

代价：前缀从 6.5 万分之一降到 65 万分之一的口令空间。因为服务端
仍然不知道完整哈希与口令本身（只见到 4 位十六进制），这一层
保护依然成立；泄露的主要是「你查的那个桶里还有哪些后缀」——
但那是服务端本来就持有的公开泄露数据，不涉及查询者隐私。

## 存储布局

不用「每个前缀一个文件」：95 万个小文件会产生 3.6 GB 的文件系统
块开销（实测）。改为**单一分片文件 + 前缀偏移索引**：

    breach.bin    所有桶按前缀升序拼接，每条记录 `<suffix>:<count>\n`
    breach.idx    65536 项 u64 偏移（每个前缀在 breach.bin 中的起点）

查询时用二分/直接索引定位到 `[off[p], off[p+1])` 读出。
文件总量约 60 MB，机械盘与 SSD 上都只需一次 seek。
"""
import argparse
import hashlib
import os
import struct
import sys
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="data/raw/rockyou-withcount.txt")
    ap.add_argument("--out", default="data/generated/breach")
    ap.add_argument("--prefix-bits", type=int, default=16)
    ap.add_argument("--min-count", type=int, default=2,
                    help="只收录出现次数 ≥ N 的口令")
    ap.add_argument("--max-entries", type=int, default=4000,
                    help="单个前缀最多保留的记录数，超出按次数截断")
    args = ap.parse_args()

    hex_len = args.prefix_bits // 4
    n_buckets = 16 ** hex_len

    counts = defaultdict(int)
    total = 0
    with open(args.raw, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split(None, 1)
            if len(parts) != 2:
                continue
            try:
                n = int(parts[0])
            except ValueError:
                continue
            pw = parts[1].strip()
            if not pw:
                continue
            counts[pw] += n
            total += 1
    print(f"读取 {total} 行，去重后 {len(counts)} 条口令", file=sys.stderr)

    buckets = defaultdict(list)
    kept = 0
    for pw, n in counts.items():
        if n < args.min_count:
            continue
        digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        prefix = int(digest[:hex_len], 16)
        suffix = digest[hex_len:]
        buckets[prefix].append((suffix, n))
        kept += 1
    print(f"收录 {kept} 条（≥{args.min_count} 次）", file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    bin_path = os.path.join(args.out, "breach.bin")
    idx_path = os.path.join(args.out, "breach.idx")

    offsets = [0] * (n_buckets + 1)
    entries = 0
    with open(bin_path, "wb") as fbin:
        pos = 0
        for p in range(n_buckets):
            rows = buckets.get(p)
            offsets[p] = pos
            if not rows:
                continue
            rows.sort(key=lambda r: (-r[1], r[0]))
            if len(rows) > args.max_entries:
                rows = rows[: args.max_entries]
            for suffix, n in rows:
                line = f"{suffix}:{n}\n".encode("ascii")
                fbin.write(line)
                pos += len(line)
                entries += 1
        offsets[n_buckets] = pos

    # 索引：每桶 (offset:u64, length:u32)
    with open(idx_path, "wb") as fidx:
        fidx.write(b"PMB1")
        fidx.write(struct.pack("<I", n_buckets))
        fidx.write(struct.pack("<I", hex_len))
        for p in range(n_buckets):
            length = offsets[p + 1] - offsets[p]
            fidx.write(struct.pack("<Q", offsets[p]))
            fidx.write(struct.pack("<I", length))

    sizes = sorted(len(v) for v in buckets.values())
    empty = n_buckets - len(sizes)
    print(f"桶数 {n_buckets}，有数据 {len(sizes)}，空桶 {empty}", file=sys.stderr)
    if sizes:
        print(
            f"k 值: min={sizes[0]} p50={sizes[len(sizes)//2]} "
            f"p90={sizes[int(len(sizes) * 0.9)]} max={sizes[-1]}",
            file=sys.stderr,
        )
        if sizes[0] < 10:
            print(
                f"警告：最小 k={sizes[0]} 低于推荐的 10，"
                f"请减小 --prefix-bits 或放宽 --min-count",
                file=sys.stderr,
            )
    print(
        f"写出 {entries} 条记录，breach.bin {os.path.getsize(bin_path)//1024} KB，"
        f"breach.idx {os.path.getsize(idx_path)//1024} KB",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
