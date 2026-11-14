#!/usr/bin/env python3
"""对比测试：我们的猜测数排序 vs 真实泄露频次 / zxcvbn / 独立排名表。

验证方式（三条互相独立的证据）：

1. **与真实频次的相关性**（最重要）
   同一批 rockyou 口令，其真实频次名次是「正确排序」。计算
   我们 log10(guesses) 与真实 log10(名次) 的 Spearman / Kendall τ。
   相关性高 = 我们的「强度排序」与「真实被猜中的先后」一致。

2. **与 zxcvbn 的一致性**
   在纯英文口令上，两家实现应当大体同序。Spearman 当作回归护栏：
   跌到 0.8 以下说明类别权重或分档被改坏了。

3. **跨语料泛化**
   用独立的排名表（Pwdb / xato / darkweb / 10k-most-common）
   对同一批口令排序，看我们的分数是否也吻合。
   这能避免「只对 rockyou 过拟合」。

用法：
  python3 tools/compare.py --ours /tmp/pm_results.json \
      --zxcvbn /tmp/zx.json --truth tests/data/truth.jsonl
"""
import argparse
import json
import math
import statistics
import sys


def spearman(xs, ys):
    """Spearman 秩相关。并列取平均秩。"""
    def rank(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    rx, ry = rank(xs), rank(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    dy = math.sqrt(sum((b - my) ** 2 for b in ry))
    if dx == 0 or dy == 0:
        return 0.0
    return num / (dx * dy)


def kendall_tau(xs, ys):
    """Kendall τ-b（处理并列）。"""
    n = len(xs)
    concordant = discordant = tie_x = tie_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx = xs[i] - xs[j]
            dy = ys[i] - ys[j]
            if dx == 0 and dy == 0:
                tie_x += 1
                tie_y += 1
            elif dx == 0:
                tie_x += 1
            elif dy == 0:
                tie_y += 1
            elif (dx > 0) == (dy > 0):
                concordant += 1
            else:
                discordant += 1
    total = n * (n - 1) / 2
    denom = math.sqrt((total - tie_x) * (total - tie_y))
    if denom == 0:
        return 0.0
    return (concordant - discordant) / denom


def load_pm(path):
    d = json.load(open(path, encoding='utf-8'))
    return {e["password"]: e for e in d}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--zxcvbn")
    ap.add_argument("--truth", required=True, help="每行: <频次名次>\\t<口令>")
    ap.add_argument("--min-len", type=int, default=1)
    args = ap.parse_args()

    ours = load_pm(args.ours)
    zx = load_pm(args.zxcvbn) if args.zxcvbn else None

    truth_rank = {}
    for line in open(args.truth, encoding='utf-8'):
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 2:
            continue
        try:
            r = int(parts[0])
        except ValueError:
            continue
        truth_rank[parts[1]] = r

    common = [w for w in truth_rank if w in ours and len(w) >= args.min_len]
    if not common:
        print("没有可比对的样本", file=sys.stderr)
        return 1

    ours_log = [ours[w]["log10"] for w in common]
    truth_log = [math.log10(truth_rank[w]) for w in common]

    print(f"样本数: {len(common)}")
    print()
    print("== 1. 与真实泄露频次的相关性 ==")
    print(f"   Spearman ρ = {spearman(ours_log, truth_log):.4f}")
    print(f"   Kendall τ  = {kendall_tau(ours_log, truth_log):.4f}")

    # 分档一致性：把真实名次也按 zxcvbn 阈值分成 0..4
    def bins(g):
        if g < 1e3 + 5: return 0
        if g < 1e6 + 5: return 1
        if g < 1e8 + 5: return 2
        if g < 1e10 + 5: return 3
        return 4

    agree = sum(1 for w in common if bins(ours[w]["guesses"]) == bins(truth_rank[w]))
    print(f"   分档完全一致: {agree}/{len(common)} = {agree/len(common):.1%}")
    within1 = sum(1 for w in common if abs(bins(ours[w]["guesses"]) - bins(truth_rank[w])) <= 1)
    print(f"   分档差 ≤1 档: {within1}/{len(common)} = {within1/len(common):.1%}")

    # 系统性偏差
    diffs = [o - t for o, t in zip(ours_log, truth_log)]
    print(f"   log10 偏差中位数: {statistics.median(diffs):+.2f} 个数量级")
    print(f"   log10 偏差四分位距: {statistics.quantiles(diffs, n=4)}")

    # 最大的排序错误（相对真实名次）
    pairs = sorted(common, key=lambda w: ours_log[common.index(w)] - truth_log[common.index(w)])
    print()
    print("   最被高估（我们认为很难，实际很常见）:")
    for w in pairs[:5]:
        i = common.index(w)
        print(f"      {w:30} 我们 1e{ours_log[i]:.1f}  真实名次 {truth_rank[w]:8}")
    print("   最被低估（我们认为很常见，实际排名靠后）:")
    for w in pairs[-5:]:
        i = common.index(w)
        print(f"      {w:30} 我们 1e{ours_log[i]:.1f}  真实名次 {truth_rank[w]:8}")

    if zx:
        both = [w for w in common if w in zx]
        print()
        print(f"== 2. 与 zxcvbn 的一致性（{len(both)} 条） ==")
        print(f"   Spearman ρ = {spearman([ours[w]['log10'] for w in both], [zx[w]['log10'] for w in both]):.4f}")
        print(f"   Kendall τ  = {kendall_tau([ours[w]['log10'] for w in both], [zx[w]['log10'] for w in both]):.4f}")
        # 纯 ASCII 且无中文的子集
        ascii_only = [w for w in both if all(ord(c) < 128 for c in w)]
        if len(ascii_only) > 20:
            print(f"   仅 ASCII 子集（{len(ascii_only)} 条）:")
            print(f"     Spearman ρ = {spearman([ours[w]['log10'] for w in ascii_only], [zx[w]['log10'] for w in ascii_only]):.4f}")
        # 分档一致率
        agree = sum(1 for w in both if ours[w]['score'] == zx[w]['score'])
        print(f"   分档完全一致: {agree}/{len(both)} = {agree/len(both):.1%}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
