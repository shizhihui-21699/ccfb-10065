#!/usr/bin/env python3
"""从公开语料构建 passmeter 的词典索引与拼音表。

输入（data/raw/，不提交，获取方式见 docs/DATA.md）：
  rockyou-withcount.txt   1430 万条带频次的真实泄露口令
  jieba_dict.txt          jieba 中文分词词典（词 + 词频，仅作切分用）
  zh_zipf.json            中文词频 [[词, zipf], ...]，来自 wordfreq 的中文
                          混合语料（字幕/Twitter/维基），比新闻语料更贴近口令素材
  names120w.txt           中文人名语料（约 114 万条）
  ancient_names.txt       古代人名语料（约 25 万条）
  chengyu.txt             成语语料（约 5 万条）
  pinyin_chars.json       pypinyin 单字拼音表 {codepoint: "a,b,c"}
  pinyin_phrases.json     pypinyin 词组拼音表 {词: [[拼音],...]}
  zx_lists.json           zxcvbn 4.4.2 的六张频次表

输出（data/generated/，提交）：
  dict1.bin               嵌入 WASM 的高价值词典索引（约 4 万条）
  dict2.bin               按需加载的扩展索引（约 20 万条）
  syllables.bin           拼音音节表，用于拼音切分
  pinyin_gloss.txt        高频拼音 → 汉字，仅用于反馈文案
  stats.json              构建统计，供文档引用

索引条目统一 13 字节：
  u64 FNV-1a(词 UTF-8 字节) | u32 有效名次 | u8 来源标签
按哈希升序排列，运行时二分查找。词串本身不进入运行时表——
匹配只需要「这个词是否在表里、名次多少」，命中的片段直接从用户输入里取。

设计说明见 docs/DATA.md。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
import unicodedata
from collections import Counter, defaultdict

CJK = re.compile(r"^[㐀-䶿一-鿿]+$")
ASCII_WORD = re.compile(r"^[a-z][a-z0-9']*$")
PINYIN_RUN = re.compile(r"^[a-z]+$")

# 来源标签，必须与 passmeter-core/src/data.rs 的 Source 枚举一致。
SOURCES = {
    "pwned": 0,
    "en_common": 1,
    "en_wiki": 2,
    "en_names": 3,
    "en_tv": 4,
    "zh_words": 5,
    "zh_names": 6,
    "zh_pinyin": 7,
    "zh_pinyin_name": 8,
    "en_zipf": 9,
}

# 权重 = 「语料内名次」到「真实口令名次」的折算系数。
#
# 不是拍脑袋：用 rockyou（1430 万条真实泄露口令）对每张 zxcvbn 表做回归，
# 取 password_rank / list_position 的中位数（见 docs/DATA.md 表 2）：
#   passwords 4.9 | english_wikipedia 56.9 | female_names 25.1
#   male_names 20.1 | surnames 73.3 | us_tv_and_film 65.9
# 即语义类词表内部的名次普遍比口令名次「乐观」20~70 倍，必须放大。
# 中文语料没有口令级观测，按下面的 ZH_OFFSET 模型单独处理。
WEIGHTS = {
    "pwned": 1.0,       # 本身就是口令频次名次，无需折算
    "en_common": 1.0,   # rockyou 已直接覆盖这张表，名次即真值
    "en_wiki": 57.0,    # password_rank / list_pos 中位数
    "en_names": 22.0,   # 男/女名/姓氏 20.1 / 25.1 / 73.3，取偏保守的 22
    "en_tv": 66.0,
    "zh_words": 1.0,    # 已按词频位置直接定名次，不再二次折算
    "zh_names": 1.0,
    "zh_pinyin": 1.0,   # 拼音按 PY_RATIO 单独定名次
    "zh_pinyin_name": 1.0,  # 已由 PY_NAME_PENALTY 折算
    "en_zipf": 1.0,         # 已用概率模型直接换算
}

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1

# 中文语料的名次模型（无公开中文口令语料，属明确假设，见 docs/DATA.md §4）。
#
# 用概率而非词表位置：中文词表有 26 万条，被大量低频词稀释，
# 「木星」排第 8.4 万位，但攻击者不会为了猜中文口令枚举 8 万个词。
#
# 做法：用 wordfreq 的 zipf 还原概率 p = 10^(zipf-9)，名次 = C/p。
# C 由 rockyou 里可观测的拼音锚点反解（见 docs/DATA.md 表 4）：
#   baobei(宝贝) 实测 14001 → C=0.508
#   mima(密码)   实测 12545 → C=0.560
#   tianshi(天使) 实测 13142 → C=0.535
# 取 C=0.5（偏保守，即名次偏小=密码偏弱）。
# 结果：「中国」181、「密码」11193、「木星」19 万，与直觉一致。
ZH_COVERAGE = 0.5
EN_COVERAGE = 1.0   # 英文的 implied C 中位数（rockyou 校准，见 docs/DATA.md）
ZH_OFFSET = 1          # 名次下限
PY_RATIO = 1.6         # 拼音版本比汉字版本少见，名次乘 1.6
# 姓名概率 → 名次的系数。姓名/词的边际概率相乘后会远小于真实姓名概率，
# NAME_C 把它校准到「王伟 ≈ 20 名、冷僻组合 ≈ 数万名」的量级。
NAME_C = 0.02
PY_NAME_RATIO = 0.35    # 姓名拼音比汉字姓名靠前（中文口令几乎都用拼音输入）
PY_NAME_PENALTY = 3.0   # 但拼音姓名整体弱于拼音词：同一串若源自真实词，取真实词
PY_NAME_MAX_RANK = 40000  # 只保留名次在此之内的姓名拼音，避免全组合洪水
ZH_NAME_MAX_RANK = 60000  # 汉字姓名同理


def zipf_rank(zipf: float, coverage: float = ZH_COVERAGE) -> int:
    """zipf 得分 → 等效口令名次。p = 10^(z-9)，rank = C/p。"""
    p = 10.0 ** (zipf - 9.0)
    return max(ZH_OFFSET, int(coverage / max(p, 1e-12)))


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    h = ((h ^ (len(data) & 0xFF)) * FNV_PRIME) & MASK64
    h = ((h ^ ((len(data) >> 8) & 0xFF)) * FNV_PRIME) & MASK64
    return h


def normalize(s: str) -> str:
    return unicodedata.normalize("NFKC", s).lower()


def strip_tone(s: str) -> str:
    """拼音去声调：ü→v，其余组合音标去掉。"""
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("ü", "v").replace("u:", "v").lower()


def read_lines(path: str):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            if line:
                yield line


def parse_rockyou(path: str) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for line in read_lines(path):
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        try:
            n = int(parts[0])
        except ValueError:
            continue
        word = normalize(parts[1].strip())
        if not word or len(word.encode("utf-8")) > 128:
            continue
        counts[word] += n
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def rank_by_count(ranked: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """频次名次。同频组取组内最小名次（对用户取更保守的一侧）。"""
    out = []
    prev = None
    rank = 0
    for idx, (word, count) in enumerate(ranked, start=1):
        if count != prev:
            rank = idx
            prev = count
        out.append((word, rank))
    return out


def build_zh_words(zipf_path: str) -> list[tuple[str, float]]:
    """中文词 + zipf 得分（1.5..6.6，越高越常见），按得分降序。"""
    with open(zipf_path, encoding="utf-8") as fh:
        rows = json.load(fh)
    out = []
    seen = set()
    for word, zipf in rows:
        if not CJK.match(word) or not (2 <= len(word) <= 6) or word in seen:
            continue
        seen.add(word)
        out.append((word, float(zipf)))
    out.sort(key=lambda kv: (-kv[1], kv[0]))
    return out


# 攻击者词表的起点偏移：在枚举到「中文常用词」之前，攻击者会先试完
# 数字、日期、英文高频词等。这个偏移把中文素材放到合理位置。
ZH_WORD_OFFSET = 1
ZH_NAME_OFFSET = 1



def build_en_words(zipf_path: str) -> list[tuple[str, float]]:
    """英文词 + zipf。只保留纯字母 3..20 字符，避免数字串与短语干扰。"""
    with open(zipf_path, encoding="utf-8") as fh:
        rows = json.load(fh)
    out = []
    for word, zipf in rows:
        if not ASCII_WORD.match(word) or not (3 <= len(word) <= 20):
            continue
        out.append((word, float(zipf)))
    return out


def build_names(paths: list[str]) -> list[str]:
    out, seen = [], set()
    for path in paths:
        if not path or not os.path.exists(path):
            continue
        for line in read_lines(path):
            word = line.strip()
            if not CJK.match(word) or not (2 <= len(word) <= 4):
                continue
            if word in seen:
                continue
            seen.add(word)
            out.append(word)
    return out


def pinyin_char_table(char_json: str) -> dict[str, str]:
    """码位 → 首选无声调读音。"""
    with open(char_json, encoding="utf-8") as fh:
        raw = json.load(fh)
    return {cp: strip_tone(readings.split(",")[0]) for cp, readings in raw.items()}


def build_syllables(char_json: str, phrase_json: str) -> list[str]:
    with open(char_json, encoding="utf-8") as fh:
        raw_chars = json.load(fh)
    with open(phrase_json, encoding="utf-8") as fh:
        phrase_map = json.load(fh)

    counter: Counter[str] = Counter()
    for readings in raw_chars.values():
        for r in readings.split(","):
            r = strip_tone(r.strip())
            if 1 <= len(r) <= 7 and PINYIN_RUN.match(r):
                counter[r] += 1
    for readings in phrase_map.values():
        for sl in readings:
            for r in sl:
                r = strip_tone(r)
                if 1 <= len(r) <= 7 and PINYIN_RUN.match(r):
                    counter[r] += 2
    return sorted(counter, key=lambda s: (-counter[s], s))


def name_ranks(names: list[str]) -> list[tuple[str, int]]:
    """姓名语料无频次，用「姓 × 名用字」的边际频率排序。

    语料是按拼音排序的全组合枚举，位置没有频次含义；更麻烦的是它把
    所有姓氏×名字的组合都生成了一遍，「文王」「阿安」这类组合未必
    真有人用。因此不能把整份语料都放进索引。

    口径：
    - 用 f(姓)·f(名用字) 的概率（边际频率相乘）作为「这个姓名有多像
      真实高频姓名」的近似；
    - 名次 = NAME_C / 概率，与中文词使用同一套概率→名次换算
      （见 zipf_rank），这样姓名与常用词在同一个尺度上比较。
      「王伟」在榜首附近，「王梓萱」落在数百名，冷僻组合落到数万名——
      而不是像按秩排序那样把 140 万个组合均匀铺到 1..350 万。
    """
    surname = Counter()
    given = Counter()
    for word in names:
        surname[word[0]] += 1
        for ch in word[1:]:
            given[ch] += 1
    total = len(names)
    out = []
    for word in names:
        s = surname[word[0]] / total
        g = 1.0
        for ch in word[1:]:
            g *= given[ch] / total
        p = max(s * g, 1e-12)
        out.append((word, max(1, int(NAME_C / p)) if p > 0 else 10_000_000))
    out.sort(key=lambda kv: (kv[1], kv[0]))
    return out


def pinyin_name_ranks(names: list[str], char_map: dict[str, str]) -> list[tuple[str, int]]:
    """姓名 → 拼音，名次比汉字版本更靠前。

    中文口令里「wangwei」远比「王伟」更常被使用（拼音可以直接
    用英文键盘输入）。因此对每个姓名拼音，取其汉字名次再乘
    PY_NAME_RATIO（< 1，即更靠前）。

    关键限制：姓名语料是 140 万条全组合枚举，拼音化后会产生 73 万个
    不同的字母串；若全部入库，「fengling」（风铃的拼音，一个常见词）
    会以某个人名的身份排到第 172 名——这是错误的。只保留名次靠前的
    PY_NAME_MAX_RANK 条，让拼音姓名表与「真实常见姓名」的规模相当。
    """
    def to_pinyin(word: str) -> str | None:
        out = []
        for ch in word:
            py = char_map.get(str(ord(ch)))
            if py is None:
                return None
            out.append(py)
        return "".join(out)

    best: dict[str, int] = {}
    for word, han_rank in name_ranks(names):
        py = to_pinyin(word)
        if not py or not (4 <= len(py) <= 24):
            continue
        rank = max(1, int(han_rank * PY_NAME_RATIO))
        if rank > PY_NAME_MAX_RANK:
            continue
        if py not in best or rank < best[py]:
            best[py] = rank
    return sorted(best.items(), key=lambda kv: (kv[1], kv[0]))


def pinyin_word_ranks(
    zh_words: list[tuple[str, float]], char_map: dict[str, str]
) -> list[tuple[str, int]]:
    """常见中文词 → 拼音串，沿用该词的词表位置。

    不收录无依据的音节组合：不对英文词做无差别切分
    （sun-shine 不是「孙-闪」），只转写词表里真实存在的汉语词。
    """
    def to_pinyin(word: str) -> str | None:
        buf = []
        for ch in word:
            py = char_map.get(str(ord(ch)))
            if py is None:
                return None
            buf.append(py)
        return "".join(buf)

    best: dict[str, int] = {}
    for word, zipf in zh_words:
        py = to_pinyin(word)
        if not py or not (2 <= len(py) <= 24):
            continue
        rank = max(1, int(zipf_rank(zipf) * PY_RATIO))
        if py not in best or rank < best[py]:
            best[py] = rank
    return sorted(best.items(), key=lambda kv: (kv[1], kv[0]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="data/raw")
    ap.add_argument("--out", default="data/generated")
    ap.add_argument("--tier1", type=int, default=120000)
    ap.add_argument("--tier2", type=int, default=600000)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    raw = lambda name: os.path.join(args.raw, name)

    print("[1/6] rockyou 频次名次…", file=sys.stderr)
    rockyou = rank_by_count(parse_rockyou(raw("rockyou-withcount.txt")))
    print(f"      去重 {len(rockyou)} 条", file=sys.stderr)

    print("[2/6] 中文词 / 姓名…", file=sys.stderr)
    zh_words = build_zh_words(raw("zh_zipf.json"))
    names = build_names([raw("names120w.txt"), raw("ancient_names.txt"), raw("chengyu.txt")])
    en_words = build_en_words(raw("en_zipf.json"))
    print(f"      中文词 {len(zh_words)}，英文词 {len(en_words)}，姓名/成语 {len(names)}", file=sys.stderr)

    print("[3/6] 拼音…", file=sys.stderr)
    char_map = pinyin_char_table(raw("pinyin_chars.json"))
    syllables = build_syllables(raw("pinyin_chars.json"), raw("pinyin_phrases.json"))
    py_words = pinyin_word_ranks(zh_words, char_map)
    print(f"      音节 {len(syllables)}，拼音词 {len(py_words)}", file=sys.stderr)

    print("[4/6] 汇总各来源…", file=sys.stderr)
    entries: list[tuple[str, int, str]] = []
    for word, rank in rockyou:
        entries.append((word, rank, "pwned"))

    with open(raw("zx_lists.json"), encoding="utf-8") as fh:
        zx = json.load(fh)
    zx_map = {
        "passwords": "en_common",
        "english_wikipedia": "en_wiki",
        "female_names": "en_names",
        "male_names": "en_names",
        "surnames": "en_names",
        "us_tv_and_film": "en_tv",
    }
    for name, source in zx_map.items():
        for rank, word in enumerate(zx[name], start=1):
            w = normalize(word)
            if not w or not ASCII_WORD.match(w) or len(w) > 32:
                continue
            entries.append((w, rank, source))

    for word, zipf in zh_words:
        entries.append((word, zipf_rank(zipf), "zh_words"))
    en_words = build_en_words(raw("en_zipf.json"))
    for word, zipf in en_words:
        entries.append((word, zipf_rank(zipf, EN_COVERAGE), "en_zipf"))
    for word, rank in name_ranks(names):
        if rank > ZH_NAME_MAX_RANK:
            continue
        entries.append((word, rank, "zh_names"))
    # 注意顺序与权重：音节串可能同时是「常见词的拼音」和「某人名的拼音」。
    # 前者有真实文本依据（fengling=风铃），后者只是组合枚举的副作用，
    # 因此拼音姓名要明显弱于拼音词，避免「风铃」被当成某个人名而虚高。
    for py, rank in py_words:
        entries.append((py, rank, "zh_pinyin"))
    for py, rank in pinyin_name_ranks(names, char_map):
        entries.append((py, int(rank * PY_NAME_PENALTY), "zh_pinyin_name"))

    merged: dict[str, tuple[int, str]] = {}
    for word, rank, source in entries:
        if not word:
            continue
        effective = max(1, int(rank * WEIGHTS[source]))
        cur = merged.get(word)
        if cur is None or effective < cur[0]:
            merged[word] = (effective, source)
    print(f"      合并后 {len(merged)} 个唯一词", file=sys.stderr)

    # 分级：按名次排序后切两层，但对「姓名/拼音」类来源设配额上限，
    # 否则几十万条姓名会把真实口令表挤出窗口。
    #   - 真实口令、通用词表：名次落在窗口内就全保留；
    #   - 姓名、拼音：最多占该层条目的 45%（tier1）/ 55%（tier2）。
    ordered = sorted(merged.items(), key=lambda kv: (kv[1][0], kv[0]))
    ZH_SOURCES = ("zh_names", "zh_pinyin", "zh_pinyin_name")

    def pick_from(
        rows: list[tuple[str, tuple[int, str]]], limit: int, zh_cap_frac: float
    ) -> list[tuple[str, tuple[int, str]]]:
        # 只有姓名类受配额限制；拼音词、中文词、口令表都按名次竞争
        zh_cap = int(limit * zh_cap_frac)
        out: list[tuple[str, tuple[int, str]]] = []
        zh_used = 0
        for word, val in rows:
            if val[1] in ("zh_names", "zh_pinyin_name"):
                if zh_used >= zh_cap:
                    continue
                zh_used += 1
            out.append((word, val))
            if len(out) >= limit:
                break
        return out

    tier1 = pick_from(ordered, args.tier1, 0.45)
    taken = {w for w, _ in tier1}
    rest = [(w, v) for w, v in ordered if w not in taken]
    tier2 = pick_from(rest, args.tier2, 0.55)

    def write_blob(path: str, rows: list[tuple[str, tuple[int, str]]]) -> int:
        records = []
        for word, (rank, source) in rows:
            records.append((fnv1a(word.encode("utf-8")), rank, SOURCES[source], word))
        records.sort(key=lambda r: r[0])
        for a, b in zip(records, records[1:]):
            if a[0] == b[0] and a[3] != b[3]:
                raise SystemExit(f"哈希冲突: {a[3]!r} / {b[3]!r}")
        with open(path, "wb") as fh:
            fh.write(b"PMD1")
            fh.write(struct.pack("<I", len(records)))
            for h, rank, source, _w in records:
                fh.write(struct.pack("<QIB", h, min(rank, 0xFFFFFFFF), source))
        return len(records)

    n1 = write_blob(os.path.join(args.out, "dict1.bin"), tier1)
    n2 = write_blob(os.path.join(args.out, "dict2.bin"), tier2)
    print(f"      dict1: {n1}，dict2: {n2}", file=sys.stderr)

    print("[5/6] 拼音音节表…", file=sys.stderr)
    syl_records = sorted((fnv1a(s.encode("utf-8")), i + 1) for i, s in enumerate(syllables))
    with open(os.path.join(args.out, "syllables.bin"), "wb") as fh:
        fh.write(b"PMS1")
        fh.write(struct.pack("<I", len(syl_records)))
        for h, rank in syl_records:
            fh.write(struct.pack("<QI", h, rank))

    # 高频拼音 → 汉字，只用于前端反馈文案
    gloss: list[tuple[str, str]] = []
    seen_py = set()
    for word, zipf in sorted(zh_words, key=lambda kv: (-kv[1], kv[0])):
        py = "".join(char_map.get(str(ord(c)), "") for c in word)
        if not py or py in seen_py:
            continue
        seen_py.add(py)
        gloss.append((py, word))
        if len(gloss) >= 3000:
            break
    with open(os.path.join(args.out, "pinyin_gloss.txt"), "w", encoding="utf-8") as fh:
        for py, word in gloss:
            fh.write(f"{py}\t{word}\n")
    print(f"      音节 {len(syl_records)}，反馈词条 {len(gloss)}", file=sys.stderr)

    print("[6/6] 统计…", file=sys.stderr)
    src_counts: Counter[str] = Counter(s for _w, (_r, s) in merged.items())
    stats = {
        "unique_words": len(merged),
        "tier1": n1,
        "tier2": n2,
        "syllables": len(syl_records),
        "sources": dict(src_counts),
        "weights": WEIGHTS,
        "tier1_bytes": os.path.getsize(os.path.join(args.out, "dict1.bin")),
        "tier2_bytes": os.path.getsize(os.path.join(args.out, "dict2.bin")),
    }
    with open(os.path.join(args.out, "stats.json"), "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)
    print(json.dumps(stats, ensure_ascii=False, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
