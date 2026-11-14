#!/usr/bin/env python3
"""从 wordfreq 导出中英文词频（zipf 得分）到 data/raw/。

wordfreq 的中文数据来自字幕、Twitter 与维基的混合语料，
比新闻语料更贴近口令素材（口令里出现的是「宝贝」「加油」，
而不是「发展」「改革」）。

许可：wordfreq 的数据来自多份公开语料，见其 README。
"""
import json
import os
import re

CJK = re.compile(r"^[㐀-䶿一-鿿]{2,6}$")
ASCII_WORD = re.compile(r"^[a-z]{3,20}$")

def main():
    from wordfreq import top_n_list, zipf_frequency

    raw = os.environ.get("RAW_DIR", "data/raw")
    os.makedirs(raw, exist_ok=True)

    zh = []
    for word in top_n_list("zh", 400000):
        if not CJK.match(word):
            continue
        z = zipf_frequency(word, "zh")
        if z >= 1.5:
            zh.append([word, round(z, 2)])
    with open(os.path.join(raw, "zh_zipf.json"), "w", encoding="utf-8") as f:
        json.dump(zh, f, ensure_ascii=False)
    print(f"zh_zipf.json: {len(zh)} 个词")

    en = []
    for word in top_n_list("en", 200000):
        if not ASCII_WORD.match(word):
            continue
        z = zipf_frequency(word, "en")
        if z >= 1.0:
            en.append([word, round(z, 2)])
    with open(os.path.join(raw, "en_zipf.json"), "w", encoding="utf-8") as f:
        json.dump(en, f)
    print(f"en_zipf.json: {len(en)} 个词")

if __name__ == "__main__":
    main()
