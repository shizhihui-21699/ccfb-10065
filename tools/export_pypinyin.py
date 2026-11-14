#!/usr/bin/env python3
"""从 pypinyin 导出单字/词组拼音表到 data/raw/。

pypinyin 的拼音表是 MIT 许可的公开数据。这里只导出**无声调**读音，
因为口令里的拼音从不带声调。
"""
import json
import os
import unicodedata

def strip_tone(s: str) -> str:
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("ü", "v").replace("u:", "v").lower()

def main():
    from pypinyin import pinyin_dict, phrases_dict

    raw = os.environ.get("RAW_DIR", "data/raw")
    os.makedirs(raw, exist_ok=True)

    chars = {}
    for cp, readings in pinyin_dict.items():
        # pypinyin 的 key 是码位整数；导出为字符串键，与 build_data.py 一致
        chars[str(cp)] = ",".join(strip_tone(r) for r in readings.split(","))
    with open(os.path.join(raw, "pinyin_chars.json"), "w", encoding="utf-8") as f:
        json.dump(chars, f, ensure_ascii=False)
    print(f"pinyin_chars.json: {len(chars)} 个码位")

    phrases = {}
    for word, readings in phrases_dict.items():
        phrases[word] = [[strip_tone(r) for r in part] for part in readings]
    with open(os.path.join(raw, "pinyin_phrases.json"), "w", encoding="utf-8") as f:
        json.dump(phrases, f, ensure_ascii=False)
    print(f"pinyin_phrases.json: {len(phrases)} 个词组")

if __name__ == "__main__":
    main()
