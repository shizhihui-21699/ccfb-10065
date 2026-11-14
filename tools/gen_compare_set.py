#!/usr/bin/env python3
"""生成对比测试用的口令集：真实泄露口令 + 结构化样本。

样本来源：
- rockyou 前 N 名（真实口令，有真实频次作为「真值」排序）
- 独立排名表（Pwdb / xato / darkweb / 10k-most-common）用于交叉验证
- 手工构造的边界样本（中文、l33t、日期、走位）
"""
import json, random, sys

def main():
    rng = random.Random(20251115)
    N = 3000
    # 1) 从 rockyou 取前 100000 名的随机样本（避免只取最高频导致「太容易」）
    rockyou = []
    with open('data/raw/rockyou-withcount.txt', encoding='utf-8', errors='replace') as f:
        for line in f:
            p = line.rstrip('\n').split(None, 1)
            if len(p) != 2: continue
            try: c = int(p[0])
            except: continue
            rockyou.append((c, p[1].strip()))
            if len(rockyou) >= 100000: break
    rockyou.sort(key=lambda kv: -kv[0])
    sample = rng.sample(rockyou[:100000], N)
    # 按真实频次排序，作为「真值排序」
    sample.sort(key=lambda kv: -kv[0])
    truth = [w for _, w in sample]

    # 2) 中文与结构化样本手工补充
    extra = [
        "woaini1314","woaini520","wangwei123","zhangwei1991","zhangsan",
        "王伟","张伟","我爱你","密码","5201314","1314520",
        "P@ssw0rd","P@ssw0rd!","p@ssword","pa55word","1337","l3tm31n",
        "qwedcxza","qazwsx","1qaz2wsx","asdfgh","zxcvbnm",
        "19910101","1991-01-01","01/01/1991","1122","2024",
        "aaaaaaaa","abcabcabc","abcdefg","1234567890",
        "correcthorsebatterystaple","木星斑马图书馆风铃",
        "MyL0ng&Compl3x!Passw0rd#2024","x","a","1",
    ]
    # 去重保持顺序
    seen = set(); mixed = []
    for w in extra + truth:
        if w in seen: continue
        seen.add(w); mixed.append(w)
    with open('tests/data/compare_set.txt','w',encoding='utf-8') as f:
        f.write('\n'.join(mixed) + '\n')
    print(f'写出 {len(mixed)} 条（含真实口令 {len(truth)} 条）', file=sys.stderr)

if __name__ == '__main__':
    main()
