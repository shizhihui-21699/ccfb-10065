#!/usr/bin/env bash
# 下载 passmeter 所需的全部公开语料到 data/raw/。
#
# 这些文件不进版本库（合计约 300 MB），但构建是确定性的：
# 同样的语料跑 build_data.py 会得到同样的 dict*.bin。
#
# 用法：bash tools/fetch_data.sh [--force]
set -euo pipefail

RAW="${RAW_DIR:-data/raw}"
FORCE="${1:-}"
mkdir -p "$RAW"

fetch() {
  local url="$1" dest="$2"
  if [[ -s "$RAW/$dest" && "$FORCE" != "--force" ]]; then
    echo "跳过 $dest（已存在）"
    return
  fi
  echo "下载 $dest …"
  # --http1.1 + curl -C - 是为了应对 GitHub raw 在 HTTP/2 下的中断
  curl -sSL --http1.1 -C - --retry 8 --retry-delay 2 --retry-all-errors \
       -o "$RAW/$dest" "$url"
  local size
  size=$(wc -c < "$RAW/$dest" | tr -d ' ')
  if [[ "$size" -lt 1000 ]]; then
    echo "错误：$dest 只有 $size 字节，下载失败" >&2
    rm -f "$RAW/$dest"
    exit 1
  fi
}

SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords"

fetch "$SECLISTS/Leaked-Databases/rockyou-withcount.txt.tar.gz" rockyou-withcount.txt.tar.gz
if [[ ! -s "$RAW/rockyou-withcount.txt" ]]; then
  tar xzf "$RAW/rockyou-withcount.txt.tar.gz" -C "$RAW"
fi

fetch "https://raw.githubusercontent.com/fxsjy/jieba/master/jieba/dict.txt" jieba_dict.txt

NAMES="https://raw.githubusercontent.com/wainshine/Chinese-Names-Corpus/master"
fetch "$NAMES/Chinese_Names_Corpus/Chinese_Names_Corpus%EF%BC%88120W%EF%BC%89.txt" names120w.txt
fetch "$NAMES/Chinese_Names_Corpus/Ancient_Names_Corpus%EF%BC%8825W%EF%BC%89.txt" ancient_names.txt
fetch "$NAMES/Chinese_Dict_Corpus/ChengYu_Corpus%EF%BC%885W%EF%BC%89.txt" chengyu.txt

echo
echo "以下三项由 pypinyin / wordfreq 导出。它们不是纯下载，"
echo "需要先安装对应 Python 包："
echo "  python3 -m pip install pypinyin wordfreq"
echo "  python3 tools/export_pypinyin.py"
echo "  python3 tools/export_wordfreq.py"
echo
echo "zxcvbn 的六张表由 npm 包导出："
echo "  npm pack zxcvbn@4.4.2 && tar xzf zxcvbn-4.4.2.tgz"
echo "  node tools/export_zxcvbn.js"
echo
echo "原始语料就绪后运行：python3 tools/build_data.py"
