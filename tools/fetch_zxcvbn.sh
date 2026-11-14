#!/usr/bin/env bash
# 下载 zxcvbn 4.4.2（对比测试的参照实现）。不提交到版本库。
#
# 用法：bash tools/fetch_zxcvbn.sh
set -euo pipefail
VENDOR="${VENDOR_DIR:-vendor}"
mkdir -p "$VENDOR"
if [[ -s "$VENDOR/zxcvbn.js" ]]; then
  echo "已存在 vendor/zxcvbn.js"
  exit 0
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "下载 zxcvbn 4.4.2 …"
(cd "$TMP" && npm pack zxcvbn@4.4.2 --silent >/dev/null)
tar xzf "$TMP"/zxcvbn-4.4.2.tgz -C "$TMP"
cp "$TMP/package/dist/zxcvbn.js" "$VENDOR/zxcvbn.js"
cp "$TMP/package/LICENSE.txt" "$VENDOR/zxcvbn-LICENSE.txt"
echo "完成：vendor/zxcvbn.js（MIT 许可，见 vendor/zxcvbn-LICENSE.txt）"
