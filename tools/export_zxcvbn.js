#!/usr/bin/env node
/**
 * 从 zxcvbn 4.4.2 的 npm 包里导出六张频次表到 data/raw/zx_lists.json。
 * zxcvbn 是 MIT 许可。
 *
 * 用法：
 *   npm pack zxcvbn@4.4.2 && tar xzf zxcvbn-4.4.2.tgz
 *   node tools/export_zxcvbn.js [package 目录，默认 ./package]
 */
const fs = require('fs');
const path = require('path');

const pkgDir = process.argv[2] || 'package';
const lists = require(path.resolve(pkgDir, 'lib/frequency_lists.js'));
const out = {};
for (const k of Object.keys(lists)) {
  out[k] = Array.from(lists[k]);
}
const dest = path.join('data', 'raw', 'zx_lists.json');
fs.mkdirSync(path.dirname(dest), { recursive: true });
fs.writeFileSync(dest, JSON.stringify(out));
console.log(`zx_lists.json: ${Object.entries(out).map(([k, v]) => `${k}=${v.length}`).join(', ')}`);
