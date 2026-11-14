#!/usr/bin/env node
/**
 * 用 zxcvbn（业界基准实现）对同一批口令打分，输出 JSON。
 *
 * 用途：给 tests/compare.rs 提供对照数据。zxcvbn 作为参考而非「正确答案」——
 * 它在中文口令上明显偏弱（没有拼音/中文词表），对比的意义在于
 * 检查我们的排序是否与「真实泄露频次」一致，以及和成熟实现在
 * 英文口令上是否大体吻合。
 *
 * 用法：node tools/run_zxcvbn.js < 口令文件 > 结果 JSON
 */
const fs = require('fs');
const path = require('path');

const zxcvbnPath = process.env.ZXCVBN_PATH ||
  path.join(__dirname, '..', 'vendor', 'zxcvbn.js');
const zxcvbn = require(zxcvbnPath);

const words = fs.readFileSync(0, 'utf8').split('\n').filter(w => w.length > 0);
const out = words.map(w => {
  const r = zxcvbn(w);
  return {
    password: w,
    guesses: r.guesses,
    log10: r.guesses_log10,
    score: r.score,
    patterns: r.sequence.map(m => m.pattern),
  };
});
process.stdout.write(JSON.stringify(out, null, 0));
