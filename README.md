# passmeter — 面向中文用户的口令强度评估

Rust 写核心、编译到 WASM 在浏览器里跑的口令强度评估器。
除了识别键盘走位、日期、重复、序列、词典词与 l33t 替换，
还专门处理**拼音、中文常用词、中文姓名**——这是 zxcvbn 等主流实现
的盲区。

```
输入 "123qweASD"  →  1 档（很弱），约 2.0×10⁴ 次猜测
     └─ 整串命中真实泄露口令表第 10 133 名
输入 "密码"        →  1 档，1.1×10⁴ 次（拼音 mima 排第 1.8 万）
输入 "木星斑马图书馆风铃" → 4 档，1.4×10²⁰ 次
```

## 它解决什么问题

现有的强度提示器对中文用户的判断经常是错的：

| 口令 | zxcvbn | passmeter | 真实情况 |
|---|---|---|---|
| `密码` | 100 次（"极弱"） | 11 000 次 | 常见中文口令素材 |
| `woaini1314` | 8.5×10⁷（"中等"） | 5.1×10⁷（"中等"） | 真实泄露库第 9.2 万名 |
| `木星斑马图书馆风铃` | 1×10⁹（"较强"） | 1.4×10²⁰（"很强"） | 9 个随机汉字，确实很强 |

zxcvbn 把汉字当暴力段、用基数 10 估算，等于说两个汉字和 `ab` 一样强。
passmeter 用中文词频、拼音表与姓名语料给它们真实的名次。

## 快速开始

```bash
# 1. 原始语料（约 300 MB，一次性）
bash tools/fetch_data.sh
python3 -m pip install pypinyin wordfreq
python3 tools/export_pypinyin.py && python3 tools/export_wordfreq.py

# 2. 构建数据表
make data breach

# 3. 编译 WASM 与服务端
make wasm server

# 4. 起服务，打开 http://127.0.0.1:8787
./target/release/passmeter-server
```

页面在输入时实时评估，并把每个匹配片段按模式着色（词典词红色、
走位橙色、日期蓝色……），下方给出破解时间与针对每个片段的具体建议。

## 结构

```
crates/passmeter-core/     评估核心（无外部依赖，#![forbid(unsafe_code)]）
  src/norm.rs              归一化与原文偏移映射
  src/hash.rs              FNV-1a（词典滑窗）+ SHA-1（k-匿名）
  src/index.rs             二进制词典索引（排序数组 + 二分）
  src/dictionary.rs        普通/反转/l33t/拼音匹配
  src/spatial.rs           键盘走位
  src/repeat.rs            重复与序列
  src/date.rs              日期
  src/chinese.rs           中文字符段估算
  src/scoring.rs           最优匹配序列 DP
  src/feedback.rs          反馈文案
  src/breach.rs            k-匿名协议（哈希、前缀、响应解析）
crates/passmeter-wasm/     WASM 绑定（裸 C ABI，不用 wasm-bindgen）
crates/passmeter-server/   k-匿名查询服务 + 静态站点（无外部依赖）
web/                       前端页面与 JS 封装
tools/                     数据构建、对比测试、基准脚本
docs/                      数据、泄露库、对比测试的设计说明
```

全部 crate **零第三方依赖**：没有 serde、没有 axum、没有 wasm-bindgen。
HTTP 服务是手写的（约 300 行），WASM 导出是裸 C ABI，JSON 是手写序列化。
这样构建可复现、无供应链风险，WASM 产物只有 1.7 MB。

## 性能

单次评估必须 < 5 ms（前端每次按键都要跑）：

| 场景 | 原生 | WASM |
|---|---|---|
| 典型口令（平均） | 33 µs | **22 µs** |
| 最坏短口令 | 0.27 ms | — |
| 140 字节长输入 | 1.3 ms | **1.0 ms** |

余量来自三处：词典用排序数组 + 二分（不建哈希表）、滑窗增量哈希
（每个子串只做常数次 FNV 步）、DP 的暴力段回看窗口限制在 16 字节。

## k-匿名泄露查询

只发送 SHA-1 的 **16 bit 前缀**（4 位十六进制），服务端返回该前缀下的
全部「后缀:出现次数」，客户端本地比对。

为什么是 16 bit 而不是 HIBP 的 20 bit：本语料 245 万条唯一口令下，
20 bit 每桶中位数只有 2 条记录，k 太小；16 bit 下 **k 中位 37、最小 12**。
详细推导见 [docs/BREACH.md](docs/BREACH.md)。

```bash
curl http://127.0.0.1:8787/range/5baa | head -3
# 61E4C9B93F3F0682250B6CF8331B7EE68FD8:59463   ← password
```

## 对比测试（质量护栏）

和真实泄露频次、zxcvbn、独立排名表三方交叉验证，详见
[docs/COMPARISON.md](docs/COMPARISON.md)。

| 检验 | 结果 |
|---|---|
| 与 rockyou 真实频次名次的 Spearman ρ（2851 条） | **0.626** |
| 前 1 万名区间 ρ | **0.774** |
| 分档（0..4）完全一致 | **97.1%** |
| 分档差 ≤1 档 | **100%** |
| 与 zxcvbn 的 ρ | **0.660**（log10 偏差中位数 −0.01） |

```bash
make compare    # 生成完整报告
make test       # CI：含相关性阈值断言
```

## 名次怎么来

这是项目里最需要解释的部分：词典词的「名次」决定它被判为
「攻击者第几次尝试就能猜中」。项目**不用词表位置**（会被长尾稀释），
而用 **zipf 概率** 换算，系数由 rockyou 里的拼音锚点实测反解：

| 词 | zipf | 实测锚点 | 反解系数 |
|---|---|---|---|
| 宝贝 | 4.56 | `baobei` 在 rockyou 第 14 001 名 | 0.508 |
| 密码 | 4.65 | `mima` 第 12 545 名 | 0.560 |
| 天使 | 4.61 | `tianshi` 第 13 142 名 | 0.535 |

取 C = 0.5，得到「中国」第 181 名、「我爱你」第 15 811 名、
「木星」第 19 万名。英文用同样方法在 2 万词上校准得 C = 1.0。
完整推导见 [docs/DATA.md](docs/DATA.md)。

## 测试

```bash
cargo test --workspace        # 72 个测试
```

覆盖：归一化的字节偏移映射（中文/全角/emoji）、序列无缝覆盖整串、
确定性、单调性（加字符不变弱）、5 ms 预算、中文与拼音识别、
l33t/倒写、SHA-1 已知向量、k-匿名协议、路径穿越防护、
以及与真实频次的相关性阈值。

## 已知局限

1. **中文名次模型没有口令级验证**——C=0.5 来自 3 个拼音锚点，
   属于明确假设而非测量（见 docs/DATA.md §7）。
2. **rockyou 是 2009 年西方语料**，对近十年的新口令素材覆盖不足。
3. **16 bit 前缀仍可被计数侧信道关联**（服务端不记录来源，但网络层可见）；
   更强的保护需要 PIR，超出本项目范围。
4. 前端页面未做无障碍与移动端细节打磨，定位是可用的参考实现。

## 许可

代码 MIT。数据来源与许可：
- rockyou（SecLists 镜像）——公开泄露数据
- zxcvbn 频次表——MIT
- Chinese-Names-Corpus——Apache-2.0
- pypinyin——MIT
- wordfreq——见其 README

`data/raw/` 不入库，`data/generated/` 只保留派生索引。
