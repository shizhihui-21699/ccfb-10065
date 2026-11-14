//! 密码强度评估核心。
//!
//! 设计目标：
//! 1. **快**：单次评估在 WASM 里 < 1 ms（目标上限 5 ms），因此数据表
//!    布局以缓存友好为先（排序数组 + 二分，不用哈希表）。
//! 2. **中文优先**：除 zxcvbn 的英文模式外，额外识别拼音、中文词、
//!    中文姓名，并针对中文口令素材做名次校准。
//! 3. **可解释**：每个匹配片段都带位置、模式、猜测量，前端可逐段高亮。
//! 4. **隐私**：泄露查询只发送 SHA-1 前 5 位十六进制（20 bit）。

#![forbid(unsafe_code)]
// 内部类型（每个字段的含义在字段名与上下文中已足够清楚）不强制文档，
// 对外 API 的关键约定在模块级文档里说明。
#![allow(missing_docs)]

pub mod breach;
pub mod chinese;
pub mod date;
pub mod dictionary;
pub mod eval;
pub mod feedback;
#[doc(hidden)]
pub mod graphs_data;
pub mod hash;
pub mod index;
pub mod norm;
pub mod repeat;
pub mod scoring;
pub mod spatial;
pub mod types;

pub use eval::{evaluate_quick, Evaluator, FullResult, PREFIX_BYTES};
pub use types::{Evaluation, Match, Pattern, Source, SCENARIOS};
