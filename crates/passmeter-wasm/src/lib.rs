//! WASM 绑定。
//!
//! 设计取舍：**不使用 wasm-bindgen**。
//! - 少一层工具链依赖（不需要 wasm-bindgen-cli 与 JS glue），
//!   构建只需要 `cargo build --target wasm32-unknown-unknown`；
//! - 导出的是裸 C ABI，任何语言都能直接实例化调用；
//! - 代价是手写内存管理与 JSON 序列化，见下。
//!
//! 内存协议（与 `web/passmeter.js` 一致）：
//! ```text
//! ptr = pm_alloc(n)          // 申请 n 字节的输入缓冲
//! (JS 把 UTF-8 口令写进 memory[ptr..ptr+n])
//! pm_eval(ptr, n)            // 评估，返回 1 成功 / 0 失败
//! pm_result_ptr()            // 取结果 JSON 的起始地址
//! pm_result_len()            // 取结果 JSON 的长度
//! pm_free_result()
//! ```
//!
//! 结果是一次完整评估的 JSON，字段见 [`eval_to_json`]。
//! 之所以一次性返回整块 JSON（而不是逐字段 getter），是因为
//! 前端每次按键都要重算，一次内存拷贝 + 一次 `JSON.parse` 比几十次
//! 跨边界调用快得多。

use passmeter_core::feedback::Advice;
use passmeter_core::{Evaluator, FullResult};
use std::cell::RefCell;

// ---------------------------------------------------------------------------
// 全局状态
//
// WASM 实例是单线程的，因此用 thread_local + RefCell 而不是锁。
// ---------------------------------------------------------------------------

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::new());
}

struct State {
    evaluator: Option<Evaluator>,
    /// 输入缓冲（JS 写入待评估口令）
    input: Vec<u8>,
    /// 输出缓冲（结果 JSON）
    output: Vec<u8>,
    /// 最后一次错误信息
    error: Vec<u8>,
}

impl State {
    fn new() -> Self {
        State {
            evaluator: None,
            input: Vec::new(),
            output: Vec::new(),
            error: Vec::new(),
        }
    }
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

// ---------------------------------------------------------------------------
// 导出：初始化与内存
// ---------------------------------------------------------------------------

/// 初始化评估器（加载内嵌一级词典）。
/// 返回 1 成功，0 失败（可用 `pm_error_ptr/pm_error_len` 取原因）。
#[no_mangle]
pub extern "C" fn pm_init() -> i32 {
    with_state(|st| match Evaluator::with_embedded() {
        Ok(ev) => {
            st.evaluator = Some(ev);
            1
        }
        Err(e) => {
            st.error = e.into_bytes();
            0
        }
    })
}

/// 判断二级词典是否已加载。前端据此决定是否需要 fetch。
#[no_mangle]
pub extern "C" fn pm_has_tier2() -> i32 {
    with_state(|st| match &st.evaluator {
        Some(ev) if ev.has_tier2() => 1,
        _ => 0,
    })
}

/// 加载二级词典。`ptr/len` 指向 `dict2.bin` 的字节。返回 1 成功。
///
/// # Safety
/// `ptr` 必须指向至少 `len` 字节、由 [`pm_alloc`] 分配且在调用期间
/// 未被释放的缓冲。JS 侧的唯一调用路径（分配→写入→调用）满足这个条件。
#[no_mangle]
pub unsafe extern "C" fn pm_load_tier2(ptr: *const u8, len: usize) -> i32 {
    with_state(|st| {
        let Some(ev) = st.evaluator.as_mut() else {
            st.error = "尚未调用 pm_init".as_bytes().to_vec();
            return 0;
        };
        // 把字节复制进一个泄漏的静态缓冲：Index::parse 要求 'static 生命周期，
        // 而 WASM 实例通常只加载一次数据表，泄漏是可接受的（几十 MB 上限）。
        if ptr.is_null() || len == 0 {
            st.error = "二级词典指针为空".as_bytes().to_vec();
            return 0;
        }
        // SAFETY: 调用方保证 ptr/len 有效（见函数文档）。
        // 这块内存由 pm_alloc 分配、调用期间不释放。
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        let bytes: &'static [u8] = Box::leak(slice.to_vec().into_boxed_slice());
        match ev.load_tier2(bytes) {
            Ok(()) => 1,
            Err(e) => {
                st.error = e.into_bytes();
                0
            }
        }
    })
}

/// 申请输入缓冲，返回指针。`len` 为字节数。
///
/// 返回的指针在下次 `pm_alloc` 前有效；前端应在同一轮里立刻写入。
#[no_mangle]
pub extern "C" fn pm_alloc(len: usize) -> *mut u8 {
    with_state(|st| {
        st.input.clear();
        st.input.resize(len, 0);
        st.input.as_mut_ptr()
    })
}

/// 释放输入缓冲（可选；下轮 `pm_alloc` 会复用）。
#[no_mangle]
pub extern "C" fn pm_free(ptr: *mut u8, len: usize) {
    let _ = (ptr, len);
    with_state(|st| {
        st.input.clear();
        st.input.shrink_to_fit();
    });
}

// ---------------------------------------------------------------------------
// 导出：评估
// ---------------------------------------------------------------------------

/// 评估 `ptr/len` 处的 UTF-8 口令。返回 1 成功、0 失败。
///
/// # Safety
/// `ptr` 必须指向至少 `len` 字节、由 [`pm_alloc`] 分配且在调用期间
/// 未被释放的缓冲。
#[no_mangle]
pub unsafe extern "C" fn pm_eval(ptr: *const u8, len: usize) -> i32 {
    with_state(|st| {
        if ptr.is_null() {
            st.error = "输入指针为空".as_bytes().to_vec();
            return 0;
        }
        let Some(ev) = st.evaluator.as_ref() else {
            st.error = "尚未调用 pm_init".as_bytes().to_vec();
            return 0;
        };
        // SAFETY: 调用方保证 ptr/len 有效（见函数文档）。
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        let password = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                st.error = "输入不是合法 UTF-8".as_bytes().to_vec();
                return 0;
            }
        };
        let result = ev.evaluate(password);
        st.output = eval_to_json(password, &result).into_bytes();
        1
    })
}

/// 结果 JSON 的起始地址。
#[no_mangle]
pub extern "C" fn pm_result_ptr() -> *const u8 {
    with_state(|st| st.output.as_ptr())
}

/// 结果 JSON 的字节长度。
#[no_mangle]
pub extern "C" fn pm_result_len() -> usize {
    with_state(|st| st.output.len())
}

/// 释放结果缓冲。
#[no_mangle]
pub extern "C" fn pm_free_result() {
    with_state(|st| {
        st.output.clear();
        st.output.shrink_to_fit();
    });
}

/// 错误信息指针。
#[no_mangle]
pub extern "C" fn pm_error_ptr() -> *const u8 {
    with_state(|st| st.error.as_ptr())
}

/// 错误信息长度。
#[no_mangle]
pub extern "C" fn pm_error_len() -> usize {
    with_state(|st| st.error.len())
}

// ---------------------------------------------------------------------------
// JSON 序列化
//
// 手写而非 serde：WASM 体积敏感，这点代码比引入 serde_json 划算。
// ---------------------------------------------------------------------------

fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

fn num(v: f64) -> String {
    if v.is_finite() {
        // 保留 6 位有效数字，足够前端显示「1.2 万亿年」这类量级
        format!("{:.6e}", v)
    } else {
        "1e308".to_string()
    }
}

fn eval_to_json(password: &str, r: &FullResult) -> String {
    let mut s = String::with_capacity(1024);
    s.push('{');

    s.push_str("\"score\":");
    s.push_str(&r.score.to_string());

    s.push_str(",\"guesses\":");
    s.push_str(&num(r.guesses));

    s.push_str(",\"guessesLog10\":");
    s.push_str(&format!("{:.4}", r.guesses_log10));

    s.push_str(",\"charCount\":");
    s.push_str(&r.char_count.to_string());

    // 破解时间：秒
    s.push_str(",\"crackSeconds\":[");
    for (i, v) in r.crack_seconds.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&num(*v));
    }
    s.push(']');

    // 字符类别（用于前端提示「已含大小写/数字/符号」）
    s.push_str(",\"classes\":{");
    s.push_str(&format!("\"lower\":{}", r.classes.has_lower as u8));
    s.push_str(&format!(",\"upper\":{}", r.classes.has_upper as u8));
    s.push_str(&format!(",\"digit\":{}", r.classes.has_digit as u8));
    s.push_str(&format!(",\"symbol\":{}", r.classes.has_symbol as u8));
    s.push_str(&format!(",\"cjk\":{}", r.classes.has_cjk as u8));
    s.push('}');

    // 匹配序列
    s.push_str(",\"sequence\":[");
    for (i, m) in r.sequence.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let token_start = m.start.min(password.len());
        let token_end = m.end.min(password.len());
        let token = if token_start <= token_end
            && password.is_char_boundary(token_start)
            && password.is_char_boundary(token_end)
        {
            &password[token_start..token_end]
        } else {
            ""
        };

        s.push_str("{\"pattern\":\"");
        s.push_str(m.pattern.as_str());
        s.push_str("\",\"start\":");
        s.push_str(&m.start.to_string());
        s.push_str(",\"end\":");
        s.push_str(&m.end.to_string());
        s.push_str(",\"token\":\"");
        json_escape(token, &mut s);
        s.push_str("\",\"guesses\":");
        s.push_str(&num(m.guesses));
        if let Some(src) = m.source {
            s.push_str(",\"source\":\"");
            s.push_str(src.as_str());
            s.push('"');
        }
        if m.rank > 0 {
            s.push_str(",\"rank\":");
            s.push_str(&m.rank.to_string());
        }
        if !m.graph.is_empty() {
            s.push_str(",\"graph\":\"");
            s.push_str(m.graph);
            s.push('"');
        }
        if m.turns > 0 {
            s.push_str(",\"turns\":");
            s.push_str(&m.turns.to_string());
        }
        if m.reversed {
            s.push_str(",\"reversed\":true");
        }
        if m.l33t {
            s.push_str(",\"l33t\":true");
        }
        if m.year > 0 {
            s.push_str(",\"year\":");
            s.push_str(&m.year.to_string());
        }
        s.push('}');
    }
    s.push(']');

    // 反馈
    s.push_str(",\"feedback\":[");
    for (i, a) in r.feedback.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        advice_to_json(a, &mut s);
    }
    s.push(']');

    // SHA-1 前缀（供前端做 k-匿名查询）
    s.push_str(",\"sha1Prefix\":\"");
    for b in r.sha1_prefix.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    // 完整 SHA-1：前端拿它在本地与桶里的后缀比对。
    // 它只在浏览器进程内存在，不会随查询发送。
    s.push_str("\",\"sha1Hex\":\"");
    let hex = passmeter_core::hash::sha1(password.as_bytes());
    let mut buf = [0u8; 40];
    passmeter_core::hash::to_hex_lower(&hex, &mut buf);
    s.push_str(std::str::from_utf8(&buf).unwrap_or(""));
    s.push_str("\"}");
    s
}

fn advice_to_json(a: &Advice, s: &mut String) {
    s.push_str("{\"message\":\"");
    json_escape(&a.message, s);
    s.push_str("\",\"action\":\"");
    json_escape(&a.action, s);
    s.push('"');
    if let Some((start, end)) = a.span {
        s.push_str(&format!(",\"start\":{},\"end\":{}", start, end));
    }
    s.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_control_chars() {
        let mut s = String::new();
        json_escape("a\"b\\c\nd", &mut s);
        assert_eq!(s, "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn num_formats() {
        assert_eq!(num(1.0), "1.000000e0");
        assert_eq!(num(f64::INFINITY), "1e308");
    }
}
