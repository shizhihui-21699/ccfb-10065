//! 公共数据类型。
//!
//! 这里的所有类型都刻意保持 `Copy`/小体积，因为 WASM 侧需要把它们
//! 线性化到共享内存里交给 JS（见 `passmeter-wasm`）。

/// 匹配模式。顺序同时用于输出排序，保持稳定。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pattern {
    /// 键盘走位（qwerty / dvorak / keypad / mac_keypad）
    Spatial = 0,
    /// 重复（aaa、abcabcabc）
    Repeat = 1,
    /// 序列（abcd、9753、zyx）
    Sequence = 2,
    /// 日期（1991-01-01、1/1/91、0115）
    Date = 3,
    /// 词典词（含拼音、中文词、常见词表）
    Dictionary = 4,
    /// 纯暴力段（无任何模式命中）
    Bruteforce = 5,
    /// 连续中文字符段（未命中具体词表时的粗估）
    ChineseRun = 6,
}

impl Pattern {
    pub fn as_str(self) -> &'static str {
        match self {
            Pattern::Spatial => "spatial",
            Pattern::Repeat => "repeat",
            Pattern::Sequence => "sequence",
            Pattern::Date => "date",
            Pattern::Dictionary => "dictionary",
            Pattern::Bruteforce => "bruteforce",
            Pattern::ChineseRun => "chinese_run",
        }
    }
}

/// 词典来源。数值会写进二进制数据表，**改动必须同步 tools/build_data.py**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// 真实泄露口令（rockyou 频次）
    Pwned = 0,
    /// 英文常见口令表
    EnCommon = 1,
    /// 英文维基词频
    EnWiki = 2,
    /// 英文人名/姓氏
    EnNames = 3,
    /// 英文影视常用词
    EnTv = 4,
    /// 中文常见词
    ZhWords = 5,
    /// 中文姓名
    ZhNames = 6,
    /// 中文拼音（由常见词转写）
    ZhPinyin = 7,
    /// 中文姓名拼音（由姓名组合转写，置信度低于 ZhPinyin）
    ZhPinyinName = 8,
    /// 英文词频（wordfreq 英文语料）
    EnZipf = 9,
}

impl Source {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Source::Pwned,
            1 => Source::EnCommon,
            2 => Source::EnWiki,
            3 => Source::EnNames,
            4 => Source::EnTv,
            5 => Source::ZhWords,
            6 => Source::ZhNames,
            7 => Source::ZhPinyin,
            8 => Source::ZhPinyinName,
            9 => Source::EnZipf,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Source::Pwned => "pwned",
            Source::EnCommon => "en_common",
            Source::EnWiki => "en_wiki",
            Source::EnNames => "en_names",
            Source::EnTv => "en_tv",
            Source::ZhWords => "zh_words",
            Source::ZhNames => "zh_names",
            Source::ZhPinyin => "zh_pinyin",
            Source::ZhPinyinName => "zh_pinyin_name",
            Source::EnZipf => "en_zipf",
        }
    }

    /// 该来源是否属于「中文素材」。反馈文案据此选择语言。
    pub fn is_chinese(self) -> bool {
        matches!(
            self,
            Source::ZhWords | Source::ZhNames | Source::ZhPinyin | Source::ZhPinyinName
        )
    }
}

/// 一处匹配。
#[derive(Debug, Clone)]
pub struct Match {
    pub pattern: Pattern,
    /// 字节起止（含 `start`，不含 `end`）。始终落在 UTF-8 字符边界上。
    pub start: usize,
    pub end: usize,
    /// 估算的猜测次数（≥ 1）。
    pub guesses: f64,

    // —— 各模式的补充信息，未使用时为默认值 ——
    /// 词典来源
    pub source: Option<Source>,
    /// 词典名次（越小越常见）
    pub rank: u32,
    /// 该片段经过的真实替换（l33t / 大小写 / 反转）种类数，用于说明
    pub reversed: bool,
    pub l33t: bool,
    /// 键盘走位：使用的键位图名称
    pub graph: &'static str,
    /// 键盘走位：换向次数
    pub turns: u32,
    /// 键盘走位：按下 Shift 的字符数
    pub shifted_count: u32,
    /// 重复：基础片段长度（字节）
    pub repeat_base_len: u32,
    /// 日期：解析出的年份
    pub year: u16,
}

impl Match {
    pub fn new(pattern: Pattern, start: usize, end: usize, guesses: f64) -> Self {
        Match {
            pattern,
            start,
            end,
            guesses: guesses.max(1.0),
            source: None,
            rank: 0,
            reversed: false,
            l33t: false,
            graph: "",
            turns: 0,
            shifted_count: 0,
            repeat_base_len: 0,
            year: 0,
        }
    }

    #[inline]
    pub fn len_bytes(&self) -> usize {
        self.end - self.start
    }
}

/// 泄露库命中信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BreachInfo {
    /// 该口令在泄露库中出现的次数
    pub count: u32,
    /// 查询所用前缀是否命中
    pub prefix_matched: bool,
}

/// 一个破解场景。
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub key: &'static str,
    pub label: &'static str,
    /// 每秒猜测次数
    pub rate: f64,
    /// 该速率假设的说明
    pub note: &'static str,
}

/// 内置的六个破解场景。速率取自公开的实测/规范量级，
/// 刻意按「在线 → 离线」排列，方便前端按顺序展示。
pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        key: "throttled_online",
        label: "在线（严格限速）",
        rate: 100.0 / 3600.0,
        note: "每 36 秒一次，即每小时 100 次，常见于带账号锁定的登录页",
    },
    Scenario {
        key: "unthrottled_online",
        label: "在线（无限速）",
        rate: 10.0,
        note: "每秒 10 次，API 未限速时的典型值",
    },
    Scenario {
        key: "offline_bcrypt",
        label: "离线 · bcrypt",
        rate: 1.0e4,
        note: "每秒 1 万次，bcrypt cost=12 的单 GPU 量级",
    },
    Scenario {
        key: "offline_sha256_gpu",
        label: "离线 · SHA-256 多卡",
        rate: 1.0e10,
        note: "每秒 100 亿次，8 卡 GPU 跑未加盐 SHA-256",
    },
];

/// 完整的评估结果。
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// 最优匹配序列（已按起止位置排序）
    pub sequence: Vec<Match>,
    /// 总猜测次数
    pub guesses: f64,
    /// log10(guesses)
    pub guesses_log10: f64,
    /// 0..4，与 zxcvbn 的分档一致
    pub score: u8,
    /// 各场景的破解秒数，与 [`SCENARIOS`] 一一对应
    pub crack_seconds: [f64; 4],
    /// 泄露库信息；未查询时为 None
    pub breach: Option<BreachInfo>,
}

impl Evaluation {
    /// 把猜测次数映射到 0..4 分。
    ///
    /// 阈值沿用 zxcvbn（1e3 / 1e6 / 1e8 / 1e10），因为它已经过大规模验证；
    /// 本项目的差异在于 guesses 本身的估计更贴近中文用户。
    pub fn score_for(guesses: f64) -> u8 {
        // DELTA 用来吸收浮点误差：恰好 1000 次应算 1 分而不是 0 分。
        const DELTA: f64 = 5.0;
        if guesses < 1e3 + DELTA {
            0
        } else if guesses < 1e6 + DELTA {
            1
        } else if guesses < 1e8 + DELTA {
            2
        } else if guesses < 1e10 + DELTA {
            3
        } else {
            4
        }
    }
}
