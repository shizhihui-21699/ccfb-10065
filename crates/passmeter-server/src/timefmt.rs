//! 破解时间的可读表述。
//!
//! 单位阈值与 `web/passmeter.js` 的 `humanizeSeconds` **必须一致**，
//! 否则同一个口令在前端与 API 里会显示成不同的时间。
//! 两侧都用固定的语义常数（月=31 天、年=12 月），不依赖日历。

const MINUTE: f64 = 60.0;
const HOUR: f64 = 60.0 * MINUTE;
const DAY: f64 = 24.0 * HOUR;
const MONTH: f64 = 31.0 * DAY;
const YEAR: f64 = 12.0 * MONTH;
const CENTURY: f64 = 100.0 * YEAR;

/// 把秒数转成中文表述。
pub fn humanize(seconds: f64) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return "瞬间".to_string();
    }
    if seconds < 1.0 {
        return "不到 1 秒".to_string();
    }
    if seconds < MINUTE {
        return format!("{} 秒", seconds.round() as i64);
    }
    if seconds < HOUR {
        return format!("{} 分钟", (seconds / MINUTE).round() as i64);
    }
    if seconds < DAY {
        return format!("{} 小时", (seconds / HOUR).round() as i64);
    }
    if seconds < MONTH {
        return format!("{} 天", (seconds / DAY).round() as i64);
    }
    if seconds < YEAR {
        return format!("{} 个月", (seconds / MONTH).round() as i64);
    }
    if seconds < CENTURY {
        return format!("{} 年", (seconds / YEAR).round() as i64);
    }
    "数百年以上".to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        assert_eq!(humanize(0.0), "瞬间");
        assert_eq!(humanize(0.5), "不到 1 秒");
        assert_eq!(humanize(30.0), "30 秒");
        assert_eq!(humanize(90.0), "2 分钟");
        assert_eq!(humanize(3600.0), "1 小时");
        assert_eq!(humanize(86400.0), "1 天");
        assert_eq!(humanize(31.0 * 86400.0), "1 个月");
        assert_eq!(humanize(365.0 * 86400.0), "12 个月");
        assert_eq!(humanize(1e12), "数百年以上");
    }

    #[test]
    fn non_finite() {
        assert_eq!(humanize(f64::INFINITY), "瞬间");
        assert_eq!(humanize(f64::NAN), "瞬间");
    }
}
