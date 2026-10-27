//! RFC 3339 UTC timestamps without a date crate.
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's
/// `civil_from_days`.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (y, m, day) = civil(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        (s / 60) % 60,
        s % 60,
        d.subsec_millis()
    )
}

pub fn now() -> String {
    rfc3339(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn known_instants() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        // 2000-02-29T12:34:56.789Z (leap day).
        let t = UNIX_EPOCH + Duration::from_millis(951_827_696_789);
        assert_eq!(rfc3339(t), "2000-02-29T12:34:56.789Z");
        let t = UNIX_EPOCH + Duration::from_secs(4_102_444_800);
        assert_eq!(rfc3339(t), "2100-01-01T00:00:00.000Z");
    }
}
