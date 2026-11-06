//! Country → IANA time zone (one zone per country, the most populous).
//!
//! Used by `shuang run --tz-from-exit`: Claude Code reads the machine's
//! system time zone, so a Moscow TZ behind a Dutch exit is a giveaway. The
//! mapping is approximate (large countries have several zones) — good enough
//! to be consistent, documented as such.

/// The most representative IANA zone for an ISO 3166-1 alpha-2 country.
pub fn zone_for_country(code: &str) -> Option<&'static str> {
    let zone = match code {
        "NL" => "Europe/Amsterdam",
        "DE" => "Europe/Berlin",
        "GB" => "Europe/London",
        "FR" => "Europe/Paris",
        "US" => "America/New_York",
        "CA" => "America/Toronto",
        "JP" => "Asia/Tokyo",
        "KR" => "Asia/Seoul",
        "SG" => "Asia/Singapore",
        "HK" => "Asia/Hong_Kong",
        "TW" => "Asia/Taipei",
        "AU" => "Australia/Sydney",
        "NZ" => "Pacific/Auckland",
        "SE" => "Europe/Stockholm",
        "NO" => "Europe/Oslo",
        "DK" => "Europe/Copenhagen",
        "FI" => "Europe/Helsinki",
        "PL" => "Europe/Warsaw",
        "CZ" => "Europe/Prague",
        "AT" => "Europe/Vienna",
        "CH" => "Europe/Zurich",
        "BE" => "Europe/Brussels",
        "IE" => "Europe/Dublin",
        "ES" => "Europe/Madrid",
        "PT" => "Europe/Lisbon",
        "IT" => "Europe/Rome",
        "GR" => "Europe/Athens",
        "TR" => "Europe/Istanbul",
        "IL" => "Asia/Jerusalem",
        "AE" => "Asia/Dubai",
        "IN" => "Asia/Kolkata",
        "BR" => "America/Sao_Paulo",
        "MX" => "America/Mexico_City",
        "AR" => "America/Argentina/Buenos_Aires",
        "CL" => "America/Santiago",
        "CO" => "America/Bogota",
        "ZA" => "Africa/Johannesburg",
        _ => return None,
    };
    Some(zone)
}

/// Mainland-China / HK / MO time zones — Claude Code reads the system zone,
/// and these are a strong CN-environment signal behind a foreign exit.
pub fn is_cn_timezone(tz: &str) -> bool {
    matches!(
        tz,
        "Asia/Shanghai" | "Asia/Urumqi" | "Asia/Hong_Kong" | "Asia/Macau" | "PRC" | "CST-8"
    )
}

/// zh_CN locale in LANG/LC_ALL — the second CN-environment signal.
pub fn is_cn_locale(lang: &str) -> bool {
    lang.starts_with("zh_CN") || lang.starts_with("zh_CN.") || lang == "zh_CN"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_common_exit_countries() {
        assert_eq!(zone_for_country("NL"), Some("Europe/Amsterdam"));
        assert_eq!(zone_for_country("US"), Some("America/New_York"));
        assert_eq!(zone_for_country("XX"), None);
    }

    #[test]
    fn cn_signals() {
        assert!(is_cn_timezone("Asia/Shanghai"));
        assert!(is_cn_timezone("Asia/Hong_Kong"));
        assert!(!is_cn_timezone("Europe/Amsterdam"));
        assert!(!is_cn_timezone("Asia/Tokyo"));
        assert!(is_cn_locale("zh_CN.UTF-8"));
        assert!(is_cn_locale("zh_CN"));
        assert!(!is_cn_locale("en_US.UTF-8"));
        assert!(!is_cn_locale("zh_TW.UTF-8"));
    }
}
