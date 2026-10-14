use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    Turkish,
    #[default]
    English,
}

impl Language {
    /// Detects the system user interface language.
    /// On Windows, queries `GetUserDefaultUILanguage()`. If the primary language ID
    /// is Turkish (LANGID 0x1F / 31), returns `Language::Turkish`.
    /// On other platforms or fallback, inspects the `LANG` or `LC_ALL` environment variable.
    /// Defaults to `Language::English`.
    pub fn detect() -> Self {
        #[cfg(windows)]
        {
            #[link(name = "kernel32")]
            extern "system" {
                fn GetUserDefaultUILanguage() -> u16;
            }
            let lang_id = unsafe { GetUserDefaultUILanguage() };
            // Primary language ID is stored in the lower 10 bits: (lang_id & 0x03FF).
            // LANG_TURKISH = 0x1F (31).
            if (lang_id & 0x03FF) == 0x1F {
                return Language::Turkish;
            }
        }

        if let Ok(var) = std::env::var("LANG").or_else(|_| std::env::var("LC_ALL")) {
            let lower = var.to_lowercase();
            if lower.starts_with("tr") || lower.contains("tr_tr") || lower.contains("turkish") {
                return Language::Turkish;
            }
        }

        Language::English
    }

    /// Resolves language taking an optional explicit user override into account.
    pub fn resolve(explicit: Option<&str>) -> Self {
        if let Some(s) = explicit {
            if let Ok(l) = Self::from_str(s) {
                return l;
            }
        }
        Self::detect()
    }

    #[inline]
    pub fn is_turkish(&self) -> bool {
        matches!(self, Language::Turkish)
    }
}

impl FromStr for Language {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "tr" | "turkish" | "turkce" | "türkçe" => Ok(Language::Turkish),
            "en" | "english" => Ok(Language::English),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_from_str() {
        assert_eq!(Language::from_str("tr"), Ok(Language::Turkish));
        assert_eq!(Language::from_str("TR"), Ok(Language::Turkish));
        assert_eq!(Language::from_str("türkçe"), Ok(Language::Turkish));
        assert_eq!(Language::from_str("turkce"), Ok(Language::Turkish));
        assert_eq!(Language::from_str("turkish"), Ok(Language::Turkish));
        assert_eq!(Language::from_str("en"), Ok(Language::English));
        assert_eq!(Language::from_str("EN"), Ok(Language::English));
        assert_eq!(Language::from_str("english"), Ok(Language::English));
        assert_eq!(Language::from_str("unknown"), Err(()));
    }

    #[test]
    fn test_language_resolve_override() {
        assert_eq!(Language::resolve(Some("tr")), Language::Turkish);
        assert_eq!(Language::resolve(Some("en")), Language::English);
        // Invalid falls back to detect()
        let detected = Language::detect();
        assert_eq!(Language::resolve(Some("invalid")), detected);
        assert_eq!(Language::resolve(None), detected);
    }
}
