//! Interface languages. The English text is the key; `i18n/de.tsv` holds the
//! German version (`English<TAB>Deutsch`, one per line, `#` starts a comment).
//! A missing translation falls back to English and is remembered, so a test can
//! render every page in German and fail on gaps.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

const DE: &str = include_str!("../i18n/de.tsv");

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    De,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::De => "de",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        match code {
            "en" => Some(Lang::En),
            "de" => Some(Lang::De),
            _ => None,
        }
    }

    /// The first supported language of an `Accept-Language` header (quality values
    /// are ignored: browsers list their preferences in order); English otherwise.
    pub fn from_accept(header: &str) -> Lang {
        header
            .split(',')
            .filter_map(|part| {
                let tag = part.split(';').next()?.trim().to_ascii_lowercase();
                Lang::from_code(tag.split('-').next()?)
            })
            .next()
            .unwrap_or_default()
    }
}

fn german() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        DE.lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .collect()
    })
}

fn missing_set() -> &'static Mutex<BTreeSet<String>> {
    static SET: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// English texts that were asked for in German but have no translation yet.
pub fn missing() -> Vec<String> {
    missing_set()
        .lock()
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default()
}

/// The text in the given language (plain text: callers escape it for HTML).
pub fn t(lang: Lang, key: &str) -> String {
    match lang {
        Lang::En => key.to_owned(),
        Lang::De => match german().get(key) {
            Some(v) => (*v).to_owned(),
            None => {
                if let Ok(mut s) = missing_set().lock() {
                    s.insert(key.to_owned());
                }
                key.to_owned()
            }
        },
    }
}

/// Like [`t`] for texts that may legitimately have no translation (server
/// messages, technical values): falls back to English without noting a gap.
pub fn t_quiet(lang: Lang, key: &str) -> String {
    match lang {
        Lang::En => key.to_owned(),
        Lang::De => german()
            .get(key)
            .map_or_else(|| key.to_owned(), |v| (*v).to_owned()),
    }
}

/// Like [`t`], then replaces `{0}`, `{1}`, … with the arguments.
pub fn tf(lang: Lang, key: &str, args: &[&str]) -> String {
    let mut s = t(lang, key);
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), a);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_language() {
        assert_eq!(Lang::from_accept("de-DE,de;q=0.9,en;q=0.8"), Lang::De);
        assert_eq!(Lang::from_accept("fr-FR, en;q=0.5"), Lang::En);
        assert_eq!(Lang::from_accept("fr, de"), Lang::De);
        assert_eq!(Lang::from_accept(""), Lang::En);
        assert_eq!(Lang::from_accept("*"), Lang::En);
    }

    #[test]
    fn dictionary_is_well_formed() {
        for (i, line) in DE.lines().enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let (en, de) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("line {}: no tab", i + 1));
            assert!(!en.is_empty() && !de.is_empty(), "line {}", i + 1);
            for n in 0..4 {
                let p = format!("{{{n}}}");
                assert_eq!(
                    en.contains(&p),
                    de.contains(&p),
                    "placeholder {p} differs in line {}",
                    i + 1
                );
            }
        }
        let keys: Vec<&str> = DE
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| l.split('\t').next())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(keys.len(), sorted.len(), "duplicate keys");
    }
}
