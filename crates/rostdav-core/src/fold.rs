//! Folding of text for searching: what a person types and what is stored must meet.
//!
//! [`fold`] makes the text canonical (NFC) and lower case with full Unicode rules (not only
//! ASCII). [`fold_loose`] also drops accents, so `cafe` finds `Café` and `uber` finds `Über`.
//! Both are applied to the query and to the text, so a precomposed `é` and a decomposed
//! `e` + combining accent are the same thing, which they were not before.

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

/// Lower case plus the three letters whose lower case still differs from their case folding
/// (Unicode `CaseFolding.txt`): final sigma, sharp s and long s.
fn lower(s: &str) -> String {
    s.to_lowercase()
        .replace('\u{3c2}', "\u{3c3}")
        .replace('\u{df}', "ss")
        .replace('\u{17f}', "s")
}

/// NFC, then lower case with case folding.
pub fn fold(s: &str) -> String {
    lower(&s.nfc().collect::<String>())
}

/// Like [`fold`], and accents are removed (decompose, drop combining marks, compose).
pub fn fold_loose(s: &str) -> String {
    let stripped: String = s.nfd().filter(|c| !is_combining_mark(*c)).collect();
    lower(&stripped).nfc().collect()
}

/// Does `haystack` contain `needle`, ignoring case and accents? An empty needle matches nothing:
/// a search for nothing finds nothing.
pub fn contains_loose(haystack: &str, needle: &str) -> bool {
    let needle = fold_loose(needle);
    let needle = needle.trim();
    !needle.is_empty() && fold_loose(haystack).contains(needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composed_and_decomposed_are_the_same() {
        let composed = "Caf\u{e9}";
        let decomposed = "Cafe\u{301}";
        assert_ne!(composed, decomposed);
        assert_eq!(fold(composed), fold(decomposed));
        assert!(contains_loose(decomposed, "caf\u{e9}"));
        assert!(contains_loose(composed, "cafe\u{301}"));
    }

    #[test]
    fn case_is_folded_beyond_ascii() {
        assert_eq!(fold("ÄÖÜ"), "äöü");
        assert!(contains_loose("Große Übung.txt", "übung"));
        // sharp s is searched as "ss", and the other way round
        assert!(contains_loose("Straße.pdf", "strasse"));
        assert!(contains_loose("STRASSE.pdf", "straße"));
        assert!(contains_loose("ÉCOLE", "école"));
        // Greek and Cyrillic
        assert!(contains_loose("ΟΔΥΣΣΕΑΣ", "οδυσσεασ"));
        assert!(contains_loose("Привет мир", "ПРИВЕТ"));
    }

    #[test]
    fn accents_do_not_matter_for_the_loose_match() {
        assert!(contains_loose("Café Menü.pdf", "cafe menu"));
        assert!(contains_loose("Über uns", "uber"));
        assert!(contains_loose("naïve", "naive"));
        assert_eq!(fold_loose("Zoë"), "zoe");
        // strict folding keeps them apart
        assert_ne!(fold("Café"), fold("Cafe"));
    }

    #[test]
    fn dotted_capital_i_does_not_break_the_match() {
        // `İ` lower-cases to `i` + a combining dot; the loose fold removes the dot
        assert!(contains_loose("İstanbul", "istanbul"));
    }

    #[test]
    fn east_asian_text_and_symbols_pass_through() {
        assert!(contains_loose("日本語のファイル.txt", "ファイル"));
        assert!(!contains_loose("日本語", "中文"));
        assert!(contains_loose("a % b_c", "% b_"));
    }

    #[test]
    fn an_empty_or_blank_needle_finds_nothing() {
        assert!(!contains_loose("anything", ""));
        assert!(!contains_loose("anything", "   "));
        assert!(!contains_loose("", "x"));
    }

    #[test]
    fn the_needle_is_trimmed_but_inner_spaces_count() {
        assert!(contains_loose("my report final.txt", "  report final "));
        assert!(!contains_loose("my report.txt", "my  report"));
    }
}
