//! Turning the bytes of a file into text for the search index (ADR 0012).
//!
//! Only files that are text are read: a name with a known text extension (or none, as
//! `README`, `LICENSE`, `Makefile`), and content that has no NUL byte in its first 8 KiB.
//! The charset is found by a byte-order mark; without one, UTF-8 if it is valid, else
//! Windows-1252 (what files from older programs mostly are). Nothing here ever logs content.

use encoding_rs::{UTF_16BE, UTF_16LE, WINDOWS_1252};

/// Bumped whenever this module reads more or different files than before, so that the index
/// reads every file again with the new rules.
pub const EXTRACTOR_VERSION: i64 = 2;

const TEXT_EXTENSIONS: &[&str] = &[
    // prose and notes
    "txt",
    "text",
    "md",
    "markdown",
    "rst",
    "adoc",
    "org",
    "tex",
    "bib",
    "log",
    "me",
    "nfo",
    "rtf",
    // data
    "csv",
    "tsv",
    "json",
    "jsonl",
    "ndjson",
    "geojson",
    "xml",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "properties",
    "env",
    "sql",
    "ics",
    "vcf",
    "srt",
    "vtt",
    "gpx",
    "kml",
    "opml",
    // web
    "html",
    "htm",
    "xhtml",
    "css",
    "scss",
    "sass",
    "less",
    "svg",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "tsx",
    "vue",
    "svelte",
    "php",
    "twig",
    // programs
    "rs",
    "py",
    "rb",
    "go",
    "java",
    "kt",
    "kts",
    "scala",
    "c",
    "h",
    "cc",
    "cpp",
    "cxx",
    "hpp",
    "hh",
    "cs",
    "fs",
    "swift",
    "m",
    "mm",
    "lua",
    "pl",
    "pm",
    "r",
    "jl",
    "dart",
    "ex",
    "exs",
    "erl",
    "hs",
    "ml",
    "clj",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "bat",
    "cmd",
    "mk",
    "cmake",
    "gradle",
    "tf",
    "proto",
    "graphql",
    "gql",
    "nix",
    "dockerfile",
    "gitignore",
    "editorconfig",
    "lock",
    "diff",
    "patch",
];

/// Might the file with this name hold text? (The content decides in the end.)
pub fn may_be_text(name: &str) -> bool {
    match name.rsplit_once('.') {
        // `.gitignore` and friends: the whole name after the dot
        Some(("", ext)) | Some((_, ext)) => {
            TEXT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        }
        // README, LICENSE, Makefile, Dockerfile …
        None => true,
    }
}

/// The text of `bytes`, at most `max_bytes` of it (cut at a character), or `None` if the content
/// is not text. Control characters other than line breaks and tabs become spaces.
pub fn decode(bytes: &[u8], max_bytes: usize) -> Option<String> {
    let (text, _) = if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        (decode_utf8_or_1252(rest, max_bytes)?, ())
    } else if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        (
            UTF_16LE.decode_without_bom_handling(rest).0.into_owned(),
            (),
        )
    } else if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        (
            UTF_16BE.decode_without_bom_handling(rest).0.into_owned(),
            (),
        )
    } else {
        // a NUL in the first 8 KiB means a binary file
        if bytes.iter().take(8192).any(|b| *b == 0) {
            return None;
        }
        (decode_utf8_or_1252(bytes, max_bytes)?, ())
    };
    let mut out = String::with_capacity(text.len().min(max_bytes));
    for c in text.chars() {
        let c = if c.is_control() && !matches!(c, '\n' | '\t') {
            if c == '\r' { continue } else { ' ' }
        } else {
            c
        };
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    Some(out)
}

fn decode_utf8_or_1252(bytes: &[u8], max_bytes: usize) -> Option<String> {
    // only the part that is kept is decoded: cut a little more than the limit, at a boundary
    let take = bytes
        .len()
        .min(max_bytes.saturating_mul(2).saturating_add(8));
    let slice = &bytes[..take];
    match std::str::from_utf8(slice) {
        Ok(s) => Some(s.to_owned()),
        // cut in the middle of a character: the part before it is valid
        Err(e) if e.error_len().is_none() && take < bytes.len() => {
            Some(String::from_utf8_lossy(&slice[..e.valid_up_to()]).into_owned())
        }
        Err(_) => Some(
            WINDOWS_1252
                .decode_without_bom_handling(slice)
                .0
                .into_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_decide_what_may_be_text() {
        for n in [
            "a.txt",
            "A.MD",
            "main.rs",
            "x.JSON",
            "README",
            "Makefile",
            ".gitignore",
            "a.b.csv",
        ] {
            assert!(may_be_text(n), "{n}");
        }
        for n in [
            "a.jpg", "b.pdf", "c.docx", "d.zip", "e.mp4", "f.exe", "g.sqlite", "h.png",
        ] {
            assert!(!may_be_text(n), "{n}");
        }
    }

    #[test]
    fn utf8_with_and_without_a_marker() {
        assert_eq!(
            decode("Grüße, 日本語".as_bytes(), 1000).as_deref(),
            Some("Grüße, 日本語")
        );
        let mut with_bom = b"\xEF\xBB\xBF".to_vec();
        with_bom.extend_from_slice("Grüße".as_bytes());
        assert_eq!(decode(&with_bom, 1000).as_deref(), Some("Grüße"));
    }

    #[test]
    fn utf16_is_read_by_its_marker() {
        let mut le = vec![0xFF, 0xFE];
        le.extend("Grüße".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode(&le, 1000).as_deref(), Some("Grüße"));
        let mut be = vec![0xFE, 0xFF];
        be.extend("Grüße".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode(&be, 1000).as_deref(), Some("Grüße"));
    }

    #[test]
    fn old_files_in_windows_1252_are_read() {
        // "Café à l'œuvre" in Windows-1252 (not valid UTF-8)
        let bytes: Vec<u8> = vec![
            b'C', b'a', b'f', 0xe9, b' ', 0xe0, b' ', b'l', b'\'', 0x9c, b'u', b'v', b'r', b'e',
        ];
        assert!(std::str::from_utf8(&bytes).is_err());
        assert_eq!(decode(&bytes, 1000).as_deref(), Some("Café à l'œuvre"));
    }

    #[test]
    fn binary_content_is_refused_even_with_a_text_name() {
        let mut bytes = b"looks like text".to_vec();
        bytes.push(0);
        bytes.extend_from_slice(b"but is not");
        assert_eq!(decode(&bytes, 1000), None);
        assert_eq!(decode(&[0x89, b'P', b'N', b'G', 0, 0, 0, 13], 1000), None);
    }

    #[test]
    fn control_characters_become_spaces_and_line_ends_stay() {
        assert_eq!(
            decode(b"a\x01b\tc\r\nd\x1b[0me", 1000).as_deref(),
            Some("a b\tc\nd [0me")
        );
    }

    #[test]
    fn the_text_is_cut_at_a_character_and_never_beyond_the_limit() {
        let text = "ü".repeat(100); // 200 bytes
        let cut = decode(text.as_bytes(), 51).expect("text");
        assert!(
            cut.len() <= 51 && cut.chars().all(|c| c == 'ü'),
            "{}",
            cut.len()
        );
        assert_eq!(decode(text.as_bytes(), 0).as_deref(), Some(""));
        // a multi-megabyte file with a small limit does not decode more than it needs
        let big = "wort ".repeat(2_000_000);
        assert_eq!(decode(big.as_bytes(), 100).expect("text").len(), 100);
        // cut in the middle of a character at the decode boundary
        let mixed = format!("{}{}", "a".repeat(10), "日".repeat(50));
        let got = decode(mixed.as_bytes(), 20).expect("text");
        assert!(got.len() <= 20 && got.starts_with("aaaaaaaaaa"));
    }

    #[test]
    fn empty_files_are_empty_text_not_binary() {
        assert_eq!(decode(b"", 100).as_deref(), Some(""));
    }
}
