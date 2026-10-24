//! Text extraction from PDF and Office files (ADR 0013): fixtures and hostile input.

use std::io::Write;

use rostdav_app::extract::{Kind, extract};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/extract/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("test input")
}

fn text(kind: Kind, name: &str) -> String {
    extract(kind, fixture(name), 1 << 20).expect("test input")
}

#[test]
fn kinds_by_name() {
    assert_eq!(Kind::of_name("a/Report.PDF"), Some(Kind::Pdf));
    assert_eq!(Kind::of_name("x.odt"), Some(Kind::Odt));
    assert_eq!(Kind::of_name("x.txt"), None);
    assert_eq!(Kind::of_name("noext"), None);
    assert_eq!(Kind::from_arg(Kind::Xls.arg()), Some(Kind::Xls));
}

#[test]
fn pdf_from_chrome_keeps_capitals_and_umlauts() {
    let t = text(Kind::Pdf, "chrome-3pages.pdf");
    for word in ["Rechnung", "Übung", "Ärger"] {
        assert!(t.contains(word), "missing {word} in {t:?}");
    }
}

#[test]
fn pdf_from_writer() {
    assert!(!text(Kind::Pdf, "libreoffice-writer.pdf").is_empty());
}

#[test]
fn same_text_in_docx_and_odt() {
    let docx = text(Kind::Docx, "a.docx");
    let odt = text(Kind::Odt, "a.odt");
    assert!(!docx.is_empty());
    let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(words(&docx), words(&odt));
}

#[test]
fn spreadsheets_and_presentations() {
    for (kind, name) in [
        (Kind::Xlsx, "t.xlsx"),
        (Kind::Ods, "t.ods"),
        (Kind::Pptx, "p.pptx"),
        (Kind::Odp, "p.odp"),
    ] {
        assert!(!text(kind, name).trim().is_empty(), "{name} has no text");
    }
}

#[test]
fn output_is_cut_at_the_limit_on_a_character() {
    let t = extract(Kind::Pdf, fixture("chrome-3pages.pdf"), 40).expect("test input");
    assert!(t.len() <= 40);
}

#[test]
fn garbage_is_an_error_for_every_kind() {
    for kind in [
        Kind::Pdf,
        Kind::Docx,
        Kind::Xlsx,
        Kind::Pptx,
        Kind::Doc,
        Kind::Xls,
        Kind::Ppt,
        Kind::Odt,
        Kind::Ods,
        Kind::Odp,
    ] {
        assert!(
            extract(kind, b"not a document".to_vec(), 1 << 20).is_err(),
            "{kind:?}"
        );
        assert!(
            extract(kind, Vec::new(), 1 << 20).is_err(),
            "{kind:?} empty"
        );
    }
}

fn odf_with(content: &str) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        zip.start_file("content.xml", zip::write::SimpleFileOptions::default())
            .expect("test input");
        zip.write_all(content.as_bytes()).expect("test input");
        zip.finish().expect("test input");
    }
    out
}

#[test]
fn odf_with_document_type_is_refused() {
    let xml = r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><office:document-content xmlns:office="o" xmlns:text="t"><text:p>&a;</text:p></office:document-content>"#;
    assert!(extract(Kind::Odt, odf_with(xml), 1 << 20).is_err());
}

#[test]
fn odf_unknown_entity_and_char_refs() {
    let xml = r#"<office:document-content xmlns:office="o" xmlns:text="t"><text:p>a&amp;b &#x41; &nope; end</text:p></office:document-content>"#;
    let t = extract(Kind::Odt, odf_with(xml), 1 << 20).expect("test input");
    assert!(t.contains("a&b A"), "{t:?}");
    assert!(t.contains("end"));
}

#[test]
fn odf_annotations_and_styles_are_not_text() {
    let xml = r#"<office:document-content xmlns:office="o" xmlns:text="t"><office:automatic-styles>STYLE</office:automatic-styles><text:p>body<office:annotation>NOTE</office:annotation></text:p></office:document-content>"#;
    let t = extract(Kind::Odt, odf_with(xml), 1 << 20).expect("test input");
    assert!(
        t.contains("body") && !t.contains("STYLE") && !t.contains("NOTE"),
        "{t:?}"
    );
}

#[test]
fn odf_without_content_xml_is_an_error() {
    let mut out = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        zip.start_file("other.xml", zip::write::SimpleFileOptions::default())
            .expect("test input");
        zip.write_all(b"<a/>").expect("test input");
        zip.finish().expect("test input");
    }
    assert!(extract(Kind::Odt, out, 1 << 20).is_err());
}

#[test]
fn odf_output_stops_at_the_limit() {
    let body = "<text:p>word word word word</text:p>".repeat(50_000);
    let xml = format!(
        r#"<office:document-content xmlns:office="o" xmlns:text="t">{body}</office:document-content>"#
    );
    let t = extract(Kind::Odt, odf_with(&xml), 1000).expect("test input");
    assert!(t.len() <= 1000);
}

#[test]
fn control_characters_and_blank_runs_are_tidied() {
    let xml = "<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><text:p>a\u{1}b      c</text:p><text:p></text:p><text:p></text:p><text:p></text:p><text:p>d</text:p></office:document-content>";
    let t = extract(Kind::Odt, odf_with(xml), 1 << 20).expect("test input");
    assert_eq!(t, "a b c\nd");
}

// ---- the child process, with stand-in programs for the reader ------------------------------------

mod child {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use rostdav_app::extract::{Kind, Outcome, run_child};

    /// A program that is called as `<it> internal-extract <kind> <max>` and does `body`.
    pub fn fake(dir: &Path, body: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = dir.join(format!("fake-{n}"));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    async fn run(exe: &Path, secs: u64) -> Outcome {
        run_child(
            exe,
            Kind::Pdf,
            b"%PDF".to_vec(),
            1000,
            Duration::from_secs(secs),
        )
        .await
    }

    #[tokio::test]
    async fn text_on_standard_output_is_the_result() {
        let dir = tempfile::tempdir().expect("dir");
        let exe = fake(dir.path(), "cat >/dev/null; printf 'hello %s' \"$2\"");
        assert_eq!(run(&exe, 10).await, Outcome::Text("hello pdf".into()));
    }

    #[tokio::test]
    async fn exit_code_two_means_unreadable_and_anything_else_failed() {
        let dir = tempfile::tempdir().expect("dir");
        assert_eq!(
            run(&fake(dir.path(), "exit 2"), 10).await,
            Outcome::Unreadable
        );
        assert_eq!(run(&fake(dir.path(), "exit 3"), 10).await, Outcome::Failed);
        assert_eq!(
            run(&fake(dir.path(), "kill -SEGV $$"), 10).await,
            Outcome::Failed
        );
        assert_eq!(
            run(&dir.path().join("does-not-exist"), 10).await,
            Outcome::Failed
        );
    }

    #[tokio::test]
    async fn output_over_the_limit_is_a_failure_not_a_big_allocation() {
        let dir = tempfile::tempdir().expect("dir");
        let exe = fake(dir.path(), "yes aaaaaaaaaaaaaaaaaaaa | head -c 100000000");
        assert_eq!(run(&exe, 20).await, Outcome::Failed);
    }

    #[tokio::test]
    async fn a_reader_that_hangs_is_stopped_and_does_not_outlive_the_call() {
        let dir = tempfile::tempdir().expect("dir");
        let pid_file = dir.path().join("pid");
        let exe = fake(
            dir.path(),
            &format!("echo $$ > {}; exec sleep 60", pid_file.display()),
        );
        let t = Instant::now();
        assert_eq!(run(&exe, 1).await, Outcome::Failed);
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        let pid = std::fs::read_to_string(&pid_file)
            .expect("pid")
            .trim()
            .to_owned();
        // the process is gone, or at most a zombie that nobody has collected yet
        for _ in 0..50 {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => return,
                Ok(s) if s.contains(") Z") => return,
                Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        panic!("the reader still runs");
    }

    #[tokio::test]
    async fn the_reader_does_not_see_the_servers_environment() {
        let dir = tempfile::tempdir().expect("dir");
        // HOME is set in nearly every environment a test runs in; the reader must not see it
        let exe = fake(
            dir.path(),
            "printf '%s' \"${HOME:-unset}${ROSTDAV_TOTP_KEY:-unset}\"",
        );
        assert_eq!(run(&exe, 10).await, Outcome::Text("unsetunset".into()));
    }
}
