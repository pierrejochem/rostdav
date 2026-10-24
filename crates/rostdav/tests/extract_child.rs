//! The real `rostdav internal-extract` process on documents, good and hostile (ADR 0013).

use std::time::Duration;

use rostdav_app::extract::{Kind, Outcome, run_child};

fn exe() -> std::path::PathBuf {
    env!("CARGO_BIN_EXE_rostdav").into()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../rostdav-app/tests/fixtures/extract/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("fixture")
}

async fn read(kind: Kind, bytes: Vec<u8>) -> Outcome {
    run_child(&exe(), kind, bytes, 1 << 20, Duration::from_secs(60)).await
}

#[tokio::test]
async fn every_fixture_is_read_by_the_real_child() {
    for (kind, name, word) in [
        (Kind::Pdf, "chrome-3pages.pdf", "Rechnung"),
        (Kind::Docx, "a.docx", ""),
        (Kind::Odt, "a.odt", ""),
        (Kind::Xlsx, "t.xlsx", ""),
        (Kind::Ods, "t.ods", ""),
        (Kind::Pptx, "p.pptx", ""),
        (Kind::Odp, "p.odp", ""),
    ] {
        match read(kind, fixture(name)).await {
            Outcome::Text(t) => assert!(t.contains(word) && !t.is_empty(), "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn files_that_are_not_what_they_claim_are_unreadable_not_failed() {
    assert_eq!(
        read(Kind::Pdf, b"just some text".to_vec()).await,
        Outcome::Unreadable
    );
    assert_eq!(
        read(Kind::Docx, b"PK\x03\x04 broken".to_vec()).await,
        Outcome::Unreadable
    );
}

#[tokio::test]
async fn a_pdf_nested_a_hundred_thousand_levels_deep_cannot_hurt_the_test_process() {
    // the reader may report it or die of it (a stack overflow aborts the process); either way this
    // process goes on and no text comes out
    let mut pdf = b"%PDF-1.4\n1 0 obj\n".to_vec();
    pdf.extend(std::iter::repeat_n(b'[', 200_000));
    pdf.extend_from_slice(b"\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let out = read(Kind::Pdf, pdf).await;
    assert!(
        matches!(out, Outcome::Unreadable | Outcome::Failed),
        "{out:?}"
    );
}

#[tokio::test]
async fn a_zip_bomb_in_an_office_file_is_refused() {
    use std::io::Write;
    // 520 MiB of blanks in a part of a docx: tiny on disk, huge when unpacked
    let mut out = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("word/document.xml", opts).expect("start");
        let chunk = vec![b' '; 1 << 20];
        for _ in 0..520 {
            zip.write_all(&chunk).expect("write");
        }
        zip.finish().expect("finish");
    }
    assert!(out.len() < 4 << 20, "the bomb is small: {}", out.len());
    let r = read(Kind::Docx, out).await;
    assert!(!matches!(r, Outcome::Text(_)), "{r:?}");
}
