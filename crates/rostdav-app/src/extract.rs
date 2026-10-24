//! Text out of PDF and Office files (ADR 0013).
//!
//! These parsers read files that anybody can upload, so they are **never run in the server
//! process**: [`crate::indexer`] starts `rostdav internal-extract <kind>` as a child process with a
//! memory limit, a CPU limit and a time-out, hands it the file on standard input and reads at most
//! a bounded amount of text back. A crash, a hang or a memory blow-up of a parser costs one child
//! and one file. This module is what runs inside the child (and what the tests call directly).

use std::io::{Cursor, Read};

use rostdav_core::{Error, Result};

/// The kinds of file with a reader of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Pdf,
    Docx,
    Xlsx,
    Pptx,
    /// The old binary Word, Excel and PowerPoint formats.
    Doc,
    Xls,
    Ppt,
    Odt,
    Ods,
    Odp,
}

impl Kind {
    /// The argument of `rostdav internal-extract`.
    pub fn arg(self) -> &'static str {
        match self {
            Kind::Pdf => "pdf",
            Kind::Docx => "docx",
            Kind::Xlsx => "xlsx",
            Kind::Pptx => "pptx",
            Kind::Doc => "doc",
            Kind::Xls => "xls",
            Kind::Ppt => "ppt",
            Kind::Odt => "odt",
            Kind::Ods => "ods",
            Kind::Odp => "odp",
        }
    }

    pub fn from_arg(arg: &str) -> Option<Kind> {
        [
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
        ]
        .into_iter()
        .find(|k| k.arg() == arg)
    }

    /// By the extension of the name (the content is checked by the reader).
    pub fn of_name(name: &str) -> Option<Kind> {
        let (_, ext) = name.rsplit_once('.')?;
        Kind::from_arg(&ext.to_ascii_lowercase())
    }
}

/// Pages of a PDF read at most: the text limit usually stops earlier.
const MAX_PDF_PAGES: usize = 5000;

/// Text of at most `max_bytes` bytes (cut at a character) out of `bytes`, read as `kind`.
/// Control characters become spaces, runs of blanks and blank lines are shortened.
pub fn extract(kind: Kind, bytes: Vec<u8>, max_bytes: usize) -> Result<String> {
    let raw = match kind {
        Kind::Pdf => pdf(bytes, max_bytes)?,
        Kind::Docx | Kind::Xlsx | Kind::Pptx | Kind::Doc | Kind::Xls | Kind::Ppt => {
            office(kind, bytes)?
        }
        Kind::Odt | Kind::Ods | Kind::Odp => odf(bytes, max_bytes)?,
    };
    Ok(tidy(&raw, max_bytes))
}

fn pdf(bytes: Vec<u8>, max_bytes: usize) -> Result<String> {
    let doc = pdf_oxide::PdfDocument::from_bytes(bytes)
        .map_err(|_| Error::BadRequest("not a readable PDF"))?;
    let pages = doc
        .page_count()
        .map_err(|_| Error::BadRequest("not a readable PDF"))?
        .min(MAX_PDF_PAGES);
    let mut out = String::new();
    for page in 0..pages {
        // a page that cannot be read does not spoil the others
        if let Ok(text) = doc.extract_text(page) {
            out.push_str(&text);
            out.push('\n');
        }
        if out.len() > max_bytes.saturating_mul(2) {
            break;
        }
    }
    Ok(out)
}

fn office(kind: Kind, bytes: Vec<u8>) -> Result<String> {
    use office_oxide::DocumentFormat as F;
    let format = match kind {
        Kind::Docx => F::Docx,
        Kind::Xlsx => F::Xlsx,
        Kind::Pptx => F::Pptx,
        Kind::Doc => F::Doc,
        Kind::Xls => F::Xls,
        _ => F::Ppt,
    };
    // what one document may make the reader build: a spreadsheet can use one string in a million
    // cells, and a package can unpack to far more than it is
    office_oxide::limits::set_max_text_chars(16 << 20);
    office_oxide::limits::set_max_package_bytes(256 << 20);
    office_oxide::limits::set_max_package_entries(20_000);
    let doc = office_oxide::Document::from_reader(Cursor::new(bytes), format)
        .map_err(|_| Error::BadRequest("not a readable Office file"))?;
    Ok(doc.plain_text())
}

/// OpenDocument text, spreadsheets and presentations: the character data of `content.xml`.
fn odf(bytes: Vec<u8>, max_bytes: usize) -> Result<String> {
    use quick_xml::events::Event;
    const MAX_ENTRIES: usize = 20_000;
    const MAX_CONTENT: u64 = 256 << 20;
    let bad = || Error::BadRequest("not a readable OpenDocument file");
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| bad())?;
    if zip.len() > MAX_ENTRIES {
        return Err(bad());
    }
    let mut xml = Vec::new();
    zip.by_name("content.xml")
        .map_err(|_| bad())?
        // the size in the archive's directory is only what the file claims: count what comes out
        .take(MAX_CONTENT + 1)
        .read_to_end(&mut xml)
        .map_err(|_| bad())?;
    if xml.len() as u64 > MAX_CONTENT {
        return Err(bad());
    }
    let mut reader = quick_xml::Reader::from_reader(Cursor::new(xml));
    let mut out = String::new();
    let mut buf = Vec::new();
    // `office:annotation` and `office:automatic-styles` hold no text of the document
    let mut skip = 0u32;
    loop {
        match reader.read_event_into(&mut buf).map_err(|_| bad())? {
            // no document type declaration, so no entities to expand: refuse such a file
            Event::DocType(_) => return Err(bad()),
            Event::Eof => break,
            Event::Start(e) => {
                let name = e.name();
                if matches!(
                    name.0,
                    "office:annotation"
                        | "office:automatic-styles"
                        | "office:styles"
                        | "office:font-face-decls"
                ) {
                    skip += 1;
                } else if skip == 0 {
                    match name.0 {
                        // a new paragraph, row or slide
                        "text:p" | "text:h" | "table:table-row" | "draw:page"
                        | "text:list-item" => {
                            if !out.ends_with('\n') && !out.is_empty() {
                                out.push('\n');
                            }
                        }
                        "table:table-cell" if !out.is_empty() && !out.ends_with(['\n', '\t']) => {
                            out.push('\t');
                        }
                        _ => {}
                    }
                }
            }
            Event::End(e) => {
                if matches!(
                    e.name().0,
                    "office:annotation"
                        | "office:automatic-styles"
                        | "office:styles"
                        | "office:font-face-decls"
                ) {
                    skip = skip.saturating_sub(1);
                }
            }
            Event::Empty(e) if skip == 0 => match e.name().0 {
                "text:s" => out.push(' '),
                "text:tab" => out.push('\t'),
                "text:line-break" => out.push('\n'),
                _ => {}
            },
            Event::Text(t) if skip == 0 => {
                // a bad reference (`&unknown;`) is skipped, not an error: the rest is still text
                out.push_str(&t.xml10_content());
            }
            Event::GeneralRef(r) if skip == 0 => {
                // only the five predefined entities and character references
                match Ok::<_, ()>(r.xml10_content()).as_deref() {
                    Ok("amp") => out.push('&'),
                    Ok("lt") => out.push('<'),
                    Ok("gt") => out.push('>'),
                    Ok("quot") => out.push('"'),
                    Ok("apos") => out.push('\''),
                    _ => {
                        if let Ok(Some(c)) = r.resolve_char_ref() {
                            out.push(c);
                        }
                    }
                }
            }
            Event::CData(t) if skip == 0 => {
                out.push_str(&t.xml10_content());
            }
            _ => {}
        }
        buf.clear();
        if out.len() > max_bytes.saturating_mul(2) {
            break;
        }
    }
    Ok(out)
}

/// Shortens runs of blanks and blank lines, replaces control characters, and cuts at `max_bytes`.
fn tidy(raw: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_bytes));
    let (mut blanks, mut newlines) = (0usize, 0usize);
    for c in raw.chars() {
        let c = if c.is_control() && !matches!(c, '\n' | '\t') {
            ' '
        } else {
            c
        };
        match c {
            '\n' => {
                newlines += 1;
                blanks = 0;
                if newlines > 2 {
                    continue;
                }
            }
            ' ' | '\t' => {
                blanks += 1;
                if blanks > 1 {
                    continue;
                }
            }
            _ => {
                newlines = 0;
                blanks = 0;
            }
        }
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// Largest document handed to a reader; larger files are not read (the file size limit of the
/// search settings may be lower, never higher).
pub const MAX_DOCUMENT_BYTES: u64 = 128 << 20;

/// Exit code of the child: the file is not a document of the kind it claims to be.
const EXIT_UNREADABLE: i32 = 2;
/// Exit code of the child: wrong call.
const EXIT_USAGE: i32 = 64;
/// Address space of the child, in KiB (`ulimit -v`).
const CHILD_MEMORY_KIB: u64 = 3 << 20;

/// What the child process made of a file.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Text(String),
    /// The child ran and said the content is not readable; asking again does not help.
    Unreadable,
    /// The child crashed, ran out of time or memory, or could not be started.
    Failed,
}

/// `rostdav internal-extract <kind> <max_bytes>`: reads the file from standard input, writes the
/// text to standard output. Returns the exit code. Runs without the server's runtime or data.
pub fn child_main(kind: &str, max_bytes: &str) -> i32 {
    use std::io::Write;
    let (Some(kind), Ok(max)) = (Kind::from_arg(kind), max_bytes.parse::<usize>()) else {
        return EXIT_USAGE;
    };
    let mut bytes = Vec::new();
    if std::io::stdin()
        .lock()
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_DOCUMENT_BYTES
    {
        return EXIT_USAGE;
    }
    match extract(kind, bytes, max) {
        Ok(text) => {
            let mut out = std::io::stdout().lock();
            if out
                .write_all(text.as_bytes())
                .and_then(|()| out.flush())
                .is_err()
            {
                return EXIT_USAGE;
            }
            0
        }
        Err(_) => EXIT_UNREADABLE,
    }
}

/// Runs `exe internal-extract` on `bytes` under a memory limit, a CPU limit and `timeout`.
/// A reader that crashes, hangs or eats memory costs this one file and nothing else.
pub async fn run_child(
    exe: &std::path::Path,
    kind: Kind,
    bytes: Vec<u8>,
    max_bytes: usize,
    timeout: std::time::Duration,
) -> Outcome {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    let cpu_secs = timeout.as_secs() + 5;
    // `exec` replaces the shell, so the process that is killed on a time-out is the reader itself
    let script = format!(
        "ulimit -v {CHILD_MEMORY_KIB} && ulimit -t {cpu_secs} && exec \"$0\" internal-extract \"$1\" \"$2\""
    );
    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(exe)
        .arg(kind.arg())
        .arg(max_bytes.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "could not start the document reader");
            return Outcome::Failed;
        }
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Outcome::Failed;
    };
    let work = async {
        // feeding and reading at once, or a full pipe in one direction would stall both
        let feed = async move {
            // the child may stop reading (and exit) early; its exit code tells what happened
            let _ = stdin.write_all(&bytes).await;
            drop(stdin);
        };
        let limit = u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let read = async move {
            let mut out = Vec::new();
            let mut stdout = stdout.take(limit);
            let ok = stdout.read_to_end(&mut out).await.is_ok();
            (ok, out)
        };
        let ((), (read_ok, out)) = tokio::join!(feed, read);
        let status = child.wait().await;
        (read_ok, out, status)
    };
    let Ok((read_ok, out, status)) = tokio::time::timeout(timeout, work).await else {
        // dropping the future drops the child, which kills it
        tracing::warn!("the document reader took too long and was stopped");
        return Outcome::Failed;
    };
    match status {
        Ok(s) if s.code() == Some(0) && read_ok && out.len() <= max_bytes => {
            match String::from_utf8(out) {
                Ok(text) => Outcome::Text(text),
                Err(_) => Outcome::Failed,
            }
        }
        Ok(s) if s.code() == Some(EXIT_UNREADABLE) => Outcome::Unreadable,
        _ => Outcome::Failed,
    }
}
