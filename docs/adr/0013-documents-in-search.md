# ADR 0013: PDF and Office files in the search

- Status: **Accepted** by the project owner with the release of 0.8.0 (2026-10-24), on whose request of the same day ("Next options are PDF and Office text") it was built as stage 5 of the search plan ([ADR 0012](0012-search-index.md)).
- Date: 2026-10-24

## Context

Users want to find a file by the words inside a PDF, Word, Excel, PowerPoint or OpenDocument file. The parsers for these formats read files that **anybody with an account (or an upload link) can store**, so a parser bug is reachable by an attacker. Rust parsers do not corrupt memory, but they can still panic, overflow the stack (which aborts the process), loop, or use gigabytes for a small file.

## Decision

1. **Libraries** (chosen by a spike on real and hostile files, 2026-10-24):
   - **`pdf_oxide`** for PDF (MIT OR Apache-2.0). It matched `pdftotext` on all test words, including PDFs printed by Chrome. `pdf-extract` split words after capital letters in the same files ("Rechnung", "Übung" were not found), was aborted by a flate bomb and needed 84 s for a 3 GB blank stream. On 61 hostile PDFs `pdf_oxide` gave 57 results or clean errors, 3 caught panics and 1 abort (a stack overflow at 200,000 levels of nesting): none a timeout.
   - **`office_oxide`** for `docx`, `xlsx`, `pptx` and the old binary `doc`, `xls`, `ppt` (it is also a dependency of `pdf_oxide`). On 64 hostile files: no panic, hang or abort; zip bombs are refused (512 MiB per part), entity bombs and external entities are not expanded. A spreadsheet that repeats one string in millions of cells made 268 MB of text and 645 MiB of memory, so the reader runs with `limits::set_max_text_chars` (16 Mi characters), `set_max_package_bytes` (256 MiB) and an entry limit.
   - **Own reader for OpenDocument** (`zip` and `quick-xml`, which the project already uses): only `content.xml`, read through `take()` with a 256 MiB limit, no document type declaration (so no entities), at most 20,000 archive entries. `office_oxide` does not read ODF.
   - `zip` is a direct dependency (the same major version as `office_oxide` uses, so one copy); deflate only.
2. **A separate process.** Panics could be caught, but a stack overflow, an out-of-memory kill or an endless loop cannot be caught in the process that also serves everybody's files. The indexer starts `rostdav internal-extract <kind> <max_bytes>` per document, through `sh -c 'ulimit -v 3 GiB && ulimit -t 65 && exec …'`, with an empty environment, the file on standard input, the text on standard output (read up to the limit only), a 60 second time-out and `kill_on_drop`. The child needs neither configuration nor the async runtime. Exit code 0 is a result, 2 means "not a readable document" (the file is marked not readable, no retry), anything else (a signal, a time-out, another code) counts as a failure and the file is tried again, three times at most (as for text files).
3. **Limits:** files over 128 MiB are not read (the setting "largest file whose text is read" can lower it); at most `search.max_text_kib` of text is kept; control characters become blanks; runs of blanks and empty lines are shortened.
4. **Setting:** `search.documents` (`[search] documents`, Administration, Server; on by default). Off, or on again, reads the files once more, and off removes their stored texts. The text reader's version is now 2, so every file that was "not text" before is looked at again once.
5. **Not covered:** scanned PDFs (no text layer, no OCR), password-protected files (reported as unreadable), embedded files, text in images.
6. **Advisory:** `pdf_oxide` depends on `ttf-parser`, which is marked unmaintained (RUSTSEC-2026-0192; no vulnerability is known). `deny.toml` ignores that one advisory with a reason; the code runs only in the limited child process.
7. **Rust 1.88** is the minimum from now on (`pdf_oxide` needs it). The newer lints that came with it (`collapsible_if` with `let` chains) were applied across the code.

## Consequences

- Many more crates in the dependency tree (mostly `pdf_oxide`'s image and font readers); the binary grows. They are only called in the child process.
- One more process per document while indexing: tens of milliseconds start-up, run one at a time with pauses, so uploads are not slowed.
- On systems without `sh` or without `ulimit -v` (not Linux or a container image without a shell) documents are not read; the files stay findable by name.

## Tests

Fixtures from Chrome and LibreOffice Writer (PDF, docx, odt) and small hand-made xlsx, pptx, ods, odp; garbage for every kind; ODF with a document type declaration, with unknown entities, with annotations; output limits; stand-in reader programs for the parent side (result, exit codes, signal, output too large, hang and kill, empty environment); the real child on the fixtures, on a 200,000-deep PDF and on a zip bomb; the indexer with a stand-in (found, unreadable, crashing after three tries, switching on and off, nobody else sees the text).
