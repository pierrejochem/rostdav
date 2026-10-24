# ADR 0012: The search index

- Status: **Accepted** by the project owner on 2026-10-24 (search plan approved; content indexing on by default, switchable by an administrator). Stage 2 (names and text files) built the same day. PDF and Office files, and the search of the Nextcloud apps, are later stages.
- Date: 2026-10-24

## Context

Search was a filter on one folder. The owner asked for search by name across everything a user can reach, and full-text search, for the web interface and the Nextcloud apps. The metadata database is Turso Database ([ADR 0008](0008-metadata-database-turso.md)), whose full-text index is an **experimental** feature (a Tantivy index stored in ordinary tables of the database file, switched on with `Builder::experimental_index_method(true)`).

## Decision

1. **The index is a separate file** `<data_dir>/db/search.sqlite`, opened with the experimental feature. The metadata database never uses it (a test checks that `CREATE INDEX … USING fts` is refused there) and has no table for the index. The index holds nothing that exists only there: it is dropped and built again when the file is missing, has another `format_version`, or fails `PRAGMA integrity_check`, and `rostdav admin search rebuild` does it on request. Backups do not contain it.
2. **Names are not searched through the full-text index.** A name search walks the user's tree downwards (own files, mounted shares) and compares folded names (`rostdav_core::fold`: Unicode case folding, accents and the two spellings of an accented letter do not matter). It is always correct and has no engine dependency. Only the **text of files** uses the full-text index.
3. **The index only produces candidates.** Each candidate is turned into the path the caller reaches it by (own path, or `mount name/…` for a share), resolved with `resolve_access`, and accepted only if that leads back to the same node and `authorize_access(Read)` passes. Trashed nodes cannot be resolved, so they never come out. Revoked or expired shares stop mattering at once, with no wait for the indexer. Link principals cannot search.
4. **The indexer** (`crates/rostdav-app/src/indexer.rs`) finds changes itself: it walks all nodes by id in batches of 1,000, compares them with the rows of the index and writes the differences (names part, reads only the metadata database), then reads the text of files that have none, a few at a time, newest first, within a time budget and with pauses (content part). No write path of the server knows about the index. A changed `blob_id` throws the old text away; renames, moves and new modification times keep it.
5. **What is read:** files whose name has a known text extension or none (`README`), whose content has no NUL byte in its first 8 KiB, up to a size limit (default 64 MiB) and keeping at most 1 MiB of text per file. Charset: byte-order mark (UTF-8, UTF-16), else UTF-8 if valid, else Windows-1252. The rules have a version number; a newer version reads the files again.
6. **Text is stored twice** per file: as it is (for snippets) and folded (what the full-text index sees: lower case, without accents). The query is built from quoted words so that nothing a user types is read as query syntax.
7. **Settings** (Administration, Server; the `[search]` section of the configuration): `content_indexing` (on by default; off removes the stored texts at the next pass, on reads every file again), `max_file_mib`, `max_text_kib`.
8. `rostdav admin search status|rebuild` (works beside the running server, [ADR 0010](0010-admin-socket.md)); the status is on the Server page.

## What the spike found (Turso 0.8.3, release build, 5,000 documents of 12 KB)

| | |
|---|---|
| Index 5,000 documents | 38.6 s (7.7 ms each), but the last 1,000 took 10.5 s against 4.7 s for the first 1,000: indexing slows as the index grows |
| Index size | 83 MB for 60 MB of text |
| Memory | about 100 MiB |
| Plain query | 0.2 to 1.2 ms; with owner filter and score for a very common word up to 70 ms |
| Single-row update / delete of a third | 9 ms each / 77 ms |
| Crash recovery | five kills of a writer in mid-write: no lost and no phantom rows, `integrity_check` ok, every sampled row findable |
| Phrase, AND, OR, minus, case-insensitive | work |
| Rollback | leaves nothing in the index |
| Reopen without the flag | the data can be read and written (the index follows) |
| **Prefix search (`serv*`)** | **does not work** (no hits) |
| **CJK** | only whole runs match, not parts of a run |
| Unbalanced quote or parenthesis | an error (hence the quoted query) |
| `fts_highlight` | returned the text without markers (snippets are built in Rust instead) |

## Consequences

- Text search finds **whole words** (no word beginnings, no parts of CJK text); names are found by any part. This is said in the documentation.
- **The index holds the text of the files in plain form**, in a file in the data directory (mode 0700). It is as sensitive as the files themselves. An administrator can switch content indexing off; the stored texts are then removed. The file can be left out of backups.
- Indexing 100,000 or more text documents has not been measured; the slowing of inserts as the index grows is the thing to watch. The indexer is throttled and can be switched off.
- Another engine version may change the on-disk format of the index: the format is versioned and a mismatch rebuilds it.
- A second source of results: text hits come after name hits and are limited per search (over-fetch with a cap); a very selective search may be cut and says so.

## Alternatives considered

- **Full-text index in the metadata database:** an experimental feature must not endanger the critical data, and an index that cannot be dropped is not a cache.
- **ngram index for names and prefix search:** unproven with this engine, larger index, makes names depend on the experimental feature.
- **Hooks in every write path:** many places to forget; the comparison pass is simpler and also repairs everything.
- **`tantivy` directly:** the fallback if Turso's index turns out unreliable; the index is behind one module (`rostdav-meta/src/search_index.rs`), so the change would stay inside it.
