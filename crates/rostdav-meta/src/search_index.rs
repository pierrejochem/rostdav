//! The search index: a derived, rebuildable database in its own file (ADR 0012).
//!
//! It holds, per node, the folded name and the extracted text of the file. Nothing in it is the
//! only copy of anything: if the file is missing, older than the format this program writes,
//! or fails the engine's integrity check, it is deleted and built again from the metadata
//! database and the blobs. The main database is never opened with the engine's experimental
//! index methods and has no table for the index.
//!
//! The index only gives **candidates**. Who may see a hit is decided by the caller with the
//! normal access check; nothing here knows about users except the owner id that narrows the
//! candidates.

use std::path::{Path, PathBuf};

use rostdav_core::{Error, Result};

use crate::sql;

/// Bumped when the layout below changes; an index of another version is dropped and rebuilt.
pub const FORMAT_VERSION: i64 = 1;

/// Body states of a row.
pub mod state {
    /// The text has not been extracted yet.
    pub const PENDING: i64 = 0;
    /// `body` and `text` are the extracted text.
    pub const INDEXED: i64 = 1;
    /// The file is larger than the configured limit.
    pub const TOO_BIG: i64 = 2;
    /// Not a file with text (a folder, or a type that is not read), or content indexing is off.
    pub const UNSUPPORTED: i64 = 3;
    /// Extraction failed (repeatedly, after `MAX_FAILS`).
    pub const FAILED: i64 = 4;
}

/// A file that failed this many times is left alone until its content changes.
pub const MAX_FAILS: i64 = 3;

fn db_err(e: sql::Error) -> Error {
    Error::internal(e)
}

/// What the metadata database says about a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeFacts {
    pub node_id: i64,
    pub owner_id: i64,
    pub name_key: String,
    /// The name as it is compared: see `rostdav_core::fold::fold_loose`.
    pub name_fold: String,
    pub is_dir: bool,
    pub blob_id: Option<String>,
    pub size: i64,
    pub mtime: i64,
}

/// A row of the index as far as the comparison with the nodes needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocFacts {
    pub node_id: i64,
    pub owner_id: i64,
    pub name_key: String,
    pub is_dir: bool,
    pub blob_id: Option<String>,
    pub size: i64,
    pub mtime: i64,
}

/// A file whose text has to be extracted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub node_id: i64,
    pub blob_id: String,
    pub name_key: String,
    pub size: i64,
}

/// What the administration shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexStatus {
    pub docs: i64,
    pub indexed: i64,
    pub pending: i64,
    pub too_big: i64,
    pub unsupported: i64,
    pub failed: i64,
    /// Bytes of the index file and its log.
    pub size_bytes: u64,
    pub content_enabled: bool,
    pub last_pass_at: Option<i64>,
}

/// What was read from a file.
#[derive(Clone, Copy, Debug)]
pub struct Content<'a> {
    /// The text as it is (shown in snippets).
    pub text: &'a str,
    /// The folded text (what is searched).
    pub body: &'a str,
    /// One of [`state`].
    pub state: i64,
    pub extractor_ver: i64,
    pub now: i64,
}

/// A candidate found by the full-text query.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub node_id: i64,
    pub score: f64,
}

pub struct SearchIndex {
    pool: sql::Pool,
    path: PathBuf,
}

fn files_of(path: &Path) -> [PathBuf; 3] {
    let s = path.as_os_str().to_owned();
    let with = |suffix: &str| {
        let mut t = s.clone();
        t.push(suffix);
        PathBuf::from(t)
    };
    [path.to_path_buf(), with("-wal"), with("-shm")]
}

impl SearchIndex {
    /// Opens the index at `path`, creating it, or deleting and creating it again if it is of
    /// another format or damaged. Returns whether it was (re)created, i.e. is empty.
    pub async fn open(path: &Path) -> Result<(Self, bool)> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(Error::internal)?;
        }
        match Self::try_open(path).await {
            Ok(Some(index)) => return Ok((index, false)),
            Ok(None) => tracing::warn!("search index has another format: building it again"),
            Err(e) => tracing::warn!(error = %e, "search index is damaged: building it again"),
        }
        for f in files_of(path) {
            match std::fs::remove_file(&f) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::internal(e)),
            }
        }
        let index = Self::create(path).await?;
        Ok((index, true))
    }

    async fn pool_of(path: &Path) -> Result<sql::Pool> {
        let p = path
            .to_str()
            .ok_or(Error::BadRequest("the data directory path is not UTF-8"))?;
        sql::Pool::open_with(p, true).await.map_err(db_err)
    }

    /// `Ok(None)`: it exists, but is not what this program writes.
    async fn try_open(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(Some(Self::create(path).await?));
        }
        let pool = Self::pool_of(path).await?;
        let version: Option<String> =
            sql::query_scalar("SELECT value FROM meta WHERE key = 'format_version'")
                .fetch_optional(&pool)
                .await
                .map_err(db_err)?;
        if version.and_then(|v| v.parse::<i64>().ok()) != Some(FORMAT_VERSION) {
            pool.close().await;
            return Ok(None);
        }
        let check: Vec<String> = sql::query_scalar("PRAGMA integrity_check")
            .fetch_all(&pool)
            .await
            .map_err(db_err)?;
        if check != ["ok"] {
            pool.close().await;
            return Err(Error::Conflict("integrity check failed"));
        }
        Ok(Some(Self {
            pool,
            path: path.to_path_buf(),
        }))
    }

    async fn create(path: &Path) -> Result<Self> {
        let pool = Self::pool_of(path).await?;
        for ddl in [
            "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS docs(
                node_id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                name_key TEXT NOT NULL,
                name_fold TEXT NOT NULL,
                is_dir INTEGER NOT NULL,
                blob_id TEXT,
                size INTEGER NOT NULL,
                mtime INTEGER NOT NULL,
                text TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                body_state INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                extractor_ver INTEGER NOT NULL DEFAULT 0,
                indexed_at INTEGER NOT NULL DEFAULT 0)",
            "CREATE INDEX IF NOT EXISTS docs_owner ON docs(owner_id)",
            "CREATE INDEX IF NOT EXISTS docs_pending ON docs(body_state, mtime)",
            "CREATE INDEX IF NOT EXISTS docs_body_fts ON docs USING fts (body) WITH (tokenizer = 'default')",
        ] {
            sql::query(ddl).execute(&pool).await.map_err(db_err)?;
        }
        sql::query("INSERT OR REPLACE INTO meta(key, value) VALUES ('format_version', ?)")
            .bind(FORMAT_VERSION.to_string())
            .execute(&pool)
            .await
            .map_err(db_err)?;
        Ok(Self {
            pool,
            path: path.to_path_buf(),
        })
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    // ---- meta ----------------------------------------------------------------------

    pub async fn meta(&self, key: &str) -> Result<Option<String>> {
        sql::query_scalar("SELECT value FROM meta WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)
    }

    pub async fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        sql::query("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    // ---- names: comparison with the metadata database ----------------------------------

    /// The rows with `lo <= node_id <= hi`.
    pub async fn docs_between(&self, lo: i64, hi: i64) -> Result<Vec<DocFacts>> {
        type R = (i64, i64, String, i64, Option<String>, i64, i64);
        let rows: Vec<R> = sql::query_as(
            "SELECT node_id, owner_id, name_key, is_dir, blob_id, size, mtime FROM docs
             WHERE node_id >= ? AND node_id <= ? ORDER BY node_id",
        )
        .bind(lo)
        .bind(hi)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| DocFacts {
                node_id: r.0,
                owner_id: r.1,
                name_key: r.2,
                is_dir: r.3 != 0,
                blob_id: r.4,
                size: r.5,
                mtime: r.6,
            })
            .collect())
    }

    /// Writes new and changed nodes and removes the rows of nodes that are gone, in one
    /// transaction. A changed `blob_id` (or a node that became a folder) starts the text over.
    pub async fn apply(&self, upserts: &[NodeFacts], deletes: &[i64]) -> Result<()> {
        if upserts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        for n in upserts {
            let had: Option<(Option<String>,)> =
                sql::query_as("SELECT blob_id FROM docs WHERE node_id = ?")
                    .bind(n.node_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?;
            let new_state = if n.is_dir {
                state::UNSUPPORTED
            } else {
                state::PENDING
            };
            match had {
                None => {
                    sql::query(
                        "INSERT INTO docs(node_id, owner_id, name_key, name_fold, is_dir, blob_id, size, mtime, body_state)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(n.node_id)
                    .bind(n.owner_id)
                    .bind(&n.name_key)
                    .bind(&n.name_fold)
                    .bind(i64::from(n.is_dir))
                    .bind(&n.blob_id)
                    .bind(n.size)
                    .bind(n.mtime)
                    .bind(new_state)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                Some((old_blob,)) => {
                    let content_changed = old_blob != n.blob_id;
                    if content_changed {
                        sql::query(
                            "UPDATE docs SET owner_id = ?, name_key = ?, name_fold = ?, is_dir = ?, blob_id = ?, size = ?, mtime = ?,
                                 text = '', body = '', body_state = ?, fail_count = 0, extractor_ver = 0, indexed_at = 0
                             WHERE node_id = ?",
                        )
                        .bind(n.owner_id)
                        .bind(&n.name_key)
                        .bind(&n.name_fold)
                        .bind(i64::from(n.is_dir))
                        .bind(&n.blob_id)
                        .bind(n.size)
                        .bind(n.mtime)
                        .bind(new_state)
                        .bind(n.node_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    } else {
                        // a rename, a move to another owner, a new modification time: the text stays
                        sql::query(
                            "UPDATE docs SET owner_id = ?, name_key = ?, name_fold = ?, is_dir = ?, size = ?, mtime = ? WHERE node_id = ?",
                        )
                        .bind(n.owner_id)
                        .bind(&n.name_key)
                        .bind(&n.name_fold)
                        .bind(i64::from(n.is_dir))
                        .bind(n.size)
                        .bind(n.mtime)
                        .bind(n.node_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    }
                }
            }
        }
        for id in deletes {
            sql::query("DELETE FROM docs WHERE node_id = ?")
                .bind(*id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    /// Removes every row above `id` (nodes that were deleted at the end of the id range).
    pub async fn delete_above(&self, id: i64) -> Result<u64> {
        let done = sql::query("DELETE FROM docs WHERE node_id > ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    // ---- content ----------------------------------------------------------------------

    /// Files waiting for their text, the most recently changed first.
    pub async fn next_pending(&self, limit: i64) -> Result<Vec<Pending>> {
        let rows: Vec<(i64, String, String, i64)> = sql::query_as(
            "SELECT node_id, blob_id, name_key, size FROM docs
             WHERE body_state = 0 AND is_dir = 0 AND blob_id IS NOT NULL
             ORDER BY mtime DESC, node_id LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| Pending {
                node_id: r.0,
                blob_id: r.1,
                name_key: r.2,
                size: r.3,
            })
            .collect())
    }

    /// Stores the result for a file, if it still has the content the text was read from.
    pub async fn set_content(&self, node_id: i64, blob_id: &str, c: &Content<'_>) -> Result<bool> {
        let done = sql::query(
            "UPDATE docs SET text = ?, body = ?, body_state = ?, extractor_ver = ?, indexed_at = ?, fail_count = 0
             WHERE node_id = ? AND blob_id = ?",
        )
        .bind(c.text)
        .bind(c.body)
        .bind(c.state)
        .bind(c.extractor_ver)
        .bind(c.now)
        .bind(node_id)
        .bind(blob_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(done.rows_affected() > 0)
    }

    /// Counts a failed extraction; after [`MAX_FAILS`] the file is given up on until it changes.
    pub async fn note_failure(&self, node_id: i64, blob_id: &str, now: i64) -> Result<()> {
        sql::query(
            "UPDATE docs SET fail_count = fail_count + 1, indexed_at = ?,
                 body_state = CASE WHEN fail_count + 1 >= ? THEN ? ELSE body_state END
             WHERE node_id = ? AND blob_id = ?",
        )
        .bind(now)
        .bind(MAX_FAILS)
        .bind(state::FAILED)
        .bind(node_id)
        .bind(blob_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Starts the extraction over for rows made by an older extractor (`indexed` and
    /// `unsupported` ones), so that a better one gets its chance.
    pub async fn requeue_older_than(&self, extractor_ver: i64) -> Result<u64> {
        let done = sql::query(
            "UPDATE docs SET body_state = 0, fail_count = 0 WHERE is_dir = 0 AND extractor_ver < ? AND body_state IN (1, 2, 3, 4)",
        )
        .bind(extractor_ver)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    /// Content indexing was switched off: forget every text.
    pub async fn drop_contents(&self) -> Result<u64> {
        let done = sql::query(
            "UPDATE docs SET text = '', body = '', body_state = ?, extractor_ver = 0 WHERE is_dir = 0 AND (body_state != ? OR body != '')",
        )
        .bind(state::UNSUPPORTED)
        .bind(state::UNSUPPORTED)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    /// Content indexing was switched on: read every file again.
    pub async fn requeue_all(&self) -> Result<u64> {
        let done = sql::query("UPDATE docs SET body_state = 0, fail_count = 0 WHERE is_dir = 0")
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    // ---- queries ----------------------------------------------------------------------

    /// Files whose text contains what `fts_query` asks for (the engine's query language: build
    /// it with `fts_query_from_text`, never pass user input on as it is), best first. `owners`
    /// narrows the candidates to the users whose files the caller might see.
    pub async fn search_text(
        &self,
        fts_query: &str,
        owners: &[i64],
        limit: i64,
    ) -> Result<Vec<Candidate>> {
        if owners.is_empty() || fts_query.is_empty() {
            return Ok(Vec::new());
        }
        let marks = owners.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql_text = format!(
            "SELECT node_id, fts_score(body, ?1) AS s FROM docs
             WHERE body MATCH ?1 AND owner_id IN ({marks}) AND body_state = 1
             ORDER BY s DESC, node_id LIMIT ?"
        );
        // `?1` is used twice; the owners follow as `?`: bind in order of appearance
        let sql_text = sql_text.replacen("?1", "?", 2);
        let mut q = sql::query_as::<(i64, f64)>(sql_text)
            .bind(fts_query)
            .bind(fts_query);
        for o in owners {
            q = q.bind(*o);
        }
        let rows = q.bind(limit).fetch_all(&self.pool).await.map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|(node_id, score)| Candidate { node_id, score })
            .collect())
    }

    /// The stored text of one file, for the snippet of a hit the caller was allowed to see.
    pub async fn text_of(&self, node_id: i64) -> Result<Option<String>> {
        sql::query_scalar("SELECT text FROM docs WHERE node_id = ? AND body_state = 1")
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)
    }

    pub async fn status(&self) -> Result<IndexStatus> {
        let counts: Vec<(i64, i64)> = sql::query_as(
            "SELECT body_state, count(*) FROM docs WHERE is_dir = 0 GROUP BY body_state",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let total: i64 = sql::query_scalar("SELECT count(*) FROM docs")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        let mut s = IndexStatus {
            docs: total,
            ..IndexStatus::default()
        };
        for (st, n) in counts {
            match st {
                state::INDEXED => s.indexed = n,
                state::PENDING => s.pending = n,
                state::TOO_BIG => s.too_big = n,
                state::UNSUPPORTED => s.unsupported = n,
                state::FAILED => s.failed = n,
                _ => {}
            }
        }
        s.size_bytes = files_of(&self.path)
            .iter()
            .filter_map(|f| std::fs::metadata(f).ok())
            .map(|m| m.len())
            .sum();
        s.content_enabled = self.meta("content_enabled").await?.as_deref() != Some("0");
        s.last_pass_at = self
            .meta("last_pass_at")
            .await?
            .and_then(|v| v.parse().ok());
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: i64, owner: i64, name: &str, blob: Option<&str>) -> NodeFacts {
        NodeFacts {
            node_id: id,
            owner_id: owner,
            name_key: name.to_owned(),
            name_fold: rostdav_core::fold::fold_loose(name),
            is_dir: blob.is_none(),
            blob_id: blob.map(str::to_owned),
            size: 1,
            mtime: id,
        }
    }

    async fn fresh() -> (tempfile::TempDir, SearchIndex) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (index, created) = SearchIndex::open(&dir.path().join("db").join("search.sqlite"))
            .await
            .expect("open");
        assert!(!created, "a missing file is created, not 'rebuilt'");
        (dir, index)
    }

    async fn index_text(i: &SearchIndex, id: i64, blob: &str, text: &str) {
        let body = rostdav_core::fold::fold_loose(text);
        let c = Content {
            text,
            body: &body,
            state: state::INDEXED,
            extractor_ver: 1,
            now: 100,
        };
        assert!(i.set_content(id, blob, &c).await.expect("set"));
    }

    #[tokio::test]
    async fn new_changed_and_removed_nodes_are_carried_over() {
        let (_d, i) = fresh().await;
        i.apply(
            &[
                node(1, 1, "Docs", None),
                node(2, 1, "a.txt", Some("B1")),
                node(3, 2, "b.txt", Some("B2")),
            ],
            &[],
        )
        .await
        .expect("apply");
        let docs = i.docs_between(0, 100).await.expect("docs");
        assert_eq!(
            docs.iter().map(|d| d.node_id).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(docs[0].is_dir && !docs[1].is_dir);
        // files wait for their text, folders never do
        let pending = i.next_pending(10).await.expect("pending");
        assert_eq!(
            pending.iter().map(|p| p.node_id).collect::<Vec<_>>(),
            [3, 2],
            "newest first"
        );
        // a rename keeps the text; a new blob throws it away
        index_text(&i, 2, "B1", "Hello World").await;
        i.apply(&[node(2, 1, "renamed.txt", Some("B1"))], &[])
            .await
            .expect("rename");
        assert_eq!(
            i.text_of(2).await.expect("text").as_deref(),
            Some("Hello World")
        );
        i.apply(&[node(2, 1, "renamed.txt", Some("B1-new"))], &[])
            .await
            .expect("edit");
        assert_eq!(i.text_of(2).await.expect("text"), None);
        assert_eq!(i.next_pending(10).await.expect("pending").len(), 2);
        // removal
        i.apply(&[], &[3]).await.expect("delete");
        assert_eq!(i.docs_between(0, 100).await.expect("docs").len(), 2);
        assert_eq!(i.delete_above(1).await.expect("above"), 1);
        assert_eq!(i.docs_between(0, 100).await.expect("docs").len(), 1);
    }

    #[tokio::test]
    async fn text_is_found_by_whole_words_with_the_owner_as_a_filter() {
        let (_d, i) = fresh().await;
        i.apply(
            &[
                node(1, 1, "one.txt", Some("B1")),
                node(2, 1, "two.txt", Some("B2")),
                node(3, 2, "three.txt", Some("B3")),
            ],
            &[],
        )
        .await
        .expect("apply");
        index_text(&i, 1, "B1", "The quarterly report of the Rust server").await;
        index_text(&i, 2, "B2", "Café menu, über-nice naïve coöperation").await;
        index_text(&i, 3, "B3", "report of another owner, secret plans").await;
        let ids = |c: Vec<Candidate>| c.into_iter().map(|c| c.node_id).collect::<Vec<_>>();
        assert_eq!(
            ids(i.search_text("\"report\"", &[1], 10).await.expect("s")),
            [1]
        );
        assert_eq!(
            ids(i.search_text("\"report\"", &[2], 10).await.expect("s")),
            [3]
        );
        let mut both = ids(i.search_text("\"report\"", &[1, 2], 10).await.expect("s"));
        both.sort_unstable();
        assert_eq!(both, [1, 3]);
        assert!(
            i.search_text("\"report\"", &[], 10)
                .await
                .expect("s")
                .is_empty()
        );
        // accents are folded on both sides by the caller; here the folded text is what is searched
        assert_eq!(
            ids(i.search_text("\"cafe\"", &[1], 10).await.expect("s")),
            [2]
        );
        assert_eq!(
            ids(i
                .search_text("\"naive\" AND \"cooperation\"", &[1], 10)
                .await
                .expect("s")),
            [2]
        );
        // phrases, AND, OR, NOT
        assert_eq!(
            ids(i.search_text("\"rust server\"", &[1], 10).await.expect("s")),
            [1]
        );
        assert!(
            i.search_text("\"server rust\"", &[1], 10)
                .await
                .expect("s")
                .is_empty()
        );
        assert_eq!(
            ids(i
                .search_text("\"quarterly\" OR \"menu\"", &[1], 10)
                .await
                .expect("s"))
            .len(),
            2
        );
        // nothing for words that are not there, and the result is ranked with a score
        assert!(
            i.search_text("\"zzzz\"", &[1, 2], 10)
                .await
                .expect("s")
                .is_empty()
        );
        let hit = &i.search_text("\"report\"", &[1], 10).await.expect("s")[0];
        assert!(hit.score.is_finite());
        // a file whose text is not (yet) indexed is not found
        i.apply(&[node(1, 1, "one.txt", Some("B1-new"))], &[])
            .await
            .expect("edit");
        assert!(
            i.search_text("\"quarterly\"", &[1], 10)
                .await
                .expect("s")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn updated_and_deleted_text_stops_matching() {
        let (_d, i) = fresh().await;
        i.apply(&[node(1, 1, "a.txt", Some("B1"))], &[])
            .await
            .expect("apply");
        index_text(&i, 1, "B1", "alpha beta").await;
        assert_eq!(
            i.search_text("\"alpha\"", &[1], 10).await.expect("s").len(),
            1
        );
        i.apply(&[node(1, 1, "a.txt", Some("B2"))], &[])
            .await
            .expect("edit");
        index_text(&i, 1, "B2", "gamma delta").await;
        assert!(
            i.search_text("\"alpha\"", &[1], 10)
                .await
                .expect("s")
                .is_empty()
        );
        assert_eq!(
            i.search_text("\"gamma\"", &[1], 10).await.expect("s").len(),
            1
        );
        i.apply(&[], &[1]).await.expect("delete");
        assert!(
            i.search_text("\"gamma\"", &[1], 10)
                .await
                .expect("s")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_result_for_an_old_blob_is_not_stored_and_failures_give_up_after_three() {
        let (_d, i) = fresh().await;
        i.apply(&[node(1, 1, "a.txt", Some("B2"))], &[])
            .await
            .expect("apply");
        // the extractor read B1, but the file is B2 by now
        let old = Content {
            text: "old",
            body: "old",
            state: state::INDEXED,
            extractor_ver: 1,
            now: 1,
        };
        assert!(!i.set_content(1, "B1", &old).await.expect("set"));
        assert_eq!(i.status().await.expect("status").pending, 1);
        for _ in 0..MAX_FAILS - 1 {
            i.note_failure(1, "B2", 5).await.expect("fail");
        }
        assert_eq!(i.next_pending(10).await.expect("p").len(), 1, "still tried");
        i.note_failure(1, "B2", 6).await.expect("fail");
        let st = i.status().await.expect("status");
        assert_eq!((st.pending, st.failed), (0, 1));
        // a new content gives it another chance
        i.apply(&[node(1, 1, "a.txt", Some("B3"))], &[])
            .await
            .expect("edit");
        assert_eq!(i.status().await.expect("status").pending, 1);
    }

    #[tokio::test]
    async fn switching_content_off_and_on_and_a_new_extractor_requeue_the_files() {
        let (_d, i) = fresh().await;
        i.apply(
            &[node(1, 1, "a.txt", Some("B1")), node(2, 1, "dir", None)],
            &[],
        )
        .await
        .expect("apply");
        index_text(&i, 1, "B1", "findable words").await;
        assert_eq!(i.requeue_older_than(1).await.expect("same version"), 0);
        assert_eq!(i.requeue_older_than(2).await.expect("newer extractor"), 1);
        assert_eq!(i.status().await.expect("s").pending, 1);
        index_text(&i, 1, "B1", "findable words").await;
        // off: the text is forgotten, the file counts as unsupported, nothing is found
        assert_eq!(i.drop_contents().await.expect("drop"), 1);
        assert!(
            i.search_text("\"findable\"", &[1], 10)
                .await
                .expect("s")
                .is_empty()
        );
        let st = i.status().await.expect("s");
        assert_eq!(
            (st.indexed, st.pending, st.unsupported),
            (0, 0, 1),
            "folders are not counted"
        );
        // on: every file is read again (folders are not files)
        assert_eq!(i.requeue_all().await.expect("on"), 1);
        assert_eq!(i.status().await.expect("s").pending, 1);
    }

    #[tokio::test]
    async fn the_index_survives_a_reopen_and_status_counts_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("search.sqlite");
        {
            let (i, _) = SearchIndex::open(&path).await.expect("open");
            i.apply(&[node(1, 1, "a.txt", Some("B1"))], &[])
                .await
                .expect("apply");
            index_text(&i, 1, "B1", "persisted words").await;
            i.set_meta("last_pass_at", "1234").await.expect("meta");
            i.close().await;
        }
        let (i, created) = SearchIndex::open(&path).await.expect("reopen");
        assert!(!created);
        assert_eq!(
            i.search_text("\"persisted\"", &[1], 10)
                .await
                .expect("s")
                .len(),
            1
        );
        let st = i.status().await.expect("status");
        assert_eq!((st.docs, st.indexed, st.last_pass_at), (1, 1, Some(1234)));
        assert!(st.content_enabled && st.size_bytes > 0);
    }

    #[tokio::test]
    async fn another_format_or_a_broken_file_is_replaced_by_an_empty_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("search.sqlite");
        {
            let (i, _) = SearchIndex::open(&path).await.expect("open");
            i.apply(&[node(1, 1, "a.txt", Some("B1"))], &[])
                .await
                .expect("apply");
            i.set_meta("format_version", "999").await.expect("meta");
            i.close().await;
        }
        let (i, created) = SearchIndex::open(&path).await.expect("reopen");
        assert!(created, "another format is built again");
        assert_eq!(i.status().await.expect("s").docs, 0);
        i.close().await;
        // a file that is not a database at all
        std::fs::write(&path, b"this is not a database, not even close, at all, no")
            .expect("write");
        let (i, created) = SearchIndex::open(&path).await.expect("reopen");
        assert!(created, "a broken file is built again");
        assert_eq!(i.status().await.expect("s").docs, 0);
    }

    #[tokio::test]
    async fn the_main_database_is_not_touched_by_the_index_flag() {
        // the index methods are only switched on for the index file
        let dir = tempfile::tempdir().expect("tempdir");
        let main = sql::Pool::open(dir.path().join("main.sqlite").to_str().expect("utf8"))
            .await
            .expect("main");
        sql::query("CREATE TABLE t(x TEXT)")
            .execute(&main)
            .await
            .expect("table");
        let made = sql::query("CREATE INDEX t_fts ON t USING fts (x)")
            .execute(&main)
            .await;
        assert!(made.is_err(), "no full-text index in the main database");
    }
}
