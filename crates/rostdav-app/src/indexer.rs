//! Keeping the search index in step with the files (ADR 0012).
//!
//! A pass has two parts. The **names part** walks all nodes of the metadata database in order of
//! id, compares them with the rows of the index and writes what differs. It only reads the
//! metadata database. The **content part** reads the text of files that have none yet, a few at
//! a time, and sleeps between them so that uploads and downloads are not slowed. Nothing in the
//! write paths of the server knows about the index; a pass finds every change by itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rostdav_core::fold::fold_loose;
use rostdav_core::{Error, Result};
use rostdav_meta::{Content, DocFacts, IndexStatus, NodeFacts, SearchIndex, search_state};
use rostdav_storage::BlobId;

use crate::admin::Actor;
use crate::textdecode::{EXTRACTOR_VERSION, decode, may_be_text};
use crate::{AppState, now_secs};

/// Nodes compared per step of the names part.
const NODE_BATCH: i64 = 1000;
/// Time one pass may spend on reading text before it hands back.
const CONTENT_BUDGET: Duration = Duration::from_secs(20);
/// Files fetched from the index per step of the content part.
const CONTENT_STEP: i64 = 20;

/// What a pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    pub names_written: u64,
    pub names_removed: u64,
    pub texts_read: u64,
    /// Files that still wait for their text after this pass.
    pub pending: i64,
}

/// The index as the administration shows it.
#[derive(Clone, Debug, Default)]
pub struct SearchStatus {
    pub ready: bool,
    pub index: IndexStatus,
}

impl AppState {
    /// The index, opened on first use. `None` if it cannot be opened at all (search then works by
    /// names only, through the plain scan).
    pub(crate) async fn search_index(&self) -> Option<Arc<SearchIndex>> {
        if let Some(i) = self.inner.search_index.read().await.as_ref() {
            return Some(Arc::clone(i));
        }
        let mut slot = self.inner.search_index.write().await;
        if let Some(i) = slot.as_ref() {
            return Some(Arc::clone(i));
        }
        let path = self.inner.store.root().join("db").join("search.sqlite");
        match SearchIndex::open(&path).await {
            Ok((index, rebuilt)) => {
                if rebuilt {
                    tracing::info!("search index created");
                }
                let index = Arc::new(index);
                *slot = Some(Arc::clone(&index));
                Some(index)
            }
            Err(err) => {
                tracing::error!(error = %err, "search index cannot be opened; content search is off");
                None
            }
        }
    }

    /// One pass: compares names, then reads some text. Safe to call at any time; a second call
    /// while one runs does nothing.
    pub async fn indexer_pass(&self) -> Result<PassReport> {
        let Ok(_guard) = self.inner.indexing.try_lock() else {
            return Ok(PassReport::default());
        };
        let Some(index) = self.search_index().await else {
            return Ok(PassReport::default());
        };
        let mut report = PassReport::default();
        let cfg = self.cfg().search;

        // the setting and the stored state agree, or the texts are dropped / read again
        let was_on = index.meta("content_enabled").await?.as_deref() != Some("0");
        if was_on && !cfg.content {
            let n = index.drop_contents().await?;
            tracing::info!(
                files = n,
                "content indexing is off: texts removed from the index"
            );
        } else if !was_on && cfg.content {
            let n = index.requeue_all().await?;
            tracing::info!(files = n, "content indexing is on: texts will be read");
        }
        index
            .set_meta("content_enabled", if cfg.content { "1" } else { "0" })
            .await?;
        if cfg.content {
            let n = index.requeue_older_than(EXTRACTOR_VERSION).await?;
            if n > 0 {
                tracing::info!(files = n, "text reader changed: reading files again");
            }
        }

        self.names_part(&index, &mut report).await?;
        if cfg.content {
            self.content_part(&index, &mut report).await?;
        }
        report.pending = index.status().await?.pending;
        if !cfg.content {
            report.pending = 0;
        }
        index
            .set_meta("last_pass_at", &now_secs().to_string())
            .await?;
        Ok(report)
    }

    async fn names_part(&self, index: &SearchIndex, report: &mut PassReport) -> Result<()> {
        let mut cursor = 0i64;
        loop {
            let batch = self.inner.db.nodes_after(cursor, NODE_BATCH).await?;
            let Some(last) = batch.last().map(|n| n.node_id) else {
                break;
            };
            let have = index.docs_between(cursor + 1, last).await?;
            let (upserts, deletes) = diff(&batch, &have);
            report.names_written += upserts.len() as u64;
            report.names_removed += deletes.len() as u64;
            index.apply(&upserts, &deletes).await?;
            cursor = last;
            if (batch.len() as i64) < NODE_BATCH {
                break;
            }
            tokio::task::yield_now().await;
        }
        report.names_removed += index.delete_above(cursor).await?;
        Ok(())
    }

    async fn content_part(&self, index: &SearchIndex, report: &mut PassReport) -> Result<()> {
        let cfg = self.cfg().search;
        let started = Instant::now();
        while started.elapsed() < CONTENT_BUDGET {
            let todo = index.next_pending(CONTENT_STEP).await?;
            if todo.is_empty() {
                break;
            }
            for item in todo {
                let t = Instant::now();
                let (text, st) = if item.size
                    > i64::try_from(cfg.max_file_bytes).unwrap_or(i64::MAX)
                {
                    (String::new(), search_state::TOO_BIG)
                } else if !may_be_text(&item.name_key) {
                    (String::new(), search_state::UNSUPPORTED)
                } else {
                    match self
                        .read_text(&item.blob_id, cfg.max_file_bytes, cfg.max_text_bytes)
                        .await
                    {
                        Ok(Some(text)) => (text, search_state::INDEXED),
                        Ok(None) => (String::new(), search_state::UNSUPPORTED),
                        Err(err) => {
                            // the blob may be gone or unreadable; never log the name or the text
                            tracing::warn!(node = item.node_id, error = %err, "could not read a file for the search index");
                            index
                                .note_failure(item.node_id, &item.blob_id, now_secs())
                                .await?;
                            continue;
                        }
                    }
                };
                let body = fold_loose(&text);
                let content = Content {
                    text: &text,
                    body: &body,
                    state: st,
                    extractor_ver: EXTRACTOR_VERSION,
                    now: now_secs(),
                };
                index
                    .set_content(item.node_id, &item.blob_id, &content)
                    .await?;
                report.texts_read += 1;
                // as long as the work took again: at most half the time goes to the index
                tokio::time::sleep(t.elapsed().min(Duration::from_millis(500))).await;
            }
        }
        Ok(())
    }

    /// The text of a blob, or `None` if it is not text.
    async fn read_text(
        &self,
        blob_id: &str,
        max_file: u64,
        max_text: usize,
    ) -> Result<Option<String>> {
        use tokio::io::AsyncReadExt;
        let file = self.inner.store.open_blob(&BlobId::parse(blob_id)?).await?;
        // a little more than the text limit is enough to find it: UTF-16 doubles the bytes
        let want = u64::try_from(max_text)
            .unwrap_or(u64::MAX)
            .saturating_mul(2)
            .saturating_add(16)
            .min(max_file);
        let mut buf = Vec::new();
        file.take(want)
            .read_to_end(&mut buf)
            .await
            .map_err(Error::internal)?;
        Ok(decode(&buf, max_text))
    }

    /// The index for the administration (administrators only).
    pub async fn search_status(&self, actor: &Actor<'_>) -> Result<SearchStatus> {
        actor.require_admin()?;
        match self.search_index().await {
            Some(i) => Ok(SearchStatus {
                ready: true,
                index: i.status().await?,
            }),
            None => Ok(SearchStatus::default()),
        }
    }

    /// Throws the index away and builds it again from the metadata database and the blobs.
    pub async fn search_rebuild(&self, actor: &Actor<'_>) -> Result<()> {
        actor.require_admin()?;
        let _guard = self.inner.indexing.lock().await;
        let old = self.inner.search_index.write().await.take();
        if let Some(i) = old {
            i.close().await;
        }
        let path = self.inner.store.root().join("db").join("search.sqlite");
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.clone().into_os_string();
            p.push(suffix);
            match tokio::fs::remove_file(&p).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::internal(e)),
            }
        }
        self.audit(
            &actor.name(),
            "admin.search_rebuild",
            "",
            None,
            serde_json::json!({}),
        )
        .await;
        Ok(())
    }
}

/// What has to be written so that the rows `have` match `nodes` (both cover the same id range).
fn diff(nodes: &[NodeFacts], have: &[DocFacts]) -> (Vec<NodeFacts>, Vec<i64>) {
    let by_id: std::collections::HashMap<i64, &DocFacts> =
        have.iter().map(|d| (d.node_id, d)).collect();
    let upserts = nodes
        .iter()
        .filter(|n| {
            by_id.get(&n.node_id).is_none_or(|d| {
                d.owner_id != n.owner_id
                    || d.name_key != n.name_key
                    || d.is_dir != n.is_dir
                    || d.blob_id != n.blob_id
                    || d.size != n.size
                    || d.mtime != n.mtime
            })
        })
        .cloned()
        .collect();
    let live: std::collections::HashSet<i64> = nodes.iter().map(|n| n.node_id).collect();
    let deletes = have
        .iter()
        .map(|d| d.node_id)
        .filter(|id| !live.contains(id))
        .collect();
    (upserts, deletes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: i64, name: &str, blob: Option<&str>) -> NodeFacts {
        NodeFacts {
            node_id: id,
            owner_id: 1,
            name_key: name.into(),
            name_fold: fold_loose(name),
            is_dir: blob.is_none(),
            blob_id: blob.map(str::to_owned),
            size: 1,
            mtime: 1,
        }
    }

    fn d(id: i64, name: &str, blob: Option<&str>) -> DocFacts {
        DocFacts {
            node_id: id,
            owner_id: 1,
            name_key: name.into(),
            is_dir: blob.is_none(),
            blob_id: blob.map(str::to_owned),
            size: 1,
            mtime: 1,
        }
    }

    #[test]
    fn the_diff_finds_new_changed_and_gone_nodes_only() {
        let nodes = [
            n(1, "a", Some("B1")),
            n(2, "b", Some("B2")),
            n(4, "new", Some("B4")),
        ];
        let have = [
            d(1, "a", Some("B1")),
            d(2, "b-old", Some("B2")),
            d(3, "gone", Some("B3")),
        ];
        let (up, del) = diff(&nodes, &have);
        assert_eq!(up.iter().map(|x| x.node_id).collect::<Vec<_>>(), [2, 4]);
        assert_eq!(del, [3]);
        // identical: nothing to do
        let (up, del) = diff(&nodes[..1], &have[..1]);
        assert!(up.is_empty() && del.is_empty());
    }

    #[test]
    fn a_new_modification_time_or_owner_or_size_counts_as_a_change() {
        let mut changed = d(1, "a", Some("B1"));
        for f in [
            |x: &mut DocFacts| x.mtime = 2,
            |x: &mut DocFacts| x.size = 2,
            |x: &mut DocFacts| x.owner_id = 2,
        ] {
            f(&mut changed);
            assert_eq!(
                diff(&[n(1, "a", Some("B1"))], &[changed.clone()]).0.len(),
                1
            );
            changed = d(1, "a", Some("B1"));
        }
    }
}
