//! Search by name over everything the caller may read (search plan, stage 1).
//!
//! The scan walks **downwards** from the caller's own tree and the mount points of the shares
//! they received, and every node it reports has passed [`authorize_access`] with the access it
//! was reached by (own tree, or one share). Nothing is decided in SQL and nothing walks upwards,
//! so a hit can never be a node the caller could not also open by its path. Trashed nodes are not
//! visited (`children` leaves them out). A later index may supply candidates faster; it has to
//! go through the same check.

use rostdav_core::fold::{contains_loose, fold_loose};
use rostdav_core::{Error, LogicalPath, Name, Result};
use rostdav_meta::{Node, NodeKind};

use crate::AppState;
use crate::access::{Access, Need, Origin, authorize_access};
use crate::auth::Principal;
use rostdav_meta::PERM_ALL;

/// A scan looks at no more nodes than this; the page then says `truncated`.
pub const MAX_VISITED: usize = 200_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KindFilter {
    #[default]
    Any,
    Files,
    Folders,
}

#[derive(Clone, Debug)]
pub struct SearchQuery {
    /// What to look for in names: case, accents and the two spellings of an accented letter do
    /// not matter. Empty finds nothing.
    pub text: String,
    /// Where to look: the caller's root searches everything they can reach.
    pub scope: LogicalPath,
    pub kind: KindFilter,
    pub offset: usize,
    pub limit: usize,
    /// Upper bound of nodes looked at.
    pub max_visited: usize,
}

impl SearchQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            scope: LogicalPath::root(),
            kind: KindFilter::Any,
            offset: 0,
            limit: 50,
            max_visited: MAX_VISITED,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchHit {
    /// Where the caller reaches it (own path, or `<mount name>/…` for a share).
    pub path: LogicalPath,
    pub node: Node,
    pub origin: Origin,
    /// 0 exact name, 1 name starts with the text, 2 name contains it, 3 only the text of the
    /// file contains it.
    pub rank: u8,
    /// What the file says around the words that were searched (content hits only).
    pub snippet: Vec<SnippetPart>,
}

/// A piece of a snippet: plain text, or a word that was searched for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnippetPart {
    pub text: String,
    pub hit: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SearchPage {
    pub hits: Vec<SearchHit>,
    /// More hits exist after this page.
    pub more: bool,
    /// The scan stopped at `max_visited`: there may be hits that were not looked at.
    pub truncated: bool,
}

fn rank_of(name: &str, wanted: &str) -> Option<u8> {
    if !contains_loose(name, wanted) {
        return None;
    }
    let (n, w) = (fold_loose(name), fold_loose(wanted));
    let w = w.trim();
    Some(if n == w {
        0
    } else if n.starts_with(w) {
        1
    } else {
        2
    })
}

impl AppState {
    /// Searches names below `q.scope`, for a principal that signed in with a password (links and
    /// app passwords with a narrower scope cannot search).
    pub async fn search_names(&self, p: &Principal, q: &SearchQuery) -> Result<SearchPage> {
        let (found, truncated) = self.name_hits(p, q).await?;
        let total = found.len();
        let mut page = SearchPage {
            truncated,
            ..SearchPage::default()
        };
        page.hits = found.into_iter().skip(q.offset).take(q.limit).collect();
        page.more = total > q.offset + page.hits.len();
        Ok(page)
    }

    /// Every hit by name, best first, and whether the scan was cut short.
    async fn name_hits(&self, p: &Principal, q: &SearchQuery) -> Result<(Vec<SearchHit>, bool)> {
        // links and narrower principals cannot search: checked first, before anything is read
        Self::require_full(p)?;
        let mut truncated = false;
        if q.text.trim().is_empty() || q.limit == 0 {
            return Ok((Vec::new(), false));
        }
        let db = &self.inner.db;
        let scope = self.resolve_access(p, &q.scope).await?;
        authorize_access(p, &scope, Need::Read)?;
        if scope.node.kind != NodeKind::Dir {
            return Err(Error::BadRequest("the search scope must be a folder"));
        }

        // (directory access, its path)
        let mut queue: Vec<(Access, LogicalPath)> = Vec::new();
        let mut found: Vec<SearchHit> = Vec::new();
        let mut visited = 0usize;
        let consider = |access: &Access, path: &LogicalPath, found: &mut Vec<SearchHit>| {
            let kind_ok = match q.kind {
                KindFilter::Any => true,
                KindFilter::Files => access.node.kind == NodeKind::File,
                KindFilter::Folders => access.node.kind == NodeKind::Dir,
            };
            if !kind_ok {
                return;
            }
            let name = path.segments().last().map_or("", Name::as_str);
            if let Some(rank) = rank_of(name, &q.text) {
                found.push(SearchHit {
                    path: path.clone(),
                    node: access.node.clone(),
                    origin: access.origin,
                    rank,
                    snippet: Vec::new(),
                });
            }
        };

        // the mount points are part of the caller's root
        if q.scope.is_root() && scope.origin == Origin::Own {
            for m in self.mounts_of(p).await? {
                let Ok(name) = Name::parse(&m.name) else {
                    continue;
                };
                let access = Access {
                    node: m.node.clone(),
                    holder: p.user_id,
                    perms: m.share.permissions,
                    origin: Origin::Share(m.share.id),
                    mount_root: true,
                };
                if authorize_access(p, &access, Need::Read).is_err() {
                    continue;
                }
                let path = q.scope.join(&name);
                visited += 1;
                consider(&access, &path, &mut found);
                if access.is_dir() {
                    queue.push((access, path));
                }
            }
        }
        queue.push((scope, q.scope.clone()));

        'scan: while let Some((dir, dir_path)) = queue.pop() {
            for child in db.children(dir.node.id).await? {
                let Ok(name) = Name::parse(&child.name) else {
                    continue;
                };
                // a child is reached by the same right as the folder it is in
                let access = Access {
                    holder: dir.holder,
                    perms: if dir.origin == Origin::Own {
                        PERM_ALL
                    } else {
                        dir.perms
                    },
                    origin: dir.origin,
                    mount_root: false,
                    node: child,
                };
                if authorize_access(p, &access, Need::Read).is_err() {
                    continue;
                }
                visited += 1;
                if visited > q.max_visited {
                    truncated = true;
                    break 'scan;
                }
                let path = dir_path.join(&name);
                consider(&access, &path, &mut found);
                if access.is_dir() {
                    queue.push((access, path));
                }
            }
        }

        found.sort_by_cached_key(|h| {
            let name = h.path.segments().last().map_or("", Name::as_str);
            let whole: Vec<&str> = h.path.segments().iter().map(Name::as_str).collect();
            (h.rank, fold_loose(name), whole.join("/"))
        });
        Ok((found, truncated))
    }

    /// Names first, then files whose **text** contains the words (when the index is ready and
    /// content indexing is on). Every hit, by name or by text, passed the access check; a text
    /// hit is only accepted if its path, as the caller sees it, leads back to the same node.
    pub async fn search(&self, p: &Principal, q: &SearchQuery) -> Result<SearchPage> {
        let (mut hits, truncated) = self.name_hits(p, q).await?;
        let mut more_content = false;
        if q.kind != KindFilter::Folders {
            if let Some(fts) = fts_query_from_text(&q.text) {
                if self.cfg().search.content {
                    if let Some(index) = self.search_index().await {
                        let (found, cut) = self.text_hits(p, q, &index, &fts, &hits).await?;
                        more_content = cut;
                        hits.extend(found);
                    }
                }
            }
        }
        let total = hits.len();
        let mut page = SearchPage {
            truncated,
            ..SearchPage::default()
        };
        page.hits = hits.into_iter().skip(q.offset).take(q.limit).collect();
        page.more = more_content || total > q.offset + page.hits.len();
        Ok(page)
    }

    /// Text hits for `fts`, best first, without the nodes already found by name.
    async fn text_hits(
        &self,
        p: &Principal,
        q: &SearchQuery,
        index: &rostdav_meta::SearchIndex,
        fts: &str,
        by_name: &[SearchHit],
    ) -> Result<(Vec<SearchHit>, bool)> {
        // whose files could the caller see at all: their own and those of the share owners
        let mounts = self.mounts_of(p).await?;
        let mut owners: Vec<i64> = vec![p.user_id];
        owners.extend(mounts.iter().map(|m| m.node.owner_id));
        owners.sort_unstable();
        owners.dedup();
        let cap =
            i64::try_from((q.offset + q.limit).saturating_mul(3).clamp(60, 600)).unwrap_or(600);
        let candidates = index.search_text(fts, &owners, cap).await?;
        let reached_cap = i64::try_from(candidates.len()).unwrap_or(0) >= cap;

        // where each received share starts, in its owner's tree
        let mut roots: Vec<(Vec<String>, &crate::access::MountView)> = Vec::new();
        for m in &mounts {
            let path = self.inner.db.node_path(m.node.id).await?;
            roots.push((split_path(&path), m));
        }
        let known: std::collections::HashSet<i64> = by_name.iter().map(|h| h.node.id).collect();
        let terms = query_words(&q.text);
        let mut out = Vec::new();
        for c in candidates {
            if known.contains(&c.node_id) {
                continue;
            }
            let Some(node) = self.inner.db.node_by_id(c.node_id).await? else {
                continue;
            };
            if node.kind != NodeKind::File {
                continue;
            }
            let owner_path = split_path(&self.inner.db.node_path(node.id).await?);
            // the way the caller reaches it: own tree, or below the mount point of a share
            let mut ways: Vec<Vec<String>> = Vec::new();
            if node.owner_id == p.user_id {
                ways.push(owner_path.clone());
            }
            for (root, m) in &roots {
                if node.owner_id == m.node.owner_id && owner_path.starts_with(root) {
                    let mut w = vec![m.name.clone()];
                    w.extend(owner_path[root.len()..].iter().cloned());
                    ways.push(w);
                }
            }
            for way in ways {
                let Some(path) = to_logical(&way) else {
                    continue;
                };
                if !path.segments().starts_with(q.scope.segments()) {
                    continue;
                }
                // the decision: resolve the path as the caller and check the read right
                let Ok(access) = self.resolve_access(p, &path).await else {
                    continue;
                };
                if access.node.id != node.id || authorize_access(p, &access, Need::Read).is_err() {
                    continue;
                }
                let snippet = match index.text_of(node.id).await? {
                    Some(text) => snippet_of(&text, &terms),
                    None => Vec::new(),
                };
                out.push(SearchHit {
                    path,
                    node: access.node.clone(),
                    origin: access.origin,
                    rank: 3,
                    snippet,
                });
                break;
            }
        }
        Ok((out, reached_cap))
    }
}

fn split_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn to_logical(segments: &[String]) -> Option<LogicalPath> {
    let mut p = LogicalPath::root();
    for s in segments {
        p = p.join(&Name::parse(s).ok()?);
    }
    Some(p)
}

const MAX_TERMS: usize = 8;
const MAX_TERM_CHARS: usize = 64;

/// The words and quoted phrases of what the user typed, folded like the index text.
fn query_words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text.trim();
    while !rest.is_empty() && out.len() < MAX_TERMS {
        let (piece, tail) = if let Some(r) = rest.strip_prefix('"') {
            match r.split_once('"') {
                Some((phrase, tail)) => (phrase, tail),
                None => (r, ""),
            }
        } else {
            match rest.split_once(char::is_whitespace) {
                Some((w, tail)) => (w, tail),
                None => (rest, ""),
            }
        };
        rest = tail.trim_start();
        let folded: String = fold_loose(piece)
            .chars()
            .filter(|c| *c != '"' && *c != '\\')
            .take(MAX_TERM_CHARS)
            .collect();
        let folded = folded.trim().to_owned();
        if folded.chars().any(char::is_alphanumeric) {
            out.push(folded);
        }
    }
    out
}

/// The query for the index: every word or phrase quoted (so that nothing the user types can be
/// read as an operator or break the syntax) and all of them required. `None` if there is nothing
/// to look for.
pub(crate) fn fts_query_from_text(text: &str) -> Option<String> {
    let words = query_words(text);
    if words.is_empty() {
        return None;
    }
    Some(
        words
            .iter()
            .map(|w| format!("\"{w}\""))
            .collect::<Vec<_>>()
            .join(" AND "),
    )
}

const SNIPPET_WORDS_BEFORE: usize = 8;
const SNIPPET_WORDS_AFTER: usize = 14;

/// A few words of `text` around the first place that matches one of `terms`, with the matching
/// words marked. Whole words of the original are kept, so accents and capitals stay as written.
fn snippet_of(text: &str, terms: &[String]) -> Vec<SnippetPart> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let folded: Vec<String> = words.iter().map(|w| fold_loose(w)).collect();
    let is_hit = |i: usize| {
        terms
            .iter()
            .any(|t| !t.contains(' ') && folded[i].contains(t.as_str()))
    };
    // a phrase hit: its words in a row
    let phrase_hit = |i: usize| {
        terms.iter().any(|t| {
            let parts: Vec<&str> = t.split_whitespace().collect();
            parts.len() > 1
                && i + parts.len() <= folded.len()
                && parts
                    .iter()
                    .enumerate()
                    .all(|(k, w)| folded[i + k].contains(w))
        })
    };
    let first = (0..words.len()).find(|i| is_hit(*i) || phrase_hit(*i));
    let Some(first) = first else {
        return Vec::new();
    };
    let from = first.saturating_sub(SNIPPET_WORDS_BEFORE);
    let to = (first + SNIPPET_WORDS_AFTER).min(words.len());
    let mut parts: Vec<SnippetPart> = Vec::new();
    // adjacent pieces of the same kind are one piece; the blanks between words are never marked
    let mut push = |text: &str, hit: bool| match parts.last_mut() {
        Some(last) if last.hit == hit => last.text.push_str(text),
        _ => parts.push(SnippetPart {
            text: text.to_owned(),
            hit,
        }),
    };
    if from > 0 {
        push("… ", false);
    }
    for (i, w) in words.iter().enumerate().take(to).skip(from) {
        if i > from {
            push(" ", false);
        }
        push(w, is_hit(i));
    }
    if to < words.len() {
        push(" …", false);
    }
    parts
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn the_index_query_quotes_everything_the_user_types() {
        assert_eq!(
            fts_query_from_text("Rust Server").as_deref(),
            Some("\"rust\" AND \"server\"")
        );
        assert_eq!(
            fts_query_from_text("\"file server\" rust").as_deref(),
            Some("\"file server\" AND \"rust\"")
        );
        // operators and syntax characters are words, not syntax
        assert_eq!(
            fts_query_from_text("a OR b").as_deref(),
            Some("\"a\" AND \"or\" AND \"b\"")
        );
        assert_eq!(fts_query_from_text("(rust").as_deref(), Some("\"(rust\""));
        assert_eq!(
            fts_query_from_text("body:rust -x").as_deref(),
            Some("\"body:rust\" AND \"-x\"")
        );
        assert_eq!(
            fts_query_from_text("\"unclosed").as_deref(),
            Some("\"unclosed\"")
        );
        assert_eq!(
            fts_query_from_text("say \\\"hi").as_deref(),
            Some("\"say\" AND \"hi\"")
        );
        // accents and case are folded like the text
        assert_eq!(
            fts_query_from_text("Café STRASSE").as_deref(),
            Some("\"cafe\" AND \"strasse\"")
        );
        // nothing to look for
        for none in ["", "   ", "***", "\"\"", "- - -", "\" \""] {
            assert_eq!(fts_query_from_text(none), None, "{none:?}");
        }
        // bounded
        let many = (0..30)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            fts_query_from_text(&many)
                .expect("q")
                .matches(" AND ")
                .count(),
            MAX_TERMS - 1
        );
        let long = "x".repeat(500);
        assert!(fts_query_from_text(&long).expect("q").len() <= MAX_TERM_CHARS + 2);
    }

    fn joined(parts: &[SnippetPart]) -> String {
        parts.iter().map(|p| p.text.as_str()).collect()
    }

    #[test]
    fn a_snippet_keeps_the_original_words_and_marks_the_ones_searched() {
        let text = "Der Bericht über das Café an der Strasse wurde gestern fertig und liegt jetzt im Ordner";
        let s = snippet_of(text, &["cafe".to_owned()]);
        let marked: Vec<&str> = s.iter().filter(|p| p.hit).map(|p| p.text.trim()).collect();
        assert_eq!(marked, ["Café"]);
        assert!(
            joined(&s).contains("über das Café an der"),
            "{}",
            joined(&s)
        );
        // far into a long text: cut with dots at both ends
        let long = format!("{} Treffer {}", "vorher ".repeat(50), "nachher ".repeat(50));
        let s = snippet_of(&long, &["treffer".to_owned()]);
        let j = joined(&s);
        assert!(
            j.starts_with("… ") && j.ends_with(" …") && j.contains("Treffer"),
            "{j}"
        );
        assert!(j.split_whitespace().count() < 30);
        // a phrase is marked word by word only when found as a phrase start; no match, no snippet
        assert!(snippet_of("nothing here", &["zzz".to_owned()]).is_empty());
        assert!(snippet_of("", &["x".to_owned()]).is_empty());
    }

    #[test]
    fn text_with_markup_stays_text() {
        // the snippet never adds markup; the page escapes every part
        let s = snippet_of("<script>alert(1)</script> findme", &["findme".to_owned()]);
        assert!(joined(&s).contains("<script>"));
        assert!(s.iter().all(|p| !p.text.contains("<mark>")));
    }
}
