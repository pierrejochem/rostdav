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
    /// 0 exact name, 1 name starts with the text, 2 name contains it.
    pub rank: u8,
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
        Self::require_full(p)?;
        let mut page = SearchPage::default();
        if q.text.trim().is_empty() || q.limit == 0 {
            return Ok(page);
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
                    page.truncated = true;
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
        let total = found.len();
        page.hits = found.into_iter().skip(q.offset).take(q.limit).collect();
        page.more = total > q.offset + page.hits.len();
        Ok(page)
    }
}
