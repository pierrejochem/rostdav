//! Search by name: what is found, and above all what is not (search plan, stage 1).

use std::net::{IpAddr, Ipv4Addr};

use rostdav_core::{Error, LogicalPath};
use rostdav_meta::{Db, WriteCondition};
use rostdav_storage::LocalStore;

use crate::*;

const PW: &str = "korrekt-pferd-batterie";
const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct World {
    _dir: tempfile::TempDir,
    st: AppState,
    anna: Principal,
    bob: Principal,
}

fn lp(s: &str) -> LogicalPath {
    LogicalPath::from_url_path(s).expect("path")
}

async fn put(st: &AppState, p: &Principal, path: &str) {
    st.put(p, &lp(path), "x".as_bytes(), None, &WriteCondition::None)
        .await
        .expect("put");
}

async fn world() -> World {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalStore::open(dir.path().join("data"))
        .await
        .expect("store");
    let db = Db::open(&Db::default_url(store.root())).await.expect("db");
    db.migrate().await.expect("migrate");
    let st = AppState::new(db, store).await.expect("state");
    for n in ["anna", "bob"] {
        st.add_user(n, PW, false).await.expect("user");
    }
    let anna = st.authenticate("anna", PW, IP).await.expect("auth");
    let bob = st.authenticate("bob", PW, IP).await.expect("auth");
    World {
        _dir: dir,
        st,
        anna,
        bob,
    }
}

fn share(path: &str, with: &str, perms: i64) -> ShareCreate {
    ShareCreate {
        path: Some(lp(path)),
        share_type: 0,
        share_with: Some(with.into()),
        permissions: Some(perms),
        password: None,
        expire: None,
        note: String::new(),
        label: String::new(),
        hide_download: false,
    }
}

async fn found(st: &AppState, p: &Principal, q: &str) -> Vec<String> {
    let page = st
        .search_names(p, &SearchQuery::new(q))
        .await
        .expect("search");
    page.hits
        .iter()
        .map(|h| {
            h.path
                .segments()
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

#[tokio::test]
async fn finds_files_and_folders_anywhere_in_the_own_tree_best_match_first() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/Docs")).await.expect("mkcol");
    st.mkcol(anna, &lp("/Docs/Reports")).await.expect("mkcol");
    st.mkcol(anna, &lp("/Photos")).await.expect("mkcol");
    put(st, anna, "/report").await;
    put(st, anna, "/Docs/Reports/report-2026.txt").await;
    put(st, anna, "/Docs/old report.txt").await;
    put(st, anna, "/Photos/IMG_1.jpg").await;
    // exact name first, then names that start with it (alphabetically), then the rest;
    // folders count too
    assert_eq!(
        found(st, anna, "report").await,
        [
            "report",
            "Docs/Reports/report-2026.txt",
            "Docs/Reports",
            "Docs/old report.txt"
        ]
    );
    assert_eq!(found(st, anna, "img_1").await, ["Photos/IMG_1.jpg"]);
    assert!(found(st, anna, "nothing like this").await.is_empty());
    // an empty search finds nothing, and `%` and `_` are plain characters
    assert!(found(st, anna, "").await.is_empty());
    assert!(found(st, anna, "   ").await.is_empty());
    assert!(found(st, anna, "%").await.is_empty());
    assert!(found(st, anna, "img%1").await.is_empty());
}

#[tokio::test]
async fn case_accents_and_the_two_spellings_of_an_accented_letter_do_not_matter() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    put(st, anna, "/Caf%C3%A9 Men%C3%BC.txt").await; // precomposed é and ü
    put(st, anna, "/Strasse.txt").await;
    put(st, anna, "/Zoe%CC%88.txt").await; // e + combining diaeresis
    for q in ["CAFÉ", "cafe", "cafe\u{301}", "menü", "MENU"] {
        assert_eq!(found(st, anna, q).await, ["Café Menü.txt"], "{q}");
    }
    assert_eq!(found(st, anna, "straße").await, ["Strasse.txt"]);
    assert_eq!(found(st, anna, "zoë").await.len(), 1);
    assert_eq!(found(st, anna, "zoe").await.len(), 1);
}

#[tokio::test]
async fn nobody_finds_files_of_other_users() {
    let w = world().await;
    let (st, anna, bob) = (&w.st, &w.anna, &w.bob);
    st.mkcol(bob, &lp("/Private")).await.expect("mkcol");
    put(st, bob, "/Private/secret-plan.txt").await;
    put(st, bob, "/bobs-notes.txt").await;
    put(st, anna, "/annas-notes.txt").await;
    assert!(found(st, anna, "secret").await.is_empty());
    assert!(found(st, anna, "bobs").await.is_empty());
    assert!(found(st, anna, "Private").await.is_empty());
    assert_eq!(found(st, bob, "notes").await, ["bobs-notes.txt"]);
    assert_eq!(found(st, anna, "notes").await, ["annas-notes.txt"]);
    // the scope cannot be pointed into somebody else's tree either
    let mut q = SearchQuery::new("secret");
    q.scope = lp("/Private");
    assert!(matches!(
        st.search_names(anna, &q).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn a_received_share_is_found_under_its_mount_and_only_while_it_exists() {
    let w = world().await;
    let (st, anna, bob) = (&w.st, &w.anna, &w.bob);
    st.mkcol(bob, &lp("/Team")).await.expect("mkcol");
    st.mkcol(bob, &lp("/Team/deep")).await.expect("mkcol");
    st.mkcol(bob, &lp("/Elsewhere")).await.expect("mkcol");
    put(st, bob, "/Team/budget.xlsx").await;
    put(st, bob, "/Team/deep/budget-draft.txt").await;
    put(st, bob, "/Elsewhere/budget-private.txt").await;
    let s = st
        .share_create(bob, share("/Team", "anna", 1))
        .await
        .expect("share");
    // read-only is enough to search; the mount itself and everything below it is found
    assert_eq!(
        found(st, anna, "budget").await,
        ["Team/deep/budget-draft.txt", "Team/budget.xlsx"]
    );
    assert_eq!(found(st, anna, "team").await, ["Team"]);
    // what is outside the shared folder stays hidden
    assert!(found(st, anna, "private").await.is_empty());
    // a scope inside the share works, and the hit carries the way it was reached
    let mut q = SearchQuery::new("budget");
    q.scope = lp("/Team/deep");
    let page = st.search_names(anna, &q).await.expect("scoped");
    assert_eq!(page.hits.len(), 1);
    assert!(matches!(page.hits[0].origin, Origin::Share(id) if id == s.share.id));
    // revoked: gone at once
    st.share_delete(bob, s.share.id).await.expect("revoke");
    assert!(found(st, anna, "budget").await.is_empty());
    assert!(found(st, anna, "team").await.is_empty());
}

#[tokio::test]
async fn a_shared_single_file_is_found_by_its_name() {
    let w = world().await;
    let (st, anna, bob) = (&w.st, &w.anna, &w.bob);
    put(st, bob, "/offer.pdf").await;
    put(st, bob, "/offer-secret.pdf").await;
    st.share_create(bob, share("/offer.pdf", "anna", 1))
        .await
        .expect("share");
    assert_eq!(found(st, anna, "offer").await, ["offer.pdf"]);
}

#[tokio::test]
async fn deleted_files_are_not_found() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/Old")).await.expect("mkcol");
    put(st, anna, "/Old/gone-file.txt").await;
    put(st, anna, "/gone-too.txt").await;
    assert_eq!(found(st, anna, "gone").await.len(), 2);
    st.delete(anna, &lp("/gone-too.txt"), None)
        .await
        .expect("delete");
    st.delete(anna, &lp("/Old"), None).await.expect("delete");
    assert!(found(st, anna, "gone").await.is_empty());
    assert!(found(st, anna, "old").await.is_empty());
}

#[tokio::test]
async fn the_scope_limits_the_search_and_must_be_a_readable_folder() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/A")).await.expect("mkcol");
    st.mkcol(anna, &lp("/B")).await.expect("mkcol");
    put(st, anna, "/A/note-a.txt").await;
    put(st, anna, "/B/note-b.txt").await;
    let mut q = SearchQuery::new("note");
    q.scope = lp("/A");
    let page = st.search_names(anna, &q).await.expect("scoped");
    assert_eq!(page.hits.len(), 1);
    assert_eq!(page.hits[0].node.name, "note-a.txt");
    q.scope = lp("/A/note-a.txt");
    assert!(matches!(
        st.search_names(anna, &q).await,
        Err(Error::BadRequest(_))
    ));
    q.scope = lp("/missing");
    assert!(matches!(
        st.search_names(anna, &q).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn public_link_principals_cannot_search() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/Pub")).await.expect("mkcol");
    put(st, anna, "/Pub/file.txt").await;
    let node = st.stat(anna, &lp("/Pub")).await.expect("stat");
    let link = Principal {
        user_id: anna.user_id,
        name: anna.name.clone(),
        is_admin: false,
        via: anna.via,
        scope: Scope::Link {
            share_id: 1,
            node_id: node.id,
            perms: 1,
        },
    };
    assert!(matches!(
        st.search_names(&link, &SearchQuery::new("file")).await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn paging_kind_filter_and_the_scan_limit() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/data-dir")).await.expect("mkcol");
    for i in 0..5 {
        put(st, anna, &format!("/data-{i}.txt")).await;
    }
    let mut q = SearchQuery::new("data");
    q.limit = 2;
    let p1 = st.search_names(anna, &q).await.expect("p1");
    assert_eq!((p1.hits.len(), p1.more), (2, true));
    q.offset = 4;
    let p3 = st.search_names(anna, &q).await.expect("p3");
    assert_eq!((p3.hits.len(), p3.more), (2, false));
    // same query, same order, no overlap between pages
    q.offset = 0;
    let all = st
        .search_names(
            anna,
            &SearchQuery {
                limit: 100,
                ..q.clone()
            },
        )
        .await
        .expect("all");
    assert_eq!(all.hits.len(), 6);
    assert_eq!(all.hits[0].node.name, "data-0.txt");
    let only_folders = SearchQuery {
        kind: KindFilter::Folders,
        limit: 100,
        ..q.clone()
    };
    assert_eq!(
        st.search_names(anna, &only_folders)
            .await
            .expect("f")
            .hits
            .len(),
        1
    );
    let only_files = SearchQuery {
        kind: KindFilter::Files,
        limit: 100,
        ..q.clone()
    };
    assert_eq!(
        st.search_names(anna, &only_files)
            .await
            .expect("f")
            .hits
            .len(),
        5
    );
    // a scan that is cut short says so
    let cut = SearchQuery {
        max_visited: 3,
        limit: 100,
        ..q
    };
    assert!(st.search_names(anna, &cut).await.expect("cut").truncated);
}
