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

// ---- search in the text of files (the index, ADR 0012) ------------------------------------------

async fn put_text(st: &AppState, p: &Principal, path: &str, text: &str) {
    st.put(p, &lp(path), text.as_bytes(), None, &WriteCondition::None)
        .await
        .expect("put");
}

/// Passes of the indexer until nothing is left to read (a test world is small).
async fn index(st: &AppState) {
    for _ in 0..10 {
        let r = st.indexer_pass().await.expect("pass");
        if r.pending == 0 {
            return;
        }
    }
    panic!("the indexer did not finish");
}

async fn paths(st: &AppState, p: &Principal, q: &str) -> Vec<String> {
    let page = st.search(p, &SearchQuery::new(q)).await.expect("search");
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
async fn the_text_of_files_is_found_with_a_snippet_and_names_come_first() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/Docs")).await.expect("mkcol");
    put_text(
        st,
        anna,
        "/Docs/minutes.txt",
        "The committee agreed on the Quarterly budget and the new Café menu.",
    )
    .await;
    put_text(st, anna, "/budget-2026.txt", "figures only").await;
    put_text(st, anna, "/photo.jpg", "budget hidden in a picture").await;
    // nothing is found before the indexer has read the files
    assert_eq!(paths(st, anna, "committee").await, Vec::<String>::new());
    index(st).await;
    // by text; accents and case do not matter; a word that is a part of another is not a match
    assert_eq!(paths(st, anna, "committee").await, ["Docs/minutes.txt"]);
    assert_eq!(paths(st, anna, "CAFE").await, ["Docs/minutes.txt"]);
    assert!(
        paths(st, anna, "committ").await.is_empty(),
        "whole words only"
    );
    // two words: both must be there; a phrase must be in that order
    assert_eq!(
        paths(st, anna, "quarterly menu").await,
        ["Docs/minutes.txt"]
    );
    assert_eq!(
        paths(st, anna, "\"new café menu\"").await,
        ["Docs/minutes.txt"]
    );
    assert!(paths(st, anna, "\"menu new\"").await.is_empty());
    assert!(paths(st, anna, "committee zzzz").await.is_empty());
    // a name hit comes before a text hit, and a file is listed once
    assert_eq!(
        paths(st, anna, "budget").await,
        ["budget-2026.txt", "Docs/minutes.txt"]
    );
    // only text-like files are read: the picture's "text" is not searched
    assert!(
        !paths(st, anna, "hidden")
            .await
            .contains(&"photo.jpg".to_owned())
    );
    // the snippet shows the words around the hit, with the searched word marked
    let page = st
        .search(anna, &SearchQuery::new("budget"))
        .await
        .expect("s");
    let text_hit = page.hits.iter().find(|h| h.rank == 3).expect("text hit");
    let shown: String = text_hit.snippet.iter().map(|p| p.text.as_str()).collect();
    assert!(shown.contains("Quarterly budget and the new"), "{shown}");
    assert_eq!(
        text_hit
            .snippet
            .iter()
            .filter(|p| p.hit)
            .map(|p| p.text.trim())
            .collect::<Vec<_>>(),
        ["budget"]
    );
    // folders have no text: the "folders only" search ignores content
    let q = SearchQuery {
        kind: KindFilter::Folders,
        ..SearchQuery::new("committee")
    };
    assert!(st.search(anna, &q).await.expect("s").hits.is_empty());
}

#[tokio::test]
async fn nobody_finds_the_text_of_files_they_may_not_read() {
    let w = world().await;
    let (st, anna, bob) = (&w.st, &w.anna, &w.bob);
    st.mkcol(bob, &lp("/Private")).await.expect("mkcol");
    put_text(
        st,
        bob,
        "/Private/plan.txt",
        "the secret acquisition of zebrafish",
    )
    .await;
    put_text(st, bob, "/note.txt", "zebrafish are small").await;
    put_text(st, anna, "/mine.txt", "annas own zebrafish notes").await;
    index(st).await;
    // each finds only their own, by text and in the snippets
    assert_eq!(paths(st, anna, "zebrafish").await, ["mine.txt"]);
    let mut b = paths(st, bob, "zebrafish").await;
    b.sort();
    assert_eq!(b, ["Private/plan.txt", "note.txt"]);
    let page = st
        .search(anna, &SearchQuery::new("secret acquisition"))
        .await
        .expect("s");
    assert!(page.hits.is_empty());
    // a scope in somebody else's tree is not found, for text too
    let mut q = SearchQuery::new("zebrafish");
    q.scope = lp("/Private");
    assert!(matches!(st.search(anna, &q).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn text_in_a_received_share_is_found_under_its_mount_until_the_share_ends() {
    let w = world().await;
    let (st, anna, bob) = (&w.st, &w.anna, &w.bob);
    st.mkcol(bob, &lp("/Team")).await.expect("mkcol");
    st.mkcol(bob, &lp("/Team/deep")).await.expect("mkcol");
    st.mkcol(bob, &lp("/Elsewhere")).await.expect("mkcol");
    put_text(
        st,
        bob,
        "/Team/deep/agenda.txt",
        "discuss the walrus proposal",
    )
    .await;
    put_text(
        st,
        bob,
        "/Elsewhere/other.txt",
        "the walrus is not for sharing",
    )
    .await;
    index(st).await;
    assert!(paths(st, anna, "walrus").await.is_empty(), "not shared yet");
    let s = st
        .share_create(bob, share("/Team", "anna", 1))
        .await
        .expect("share");
    // read-only is enough; found below the mount point, and only what is in the shared folder
    assert_eq!(paths(st, anna, "walrus").await, ["Team/deep/agenda.txt"]);
    // a scope inside the share works, a scope outside it does not widen anything
    let mut q = SearchQuery::new("walrus");
    q.scope = lp("/Team/deep");
    let page = st.search(anna, &q).await.expect("scoped");
    assert!(matches!(page.hits[0].origin, Origin::Share(id) if id == s.share.id));
    q.scope = lp("/Elsewhere");
    assert!(st.search(anna, &q).await.is_err());
    // stopped: gone at once, without waiting for the indexer
    st.share_delete(bob, s.share.id).await.expect("revoke");
    assert!(paths(st, anna, "walrus").await.is_empty());
}

#[tokio::test]
async fn edits_moves_deletes_and_restores_are_followed() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    st.mkcol(anna, &lp("/A")).await.expect("mkcol");
    st.mkcol(anna, &lp("/B")).await.expect("mkcol");
    put_text(st, anna, "/A/doc.txt", "original wording about pelicans").await;
    index(st).await;
    assert_eq!(paths(st, anna, "pelicans").await, ["A/doc.txt"]);
    // edited: the old words stop matching, the new ones match after the next pass
    put_text(
        st,
        anna,
        "/A/doc.txt",
        "completely new text about flamingos",
    )
    .await;
    index(st).await;
    assert!(paths(st, anna, "pelicans").await.is_empty());
    assert_eq!(paths(st, anna, "flamingos").await, ["A/doc.txt"]);
    // moved: found at the new place at once (paths are worked out when searching)
    st.move_to(anna, &lp("/A/doc.txt"), &lp("/B/moved.txt"), false)
        .await
        .expect("move");
    assert_eq!(paths(st, anna, "flamingos").await, ["B/moved.txt"]);
    index(st).await;
    assert_eq!(paths(st, anna, "flamingos").await, ["B/moved.txt"]);
    // deleted: hidden at once, even before a pass; restored: found again, no reading needed
    st.delete(anna, &lp("/B/moved.txt"), None)
        .await
        .expect("delete");
    assert!(paths(st, anna, "flamingos").await.is_empty());
    index(st).await;
    assert!(paths(st, anna, "flamingos").await.is_empty());
    let item = st
        .trash_list(anna)
        .await
        .expect("trash")
        .into_iter()
        .next()
        .expect("item");
    st.trash_restore(anna, &item.entry_name())
        .await
        .expect("restore");
    assert_eq!(paths(st, anna, "flamingos").await.len(), 1);
    // purged for good: gone from the index with the next pass
    st.delete(anna, &lp("/B/moved.txt"), None).await.ok();
    let item = st.trash_list(anna).await.expect("trash").into_iter().next();
    if let Some(item) = item {
        st.trash_delete(anna, &item.entry_name())
            .await
            .expect("purge");
    }
    index(st).await;
    assert!(paths(st, anna, "flamingos").await.is_empty());
    let status = st.search_status(&Actor::Cli).await.expect("status");
    assert!(status.ready && status.index.docs >= 2, "{status:?}");
}

#[tokio::test]
async fn switching_content_indexing_off_removes_the_texts_and_on_reads_them_again() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    put_text(st, anna, "/notes.txt", "mention of the narwhal here").await;
    index(st).await;
    assert_eq!(paths(st, anna, "narwhal").await, ["notes.txt"]);
    st.set_tunable(&Actor::Cli, "search.content_indexing", "0")
        .await
        .expect("off");
    // no content hit at once; the stored texts are removed by the next pass
    assert!(paths(st, anna, "narwhal").await.is_empty());
    index(st).await;
    let s = st.search_status(&Actor::Cli).await.expect("status").index;
    assert_eq!((s.indexed, s.content_enabled), (0, false));
    // names are still found
    assert_eq!(paths(st, anna, "notes").await, ["notes.txt"]);
    st.set_tunable(&Actor::Cli, "search.content_indexing", "1")
        .await
        .expect("on");
    index(st).await;
    assert_eq!(paths(st, anna, "narwhal").await, ["notes.txt"]);
}

#[tokio::test]
async fn limits_decide_what_is_read_and_a_lost_index_is_built_again() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    put_text(st, anna, "/small.txt", "findable platypus").await;
    put_text(st, anna, "/binary.txt", "platypus\u{0}with a NUL byte").await;
    put_text(
        st,
        anna,
        "/long.txt",
        &format!("{} platypus", "padding ".repeat(5000)),
    )
    .await;
    st.set_tunable(&Actor::Cli, "search.max_text_kib", "16")
        .await
        .expect("limit");
    index(st).await;
    // the NUL byte makes it binary; the long file is cut after 16 KiB, before its last word
    assert_eq!(paths(st, anna, "platypus").await, ["small.txt"]);
    let s = st.search_status(&Actor::Cli).await.expect("status").index;
    assert_eq!((s.indexed, s.unsupported), (2, 1), "{s:?}");
    // the limits are checked
    assert!(
        st.set_tunable(&Actor::Cli, "search.max_text_kib", "8")
            .await
            .is_err()
    );
    assert!(
        st.set_tunable(&Actor::Cli, "search.max_file_mib", "0")
            .await
            .is_err()
    );
    assert!(
        st.set_tunable(&Actor::Cli, "search.content_indexing", "2")
            .await
            .is_err()
    );
    // throw the index away: the next pass builds it again from the nodes and the blobs
    st.search_rebuild(&Actor::Cli).await.expect("rebuild");
    assert!(
        paths(st, anna, "platypus").await.is_empty(),
        "empty until it is built"
    );
    index(st).await;
    assert_eq!(paths(st, anna, "platypus").await, ["small.txt"]);
}

#[tokio::test]
async fn only_administrators_manage_the_index_and_links_cannot_search_text() {
    let w = world().await;
    let (st, anna) = (&w.st, &w.anna);
    put_text(st, anna, "/a.txt", "words").await;
    index(st).await;
    assert!(matches!(
        st.search_status(&Actor::User(anna)).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        st.search_rebuild(&Actor::User(anna)).await,
        Err(Error::Forbidden)
    ));
    let node = st.stat(anna, &lp("/")).await.expect("root");
    let link = Principal {
        scope: Scope::Link {
            share_id: 1,
            node_id: node.id,
            perms: 1,
        },
        ..anna.clone()
    };
    assert!(matches!(
        st.search(&link, &SearchQuery::new("words")).await,
        Err(Error::Forbidden)
    ));
}

// ---- PDF and Office files (ADR 0013), with a stand-in for the reader process ---------------------

fn fake_reader(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("reader");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

#[tokio::test]
async fn documents_are_read_by_the_reader_process_and_found() {
    let w = world().await;
    let exe = fake_reader(
        w._dir.path(),
        "cat >/dev/null; echo 'Invoice for the aardvark order'",
    );
    let st = w.st.clone().with_extractor(exe);
    let anna = &w.anna;
    put_text(&st, anna, "/invoice.pdf", "%PDF-1.4 not really").await;
    put_text(&st, anna, "/letter.docx", "PK not really").await;
    put_text(&st, anna, "/plain.txt", "aardvark in a text file").await;
    index(&st).await;
    let mut got = paths(&st, anna, "aardvark").await;
    got.sort();
    assert_eq!(got, ["invoice.pdf", "letter.docx", "plain.txt"]);
}

#[tokio::test]
async fn an_unreadable_document_is_given_up_on_at_once_a_crashing_one_after_three_tries() {
    let w = world().await;
    let anna = &w.anna;
    let exe = fake_reader(w._dir.path(), "cat >/dev/null; exit 2");
    let st = w.st.clone().with_extractor(exe);
    put_text(&st, anna, "/broken.pdf", "%PDF").await;
    index(&st).await;
    let s = st.search_status(&Actor::Cli).await.expect("status").index;
    assert_eq!((s.unsupported, s.failed, s.pending), (1, 0, 0), "{s:?}");

    let w = world().await;
    let anna = &w.anna;
    let exe = fake_reader(w._dir.path(), "cat >/dev/null; kill -SEGV $$");
    let st = w.st.clone().with_extractor(exe);
    put_text(&st, anna, "/crash.pdf", "%PDF").await;
    for _ in 0..3 {
        st.indexer_pass().await.expect("pass");
    }
    let s = st.search_status(&Actor::Cli).await.expect("status").index;
    assert_eq!((s.failed, s.pending), (1, 0), "{s:?}");
    // the name is found all the same
    assert_eq!(paths(&st, anna, "crash").await, ["crash.pdf"]);
}

#[tokio::test]
async fn switching_documents_off_removes_their_texts_and_on_reads_them_again() {
    let w = world().await;
    let anna = &w.anna;
    let exe = fake_reader(w._dir.path(), "cat >/dev/null; echo 'a manatee swims'");
    let st = w.st.clone().with_extractor(exe);
    put_text(&st, anna, "/sea.pdf", "%PDF").await;
    put_text(&st, anna, "/note.txt", "the manatee in a note").await;
    index(&st).await;
    assert_eq!(paths(&st, anna, "manatee").await.len(), 2);
    st.set_tunable(&Actor::Cli, "search.documents", "0")
        .await
        .expect("off");
    index(&st).await;
    // the text file stays searchable, the PDF is found by name only
    assert_eq!(paths(&st, anna, "manatee").await, ["note.txt"]);
    assert_eq!(paths(&st, anna, "sea").await, ["sea.pdf"]);
    st.set_tunable(&Actor::Cli, "search.documents", "1")
        .await
        .expect("on");
    index(&st).await;
    assert_eq!(paths(&st, anna, "manatee").await.len(), 2);
}

#[tokio::test]
async fn a_document_text_is_not_shown_to_somebody_who_may_not_read_the_file() {
    let w = world().await;
    let exe = fake_reader(
        w._dir.path(),
        "cat >/dev/null; echo 'secret quokka figures'",
    );
    let st = w.st.clone().with_extractor(exe);
    put_text(&st, &w.anna, "/private.pdf", "%PDF").await;
    index(&st).await;
    assert_eq!(paths(&st, &w.anna, "quokka").await, ["private.pdf"]);
    assert!(paths(&st, &w.bob, "quokka").await.is_empty());
}
