//! Opening a database that the SQLite-based Rostdav 0.2.0 made.

use rostdav_meta::Db;

fn copy_fixture() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rostdav.sqlite");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/made-by-sqlite-0.2.0.db"
        ),
        &path,
    )
    .expect("copy fixture");
    let url = format!("sqlite://{}", path.display());
    (dir, url)
}

#[tokio::test]
async fn a_database_from_the_sqlite_versions_opens_and_keeps_its_data() {
    let (_dir, url) = copy_fixture();
    let db = Db::open(&url).await.expect("open");
    db.migrate().await.expect("migrate");

    // the history of the old versions counts, and only the new migration ran
    let alice = db
        .find_user("alice")
        .await
        .expect("find")
        .expect("alice is there");
    assert_eq!(alice.name, "alice");
    let root = db.root_node(alice.id).await.expect("root");
    let kids: Vec<String> = db
        .children(root.id)
        .await
        .expect("children")
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert_eq!(kids, ["Docs", "Pics"]);

    // favorites survived the conversion and can be changed (the old table could not be written)
    let docs = db.children(root.id).await.expect("c").remove(0);
    let pics = db.children(root.id).await.expect("c").remove(1);
    assert_eq!(
        db.favorites_own(alice.id).await.expect("favorites"),
        [docs.id, pics.id]
    );
    db.favorite_set(alice.id, docs.id, false)
        .await
        .expect("remove");
    assert_eq!(
        db.favorites_own(alice.id).await.expect("favorites"),
        [pics.id]
    );
    db.favorite_set(alice.id, docs.id, true).await.expect("add");
    assert_eq!(
        db.favorites_own(alice.id).await.expect("favorites").len(),
        2
    );

    // a second start does nothing more, and the data is still there after a restart
    db.migrate().await.expect("again");
    db.close().await;
    drop(db);
    let db = Db::open(&url).await.expect("reopen");
    db.migrate().await.expect("migrate after reopen");
    assert_eq!(
        db.favorites_own(alice.id).await.expect("favorites").len(),
        2
    );
    db.ping().await.expect("ping");
}

#[tokio::test]
async fn deleting_a_user_of_an_old_database_removes_the_whole_tree() {
    let (_dir, url) = copy_fixture();
    let db = Db::open(&url).await.expect("open");
    db.migrate().await.expect("migrate");
    let alice = db.find_user("alice").await.expect("find").expect("alice");
    let root = db.root_node(alice.id).await.expect("root");
    let docs = db.children(root.id).await.expect("c").remove(0);
    // Docs holds Sub: removing Docs takes Sub, and its favorite goes with it
    db.delete_node(docs.id, None).await.expect("delete Docs");
    assert!(db.node_by_id(docs.id).await.expect("q").is_none());
    assert_eq!(
        db.favorites_own(alice.id).await.expect("favorites").len(),
        1
    );
}
