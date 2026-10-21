//! Authorization matrix for shares and links (ADR 0004).

use std::net::{IpAddr, Ipv4Addr};

use rostdav_core::{Error, LogicalPath};
use rostdav_meta::{Db, ShareKind, WriteCondition};
use rostdav_storage::LocalStore;
use tokio::io::AsyncReadExt;

use crate::*;

const PW: &str = "korrekt-pferd-batterie";
const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct World {
    _dir: tempfile::TempDir,
    st: AppState,
    anna: Principal,
    bob: Principal,
    carl: Principal,
    root: Principal,
}

fn lp(s: &str) -> LogicalPath {
    LogicalPath::from_url_path(s).expect("path")
}

async fn put(
    st: &AppState,
    p: &Principal,
    path: &str,
    body: &str,
) -> Result<rostdav_meta::Written, Error> {
    st.put(p, &lp(path), body.as_bytes(), None, &WriteCondition::None)
        .await
}

async fn world() -> World {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = LocalStore::open(dir.path().join("data"))
        .await
        .expect("store");
    let db = Db::open(&Db::default_url(store.root())).await.expect("db");
    db.migrate().await.expect("migrate");
    let st = AppState::new(db, store).await.expect("state");
    for (n, admin) in [
        ("anna", false),
        ("bob", false),
        ("carl", false),
        ("root", true),
    ] {
        st.add_user(n, PW, admin).await.expect("user");
    }
    let login = |n: &'static str| {
        let st = st.clone();
        async move { st.authenticate(n, PW, IP).await.expect("auth") }
    };
    let (anna, bob, carl, root) = (
        login("anna").await,
        login("bob").await,
        login("carl").await,
        login("root").await,
    );
    st.mkcol(&anna, &lp("/Shared")).await.expect("mkcol");
    st.mkcol(&anna, &lp("/Shared/sub")).await.expect("mkcol");
    st.mkcol(&anna, &lp("/Private")).await.expect("mkcol");
    put(&st, &anna, "/Shared/hello.txt", "hello")
        .await
        .expect("put");
    put(&st, &anna, "/Shared/sub/inner.txt", "inner")
        .await
        .expect("put");
    put(&st, &anna, "/Private/secret.txt", "secret")
        .await
        .expect("put");
    put(&st, &anna, "/single.txt", "single").await.expect("put");
    put(&st, &bob, "/mine.txt", "bobs own").await.expect("put");
    World {
        _dir: dir,
        st,
        anna,
        bob,
        carl,
        root,
    }
}

fn create(path: &str, with: &str, perms: i64) -> ShareCreate {
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

fn link(path: &str, perms: i64, password: Option<&str>) -> ShareCreate {
    ShareCreate {
        share_type: 3,
        share_with: None,
        password: password.map(str::to_owned),
        ..create(path, "", perms)
    }
}

async fn text(st: &AppState, p: &Principal, path: &str) -> Result<String, Error> {
    let (_, mut f) = st.read(p, &lp(path)).await?;
    let mut s = String::new();
    f.read_to_string(&mut s).await.map_err(Error::internal)?;
    Ok(s)
}

fn denied<T: std::fmt::Debug>(r: &Result<T, Error>) -> bool {
    matches!(r, Err(Error::Forbidden))
}

// ---- recipients -----------------------------------------------------------------

#[tokio::test]
async fn recipient_rights_follow_the_permission_bits() {
    let w = world().await;
    let st = &w.st;
    for perms in [1i64, 3, 5, 7, 9, 11, 13, 15, 17, 31] {
        // a fresh share per round
        st.share_delete(
            &w.anna,
            st.shares_list(&w.anna, ShareFilter::default())
                .await
                .expect("l")
                .first()
                .map_or(0, |v| v.share.id),
        )
        .await
        .ok();
        let v = st
            .share_create(&w.anna, create("/Shared", "bob", perms))
            .await
            .expect("share");
        let eff = i64::from((perms & 15) as u8);
        assert_eq!(i64::from(v.share.permissions), eff, "bit 16 is dropped");
        let (upd, cre, del) = (eff & 2 != 0, eff & 4 != 0, eff & 8 != 0);
        let tag = format!("perms={perms}");

        // reading always works
        assert_eq!(
            text(st, &w.bob, "/Shared/hello.txt").await.expect("read"),
            "hello",
            "{tag}"
        );
        assert_eq!(
            st.list(&w.bob, &lp("/Shared"))
                .await
                .expect("list")
                .children
                .len(),
            2,
            "{tag}"
        );
        assert!(
            st.stat(&w.bob, &lp("/Shared/sub/inner.txt")).await.is_ok(),
            "{tag}"
        );

        // overwrite = update bit
        let r = put(st, &w.bob, "/Shared/hello.txt", "changed").await;
        assert_eq!(r.is_ok(), upd, "{tag} overwrite: {r:?}");
        if !upd {
            assert!(denied(&r), "{tag}");
        }
        // create = create bit (file and folder), also below subfolders
        let r = put(st, &w.bob, "/Shared/new.txt", "new").await;
        assert_eq!(r.is_ok(), cre, "{tag} create: {r:?}");
        let r = st.mkcol(&w.bob, &lp("/Shared/sub/newdir")).await;
        assert_eq!(r.is_ok(), cre, "{tag} mkcol: {r:?}");
        // delete = delete bit
        let r = st.delete(&w.bob, &lp("/Shared/sub/inner.txt"), None).await;
        assert_eq!(r.is_ok(), del, "{tag} delete: {r:?}");
        // rename inside the share needs delete + create
        let r = st
            .move_to(
                &w.bob,
                &lp("/Shared/hello.txt"),
                &lp("/Shared/renamed.txt"),
                false,
            )
            .await;
        assert_eq!(r.is_ok(), del && cre, "{tag} move: {r:?}");

        // restore the fixture state for the next round (as the owner)
        for (path, body) in [
            ("/Shared/hello.txt", "hello"),
            ("/Shared/sub/inner.txt", "inner"),
        ] {
            st.delete(&w.anna, &lp(path), None).await.ok();
            st.delete(&w.anna, &lp(&path.replace("hello", "renamed")), None)
                .await
                .ok();
            put(st, &w.anna, path, body).await.expect("restore");
        }
        for extra in ["/Shared/new.txt", "/Shared/renamed.txt"] {
            st.delete(&w.anna, &lp(extra), None).await.ok();
        }
        st.delete(&w.anna, &lp("/Shared/sub/newdir"), None)
            .await
            .ok();
    }
}

#[tokio::test]
async fn copies_leave_and_enter_shares_but_moves_do_not() {
    let w = world().await;
    let st = &w.st;
    st.share_create(&w.anna, create("/Shared", "bob", 1))
        .await
        .expect("read-only share");

    // out of a read-only share into the own tree: allowed, and it is bob's own data now
    let c = st
        .copy_to(&w.bob, &lp("/Shared/hello.txt"), &lp("/copy.txt"), false)
        .await
        .expect("copy out");
    assert_eq!(c.node.owner_id, w.bob.user_id);
    assert_eq!(
        st.user_info(&w.bob).await.expect("i").used,
        8 + 5,
        "counts for bob"
    );
    put(st, &w.bob, "/copy.txt", "bob edits his copy")
        .await
        .expect("own copy is writable");
    assert_eq!(
        text(st, &w.anna, "/Shared/hello.txt").await.expect("r"),
        "hello",
        "the original is untouched"
    );

    // into a read-only share: denied
    let r = st
        .copy_to(&w.bob, &lp("/mine.txt"), &lp("/Shared/in.txt"), false)
        .await;
    assert!(denied(&r), "{r:?}");

    // with create right a copy goes in and belongs to the owner (quota!)
    st.share_update(
        &w.anna,
        st.shares_list(&w.anna, ShareFilter::default())
            .await
            .expect("l")[0]
            .share
            .id,
        ShareChange {
            permissions: Some(15),
            ..ShareChange::default()
        },
    )
    .await
    .expect("update");
    let before = st.user_info(&w.anna).await.expect("i").used;
    let c = st
        .copy_to(&w.bob, &lp("/mine.txt"), &lp("/Shared/in.txt"), false)
        .await
        .expect("copy in");
    assert_eq!(c.node.owner_id, w.anna.user_id);
    assert_eq!(
        st.user_info(&w.anna).await.expect("i").used,
        before + 8,
        "the owner pays"
    );

    // moves between trees or shares are refused, in both directions
    let r = st
        .move_to(&w.bob, &lp("/mine.txt"), &lp("/Shared/moved.txt"), false)
        .await;
    assert!(matches!(r, Err(Error::Conflict(_))), "{r:?}");
    let r = st
        .move_to(&w.bob, &lp("/Shared/hello.txt"), &lp("/moved.txt"), false)
        .await;
    assert!(matches!(r, Err(Error::Conflict(_))), "{r:?}");
    assert_eq!(
        text(st, &w.anna, "/Shared/hello.txt").await.expect("r"),
        "hello"
    );
}

#[tokio::test]
async fn nothing_outside_the_share_is_reachable() {
    let w = world().await;
    let st = &w.st;
    st.share_create(&w.anna, create("/Shared", "bob", 15))
        .await
        .expect("share");
    // anna's other data does not exist in bob's view
    for p in [
        "/Private",
        "/Private/secret.txt",
        "/single.txt",
        "/Shared/../Private",
    ] {
        match LogicalPath::from_url_path(p) {
            Ok(path) => assert!(
                matches!(st.stat(&w.bob, &path).await, Err(Error::NotFound)),
                "{p}"
            ),
            Err(_) => assert!(p.contains("..")),
        }
    }
    // the shared path does not exist under another name or for others
    assert!(
        matches!(st.stat(&w.bob, &lp("/shared")).await, Err(Error::NotFound)),
        "names are case sensitive"
    );
    assert!(matches!(
        st.stat(&w.carl, &lp("/Shared")).await,
        Err(Error::NotFound)
    ));
    assert!(
        matches!(st.stat(&w.root, &lp("/Shared")).await, Err(Error::NotFound)),
        "admins get no implicit access"
    );
    // listing bob's root shows the mount, listing anna's root shows no mount
    let l = st.list(&w.bob, &LogicalPath::root()).await.expect("list");
    assert_eq!(
        l.mounts.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
        ["Shared"]
    );
    assert_eq!(l.owners[&w.anna.user_id], "anna");
    assert!(
        st.list(&w.anna, &LogicalPath::root())
            .await
            .expect("list")
            .mounts
            .is_empty()
    );
    assert!(
        st.list(&w.carl, &LogicalPath::root())
            .await
            .expect("list")
            .mounts
            .is_empty()
    );
    // a grant resolved for one principal is useless for another
    let a = st
        .stat_access(&w.bob, &lp("/Shared/hello.txt"))
        .await
        .expect("access");
    assert!(denied(&authorize_access(&w.carl, &a, Need::Read)));
    assert!(
        denied(&authorize_access(&w.anna, &a, Need::Read)),
        "even the owner needs her own grant"
    );
    assert!(authorize_access(&w.bob, &a, Need::Read).is_ok());
}

#[tokio::test]
async fn mount_points_can_be_renamed_and_left_but_not_clobbered() {
    let w = world().await;
    let st = &w.st;
    let v = st
        .share_create(&w.anna, create("/Shared", "bob", 1))
        .await
        .expect("share");
    // read-only recipients may still rename and leave
    st.move_to(&w.bob, &lp("/Shared"), &lp("/Team"), false)
        .await
        .expect("rename mount");
    assert!(matches!(
        st.stat(&w.bob, &lp("/Shared")).await,
        Err(Error::NotFound)
    ));
    assert_eq!(
        text(st, &w.bob, "/Team/hello.txt").await.expect("r"),
        "hello"
    );
    // names are taken
    assert!(matches!(
        st.mkcol(&w.bob, &lp("/Team")).await,
        Err(Error::AlreadyExists)
    ));
    assert!(put(st, &w.bob, "/Team", "x").await.is_err());
    let r = st
        .move_to(&w.bob, &lp("/Team"), &lp("/mine.txt"), false)
        .await;
    assert!(matches!(r, Err(Error::PreconditionFailed)), "{r:?}");
    let r = st
        .move_to(&w.bob, &lp("/mine.txt"), &lp("/Team"), true)
        .await;
    assert!(
        r.is_err(),
        "an own file cannot replace a mount point: {r:?}"
    );
    // a mount cannot be moved into a folder
    st.mkcol(&w.bob, &lp("/dir")).await.expect("dir");
    let r = st
        .move_to(&w.bob, &lp("/Team"), &lp("/dir/Team"), false)
        .await;
    assert!(matches!(r, Err(Error::Conflict(_))), "{r:?}");
    // inside the share nothing may be renamed to leave it
    // leaving ends the share for the owner as well
    st.delete(&w.bob, &lp("/Team"), None).await.expect("leave");
    assert!(matches!(
        st.stat(&w.bob, &lp("/Team")).await,
        Err(Error::NotFound)
    ));
    assert!(st.share_get(&w.anna, v.share.id).await.is_err());
    assert_eq!(
        text(st, &w.anna, "/Shared/hello.txt").await.expect("r"),
        "hello",
        "the owner's data stays"
    );
}

#[tokio::test]
async fn owner_changes_are_followed_by_the_share() {
    let w = world().await;
    let st = &w.st;
    st.share_create(&w.anna, create("/Shared", "bob", 15))
        .await
        .expect("share");
    put(st, &w.bob, "/Shared/by-bob.txt", "from bob")
        .await
        .expect("bob writes");
    assert_eq!(
        text(st, &w.anna, "/Shared/by-bob.txt").await.expect("r"),
        "from bob"
    );
    let etag = |p: &'static str, who: &Principal| {
        let st = st.clone();
        let who = who.clone();
        async move { st.stat(&who, &lp(p)).await.expect("stat").etag }
    };
    let (e0, r0) = (
        etag("/Shared", &w.bob).await,
        st.stat(&w.bob, &LogicalPath::root())
            .await
            .expect("root")
            .etag,
    );
    put(st, &w.anna, "/Shared/sub/new.txt", "x")
        .await
        .expect("owner writes");
    assert_ne!(
        etag("/Shared", &w.bob).await,
        e0,
        "recipients see changes through the folder ETag"
    );
    let _ = r0;

    // renaming/moving the shared folder keeps the share
    st.mkcol(&w.anna, &lp("/Archive")).await.expect("mkcol");
    st.move_to(&w.anna, &lp("/Shared"), &lp("/Archive/Renamed"), false)
        .await
        .expect("move");
    assert_eq!(
        text(st, &w.bob, "/Shared/hello.txt").await.expect("r"),
        "hello"
    );
    // deleting it ends the share
    st.delete(&w.anna, &lp("/Archive/Renamed"), None)
        .await
        .expect("delete");
    assert!(matches!(
        st.stat(&w.bob, &lp("/Shared")).await,
        Err(Error::NotFound)
    ));
    assert!(
        st.list(&w.bob, &LogicalPath::root())
            .await
            .expect("l")
            .mounts
            .is_empty()
    );
}

#[tokio::test]
async fn writes_in_shares_use_the_owners_quota() {
    let w = world().await;
    let st = &w.st;
    st.share_create(&w.anna, create("/Shared", "bob", 15))
        .await
        .expect("share");
    let used = st.user_info(&w.anna).await.expect("i").used;
    st.set_quota("anna", Some(used + 10)).await.expect("quota");
    put(st, &w.bob, "/Shared/ten.txt", "0123456789")
        .await
        .expect("fits the owner's quota");
    let r = put(st, &w.bob, "/Shared/one-more.txt", "x").await;
    assert!(matches!(r, Err(Error::QuotaExceeded)), "{r:?}");
    // bob's own quota is not involved
    assert_eq!(st.user_info(&w.bob).await.expect("i").used, 8);
    st.set_quota("anna", None).await.expect("quota");
    st.set_quota("bob", Some(1)).await.expect("quota");
    put(
        st,
        &w.bob,
        "/Shared/free-for-bob.txt",
        "plenty of room at anna's",
    )
    .await
    .expect("owner pays");
    // versions made by bob's overwrite belong to anna
    put(st, &w.bob, "/Shared/hello.txt", "new")
        .await
        .expect("overwrite");
    let id = st
        .stat(&w.anna, &lp("/Shared/hello.txt"))
        .await
        .expect("s")
        .id;
    assert_eq!(
        st.version_list(&w.anna, id).await.expect("l").entries.len(),
        2
    );
    assert!(
        matches!(st.version_list(&w.bob, id).await, Err(Error::NotFound)),
        "recipients never see versions"
    );
}

// ---- creating and changing shares --------------------------------------------------

#[tokio::test]
async fn creating_shares_checks_everything() {
    let w = world().await;
    let st = &w.st;
    let err = |r: Result<ShareView, ShareError>| r.expect_err("must fail");
    let e = err(st
        .share_create(&w.anna, create("/Shared", "anna", 31))
        .await);
    assert_eq!(
        (e.status, e.message.as_str()),
        (403, "Cannot share with yourself")
    );
    let e = err(st
        .share_create(&w.anna, create("/Shared", "ghost", 31))
        .await);
    assert_eq!(
        (e.status, e.message.as_str()),
        (404, "Please specify a valid account to share with")
    );
    let e = err(st.share_create(&w.anna, create("/nope", "bob", 31)).await);
    assert_eq!(
        (e.status, e.message.as_str()),
        (404, "Wrong path, file/folder does not exist")
    );
    let e = err(st
        .share_create(
            &w.anna,
            ShareCreate {
                path: None,
                ..create("/x", "bob", 31)
            },
        )
        .await);
    assert_eq!(
        (e.status, e.message.as_str()),
        (404, "Please specify a file or folder path")
    );
    for bad in [0i64, 2, 32, 99, -1] {
        let e = err(st
            .share_create(&w.anna, create("/Shared", "bob", bad))
            .await);
        assert_eq!(
            (e.status, e.message.as_str()),
            (403, "Valid permissions are required for sharing"),
            "{bad}"
        );
    }
    let e = err(st
        .share_create(
            &w.anna,
            ShareCreate {
                share_type: 77,
                ..create("/Shared", "bob", 1)
            },
        )
        .await);
    assert_eq!((e.status, e.message.as_str()), (400, "Unknown share type"));
    let e = err(st.share_create(&w.anna, create("/", "bob", 1)).await);
    assert_eq!(e.status, 403, "the root cannot be shared");
    // a disabled user cannot be offered a share
    st.user_set_disabled(&Actor::Cli, "carl", true)
        .await
        .expect("disable");
    let e = err(st.share_create(&w.anna, create("/Shared", "carl", 1)).await);
    assert_eq!(e.status, 404);
    st.user_set_disabled(&Actor::Cli, "carl", false)
        .await
        .expect("enable");

    // others cannot share anna's things; recipients cannot reshare
    let e = err(st.share_create(&w.bob, create("/Shared", "carl", 1)).await);
    assert_eq!(e.status, 404, "bob has no /Shared yet");
    st.share_create(&w.anna, create("/Shared", "bob", 15))
        .await
        .expect("share");
    let e = err(st.share_create(&w.bob, create("/Shared", "carl", 1)).await);
    assert_eq!(
        (e.status, e.message.as_str()),
        (403, "Resharing is not allowed")
    );
    let e = err(st
        .share_create(&w.bob, create("/Shared/hello.txt", "carl", 1))
        .await);
    assert_eq!(e.status, 403);

    // files: only read and update bits survive; sharing twice returns the same share
    let f = st
        .share_create(&w.anna, create("/single.txt", "bob", 31))
        .await
        .expect("file share");
    assert_eq!(f.share.permissions, 3);
    let again = st
        .share_create(&w.anna, create("/single.txt", "bob", 1))
        .await
        .expect("again");
    assert_eq!((again.share.id, again.share.permissions), (f.share.id, 3));
    // the mount name avoids clashes with bob's own files
    put(st, &w.bob, "/Docs", "x").await.expect("put");
    st.mkcol(&w.anna, &lp("/Docs")).await.expect("mkcol");
    let d = st
        .share_create(&w.anna, create("/Docs", "bob", 15))
        .await
        .expect("share");
    assert_eq!(d.share.mount_name.as_deref(), Some("Docs (2)"));
}

#[tokio::test]
async fn changing_and_removing_shares_is_for_the_owner_only() {
    let w = world().await;
    let st = &w.st;
    let v = st
        .share_create(&w.anna, create("/Shared", "bob", 15))
        .await
        .expect("share");
    let id = v.share.id;

    for who in [&w.bob, &w.carl, &w.root] {
        let r = st
            .share_update(
                who,
                id,
                ShareChange {
                    permissions: Some(1),
                    ..ShareChange::default()
                },
            )
            .await;
        let e = r.expect_err("not the owner");
        if who.user_id == w.bob.user_id {
            assert_eq!(
                (e.status, e.message.as_str()),
                (403, "You are not allowed to edit incoming shares")
            );
        } else {
            assert_eq!(
                (e.status, e.message.as_str()),
                (404, "Wrong share ID, share does not exist")
            );
        }
        assert_eq!(
            st.share_delete(who, id).await.expect_err("delete").status,
            404
        );
    }
    // visibility: owner and recipient only
    assert_eq!(
        st.share_get(&w.bob, id).await.expect("recipient").viewer,
        Viewer::Recipient
    );
    assert_eq!(
        st.share_get(&w.anna, id).await.expect("owner").viewer,
        Viewer::Owner
    );
    assert_eq!(
        st.share_get(&w.carl, id)
            .await
            .expect_err("stranger")
            .status,
        404
    );
    assert_eq!(
        st.share_get(&w.root, id).await.expect_err("admin").status,
        404
    );
    assert_eq!(
        st.share_get(&w.anna, 999)
            .await
            .expect_err("missing")
            .status,
        404
    );

    let e = st
        .share_update(
            &w.anna,
            id,
            ShareChange {
                permissions: Some(2),
                ..ShareChange::default()
            },
        )
        .await
        .expect_err("no read");
    assert_eq!(
        (e.status, e.message.as_str()),
        (403, "File share needs at least read permission.")
    );
    let e = st
        .share_update(
            &w.anna,
            id,
            ShareChange {
                expire: Some("2000-01-01".into()),
                ..ShareChange::default()
            },
        )
        .await
        .expect_err("past");
    assert_eq!(
        (e.status, e.message.as_str()),
        (404, "Expiration date is in the past")
    );
    let u = st
        .share_update(
            &w.anna,
            id,
            ShareChange {
                permissions: Some(5),
                note: Some("hi".into()),
                expire: Some("2999-01-01".into()),
                ..ShareChange::default()
            },
        )
        .await
        .expect("update");
    assert_eq!(
        (
            u.share.permissions,
            u.share.note.as_str(),
            u.share.expires_at
        ),
        (5, "hi", Some(32_472_144_000))
    );
    // the new rights apply immediately
    assert!(put(st, &w.bob, "/Shared/n.txt", "x").await.is_ok());
    assert!(denied(&put(st, &w.bob, "/Shared/hello.txt", "x").await));
    // an expired share disappears for the recipient (simulated by expiring it directly)
    st.inner
        .db
        .update_share(
            id,
            &rostdav_meta::ShareUpdate {
                expires_at: Some(Some(1)),
                ..Default::default()
            },
        )
        .await
        .expect("expire");
    assert!(matches!(
        st.stat(&w.bob, &lp("/Shared")).await,
        Err(Error::NotFound)
    ));
    assert!(
        st.shares_list(
            &w.bob,
            ShareFilter {
                shared_with_me: true,
                ..ShareFilter::default()
            }
        )
        .await
        .expect("l")
        .is_empty()
    );

    // an expired share is invisible to the API; deleting it by ID is a 404 too
    assert_eq!(
        st.share_delete(&w.anna, id)
            .await
            .expect_err("expired")
            .status,
        404
    );
    let other = st
        .share_create(&w.anna, create("/Shared", "carl", 1))
        .await
        .expect("share");
    st.share_delete(&w.anna, other.share.id)
        .await
        .expect("delete");
    assert_eq!(
        st.share_delete(&w.anna, other.share.id)
            .await
            .expect_err("again")
            .status,
        404
    );
}

#[tokio::test]
async fn listing_shares() {
    let w = world().await;
    let st = &w.st;
    st.share_create(&w.anna, create("/Shared", "bob", 15))
        .await
        .expect("s1");
    st.share_create(&w.anna, create("/single.txt", "carl", 1))
        .await
        .expect("s2");
    st.share_create(&w.anna, link("/Shared", 1, None))
        .await
        .expect("l1");
    let all = st
        .shares_list(&w.anna, ShareFilter::default())
        .await
        .expect("all");
    assert_eq!(all.len(), 3);
    assert!(
        all.iter()
            .all(|v| v.viewer == Viewer::Owner && v.owner == "anna")
    );
    let by_path = st
        .shares_list(
            &w.anna,
            ShareFilter {
                path: Some(lp("/Shared")),
                ..ShareFilter::default()
            },
        )
        .await
        .expect("p");
    assert_eq!(by_path.len(), 2);
    let sub = st
        .shares_list(
            &w.anna,
            ShareFilter {
                path: Some(LogicalPath::root()),
                subfiles: true,
                ..ShareFilter::default()
            },
        )
        .await
        .expect("sub");
    assert_eq!(sub.len(), 3, "the root's children carry all three");
    let e = st
        .shares_list(
            &w.anna,
            ShareFilter {
                path: Some(lp("/nope")),
                ..ShareFilter::default()
            },
        )
        .await
        .expect_err("nope");
    assert_eq!(e.status, 404);
    // recipients see their incoming shares only; strangers and others' lists are empty
    let mine = st
        .shares_list(
            &w.bob,
            ShareFilter {
                shared_with_me: true,
                ..ShareFilter::default()
            },
        )
        .await
        .expect("bob");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].viewer, Viewer::Recipient);
    assert_eq!(
        st.shares_list(&w.bob, ShareFilter::default())
            .await
            .expect("own")
            .len(),
        0,
        "bob gave nothing"
    );
    assert_eq!(
        st.shares_list(&w.carl, ShareFilter::default())
            .await
            .expect("carl")
            .len(),
        0
    );
    // bob cannot enumerate anna's shares through a path
    let r = st
        .shares_list(
            &w.bob,
            ShareFilter {
                path: Some(lp("/Shared")),
                ..ShareFilter::default()
            },
        )
        .await;
    assert_eq!(r.expect_err("not own").status, 404);
    assert_eq!(
        st.sharees(&w.anna, "o", 10).await.expect("s"),
        vec!["bob".to_owned(), "root".to_owned()]
    );
    assert_eq!(
        st.sharees(&w.anna, "an", 10).await.expect("s"),
        Vec::<String>::new()
    );
}

// ---- public links ---------------------------------------------------------------------

#[tokio::test]
async fn links_grant_exactly_the_shared_node() {
    let w = world().await;
    let st = &w.st;
    let v = st
        .share_create(&w.anna, link("/Shared", 1, None))
        .await
        .expect("link");
    let token = v.share.token.clone().expect("token");
    assert_eq!(token.len(), LINK_TOKEN_LEN);
    assert_eq!(v.share.kind, ShareKind::Link);

    let l = st.authenticate_link(&token, "", IP).await.expect("sign in");
    assert_eq!(
        l.scope,
        Scope::Link {
            share_id: v.share.id,
            node_id: v.node.id,
            perms: 1
        }
    );
    assert!(!l.is_admin);
    assert_eq!(text(st, &l, "/hello.txt").await.expect("r"), "hello");
    assert_eq!(
        st.list(&l, &LogicalPath::root())
            .await
            .expect("l")
            .children
            .len(),
        2
    );
    assert_eq!(text(st, &l, "/sub/inner.txt").await.expect("r"), "inner");
    // not beyond the root
    for p in [
        "/Private/secret.txt",
        "/Shared/hello.txt",
        "/single.txt",
        "/mine.txt",
    ] {
        assert!(
            matches!(st.stat(&l, &lp(p)).await, Err(Error::NotFound)),
            "{p}"
        );
    }
    // read-only: every write is denied
    assert!(denied(&put(st, &l, "/new.txt", "x").await));
    assert!(denied(&put(st, &l, "/hello.txt", "x").await));
    assert!(denied(&st.mkcol(&l, &lp("/d")).await));
    assert!(denied(&st.delete(&l, &lp("/hello.txt"), None).await));
    assert!(denied(
        &st.move_to(&l, &lp("/hello.txt"), &lp("/h2.txt"), false)
            .await
    ));
    assert!(
        denied(&st.delete(&l, &LogicalPath::root(), None).await),
        "the root of a link cannot be deleted"
    );
    assert!(
        st.move_to(&l, &LogicalPath::root(), &lp("/x"), false)
            .await
            .is_err()
    );
    // copying out is not possible (the link has no tree of its own); copying inside needs create
    assert!(denied(
        &st.copy_to(&l, &lp("/hello.txt"), &lp("/copy.txt"), false)
            .await
    ));
    // links are no users
    assert!(st.user_info(&l).await.is_err());
    assert!(st.upload_create(&l, "t").await.is_err());
    let id = st
        .stat(&w.anna, &lp("/Shared/hello.txt"))
        .await
        .expect("s")
        .id;
    assert!(matches!(
        st.version_list(&l, id).await,
        Err(Error::NotFound)
    ));
    assert_eq!(
        st.share_create(&l, create("/hello.txt", "bob", 1))
            .await
            .expect_err("e")
            .status,
        403
    );
    assert!(st.shares_list(&l, ShareFilter::default()).await.is_err());
    assert!(st.users_list(&Actor::User(&l)).await.is_err());
    // a link grant is useless for others and vice versa
    let a = st.stat_access(&l, &lp("/hello.txt")).await.expect("a");
    assert!(denied(&authorize_access(&w.bob, &a, Need::Read)));
    let own = st
        .stat_access(&w.anna, &lp("/Shared/hello.txt"))
        .await
        .expect("own");
    assert!(denied(&authorize_access(&l, &own, Need::Read)));
}

#[tokio::test]
async fn editable_links_write_into_the_owners_tree() {
    let w = world().await;
    let st = &w.st;
    let v = st
        .share_create(&w.anna, link("/Shared", 15, None))
        .await
        .expect("link");
    let l = st
        .authenticate_link(v.share.token.as_deref().expect("t"), "", IP)
        .await
        .expect("in");
    put(st, &l, "/up.txt", "via link").await.expect("create");
    put(st, &l, "/hello.txt", "edited")
        .await
        .expect("overwrite");
    st.mkcol(&l, &lp("/newdir")).await.expect("mkcol");
    st.move_to(&l, &lp("/up.txt"), &lp("/newdir/up.txt"), false)
        .await
        .expect("move inside");
    assert_eq!(
        text(st, &w.anna, "/Shared/newdir/up.txt").await.expect("r"),
        "via link"
    );
    assert_eq!(
        st.stat(&w.anna, &lp("/Shared/newdir/up.txt"))
            .await
            .expect("s")
            .owner_id,
        w.anna.user_id
    );
    st.delete(&l, &lp("/newdir"), None).await.expect("delete");
    assert!(denied(&st.delete(&l, &LogicalPath::root(), None).await));
    // create-only link ("file drop"): upload yes, nothing else
    let d = st
        .share_create(&w.anna, link("/Shared/sub", 4, None))
        .await
        .expect("drop");
    let l = st
        .authenticate_link(d.share.token.as_deref().expect("t"), "", IP)
        .await
        .expect("in");
    put(st, &l, "/dropped.txt", "x").await.expect("drop");
    assert!(
        denied(&put(st, &l, "/dropped.txt", "y").await),
        "no overwrite"
    );
    assert!(denied(&st.delete(&l, &lp("/dropped.txt"), None).await));
    // a file link
    let f = st
        .share_create(&w.anna, link("/single.txt", 1, None))
        .await
        .expect("file link");
    let l = st
        .authenticate_link(f.share.token.as_deref().expect("t"), "", IP)
        .await
        .expect("in");
    assert_eq!(text(st, &l, "/").await.expect("r"), "single");
    assert!(st.list(&l, &LogicalPath::root()).await.is_err());
    assert!(put(st, &l, "/x", "x").await.is_err());
}

#[tokio::test]
async fn link_passwords_expiry_and_rate_limit() {
    let w = world().await;
    let st = &w.st;
    let short = st
        .share_create(&w.anna, link("/Shared", 1, Some("short")))
        .await
        .expect_err("too short");
    assert_eq!(short.status, 400);
    let v = st
        .share_create(&w.anna, link("/Shared", 1, Some("link-secret-password")))
        .await
        .expect("link");
    let token = v.share.token.clone().expect("t");
    assert!(
        v.share
            .password_hash
            .as_deref()
            .is_some_and(|h| h.starts_with("$argon2id$"))
    );
    let guesser: IpAddr = "203.0.113.51".parse().expect("ip");
    for pw in ["", "wrong", "link-secret-passwor", "LINK-SECRET-PASSWORD"] {
        assert!(
            matches!(
                st.authenticate_link(&token, pw, guesser).await,
                Err(Error::Unauthenticated)
            ),
            "{pw:?}"
        );
    }
    assert!(
        st.authenticate_link(&token, "link-secret-password", IP)
            .await
            .is_ok()
    );
    // the account password of the owner is no link password
    assert!(
        st.authenticate_link(&token, PW, "203.0.113.52".parse().expect("ip"))
            .await
            .is_err()
    );
    // password removal and change
    st.share_update(
        &w.anna,
        v.share.id,
        ShareChange {
            password: Some(String::new()),
            ..ShareChange::default()
        },
    )
    .await
    .expect("remove");
    assert!(st.authenticate_link(&token, "", IP).await.is_ok());

    // unknown and malformed tokens look alike
    let prober: IpAddr = "203.0.113.50".parse().expect("ip");
    for t in [
        "",
        "x",
        "nosuchtoken123456789",
        "../../etc/passwd",
        &"a".repeat(200),
    ] {
        assert!(
            matches!(
                st.authenticate_link(t, "", prober).await,
                Err(Error::Unauthenticated)
            ),
            "{t:?}"
        );
    }
    // expiry and deletion
    st.inner
        .db
        .update_share(
            v.share.id,
            &rostdav_meta::ShareUpdate {
                expires_at: Some(Some(1)),
                ..Default::default()
            },
        )
        .await
        .expect("expire");
    assert!(st.authenticate_link(&token, "", IP).await.is_err());
    let v2 = st
        .share_create(&w.anna, link("/Shared", 1, None))
        .await
        .expect("link");
    let t2 = v2.share.token.clone().expect("t");
    let r2 = st.authenticate_link(&t2, "", IP).await;
    assert!(
        r2.is_ok(),
        "{r2:?} {} perms={:?}",
        t2.len(),
        v2.share.permissions
    );
    st.share_delete(&w.anna, v2.share.id).await.expect("delete");
    assert!(st.authenticate_link(&t2, "", IP).await.is_err());

    // guessing is rate limited per address and per link
    let v3 = st
        .share_create(&w.anna, link("/Shared", 1, Some("another-secret-pass")))
        .await
        .expect("link");
    let t3 = v3.share.token.clone().expect("t");
    let other: IpAddr = "198.51.100.9".parse().expect("ip");
    for _ in 0..10 {
        let _ = st.authenticate_link(&t3, "guess", other).await;
    }
    assert!(matches!(
        st.authenticate_link(&t3, "another-secret-pass", other)
            .await,
        Err(Error::RateLimited { .. })
    ));
    let third: IpAddr = "198.51.100.10".parse().expect("ip");
    assert!(
        matches!(
            st.authenticate_link(&t3, "another-secret-pass", third)
                .await,
            Err(Error::RateLimited { .. })
        ),
        "a hammered link stays locked for every address"
    );
    // other links are not affected
    let v4 = st
        .share_create(&w.anna, link("/Shared/sub", 1, None))
        .await
        .expect("link");
    assert!(
        st.authenticate_link(v4.share.token.as_deref().expect("t"), "", third)
            .await
            .is_ok()
    );
    // failures are in the event log without the token
    let log = format!("{:?}", st.audit_events(&Actor::Cli, 0).await.expect("e"));
    assert!(log.contains("auth.login_failed") && log.contains("auth.locked"));
    assert!(!log.contains(&t3), "tokens never reach the event log");
}

#[tokio::test]
async fn share_events_and_user_removal() {
    let w = world().await;
    let st = &w.st;
    let v = st
        .share_create(&w.anna, create("/Shared", "bob", 1))
        .await
        .expect("share");
    st.share_delete(&w.anna, v.share.id).await.expect("delete");
    let v = st
        .share_create(&w.anna, create("/Shared", "bob", 1))
        .await
        .expect("share");
    st.delete(&w.bob, &lp("/Shared"), None)
        .await
        .expect("leave");
    let ev = st.audit_events(&Actor::Cli, 0).await.expect("e");
    let acts: Vec<_> = ev
        .iter()
        .map(|e| (e.actor.as_str(), e.action.as_str()))
        .filter(|(_, a)| a.starts_with("share."))
        .collect();
    assert_eq!(
        acts,
        [
            ("anna", "share.created"),
            ("anna", "share.revoked"),
            ("anna", "share.created"),
            ("bob", "share.revoked")
        ]
    );
    assert!(st.share_get(&w.anna, v.share.id).await.is_err());

    // deleting the owner takes the shares with it; deleting the recipient too
    let a = st
        .share_create(&w.anna, create("/Shared", "bob", 1))
        .await
        .expect("share");
    st.user_delete(&Actor::Cli, "bob", &DeleteMode::DeleteData)
        .await
        .expect("delete bob");
    assert!(
        st.inner
            .db
            .get_share(a.share.id)
            .await
            .expect("g")
            .is_none()
    );
    st.share_create(&w.anna, create("/Shared", "carl", 1))
        .await
        .expect("share");
    st.user_delete(&Actor::Cli, "anna", &DeleteMode::TransferTo("carl".into()))
        .await
        .expect("transfer");
    assert!(
        st.stat(&w.carl, &lp("/Shared")).await.is_err(),
        "the share to carl is gone: the data is his own now"
    );
    assert_eq!(
        text(&w.st, &w.carl, "/anna%20(transferred)/Shared/hello.txt")
            .await
            .expect("r"),
        "hello"
    );
}
