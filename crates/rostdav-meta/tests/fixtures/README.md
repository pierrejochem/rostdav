# Fixtures

`made-by-sqlite-0.2.0.db` is a database as the SQLite-based Rostdav 0.2.0 left it: the schema of
migrations 1 to 11 (with `favorites` as a `WITHOUT ROWID` table, as that version created it), the
`_sqlx_migrations` history, one user (`alice`), a root folder with `Docs` (containing `Sub`) and
`Pics`, and two favorites (`Docs`, `Pics`). It was made with Python's `sqlite3` (SQLite 3.46) and
is used by `tests/upgrade.rs` to check that the Turso-based versions open and convert it.
