# ADR 0008: Metadata database: Turso Database instead of SQLite

- Status: **Accepted** by the project owner on 2026-10-23 (approval point 1, stack). Replaces the database engine named in [ADR 0001](0001-technology-stack.md) and [ADR 0002](0002-storage-model.md); the schema, the file format and every other decision of those ADRs stay.
- Date: 2026-10-23

## Context

Rostdav kept its metadata in SQLite through `sqlx`. The project owner decided to move to **Turso Database** (formerly Limbo), a from-scratch rewrite of SQLite in Rust that reads and writes the SQLite file format. The reasons are the owner's; this ADR records what the change means and how its risks are handled.

Turso Database is **beta** software. A file server loses user data when its metadata is wrong, so the decision rests on what was tested, not on the engine's description of itself.

## What was tested (Turso 0.8.3, the `turso` crate)

| What Rostdav uses | Result |
|---|---|
| `STRICT` tables, `CHECK`, `UNIQUE`, partial indexes, foreign keys with `ON DELETE CASCADE` and `SET NULL` | work |
| `INSERT OR IGNORE`, upsert, `RETURNING` (also with a subquery), `WITH RECURSIVE`, numbered parameters, blobs, `BEGIN IMMEDIATE`, `last_insert_rowid()` | work |
| WAL mode, `integrity_check` (it notices a damaged file), `pragma_*` table functions, `sqlite_master` | work |
| `PRAGMA foreign_key_check` | accepted but **always answers "nothing"**, even with an orphaned row present |
| `WITHOUT ROWID` tables | can be **read**, cannot be written (`favorites` was one) |
| `VACUUM INTO ?` | takes only a literal path, no parameter |
| Two connections writing at once | the second gets `Busy` at once |
| `ON DELETE CASCADE` of a parent with **several children**, foreign key column **without a plain index** | **skips rows** (the self-referencing `nodes.parent_id`; a partial index does not help) |
| The same with a plain index on the column | complete |
| Nested cascades (folder, subfolder, file, version) | complete |

The published compatibility notes of the engine list several of these as unsupported; they were out of date for the points that matter here. The cascade problem is not in them at all.

## Decision

1. **Engine:** the `turso` crate, pinned to an exact version (`=0.8.3`) and updated only on purpose, with the whole test suite as the gate. The file keeps its name and its format (`db/rostdav.sqlite`, `sqlite://` URLs).
2. **One writer.** All writes go through one connection behind an async lock; a transaction holds the lock from `BEGIN IMMEDIATE` to its end. Reads use four other connections and see the last committed state while a write transaction is open. A statement made without an explicit connection is sent to the writer or a reader by its first keyword. (`sqlx` allowed several writers to queue on `busy_timeout`; the effect is the same, only the queue is ours.)
3. **A thin layer instead of a rewrite of the queries.** `crates/rostdav-meta/src/sql.rs` keeps the call style of `sqlx` (`query`, `bind`, `fetch_one`, …), so the 184 queries changed in their executor and error types only. There is no ORM and no second database backend.
4. **Cascades must not depend on luck.** Every foreign key column that is not a row id has a plain index (migration 0012), and a schema test (`every_foreign_key_has_a_plain_index_for_cascades`) fails when a new foreign key lacks one. Behaviour tests delete folder trees with several children at every level.
5. **Migrations** come from an embedded list with a small runner (`schema_migrations`). A database made by the SQLite-based versions is recognised by its `_sqlx_migrations` table, whose successful versions count as applied; its `WITHOUT ROWID` `favorites` table is rebuilt as an ordinary table (same columns, key and rows) in one transaction. Migration `0010` no longer says `WITHOUT ROWID`.
6. **`fsck` checks the database itself.** It runs `integrity_check` and its own foreign key check (one query per foreign key of the schema, because the engine's pragma does nothing), and reports both as damage that is not repairable. A test creates an orphan on purpose and expects it to be found.
7. **Backup** keeps using `VACUUM INTO` (path quoted as a literal). The backup is a normal database file; restoring is still "copy it into place".

## Consequences

- **Upgrading a database is one-way in practice.** The first start of a Turso-based version converts the `favorites` table and adds the new indexes. The old SQLite-based versions may still read the file, but nobody has tested that, and the supported way back is the backup taken before the upgrade (`rostdav admin backup`). The upgrade notes say so.
- **Build time and size grow.** The engine is a large dependency (a first build of the workspace takes minutes longer; see the measured numbers below). The binary needs no C library any more.
- **The data layer's risk moves from the engine's maturity to our tests.** Tests that must stay: the schema test above, the upgrade tests on a database made by SQLite (`crates/rostdav-meta/tests/upgrade.rs` with its fixture), the concurrency tests of the data layer, `rostdav admin fsck`, and the load tests.
- **PostgreSQL stays a possibility** (as in ADR 0001), through the same layer, if the engine does not mature as hoped.
- **Rolling back** means checking out the last SQLite-based tag (`v0.2.0`) and restoring a backup made before the upgrade.

## Measured

Same machine, same release-mode load tests (`docs/deployment.md` has the table): large files and listings are as fast as before, small files are slower (PUT 245/s against 420/s, GET 660/s against 1100/s), the release binary grows from about 20 MB to 47 MB. A first measurement was much worse (PUT 149/s, GET 188/s) because the engine did not use the existing partial unique index for the lookup of a child by name and read all children of a folder each time; `nodes_child_lookup` (migration 0012) fixed that. Lesson kept for later: after a schema change, look at the query plans (`EXPLAIN QUERY PLAN`) of the hot queries, the engine's planner is not SQLite's.
