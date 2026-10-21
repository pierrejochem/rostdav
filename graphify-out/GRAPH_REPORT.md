# Graph Report - rostdav  (2026-10-21)

## Corpus Check
- 58 files · ~38,033 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 6, .toml 4)

## Summary
- 686 nodes · 1364 edges · 34 communities (32 shown, 2 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 36 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `faa67d15`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- rostdav-storage/src/lib.rs
- config.rs
- nodes.rs
- path.rs
- rostdav-app/src/lib.rs
- rostdav-dav/src/lib.rs
- super
- health.rs
- http.rs
- Error
- dav.rs
- Node
- Architecture
- xml.rs
- Installation and operation
- rostdav
- Endpoints and protocol contracts
- AI Agent Instructions: Rostdav – a lean Nextcloud-compatible file server
- Rostdav
- rostdav-meta/src/lib.rs
- target.rs
- Implementation plan
- Decision
- Working rules for coding agents
- Web interface
- Administration
- smoke.sh
- Contributing
- ADR 0001: Technology stack
- Nextcloud compatibility
- Security concept
- Notes for Claude Code
- litmus.sh

## God Nodes (most connected - your core abstractions)
1. `Node` - 27 edges
2. `LogicalPath` - 23 edges
3. `Principal` - 22 edges
4. `test_db()` - 22 edges
5. `Name` - 18 edges
6. `Db` - 18 edges
7. `put()` - 17 edges
8. `get()` - 16 edges
9. `LocalStore` - 16 edges
10. `DavError` - 15 edges

## Surprising Connections (you probably didn't know these)
- `check_element()` --calls--> `bad()`  [INFERRED]
  rostdav/crates/rostdav-dav/src/xml.rs → rostdav/crates/rostdav-core/src/path.rs
- `get()` --calls--> `parse_range()`  [INFERRED]
  rostdav/crates/rostdav-dav/src/lib.rs → rostdav/crates/rostdav-dav/src/range.rs
- `transfer()` --calls--> `parse_destination()`  [INFERRED]
  rostdav/crates/rostdav-dav/src/lib.rs → rostdav/crates/rostdav-dav/src/target.rs
- `propfind()` --calls--> `multistatus()`  [INFERRED]
  rostdav/crates/rostdav-dav/src/lib.rs → rostdav/crates/rostdav-dav/src/xml.rs
- `propfind()` --calls--> `parse_propfind()`  [INFERRED]
  rostdav/crates/rostdav-dav/src/lib.rs → rostdav/crates/rostdav-dav/src/xml.rs

## Import Cycles
- None detected.

## Communities (34 total, 2 thin omitted)

### Community 0 - "rostdav-storage/src/lib.rs"
Cohesion: 0.10
Nodes (18): BlobId, generated_ids_parse(), StoredBlob, aborted_stream_leaves_no_blob(), blob_path_is_sharded_and_id_derived(), crash_before_rename_leaves_only_sweepable_tmp(), delete_is_idempotent_and_open_missing_is_not_found(), empty_blob_is_allowed() (+10 more)

### Community 1 - "config.rs"
Cohesion: 0.07
Nodes (25): Config, Database, defaults_are_local_only(), file_and_env_precedence(), Limits, Log, LogFormat, Pretty (+17 more)

### Community 2 - "nodes.rs"
Cohesion: 0.09
Nodes (46): test_db(), adjust_used(), blob(), changes_renew_all_ancestor_etags_but_not_siblings(), clear_target(), COLS, copy_creates_new_ids_shares_blobs_and_counts_quota(), copy_one() (+38 more)

### Community 3 - "path.rs"
Cohesion: 0.13
Nodes (15): backslash_rejected(), bad(), case_is_significant(), decoded_once_only(), depth_limit(), dot_segments_rejected(), encoded_separators_and_nul_rejected(), invalid_utf8_rejected() (+7 more)

### Community 4 - "rostdav-app/src/lib.rs"
Cohesion: 0.10
Nodes (17): add_user_stores_verifiable_hash_not_password(), AppState, authenticate_accepts_only_correct_credentials(), authorize_denies_foreign_nodes_even_when_resolved_by_id(), crash_between_blob_and_commit_leaves_only_orphan(), failed_commit_leaves_no_blob_on_disk(), garbage_collection_removes_only_unreferenced_blobs(), Inner (+9 more)

### Community 5 - "rostdav-dav/src/lib.rs"
Cohesion: 0.08
Nodes (29): DavError, status_mapping(), unauthenticated_carries_challenge_and_internal_hides_details(), ALLOWED_METHODS, authenticate(), delete(), empty(), entry() (+21 more)

### Community 6 - "super"
Cohesion: 0.10
Nodes (13): AppState, dummy_hash(), hash_does_not_contain_password(), hash_password(), MIN_PASSWORD_CHARS, roundtrip_uses_argon2id_and_random_salt(), StringError, verify_password() (+5 more)

### Community 7 - "health.rs"
Cohesion: 0.17
Nodes (7): app_with_tempdir(), get(), healthz_ok(), readyz_ok_with_working_storage(), readyz_unavailable_when_tmp_missing(), responses_carry_request_id_and_security_headers(), unknown_route_is_404()

### Community 8 - "http.rs"
Cohesion: 0.11
Nodes (7): router(), Json, healthz(), readyz(), REQUEST_ID, router(), router()

### Community 9 - "Error"
Cohesion: 0.10
Nodes (14): Error, AlreadyExists, BadRequest, Conflict, Forbidden, Internal, Locked, NotFound (+6 more)

### Community 10 - "dav.rs"
Cohesion: 0.13
Nodes (31): A, B, basic(), Call, Call<'a>, delete_cases(), destination_must_stay_on_this_server_and_in_own_tree(), Env (+23 more)

### Community 11 - "Node"
Cohesion: 0.12
Nodes (15): Action, Read, Write, authorize(), Principal, AppState, Listing, LogicalPath (+7 more)

### Community 12 - "Architecture"
Cohesion: 0.17
Nodes (12): Architecture, Authorization, Background tasks, Configuration, Crates, Data model (core), Error mapping, Operation (+4 more)

### Community 14 - "xml.rs"
Cohesion: 0.11
Nodes (17): allprop_propname_and_prop_list(), check_element(), dav(), DAV_NS, escape(), MAX_DEPTH, MAX_PROPS, multistatus() (+9 more)

### Community 15 - "Installation and operation"
Cohesion: 0.22
Nodes (8): Backup and restore (planned), Building, Configuration, Data directory, Health-Checks, Installation and operation, Reverse proxy (planned), Shutdown

### Community 16 - "rostdav"
Cohesion: 0.68
Nodes (8): rostdav, rostdav-app, rostdav-compat, rostdav-core, rostdav-dav, rostdav-meta, rostdav-storage, rostdav-web

### Community 17 - "Endpoints and protocol contracts"
Cohesion: 0.29
Nodes (7): Common headers (all responses), Endpoints and protocol contracts, `GET /healthz`, `GET /readyz`, OCS and Login Flow, Operations (M0), WebDAV

### Community 18 - "AI Agent Instructions: Rostdav – a lean Nextcloud-compatible file server"
Cohesion: 0.07
Nodes (28): 10. Final report after every unit of work, 1. Role, goal and scope, 2.1 Users and authentication, 2.2 File management, 2.3 Deletion and trash, 2.4 File versioning (P2), 2.5 Shares (P2), 2.6 Web interface (+20 more)

### Community 19 - "Rostdav"
Cohesion: 0.29
Nodes (7): Documentation, License, Planned features, Quick start, Repository layout, Rostdav, Status

### Community 20 - "rostdav-meta/src/lib.rs"
Cohesion: 0.10
Nodes (7): PRODUCT_NAME, VERSION, Db, file_node_requires_blob_and_dir_forbids_it(), migrate_is_idempotent(), open_creates_file_and_pings(), sibling_names_unique_by_nfc_key_only()

### Community 21 - "target.rs"
Cohesion: 0.18
Nodes (9): destination_same_host_relative_and_foreign(), DestinationError, Foreign, Invalid, FILES_PREFIX, href_encoding_roundtrip(), parse_destination(), parse_user_and_path() (+1 more)

### Community 22 - "Implementation plan"
Cohesion: 0.14
Nodes (14): Approval point 1 – done (2026-10-21), Biggest risks, Implementation plan, M0 – Skeleton ✅ (2026-10-21), M1 – Metadata and storage ✅ (2026-10-21), M2 – WebDAV core (implemented 2026-10-21; `cadaver` check open), M3 – Reference recordings, M4 – Sign-in like Nextcloud (+6 more)

### Community 23 - "Decision"
Cohesion: 0.18
Nodes (10): ADR 0002: Storage model for files and metadata, Alternatives, Consequences, Contents as immutable blobs, Context, Database, Decision, Delete, move, copy (+2 more)

### Community 24 - "Working rules for coding agents"
Cohesion: 0.25
Nodes (8): Approval points (stop and ask), Architecture rules, Compatibility, Final report after every unit of work, Goal, Security, Way of working, Working rules for coding agents

### Community 25 - "Web interface"
Cohesion: 0.20
Nodes (8): Design, Accessibility (checklist per page), Design-Tokens, Logo, Pages, References, Technology, Web interface

### Community 26 - "Administration"
Cohesion: 0.40
Nodes (5): Administration, CLI (planned), Event log, Roles, Settings and precedence

### Community 28 - "Contributing"
Cohesion: 0.33
Nodes (6): Commit messages, Contributing, Daily workflow, License of contributions, Rules, Setup

### Community 29 - "ADR 0001: Technology stack"
Cohesion: 0.33
Nodes (6): ADR 0001: Technology stack, Approval (2026-10-21), Consequences, Context, Decision, Options considered

### Community 30 - "Nextcloud compatibility"
Cohesion: 0.33
Nodes (6): Known endpoints (to be verified), Nextcloud compatibility, Not supported, Open questions, Reference versions, Supported flows

### Community 31 - "Security concept"
Cohesion: 0.33
Nodes (6): Cryptography, Dependencies, Reporting vulnerabilities, Security concept, Threats and mitigations, Trust boundaries

### Community 32 - "Notes for Claude Code"
Cohesion: 0.50
Nodes (4): Commands, Current state, Notes for Claude Code, Starting a session

### Community 33 - "litmus.sh"
Cohesion: 0.50
Nodes (3): ROSTDAV_SERVER__LISTEN, ROSTDAV_STORAGE__DATA_DIR, litmus.sh script

## Knowledge Gaps
- **159 isolated node(s):** `Read`, `Write`, `AppState`, `MIN_PASSWORD_CHARS`, `NotFound` (+154 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 266 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `LogicalPath` connect `Node` to `nodes.rs`, `path.rs`, `rostdav-app/src/lib.rs`, `rostdav-dav/src/lib.rs`, `target.rs`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Why does `Node` connect `Node` to `nodes.rs`, `rostdav-dav/src/lib.rs`?**
  _High betweenness centrality (0.030) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `test_db()` (e.g. with `changes_renew_all_ancestor_etags_but_not_siblings()` and `copy_creates_new_ids_shares_blobs_and_counts_quota()`) actually correct?**
  _`test_db()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Read`, `Write`, `AppState` to the rest of the system?**
  _159 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `rostdav-storage/src/lib.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.0951219512195122 - nodes in this community are weakly interconnected._
- **Should `config.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.06866002214839424 - nodes in this community are weakly interconnected._
- **Should `nodes.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.09076682316118936 - nodes in this community are weakly interconnected._