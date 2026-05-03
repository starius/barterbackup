# Plan: Replace Proto `_ns` Timestamp Pairs and Remove Legacy Peer Fields

## Goal

Refactor the protobuf schemas so that timestamp pairs of the form:

- `*_at`
- `*_at_ns`

use `google.protobuf.Timestamp` instead of parallel integer fields, with one
explicit exception:

- `storedpb.ContentRevision.created_at` + `created_at_ns`

That one stays split because `ContentRevision` is embedded in the encrypted
revision id and we do not want to increase its serialized size. Its comment
should explicitly say that the split form is intentional for size reasons.

At the same time, remove schema-level legacy compatibility shims that only
exist for never-released backward compatibility, especially the old peer
content-id mirror field and its migration code.

The user requirement is to optimize for a clean unreleased schema, not
wire compatibility with older builds. So field numbers may be reassigned
cleanly instead of reserving old layouts for compatibility.

## Scope

### In scope

- `.proto` schema cleanup in:
  - `storedpb/stored.proto`
  - `clirpc/barter_backup_client.proto`
  - any affected `bbrpc` message if a split timestamp is found there later
- Rust code generated from those protos
- Go `clirpc` generation for the Docker harness
- storage/load/save code and tests
- CLI formatting/tests
- README or docs comments where timestamp structure is described
- Nix/dev-shell support so the standard protobuf well-known-type include path is
  available in the recommended way for codegen tools

### Out of scope

- preserving backward compatibility with old on-disk state or old RPC payloads
- changing duration fields that are not timestamps
- changing `storedpb.ContentRevision` to a message-valued timestamp

## Current timestamp pairs to replace

### `storedpb`

Replace these split timestamp fields with `google.protobuf.Timestamp`:

- `FileHeader.modified_at` + `modified_at_ns`
- `Peer.first_seen_at` + `first_seen_at_ns`
- `Peer.requester_last_advertised_at` + `requester_last_advertised_at_ns`
- `Peer.requester_last_downloaded_advertised_at`
  + `requester_last_downloaded_advertised_at_ns`
- `RecoveredRevision.created_at` + `created_at_ns`
- `Metadata.node_initialized_at` + `node_initialized_at_ns`
- `Metadata.recovery_watermark_at` + `recovery_watermark_at_ns`
- `Metadata.metadata_rollup_due_at` + `metadata_rollup_due_at_ns`

Do not replace:

- `ContentRevision.created_at` + `created_at_ns`

Required comment update there:

- explain that this message is embedded in the revision id and therefore uses a
  split representation to avoid the overhead of an embedded well-known type

### `clirpc`

Replace these split timestamp fields with `google.protobuf.Timestamp`:

- `StateContentSummary.last_updated_at` + `last_updated_at_ns`
- `StateRecoverySummary.node_initialized_at` + `node_initialized_at_ns`
- `StateRecoverySummary.recovery_watermark_at` + `recovery_watermark_at_ns`
- `StateRecoverySummary.latest_recovered_at` + `latest_recovered_at_ns`
- `StateRecoverySummary.newer_known_at` + `newer_known_at_ns`
- `File.modified_at` + `modified_at_ns`
- `FileInfo.modified_at` + `modified_at_ns`

### `bbrpc`

Current scan found no split timestamp pairs there.

## Legacy fields and code to remove

### Schema-level legacy field

Remove:

- `storedpb.Peer.content_id`

Why:

- its own comment says it is a legacy latest-content identifier kept in sync
  only for migration compatibility
- the software has not been released, so carrying a redundant migration shim is
  now cost without benefit

### Rust migration / legacy code to delete

Remove or simplify these code paths after `storedpb.Peer.content_id` goes away:

- `crates/storage/src/lib.rs`
  - `migrate_peer()` logic that maps `content_id` into:
    - `latest_known_content`
    - `latest_cached_content`
  - writes that keep `peer.content_id` mirrored from `latest_known_content`
  - `clear_peer_content_id()` implementation should become a clear of
    `latest_known_content` and `latest_cached_content` only
  - `legacy_foreign_content_ids()`
  - legacy raw-foreign-blob loading path that exists only to support older
    layouts
  - `ensure_legacy_lineage_initialized()` if it is only serving old layout
    migration; confirm whether any part is still needed for current behavior

### Tests to remove/rename

Delete or rewrite tests whose only purpose is old-layout migration support,
for example names like:

- `load_migrates_legacy_peer_content_id_into_known_and_cached_state`
- `load_drops_legacy_raw_foreign_blobs`
- any test that asserts `peer.content_id` mirroring behavior

Retain tests for the current supported invariants:

- `latest_known_content`
- `latest_cached_content`
- wrapped mirrored blobs only

## Proto design changes

### 1. Add well-known-type imports

For any proto file that gets timestamps:

```proto
import "google/protobuf/timestamp.proto";
```

Use fully qualified type names or a file-local alias pattern consistently:

- `google.protobuf.Timestamp`

### 2. Replace split fields with one timestamp field

Example transformation:

From:

```proto
int64 modified_at = 4;
int64 modified_at_ns = 5;
```

To:

```proto
google.protobuf.Timestamp modified_at = 4;
```

Because backward compatibility is intentionally not required:

- reuse or renumber field tags cleanly
- remove the old paired fields entirely rather than reserving them
- keep numbering compact and readable

### 3. Keep `ContentRevision` split and document why

Update this comment in `storedpb/stored.proto`:

- `created_at_ns` is intentionally not replaced by `google.protobuf.Timestamp`
  because `ContentRevision` participates directly in the revision-id payload and
  the embedded well-known type would make it larger

## Rust implementation impact

### `prost` generated shapes

After the schema change, `prost` will generate:

- `Option<prost_types::Timestamp>` for message-valued timestamps

This will require replacing most tuple / scalar timestamp helpers such as:

- `(secs, nanos)` pairs
- `optional_metadata_timestamp(...)`
- direct `*_ns` integer reads and writes

### Central conversion helpers

Introduce or consolidate helpers for:

- `Timestamp -> prost_types::Timestamp`
- `prost_types::Timestamp -> Timestamp` or `(i64, i32)` validation
- optional conversions with range checks

Recommended approach:

- one small conversion module/helper section in `crates/storage` and reused
  helpers in `crates/node` / `cmd/bbd` as needed
- reject invalid protobuf timestamps explicitly rather than silently clamping

### Places that will need updates

At minimum:

- `crates/storage/src/lib.rs`
  - persist/load metadata
  - persist/load peers
  - file metadata round-trips
  - recovered revision persistence
  - metadata rollup due-time persistence
- `crates/content/src/lib.rs`
  - metadata construction and round-trip tests
- `crates/node/src/lib.rs`
  - local state summaries
  - file listing / file get / file set RPC mapping
  - recovery summaries
  - tests that currently assert `*_ns` scalar fields
- `cmd/bbcli/src/lib.rs`
  - file listing parsing/formatting
  - local state parsing/formatting
- `cmd/bbd/src/app.rs`
  - any test scaffolding or RPC assertions using split timestamp fields
- `integration/docker/harness/*.go`
  - Go-side `Timestamp` accessors
- `integration/docker/integration_test.go`
  - assertions that currently use split scalar timestamp fields

## Go / Docker harness impact

The Go `clirpc` bindings will move from scalar fields to message pointers.

Example impact:

- from `LastUpdatedAt` + `LastUpdatedAtNs`
- to `LastUpdatedAt *timestamppb.Timestamp`

Need updates in:

- harness formatting/parsing helpers
- integration assertions
- any zero-value / nil handling logic

## Build and toolchain plan

### Nix / protobuf well-known types

The refactor should use the standard protobuf include tree the recommended way,
not ad-hoc vendored copies of `timestamp.proto`.

Plan:

1. Ensure the dev shell exposes a standard protobuf installation with the
   well-known-type `.proto` include tree.
2. Update any Go `make rpc` / protoc invocation so it explicitly includes that
   path when needed.
3. Keep Rust codegen on the existing `protoc-bin-vendored` path unless a change
   is truly needed there. Rust build-time codegen already has access to standard
   well-known types through `protoc`; the main thing to verify is that Go codegen
   sees the same include path consistently in and out of Nix.
4. Validate this from `nix develop` on the server.

Likely files to touch:

- `flake.nix`
- `Makefile`
- possibly any helper shell scripts used by `make rpc`

## Suggested commit split

### Commit 1: replace proto timestamp pairs

Scope:

- update `storedpb` and `clirpc` schemas to use `google.protobuf.Timestamp`
- keep `ContentRevision` split and add the explicit size comment
- regenerate / rebuild affected bindings
- adjust build tooling / Nix include-path handling if needed for `make rpc`

Validation before commit:

- `make fmt`
- `cargo build --workspace --locked`
- `make rpc`
- targeted Rust proto consumers:
  - `cargo test -p content --locked`
  - `cargo test -p storage --locked`
  - `cargo test -p node --locked`
  - `cargo test -p bbcli --locked`
  - `cargo test -p bbd --locked`
- targeted Go harness compile/tests:
  - `cd integration/docker && go test ./harness -v`

### Commit 2: remove legacy peer content-id field and migration path

Scope:

- remove `storedpb.Peer.content_id`
- remove migration / mirroring code
- remove legacy tests
- simplify current code paths to only use:
  - `latest_known_content`
  - `latest_cached_content`

Validation before commit:

- `make fmt`
- `cargo build --workspace --locked`
- targeted storage/node tests for peer-state persistence and mirrored blobs
- `cargo test --workspace --locked`

### Commit 3: final docs / cleanup if needed

Scope:

- update README or peer-storage docs if timestamp field descriptions are shown
- run any remaining generated-doc targets only if CLI surface changed

## Test plan

### Unit tests: `content`

- file metadata round-trip with `google.protobuf.Timestamp`
- content metadata round-trip with peer metadata still preserved
- explicit assertion that `ContentRevision` still uses the split timestamp form

### Unit tests: `storage`

- file-header persisted timestamp round-trips
- peer first-seen timestamp round-trips
- advertisement/downloaded-advertised timestamps round-trip
- recovery metadata timestamps round-trip
- metadata-rollup due time round-trip
- no remaining tests depend on legacy `Peer.content_id`

### Unit tests: `node`

- local state summary serialization/deserialization with WKT timestamps
- file list/get/set uses WKT timestamps correctly
- recovery summaries use WKT timestamps correctly
- current metadata-rollup tests stay green

### Unit tests: `bbcli`

- file-list formatting with WKT timestamps
- state formatting with WKT timestamps
- any local-time rendering code still behaves correctly

### Daemon tests

- local RPC round-trip for file metadata
- local RPC state round-trip for recovery timestamps

### Go harness / integration

- harness compiles against generated WKT timestamp fields
- representative Docker tests still pass

Recommended representative end-to-end subset:

- one file metadata/listing test
- one recovery/state test
- one peer publication / storage test

## Risks and weak points

### 1. Optional-vs-zero semantics will change

Scalar `0` / `0ns` fields implicitly represented "unset" in several places.
With WKT timestamps, unset becomes `nil`.

Need a consistent policy per field:

- fields that are truly optional should stay nullable
- fields that must always exist should be populated explicitly

This is the biggest semantic risk in the refactor.

### 2. `prost_types::Timestamp` range validation

The code currently uses many ad-hoc integer conversions.
With WKT timestamps, bad values can arrive through deserialization.

Need explicit validation for:

- nanosecond range
- negative values where disallowed by local policy

### 3. Go codegen include path

The Rust side is usually easier here than Go. The likely practical snag is
`make rpc` and making sure `google/protobuf/timestamp.proto` is found the same
way inside and outside the Nix shell.

### 4. Removing legacy fields may simplify more than expected

Once `storedpb.Peer.content_id` is removed, some migration helpers and older
raw-blob cleanup logic may become obviously dead. That is good, but the cleanup
should be deliberate so we do not remove behavior that is still relevant for
current wrapped mirrored blobs.

## Success criteria

The refactor is complete when:

- all proto timestamp pairs except `ContentRevision.created_at[_ns]` are gone
- `ContentRevision.created_at_ns` comment explicitly documents the size-based
  exception
- `storedpb.Peer.content_id` is gone
- migration code that only exists for that field/layout is gone
- `make rpc`, `cargo build --workspace --locked`, and
  `cargo test --workspace --locked` all pass
- representative Go harness tests pass
- the repo is cleaner, with fewer parallel sec/ns fields and no unreleased
  compatibility ballast
