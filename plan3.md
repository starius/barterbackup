# BarterBackup Direct-Execution Plan

This plan covers only the remaining TODO items that can be implemented now
without additional product discussion and without depending on blocked items.

## Included work

The following TODO items are implementable directly:

- Rewrap mirrored peer blobs before storing them on local disk.
- Finish the uncontroversial part of production hardening around observability,
  resource bounds, and hostile-input handling.
- Add deeper long-running fuzz and soak coverage.

## Excluded work

These TODO items still need product decisions first and are not part of this
plan:

- fresh-node bootstrap from seed alone;
- local `clirpc` mTLS key lifecycle;
- divergent sibling timeline UX and RPC design;
- external Tor and pluggable transport support;
- storage accounting and contract policy beyond the current model.

## Phase 1: Rewrap mirrored peer blobs locally

### Goal

Stop writing remote-provided peer blob bytes directly to local disk. Mirrored
peer blobs should be stored only inside a locally authenticated and encrypted
wrapper derived from our own seed tree.

### Scope

- Extend `storage` with a dedicated mirrored-peer blob format and key path.
- Keep local current-content blobs and mirrored peer blobs logically separate,
  even if they still share the same directory.
- Bind the local wrapper to at least:
  - format version;
  - mirrored content id;
  - local wrapping nonce;
  - authenticated metadata that prevents cross-file substitution.
- Preserve atomic write semantics and cleanup behavior.

### Main code areas

- `crates/storage/src/lib.rs`
- `crates/node/src/lib.rs`
- possibly `crates/keys/src/lib.rs` if a new labeled subkey is needed

### Concrete steps

1. Add a distinct storage API for mirrored peer blobs.
   - Replace the generic `write_content_blob` path used by peer sync with
     explicit mirrored-blob write and read helpers.
   - Keep local active content writes on the existing path.

2. Define the mirrored-peer blob envelope.
   - Use an AEAD with a unique nonce per local write.
   - Authenticate the content id and wrapper version as AAD or explicit header
     fields.
   - Make the on-disk bytes fully local-controlled, even when the payload is a
     peer-owned ciphertext blob.

3. Update peer sync and recovery to use the new wrapper.
   - `sync_peer_content_info` should persist downloaded peer blobs through the
     mirrored-blob writer.
   - Reads used for contract checks, download serving, and cleanup must unwrap
     the local wrapper before using the mirrored payload.

4. Harden startup and cleanup semantics.
   - Loading should reject malformed mirrored wrappers.
   - Cleanup should still distinguish tracked foreign blobs from local current
     content.
   - Recovery-required states should be explicit when mirrored data is locally
     corrupted.

### Required tests

- mirrored peer blob round-trip now proves the on-disk bytes differ from the
  remote payload;
- mirrored blob corruption is detected before use;
- wrong content id or wrapper metadata is rejected;
- restart after mirrored blob persistence still works;
- cleanup preserves tracked mirrored blobs and removes untracked ones;
- current local content behavior remains unchanged.

### Suggested commit slices

- add mirrored-blob wrapper format and storage API;
- switch node peer-sync paths to the wrapped mirrored storage;
- add corruption/restart/cleanup coverage for mirrored blobs.

## Phase 2: Production hardening that does not need design decisions

### Goal

Tighten the daemon's default behavior against malformed peers and make runtime
behavior easier to observe, without introducing new product-surface decisions.

### Scope

Implement the conservative hardening work that is already implied by the
existing design:

- better structured logs;
- explicit bounds derived from current protocol assumptions;
- stricter validation of hostile or malformed peer inputs;
- clearer cancellation and timeout handling in background work.

### Main code areas

- `cmd/bbd/src/app.rs`
- `crates/node/src/lib.rs`
- `crates/nettor/src/lib.rs`
- possibly `crates/clitls/src/lib.rs`

### Concrete steps

1. Improve structured logging.
   - Log peer, content id, revision, and operation outcome consistently for:
     recovery, contract proposal/check, mirrored blob refresh, and peer sync
     failures.
   - Keep logs machine-parseable and avoid free-form only messages where key
     fields are known.

2. Add explicit protocol and storage bounds.
   - Enforce current blob-size assumptions consistently on download and sync.
   - Reject oversized metadata or malformed field lengths before allocation.
   - Add explicit gRPC message-size caps that match the current whole-blob
     download model.

3. Harden hostile-input handling.
   - Reject malformed certificate identity material earlier where possible.
   - Reject inconsistent `DownloadResponse` variants, lengths, and hashes before
     any persistence.
   - Treat repeated partial or inconsistent download attempts as bounded
     failures instead of open-ended retries.

4. Tighten cancellation and timeout handling.
   - Ensure background maintenance does not keep stale peer tasks alive.
   - Add bounded dial/download timeouts where they are currently implicit.
   - Keep shutdown paths graceful and deterministic under cancellation.

### Required tests

- logging changes do not need golden text snapshots, but key paths should be
  exercised by existing tests;
- oversized or malformed peer responses fail early and do not write to disk;
- gRPC size caps reject oversized peer messages predictably;
- maintenance and recovery tasks stop cleanly under cancellation;
- timeout paths are covered with `netmock` and synthetic clock where possible.

### Suggested commit slices

- add size and validation guards for peer RPC paths;
- add cancellation and timeout handling for maintenance and peer I/O;
- add structured logging fields for recovery and contract workflows.

## Phase 3: Fuzz and soak coverage

### Goal

Add the deeper adversarial and long-horizon test coverage that the current
workspace still lacks, while staying within the already accepted architecture.

### Scope

- parser fuzzing;
- validator fuzzing;
- long-running multi-node scenario tests using `netmock` and manual clock.

### Main code areas

- new `fuzz/` workspace content for `cargo-fuzz`
- `crates/content/src/lib.rs`
- `crates/storage/src/lib.rs`
- `crates/node/src/lib.rs`
- `cmd/bbd/src/app.rs`

### Concrete steps

1. Add fuzz targets.
   - content blob parser;
   - stored metadata / peer sidecar parser;
   - local CLI key parser;
   - RPC request or response validation paths with malformed payloads.

2. Add long-running soak scenarios with `ManualClock` and `netmock`.
   - repeated successful checks over long simulated periods;
   - repeated failed checks and recovery after peers come back;
   - restart during maintenance;
   - peer corruption after previously valid mirrored sync;
   - outdated mirrored data eventually refreshed again after peer restart.

3. Add fault-injection style scenarios that are still deterministic.
   - interrupted or malformed downloads;
   - crash-safe restart behavior around mirrored-peer writes;
   - stale temp or leftover state around atomic writes where applicable.

### Required tests

- fuzz targets build and run under `cargo fuzz run`;
- scenario tests complete under synthetic time without long real sleeps;
- all new adversarial cases assert both safety and state recovery behavior.

### Suggested commit slices

- add parser and validator fuzz targets;
- add long-horizon multi-node soak scenarios;
- add deterministic fault-injection scenarios for mirrored blob and recovery
  paths.

## Execution order

1. Rewrap mirrored peer blobs locally.
2. Tighten input bounds and cancellation around peer I/O.
3. Improve structured logs for peer and recovery workflows.
4. Add fuzz targets.
5. Add longer soak and fault-injection scenarios.

## Acceptance criteria

This plan is complete when all of the following are true:

- mirrored peer blobs are no longer written to disk as raw remote-provided
  bytes;
- peer sync and recovery continue to work after the mirrored-blob change;
- oversized or malformed peer inputs are rejected before persistence;
- maintenance and recovery tasks behave predictably under timeout and
  cancellation;
- the workspace includes runnable fuzz targets;
- the long-horizon multi-node scenario suite covers the remaining uncontroversial
  hardening paths without depending on unresolved product decisions.
