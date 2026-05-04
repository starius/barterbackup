# Plan: Improve local `bbcli` responsiveness during background peer work

## Problem

Some local `bbcli` commands appear to hang while `bbd` is busy with peer
network activity.

This is not a single-event-loop issue. The local gRPC server is concurrent.
The coupling is inside shared node state:

- local-only views such as `bbcli peer list` still contend on the process-wide
  `Node::store` mutex
- `peer list` currently re-enters that mutex repeatedly and may read mirrored
  blob files while building its response
- some other commands, especially `bbcli config get`, intentionally do live
  peer probing today, so they are coupled to network latency by design

## Goals

- keep purely local CLI views responsive while background maintenance is doing
  peer RPCs or store updates
- make the local-only commands clearly local in implementation, not just in
  product intent
- avoid changing wire formats unless necessary
- preserve current operator-visible semantics unless we intentionally split a
  command into a local and a live variant

## Non-goals

- do not redesign the whole storage layer in this change
- do not remove all live network views from the CLI
- do not change peer-maintenance behavior itself unless required for
  decoupling

## Observed hot spots

### 1. `bbcli peer list`

Current path:

- `DaemonService::peers`
- `CliService::peers`
- `Node::peers_response`
- `Node::peer_inventory`

Current problem:

- `peer_inventory()` first snapshots tracked peers from the store
- then, for each known peer, it calls `mirrored_peer_content_length()`
- `mirrored_peer_content_length()` re-enters `with_store(...)`
- that path may also read the mirrored blob file

So `peer list` is local-only in product terms, but still pays repeated
synchronous store-lock and blob-read costs.

### 2. `bbcli state`

Current path:

- `DaemonService::state`
- `Node::local_state_summary`

Current problem:

- `local_state_summary()` takes multiple local snapshots and also calls helper
  paths like `mirrored_blob_usage()`
- these remain local-only, but they still compete for the same store mutex with
  background updates

### 3. `bbcli config get`

Current path:

- `DaemonService::get_storage_config`
- `Node::storage_info().await`
- `Node::get_peer_storage_response().await`

This one is different:

- it is intentionally live today
- it probes known peers with `GetContentRevision`
- so it is expected to be slower and network-coupled

We should decide explicitly whether to keep that behavior or split local and
live variants.

## Proposed approach

### Phase 1: Fix local-only commands without changing product semantics

#### A. Rewrite `peer_inventory()` to use one store snapshot

Build one local snapshot up front containing everything `peer list` needs:

- tracked peers keyed by onion
- latest known and cached content metadata
- stored mirrored content length from sidecar metadata
- score / pin / tracked-only / last-live fields

Then render `PeerInventoryEntry` from that snapshot without re-entering the
store mutex per peer.

Key change:

- stop calling `mirrored_peer_content_length()` from inside the inventory loop
- prefer sidecar metadata length instead of opening mirrored blob files for the
  listing path

Tradeoff:

- the reported mirrored-byte count becomes metadata-derived instead of
  filesystem-derived for the listing path
- this is acceptable for local inventory output and matches the local-sidecar
  model better

#### B. Keep `state` local-only and snapshot-based

Audit `local_state_summary()` and helper calls to ensure they do not do
unnecessary repeated store traversals.

Potential cleanup:

- consolidate `local_store_snapshot()` and `mirrored_blob_usage()` inputs so the
  state response is assembled from one or two bounded local snapshots instead of
  many small mutex acquisitions

### Phase 2: Separate local and live views more clearly

#### C. Decide what `bbcli config get` should mean

Options:

1. Keep `config get` live
- no CLI surface change
- document clearly that it may block on peer probing

2. Make `config get` local-only and add an explicit live command
- e.g. keep `config get` local
- move live peer-storage probing to:
  - `bbcli peer storage`
  - or `bbcli peer storage --refresh`

Recommendation:

- prefer option 2
- local admin commands should default to local responsiveness
- live probing should be explicit in the command name or flag

If we choose option 2, this is a separate follow-up commit from the local lock
contention fixes.

### Phase 3: Reduce shared blocking further if still needed

If Phase 1 is not enough, consider deeper changes:

#### D. Introduce read snapshots or an `RwLock`

Possible directions:

- replace the coarse `std::sync::Mutex<Store>` with a read/write split
- or maintain a cached immutable summary for local CLI views

This is higher risk because the store is mutation-heavy and crash-safety logic
must stay simple.

Recommendation:

- do not start here
- first measure the improvement from snapshotting and removing blob reads from
  local inventory paths

## Implementation steps

### Step 1. Inventory snapshot for `peer list`

- add one helper that returns all per-peer local listing fields from one store
  access
- refactor `peer_inventory()` to consume that snapshot
- remove per-peer `with_store(...)` calls from the inventory loop
- remove mirrored blob reads from `peer list`

### Step 2. Audit `state` path

- count current store accesses in `local_state_summary()`
- merge obviously redundant ones
- keep the output unchanged

### Step 3. Product decision for live storage/config view

- decide whether `bbcli config get` remains live or becomes local-only
- if changed, update docs and generated CLI docs

## Tests

### Unit tests

Add or update Rust tests for:

- `peer list` still renders correct lengths and flags from sidecar metadata
- corrupt or missing mirrored blob files do not stall or break `peer list`
- `state` still reports the same local summary values after snapshot refactor

### Concurrency-focused tests

Add focused daemon or node tests that simulate contention:

- hold the store busy in one background path
- prove that `peer list` no longer needs repeated per-peer store operations
- if practical, measure call count or use a counting test filesystem / store
  wrapper

### Integration tests

A full Docker test is probably unnecessary for the first phase.

Prefer deterministic daemon tests that:

- create many known peers
- exercise background maintenance activity
- assert that local-only RPCs still complete promptly

If we later split local and live commands, add CLI doc and behavior tests for
that surface change.

## Validation

Before each commit:

- `make fmt`
- targeted Rust build/tests for the touched crates

Server validation after the main behavior change:

- `cargo build -p node -p bbd --locked`
- targeted `node` and `bbd` tests for peer inventory, state, and any new
  responsiveness regression tests

## Suggested commit split

1. `Refactor peer inventory to avoid per-peer store reentry`
- inventory snapshot change
- tests for listing behavior

2. `Reduce local state summary store contention`
- local summary snapshot cleanup
- tests

3. optional, only if product direction is approved:
   `Separate live peer storage refresh from local config view`
- CLI and docs change
- regenerated CLI docs

## Risks

- using sidecar metadata lengths instead of filesystem blob reads may slightly
  change what `stored_content_bytes` means in corner cases involving local
  corruption
- local and live views may diverge more visibly once we stop deriving some
  fields from direct blob reads
- if `config get` stays live, users may still interpret its latency as a daemon
  hang even after local-only paths are fixed

## Recommendation

Start with the narrow, high-value fix:

- make `bbcli peer list` truly snapshot-based and blob-read-free
- keep `bbcli state` local-only and reduce redundant store locking

Then decide separately whether `bbcli config get` should remain a live network
view or be split into local and explicit-live commands.
