# Plan: Pinning And Focused Storage Accounting

## Goal

Implement the remaining storage/accounting work with these constraints:

1. Keep the current eviction policy and overall storage model.
2. Add peer pinning.
3. Do not redesign `bbrpc`; only add the minimum field needed for a peer to
   tell us whether it pins us.
4. Add the specific operator-facing reporting listed below, and no broader
   reporting redesign in this item.

This plan intentionally does **not** include:

- new storage tiers beyond the current model;
- chunking or transfer redesign;
- a different eviction heuristic;
- a broader rewrite of score semantics.

## Accepted Product Decisions

### 1. Keep the current storage policy

The existing policy stays in place:

- one global peer-storage budget;
- positive-score peer content is protected first;
- best-effort cached blobs are evicted first;
- if new data still does not fit, the peer can fall back to track-only.

The only new exception is pinning.

### 2. Add pinning as an absolute override

A pinned peer means:

- it has the highest peer priority;
- it is never evicted from the tracked-peer set due to capacity pressure;
- its cached mirrored content is never evicted due to score decay or offline
  status;
- it remains protected even when its score is negative.

Important clarification:

- pinning does **not** create a new general storage policy;
- it is a narrow absolute override on top of the existing one.

### 3. Keep `bbrpc` changes minimal

The only protocol change in this item should be a responder telling a requester
whether the responder pins that requester.

Recommended shape:

- extend `GetContentRevisionResponse` with:
  - `bool requester_pinned`

Meaning:

- when node `A` asks node `B` for contract state, `B` tells `A` whether `B`
  pins `A`.

That gives us the minimum needed for replica-horizon reporting without a wider
protocol redesign.

## Scope Of Reporting

This item adds only these reports.

### Per-peer reporting

Expose, for each peer:

- how much space that peer is consuming now;
- whether that peer's cached data is protected or disposable;
- whether that peer is track-only right now;
- whether the peer is pinned by us;
- whether the peer currently reports that it pins us.

### Aggregate reporting

Expose:

- how much budget is blocked by offline peers;
- how much cached peer storage is reclaimable safely now.

### Replica-horizon reporting

Expose, for our own fresh replicas:

- when we would lose all fresh replicas if we went offline now;
- when we would drop to 1 fresh replica;
- when we would drop to 2 fresh replicas;
- when we would drop to 3 fresh replicas;
- and so on, up to the current total number of fresh replicas.

Semantics:

- only count peers that currently have our fresh data;
- only count peers that passed the last contract check for that fresh data;
- pinned peers count as `never` expiring;
- for simplicity, once a peer becomes best-effort from its perspective, treat
  that as no longer a fresh durable replica for this report.

## Data Model Changes

## Phase 1: Persist pin state and minimal replica-verification state

### Stored peer metadata

Extend the stored peer record with at least:

- `pinned_by_us: bool`
- `pins_us: bool`
- `our_content_last_verified_content_id`
- `our_content_last_verified_at`

Why:

- `pinned_by_us` drives local priority and storage protection;
- `pins_us` is the last remote claim observed through `bbrpc`;
- verification state is needed because `our_content_synced` alone is not enough
  to satisfy the requirement "passed last check".

### Verification semantics

A peer counts as a fresh checked replica only if:

- it currently advertises our latest content as cached/fresh;
- the latest successful contract check verified that same content id;
- the peer is currently online.

This avoids over-reporting replicas based only on proposal/revision exchange.

## Phase 2: Local admin RPC and CLI surface for pinning

Add local admin RPCs for pinning.

Recommended shape:

- `PinPeerRequest { Peer peer }`
- `PinPeerResponse`
- `UnpinPeerRequest { Peer peer }`
- `UnpinPeerResponse`

CLI:

- `bbcli peer pin <peer-onion-id>`
- `bbcli peer unpin <peer-onion-id>`

`bbcli peer list` should show whether each peer is pinned.

Validation rules:

- pin/unpin must reject the local node;
- pinning an unknown peer should be allowed only if that peer is first added to
  tracked peer metadata in the same way `peer connect` would make it known, or
  else rejected explicitly. Pick one rule and document it.

Recommended choice:

- require the peer to be known already; keep pinning as a state change on an
  existing tracked peer.

## Phase 3: Priority and cache behavior for pinned peers

Pinning must change priority behavior, but not the general eviction algorithm.

### Tracked-peer admission priority

Update `peer_priority` so pinned peers sort above everything else.

New order:

1. pinned
2. manual
3. positive-score
4. built-in
5. outbound-discovered
6. inbound-discovered
7. unknown

Meaning:

- pinned peers are never displaced by normal capacity pressure.

### Cached outbound client pool

Pinned peers should also have highest priority in cached connection retention.

Recommended behavior:

- keep the existing cache-bounded design;
- when the cached client pool is full, evict the least-recently-used
  non-pinned client first;
- only evict a pinned cached client when every cached client is pinned.

This matches the user requirement that pinning also affects the connection
pool, not only metadata admission.

## Phase 4: Storage protection semantics for pinned peers

Keep the current protected-vs-best-effort model, but make pinned peers always
protected.

Recommended rule:

- `pinned_by_us == true` implies `Protected`, regardless of score.

This affects:

- `storage_class(...)`
- mirrored-blob admission planning
- reclaimable/disposable reporting

Important edge case:

- if a pinned peer already has a cached revision and a newer revision does not
  fit, do **not** evict the old cached pinned revision;
- keep the previously cached revision and move the peer to "newest known but not
  cached" state for the new revision, just like the existing reserved-peer
  fallback behavior.

That preserves the "never evicted" requirement without redesigning the whole
budget model.

## Phase 5: Minimal `bbrpc` pin propagation

Extend `GetContentRevisionResponse` with the responder's view of whether it pins
us.

Implementation path:

1. responder reads `pinned_by_us` for the requester;
2. responder returns `requester_pinned=true|false`;
3. requester stores that as `pins_us` for the remote peer.

This value should be refreshed on the existing revision/proposal/check flows.

No other `bbrpc` changes in this item.

## Phase 6: Focused reporting additions

## 6A. Per-peer reporting

Extend `PeerInfo` and `bbcli peer list` with:

- `pinned_by_us`
- `pins_us`
- `storage_bytes_now`
- `storage_protection`
  - recommended enum values:
    - `NONE`
    - `PINNED`
    - `PROTECTED`
    - `DISPOSABLE`
- `tracked_only`

### Meaning of `storage_bytes_now`

This needs an explicit rule.

Recommended definition:

- report the logical bytes referenced by that peer's current cached revision,
  or `0` if it is track-only.

Important note:

- if two peers reference the same cached blob, per-peer bytes are a logical
  attribution and may sum to more than the deduplicated physical total.

That is acceptable as long as aggregate physical totals are reported
separately and documented clearly.

## 6B. Aggregate storage reporting

Extend `StorageInfo` with:

- `pinned_peers_storage_bytes`
- `protected_peers_storage_bytes`
- `disposable_peers_storage_bytes`
- `tracked_only_peers_count`
- `offline_blocking_storage_bytes`
- `reclaimable_peer_storage_bytes`

Recommended meanings:

- `pinned_peers_storage_bytes`
  - deduplicated physical bytes occupied by cached blobs referenced by pinned
    peers.
- `protected_peers_storage_bytes`
  - deduplicated physical bytes occupied by cached blobs protected by
    non-pinned positive-score peers.
- `disposable_peers_storage_bytes`
  - deduplicated physical bytes occupied only by disposable peers.
- `tracked_only_peers_count`
  - peers for which latest known content exists but latest cached content does
    not.
- `offline_blocking_storage_bytes`
  - deduplicated protected bytes that remain non-reclaimable only because
    pinned or otherwise protected peers are currently offline/stale.
- `reclaimable_peer_storage_bytes`
  - deduplicated disposable bytes that could be removed now without violating
    pin/protection rules.

This stays within the current model and makes the budget understandable.

## 6C. Replica-horizon reporting

Add a repeated report structure, for example:

- `ReplicaHorizonPoint`
  - `remaining_fresh_replicas`
  - `seconds_until_threshold`
  - `never`

Add it to a read-only local surface.

Recommended placement:

- add to `GetStorageConfigResponse.info`, or
- add a separate read-only storage-report RPC.

Preferred direction:

- keep it in the storage-reporting surface, not `peer list`.

### Calculation

Build the candidate set from peers that:

- have our fresh data now;
- passed the last check for that same content id;
- are currently online.

For each candidate peer:

- if `pins_us == true`, expiry time is `never`;
- else expiry time is `max(our_remaining_seconds, 0)` from the peer's
  perspective.

Then:

- sort finite expiry times ascending;
- starting from `N` fresh replicas now, each expiry drops the count by `1`;
- emit the times when the system drops to `N-1`, `N-2`, ..., `0` fresh
  replicas;
- once the count reaches the pinned floor, lower thresholds become `never` or
  absent depending on representation.

Recommended representation:

- emit a point for every reachable count from `N-1` down to `0`;
- mark the ones below the pinned floor as `never=true`.

## Phase 7: CLI output

Keep reporting focused.

### `bbcli peer list`

Show at least:

- `pinned_by_us=true|false`
- `pins_us=true|false`
- `storage_bytes_now=...`
- `storage_protection=pinned|protected|disposable|none`
- `tracked_only=true|false`

### Storage/config reporting

Extend the existing `bbcli config get` output to include:

- the aggregate storage-accounting fields;
- the replica-horizon section.

No new large CLI redesign is required in this item.

## Tests

## Unit tests

Add focused unit coverage for:

1. pin priority
- pinned peers outrank manual peers;
- pinned peers are not displaced by normal tracked-peer admission pressure.

2. pinned cache retention
- cached client eviction prefers evicting non-pinned clients first.

3. pinned storage protection
- a pinned negative-score peer remains protected;
- best-effort peers remain disposable exactly as before.

4. pinned over-budget updates
- if a newer pinned revision does not fit, the old cached pinned revision is
  retained and the new revision becomes latest-known only.

5. reporting math
- deduplicated aggregate bytes for pinned/protected/disposable classes;
- track-only peer counting;
- offline blocking bytes;
- reclaimable bytes.

6. replica-horizon math
- no peers;
- one finite peer;
- multiple peers with staggered finite expiries;
- one or more pinned peers producing `never` thresholds;
- peers with stale or unchecked content excluded from the horizon.

7. protocol/state propagation
- responder advertises `requester_pinned` correctly;
- requester persists `pins_us` correctly.

## Local RPC / daemon tests

Add tests for:

1. pin/unpin RPC round trip;
2. `peer list` output including pinned/protection/track-only fields;
3. `config get` output including new aggregate accounting;
4. contract/report view including `pins_us` and replica horizons;
5. restart persistence of both `pinned_by_us` and `pins_us`.

## Docker integration tests

Add end-to-end scenarios for:

1. pin persistence
- pin a peer;
- restart the daemon;
- verify the peer is still pinned.

2. pin protects storage
- one pinned peer and one disposable peer compete for budget;
- disposable peer is evicted first;
- pinned peer remains cached.

3. pin affects peer admission priority
- fill peer capacity;
- pinned peer remains admitted while lower-priority peers are displaced.

4. pin affects cached connection retention
- fill the cached client pool;
- pinned peer client survives while a non-pinned cached client is evicted.

5. reporting correctness
- `bbcli`-equivalent local RPC checks show:
  - per-peer bytes;
  - protection class;
  - track-only state;
  - offline blocking bytes;
  - reclaimable bytes.

6. replica horizon
- use the logical test clock;
- create several peers with fresh checked replicas of our content;
- pin one subset and leave others unpinned;
- verify the reported thresholds for 3, 2, 1, and 0 replicas;
- verify pinned floors become `never`.

## Suggested Commit Sequence

1. persist peer pin state and add local pin/unpin RPCs
2. propagate `requester_pinned` over `bbrpc`
3. make pinning affect priority and cache retention
4. make pinning affect mirrored-storage protection
5. add focused storage-reporting fields
6. add replica-horizon reporting
7. add Docker integration scenarios
8. update docs and retire the corresponding TODO item

## Expected Result

After this plan:

- the current storage/eviction policy still works the same way by default;
- operators can pin trusted peers;
- pinned peers have absolute priority and are not evicted by normal policy;
- the daemon reports which peer data is protected, disposable, track-only, and
  reclaimable;
- the daemon reports when our fresh replica count would decay if we went
  offline now;
- the whole feature is covered by unit, local RPC, and Docker integration
  tests.
