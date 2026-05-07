# Plan: Retire Legacy Peer Clients and Idle Inner Lanes

## Goal

Finish the yamux-session migration and remove the remaining mixed transport
model.

After this follow-up:

- every peer connector in the repository is session-backed,
- the old short-lived peer-client cache and its compatibility hooks are gone,
- long-lived outer peer sessions are kept for every peer with real storage
  involvement,
- peers without storage involvement still use a small fixed-size session cache,
- idle inner gRPC/h2 lanes are closed after a short inactivity period,
- the outer yamux/TLS/Tor session stays alive while only the idle inner lane is
  dropped.

## Product Decisions

### 1. No legacy non-session connector path

The current fallback path exists only to avoid rewriting older test
connectors immediately. Retire it completely.

This means:

- remove the idea of a connector that is not session-backed,
- remove the old short-lived peer-client cache from `node`,
- remove any compatibility branching based on `session_backed()`,
- make all in-repo peer connectors expose real session state.

### 2. Session retention is based on storage involvement, not `2 * min_replicas`

Retire the `2 * min_replicas` session-capacity rule.

Instead, keep durable outer sessions for all peers where real storage is
involved:

- peers storing our data,
- peers whose data we store.

Sidecar-only relationships do not count.

Peers with no current storage relationship may still get on-demand sessions, but
those belong to a separate small bounded cache, for example `32`.

### 3. Close only idle inner lanes, not outer sessions

If a peer has a live outer session but no RPC activity for some time, close:

- the h2 connection,
- the gRPC client/server lane state,
- the yamux substream for that lane.

Keep alive:

- the yamux connection itself,
- the outer TLS session,
- the underlying Tor connection.

Target idle timeout:

- `1 minute`

## Desired Runtime Model

For each peer we now have two layers:

### Outer session

Long-lived and expensive to create:

- Tor stream / TCP-like stream
- mutual TLS
- yamux connection

Outer session lifetime ends only when:

- Tor closes it,
- TLS closes it,
- yamux fails,
- duplicate-collapse selects another outer session,
- the peer is evicted from the appropriate outer-session set,
- shutdown happens.

### Inner lane

Cheap and replaceable:

- one yamux substream
- one h2 connection
- one gRPC client or server lane

Inner lane lifetime ends when:

- it fails,
- it is explicitly idled out after `1 minute`,
- the outer session dies.

The next RPC should reopen the lane inside the same outer session.

## Scope Changes

### Remove from `node`

Delete:

- `peer_client_cache`
- `CachedPeerClient`
- `MAX_CACHED_PEER_CLIENTS`
- `PEER_CLIENT_CACHE_IDLE_TTL_SECS`
- cache pruning that only exists for short-lived peer clients
- compatibility logic in:
  - `cached_peer_client()`
  - `remember_peer_client()`
  - `has_cached_peer_client()`
  - `connect_peer_client_with_timeout_and_tracking_base()`

After this change, `connected` means only:

- a real live outer session exists

### Simplify `PeerConnector`

Retire these compatibility hooks:

- `session_backed()`

Rework the trait so session semantics are the default, not optional.

At minimum, every connector should support:

- `connect(...)`
- `connected(...)`
- desired durable-session set updates
- desired opportunistic-session cache size updates

One reasonable trait shape is:

- keep `connect(...)`
- keep `connected(...)`
- replace `set_session_capacity(...)` and `set_preferred_sessions(...)` with
  two explicit controls:
  - `set_durable_session_peers(...)`
  - `set_opportunistic_session_capacity(...)`

### Rewrite test connectors to use sessions too

Repository-internal connectors must match production structure:

- `netmock::MockPeerConnector` already does
- `PlainPeerConnector` and wrappers in node/unit tests should be retired or
  reworked

For tests that do not need Tor:

- prefer `netmock`

For tests that need intentionally simple failure injection:

- wrap a session-backed connector instead of a plain h2 connector

If a purely plain h2 test helper still exists after this follow-up, it should be
treated as technical debt not yet removed.

## New Session Policy

Split session management into two buckets.

### 1. Durable storage-involved sessions

Maintain outer sessions for every peer where:

- they store our data, or
- we store their data.

This set is unbounded except by the tracked-peer set itself.

These peers should not be evicted merely because some other peer was dialed.

### 2. Opportunistic sessions

Peers with no current storage relationship use a bounded session cache.

Examples:

- newly discovered peers,
- peers contacted for exchange or probing,
- peers that may become storage-relevant later.

This opportunistic cache can be fixed-size, for example:

- `32`

When full, evict from this bucket only.

Important rule:

- a peer moves from opportunistic to durable immediately once real storage
  begins
- sidecar-only metadata does not trigger promotion

## Storage-Involvement Definition

Define exactly what counts as “storage involved”.

Count as durable:

- `our_stored_content_bytes > 0`
- `stored_content_bytes > 0`
- equivalent persisted state showing actual mirrored bytes or actual remote
  storage of our content

Do not count as durable:

- sidecar-only tracking,
- known-peer metadata,
- latest-known-but-not-cached state,
- pin status alone without storage

If the current peer inventory fields are ambiguous, add a transport-neutral
 helper that computes:

- `stores_our_data`
- `we_store_their_data`
- `storage_involved`

and reuse that consistently.

## Idle Inner Lane Shutdown

### Outbound lane

Track last use time for each outbound lane.

If no outbound RPC uses the lane for `1 minute`:

1. close the gRPC/h2 lane cleanly,
2. close the yamux substream,
3. keep the outer session live,
4. clear the cached outbound lane handle.

The next outbound RPC should:

1. observe that no active outbound lane exists,
2. open a fresh yamux substream,
3. build a fresh h2/gRPC lane,
4. continue over the same outer session.

### Inbound lane

Track last activity for the peer-opened inbound lane too.

If the remote side leaves its lane idle for `1 minute`:

- close that inbound h2/gRPC connection
- but keep the outer session live

The peer can reopen it later on another yamux substream.

### Implementation note

Do not treat keepalive pings as application activity for the idle timer.

Otherwise the lane will never age out.

The idle timer should be reset by:

- actual outbound RPC use,
- actual inbound RPC handling

not by transport keepalive housekeeping alone.

## Background Maintenance Changes

Replace the current preferred-session preparation concept with two explicit
maintenance surfaces:

### 1. Durable session maintainer

Continuously ensure outer sessions exist for every storage-involved peer.

This set should be recomputed from peer state each maintenance pass, or from a
dedicated notifier if the state changes often enough.

### 2. Opportunistic session maintainer

Optionally keep some additional non-storage peers warm in a bounded cache.

This can still prioritize:

- pinned peers without current storage,
- likely-soon-useful peers,
- recently live peers

But these sessions must never evict durable storage-involved ones.

## Session Registry Refactor

The registry needs explicit per-peer policy state.

Each entry should know whether it is:

- durable
- opportunistic

The registry should support:

- update durable desired-peer set
- update opportunistic capacity
- evict opportunistic sessions first
- never evict durable sessions due only to opportunistic pressure

One clean structure is:

- durable slots keyed by peer onion
- opportunistic slots keyed by peer onion

Or a single map with per-entry bucket metadata plus eviction logic.

## Failure Semantics

### Outer session failures

If the outer session fails:

- all inner lanes die,
- the peer becomes disconnected,
- durable peers should reconnect automatically,
- opportunistic peers reconnect only if they are still wanted.

### Inner lane failures

If the inner lane fails while the outer session is still healthy:

- do not mark the peer disconnected,
- just clear the dead lane,
- let the next RPC reopen it,
- or proactively reopen only if there is a strong reason

Given the new RAM-saving goal, default to:

- lazy lane reopening

not proactive lane recreation.

## Connected Semantics

Keep `connected` simple:

- true if a live outer session exists
- false otherwise

Do not require the inner h2/gRPC lane to still be open.

That is important because the lane may now be intentionally idled out while the
valuable outer session remains alive.

If needed, add richer internal or operator-visible counters later:

- connected outer sessions
- open outbound lanes
- open inbound lanes
- durable sessions
- opportunistic sessions

## Tests

### Transport / node unit tests

Add deterministic coverage for:

- repeated RPCs reopen a closed idle lane inside the same outer session
- idle timeout closes only the inner lane, not the outer session
- `connected` remains true after lane idle shutdown
- durable storage-involved peers stay connected even when many opportunistic
  peers are contacted
- opportunistic peers are evicted before durable ones
- promotion from opportunistic to durable happens when real storage begins
- demotion back to opportunistic or removal happens when storage ends

### Regression tests for legacy removal

After deleting the old client cache:

- remove old cache-specific tests
- replace them with session-specific behavior tests

For example replace:

- “peer client cache reuses recent dials”

with:

- “outer session is reused across repeated RPCs”
- “idle lane is recreated inside the same outer session”

### Daemon tests

Add daemon-level coverage that:

- maintenance establishes durable sessions for storage-involved peers
- storage-involved peers remain connected regardless of opportunistic churn
- deleting storage relationship eventually removes the peer from the durable set
- idle lanes close without dropping durable outer sessions

## Suggested Commit Split

1. Remove the legacy non-session connector path and old peer-client cache.
2. Rework repository test connectors so every in-repo connector is
   session-backed.
3. Change session policy from `2 * min_replicas` to:
   - all storage-involved durable sessions
   - bounded opportunistic session cache
4. Add idle inner-lane shutdown while preserving the outer session.
5. Refresh tests and documentation to match the new semantics.

## Expected Outcome

After this follow-up:

- there is only one peer transport model in the repository,
- every real storage relationship keeps a durable outer connection,
- non-storage peers use a bounded opportunistic session pool,
- idle h2/gRPC/yamux-substream state is shed after about `1 minute`,
- the expensive Tor/TLS/yamux session stays alive underneath,
- verification and publication reuse those outer sessions and reopen inner lanes
  only when needed.
