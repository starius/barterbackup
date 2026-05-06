# Plan: Long-Lived Yamux Peer Sessions

## Goal

Replace the current short-lived peer gRPC dials with one long-lived authenticated
peer session per remote peer:

- `Tor DataStream`
- mutual TLS
- `yamux`
- one long-lived gRPC connection for `us -> them`
- one long-lived gRPC connection for `them -> us`

The outer Tor+TLS connection should stay open as long as practical. It should be
closed only because:

- Tor closed it,
- we evicted it from the bounded registry,
- or the session failed in a way that cannot be recovered inside the existing
  connection.

When one inner gRPC lane dies, we should reopen that lane on a new yamux
substream without tearing down the outer Tor+TLS session.

## Scope

This plan focuses only on the yamux design. It does not explore alternative
transport designs.

## High-Level Design

### 1. One authenticated outer session per peer

After Tor accept or Tor dial:

1. complete the existing mutual TLS handshake,
2. extract the remote Ed25519 identity from the peer certificate,
3. start a `yamux` session over that TLS stream,
4. register the resulting authenticated peer session in an in-memory session
   registry.

That outer session becomes the durable transport object. It is no longer just a
step on the way to a tonic channel.

### 2. Two long-lived gRPC lanes inside the yamux session

Each live yamux session carries two long-lived h2/gRPC lanes:

- our outbound lane:
  - opened by us on one yamux substream,
  - used by our existing tonic client to call the peer,
- peer outbound lane:
  - opened by the peer on one yamux substream,
  - used by our existing tonic server to serve that peer.

This preserves the current `.proto` service and existing tonic client/server
logic. The symmetry comes from yamux, not from changing gRPC semantics.

The normal steady state is:

- one outer Tor+TLS+yamux session,
- one healthy outbound gRPC lane,
- one healthy inbound gRPC lane.

### 3. Session-backed `connected` state

`connected` should no longer mean “we still have a cached tonic client object”.
It should mean:

- an authenticated outer yamux session to that peer is live.

Optionally, internal diagnostics can track finer-grained states:

- outer session live,
- outbound gRPC lane live,
- inbound gRPC lane live.

User-facing status can stay simple at first, but it must be backed by the real
session state.

## Protocol and Transport Changes

### 1. Peer TLS ALPN

Peer TLS currently advertises `h2` because the outer connection is directly
consumed by tonic. That will no longer be true.

Change peer transport ALPN to a transport-specific value such as:

- `bb-peer-yamux/1`

Local CLI TLS keeps its existing `h2` setup.

### 2. Yamux dependency and framing

Add `yamux` as the peer-session multiplexer over the existing TLS stream.

No additional custom framing is needed between yamux and gRPC. Each yamux
substream is handed directly to tonic/h2.

### 3. Big-bang peer transport switch

This is an unreleased protocol surface. Do not preserve backward compatibility
with the old direct-gRPC-over-TLS peer transport.

Use one atomic switch:

- new ALPN,
- new peer transport setup,
- no old fallback path.

## Session Registry

### 1. Replace the cached client map with a real session registry

Today we cache recent outbound tonic clients with a small idle TTL. Replace that
with a registry keyed by peer onion:

- one entry per peer,
- one outer session per peer,
- lane state inside that session,
- background tasks that keep the session alive.

Each session entry should hold at least:

- remote `PeerIdentity`,
- whether this outer session was inbound or outbound,
- live/connecting/closing state,
- yamux control task handles,
- current outbound gRPC client handle, if ready,
- current inbound lane health,
- last healthy time,
- last error,
- whether this peer is currently wanted proactively.

### 2. Registry capacity

Size the registry to:

- `2 * min_replicas`

This is a session capacity, not a gRPC-lane capacity.

When the registry is full:

- evict the lowest-priority session first,
- then the oldest/least useful one within that priority.

Priority order for session retention:

1. pinned peers,
2. mutual-storage peers,
3. peers storing our current content,
4. everybody else.

### 3. No short idle TTL

Remove the current short client idle expiry behavior for session-backed peers.

A live authenticated session should stay up until:

- Tor closes it,
- we explicitly evict it,
- or the session hits an unrecoverable failure.

## Duplicate Session Collapse

## Goal

When both sides dial, converge quickly to one physical outer session per peer so
one peer occupies one slot most of the time.

## Rule

Keep any single healthy authenticated session when there is no duplicate.

When a duplicate authenticated session appears for the same peer, collapse
immediately using a deterministic rule:

1. prefer the session initiated by the lexicographically smaller onion,
2. if a tie-break is still needed, prefer the older session nonce or start time.

Important nuance:

- this rule applies only when duplicates exist,
- it must not reject the only existing session merely because the “other side
  should have dialed”.

That allows a locally important peer to become connected even if only one side
currently cares enough to initiate the session.

## gRPC Lane Lifecycle

### 1. Outbound lane

For each live outer session, maintain one long-lived outbound gRPC lane:

- open one yamux substream,
- build a tonic `Channel` over it,
- keep that channel alive as the reusable peer client.

All peer RPCs from this node to that peer use this client.

### 2. Inbound lane

Accepted yamux substreams from that peer are treated as inbound gRPC lanes.

Feed them into the peer tonic server as accepted connections.

The steady-state expectation is one live inbound gRPC lane from that peer. If
the peer reopens it, accept the replacement and close the old broken one.

### 3. Lane restart inside the existing outer session

If one gRPC lane dies but the outer yamux session remains healthy:

- do not tear down the Tor+TLS session,
- reopen only the dead lane on a new yamux substream,
- replace the cached client/server-side lane state accordingly.

This should handle routine h2/tonic lane failures without losing the expensive
outer Tor connection.

### 4. Keepalive

Set long-lived h2 keepalive settings for these peer lanes so:

- idle lanes are less likely to die silently,
- dead lanes are detected reasonably quickly,
- normal idle periods do not cause churn.

The exact keepalive values can be tuned during implementation, but the plan
assumes lane keepalive exists.

## Peer Identity and Server Integration

### 1. Authenticate once at the outer TLS layer

The current peer server extracts peer identity from tonic TLS connection
extensions. That will not work once tonic runs on a yamux substream rather than
directly on the rustls connection.

Instead:

1. extract `PeerIdentity` from the outer rustls handshake once,
2. attach that identity to the session,
3. attach that identity to every inbound yamux substream accepted from that
   session.

### 2. Use tonic `Connected` metadata for inner gRPC lanes

Wrap inbound yamux substreams in a type that implements tonic’s `Connected`
trait and carries custom peer connection info.

Then update peer request authentication to:

1. first check for this custom peer-session connect info,
2. fall back only where needed for tests or transitional code.

This keeps the existing peer tonic server usable without inventing a new inner
RPC layer.

## Proactive Session Maintenance

### 1. Separate background session maintainer

Create a background session maintainer distinct from publication and
verification.

Its job is:

- choose which peers should have a prepared live session,
- establish missing sessions,
- heal broken lanes inside existing sessions,
- evict low-priority sessions when over capacity.

### 2. Candidate priority

At minimum, proactively prepare sessions for:

1. pinned peers,
2. mutual-storage peers.

Then fill the remaining capacity with peers that currently matter most for
storage and recovery, such as peers storing our current content.

### 3. Do not wait for a user RPC

If a high-priority peer currently has no live session:

- start reconnecting in the background,
- do not wait for the next `connect_peer`, publish, verify, or recovery call.

### 4. Backoff

The session maintainer needs its own reconnect backoff separate from the current
per-RPC retry budgets.

Use session-level backoff for:

- failed outer dials,
- failed TLS handshakes,
- failed yamux session setup,
- repeated lane restarts that indicate the outer session is unhealthy.

## Failure Handling

### 1. Recoverable failures

Recover inside the existing outer session when:

- one outbound gRPC lane dies,
- one inbound gRPC lane dies,
- tonic channel breaks but yamux is still healthy.

### 2. Unrecoverable failures

Tear down the whole session and reconnect when:

- Tor closes the outer stream,
- rustls closes,
- yamux session fails,
- duplicate collapse chooses another session,
- repeated lane restarts indicate the outer session is no longer trustworthy.

### 3. Explicit eviction

When capacity pressure requires removal:

- close the whole session cleanly,
- drop both gRPC lanes,
- remove the registry entry.

## Public State and CLI Reporting

### 1. `connected`

Back `connected` by the real session registry:

- true when a live authenticated outer session exists,
- false otherwise.

This is much stronger than the current “cached client object exists” meaning.

### 2. Optional richer state

Internally and optionally in `bbcli state`, track:

- total live peer sessions,
- pinned peers with live sessions,
- mutual peers with live sessions,
- peers with outer session live but outbound lane not yet ready,
- peers currently reconnecting.

These are useful for validating that the proactive maintainer is actually doing
its job.

## Implementation Phases

### Phase 1: Add the transport substrate

1. Add `yamux`.
2. Change peer TLS ALPN to the new transport ALPN.
3. Build an outer session object over rustls streams.
4. Extract peer identity from the outer TLS session.

Deliverable:

- one authenticated outer yamux session can be established over both netmock and
  Tor transport.

### Phase 2: Move inbound peer serving onto yamux substreams

1. Wrap inbound yamux substreams as tonic-compatible connections.
2. Attach custom peer identity connect info.
3. Update peer request authentication to use that connect info.

Deliverable:

- existing peer tonic server can serve RPCs over accepted yamux substreams.

### Phase 3: Move outbound peer clients onto yamux substreams

1. Open one outbound yamux substream.
2. Build a tonic client channel over it.
3. Replace direct Tor/TLS dial caching with session-backed client reuse.

Deliverable:

- one established session can carry repeated outbound RPCs without reopening the
  outer Tor connection.

### Phase 4: Add the session registry and duplicate collapse

1. Replace the old peer client cache with the session registry.
2. Add duplicate detection keyed by peer onion.
3. Implement deterministic duplicate collapse.

Deliverable:

- one peer usually occupies one slot and duplicate sessions converge fast.

### Phase 5: Add proactive session maintenance

1. Compute the desired prepared-session set from peer priority.
2. Maintain sessions in the background up to `2 * min_replicas`.
3. Reconnect broken outer sessions without waiting for user traffic.
4. Reopen dead gRPC lanes inside healthy outer sessions.

Deliverable:

- pinned and mutual peers are connected proactively when possible.

### Phase 6: Update user-visible `connected` semantics

1. Switch peer inventory status to session-backed `connected`.
2. Expose session health counts in local state if useful.
3. Remove or rename any remaining logic that still means only “cached client
   existed once”.

Deliverable:

- `bbcli peer list` and `bbcli state` report a meaningful session-backed
  connection state.

## Tests

### Unit and netmock

Add deterministic tests for:

- establishing one outer yamux session,
- opening the two directional gRPC lanes,
- reusing the same outer session across repeated RPCs,
- restarting one gRPC lane without tearing down the outer session,
- deterministic duplicate collapse,
- registry eviction order,
- session-backed `connected` reporting.

Netmock is the right first proving ground because it avoids Tor timing noise
while exercising the TLS and tonic integration.

### Tor and Docker integration

Add targeted integration coverage for:

- repeated peer RPCs reuse one long-lived session,
- reverse-direction RPC works without a second outer Tor connection,
- pinned or mutual peers become connected proactively,
- a broken lane heals inside the same outer session,
- a broken outer session reconnects in the background,
- duplicate inbound/outbound dials converge to one live session.

### Observability during rollout

Add temporary or permanent debug/info logs for:

- outer session established,
- outbound lane established,
- inbound lane established,
- lane restarted,
- duplicate session collapsed,
- session evicted,
- background reconnect scheduled and completed.

## Suggested Commit Split

1. Add yamux peer transport substrate and new peer ALPN.
2. Move inbound peer server authentication from tonic TLS info to custom
   session-backed connect info.
3. Run existing peer tonic server on accepted yamux substreams.
4. Run outbound tonic clients on locally opened yamux substreams.
5. Replace the old peer client cache with the bounded session registry.
6. Add duplicate-session collapse and session-backed `connected` state.
7. Add proactive session maintenance and lane healing.
8. Add Tor/Docker integration coverage and trim stale cache-oriented logic.

## Expected Outcome

After this refactor:

- one peer pair typically has one long-lived authenticated Tor+TLS+yamux session,
- both nodes can issue normal peer gRPC calls over that single outer session,
- `connected` means a real live peer session exists,
- pinned and mutual peers are connected in advance when possible,
- ordinary peer work no longer repeatedly pays the full Tor dial cost.
