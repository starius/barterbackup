# Peer Storage Flow

This note explains how peer storage works today, end to end.

The old term "storage contract" is no longer the right mental model. The
system now keeps one persisted peer record for every known peer and may keep
mirrored bytes for only some of them. Storage is peer-centric.

## Terms

- Local content: our current encrypted blob, built from our current file set.
- Peer sidecar: the persisted metadata record for one known peer.
- Mirrored bytes: that peer's encrypted blob cached locally.
- Fresh replica of our data: a peer that is currently online and is known to
  store our current content id.
- Mutual storage: we store that peer's data and that peer stores our data.

## High-level picture

There are two mostly separate directions:

1. Our node publishing our current content to another peer.
2. Another peer publishing its current content to our node.

Those two directions are independent. Mutual storage happens when both have
happened, not when only one has happened.

The system reaches that state automatically, when background maintenance
decides more fresh replicas are needed and selects a peer as a publication
target.

## Step 0: a peer becomes known

A peer usually becomes known through one of these paths:

- `bbcli peer connect <peer>`
- peer exchange gossip
- any authenticated inbound peer RPC from that peer

When that happens, `bbd` tracks the peer locally.

What is stored immediately:

- the peer identity
- first-seen time
- first-contact direction
- pin state
- live success/failure counters
- score state
- latest requester-side revision metadata we have observed for that peer

Important point:

- every known peer gets a sidecar record
- storing mirrored bytes is a separate decision

If tracked-peer capacity is full, the daemon may either:

- evict a lower-priority tracked peer to admit the new one, or
- reject the new one with a capacity error

## Step 1: how our node decides it needs storage peers

Background maintenance runs in `bbd`.

At the start of each pass it computes a plan:

- it builds the current peer inventory
- it builds a live peer-storage view by calling `GetContentRevision` on known
  peers
- it counts fresh replicas of our current content

A peer counts as a fresh replica only when both are true:

- the peer is online now
- the peer's `requester_latest_stored_content` matches our current content id

That is stricter than "the peer knows about our revision" and stricter than
"the peer accepted our sidecar".

If `fresh_replica_count >= min_replicas`, maintenance still verifies existing
fresh replicas, but it may also continue publishing to peers whose data we
already store so reciprocal storage is not one-sided.

If `fresh_replica_count < min_replicas`, maintenance also looks for more peers
that could store our current content.

Publication is skipped entirely when owner publication is blocked, for example:

- recovery mode is still enabled
- recovery says an older lineage must be merged first
- local recovered state is too large to publish

## Step 2: how a new publication target is selected

When more fresh replicas are needed, the daemon considers eligible peers.

A peer is eligible only if:

- it is online
- it does not already store our current content
- owner publication is currently allowed

Selection is not one flat weighted lottery.

The daemon first applies hard priority tiers:

- peers whose data we already store locally
- peers pinned by us
- peers that pin us

Only after those tiers are exhausted does it use weighted-random selection for
the remaining eligible peers.

The weighted remainder favors:

- peers first seen longer ago
- peers with better observed call-success history

This means reciprocal storage is actively prioritized instead of being only a
soft preference.

## Step 3: our node publishes to a peer

This path is used by background maintenance when it selects a peer for
publication.

The local operation is `publish_to_peer_updates()`.

If the local node currently has no content blob, publication is rejected.
Owner-originated `SetContentRevision` calls must always carry a real current
content description.

### 3.1 Connect and inspect current remote state

Our node first connects to the peer and calls:

- `GetContentRevision`

That response tells us, from that peer's point of view:

- `requester_latest_stored_content`: which revision of our data it currently
  stores and can serve
- `requester_latest_known_content`: the newest revision of our data it knows
  about, even if it does not currently store the bytes
- `requester_pinned`: whether that peer currently pins us

We persist the remote pin claim and the observed requester revision metadata in
that peer's sidecar.

### 3.2 Recovery guard before publication

Before we overwrite anything, our node checks whether the peer still has an
older lineage of our data that must be recovered first.

It examines both:

- `requester_latest_stored_content`
- `requester_latest_known_content`

If either one falls into the current recovery window, publication is blocked
until recovery merges it locally.

This prevents a newly launched replacement node from blindly overwriting an
older but still important lineage.

### 3.3 Compare-and-swap publication

If publication is allowed, our node sends:

- `SetContentRevision`

Fields:

- `previous_requester_content = requester_latest_known_content` from the just-read
  `GetContentRevision`
- `requester_content = our current content`

This is compare-and-swap semantics.

The peer will accept the update only if:

- `previous_requester_content == responder.requester_latest_known_content`

If not, the peer rejects the call with a machine-readable
`PreviousRequesterContentMismatch` failure.

### 3.4 What happens on compare-and-swap mismatch

Our node does not blindly retry the same write.

It instead:

1. calls `GetContentRevision` again
2. refreshes the peer's latest-known/latest-stored view of our data
3. if the refreshed view exposes older-lineage data that must be recovered,
   runs one automatic recovery pass
4. rechecks whether publication is now allowed
5. retries `SetContentRevision` once with the refreshed
   `previous_requester_content`

## Step 4: how the storing peer accepts or rejects the update

The responder side handles `SetContentRevision` like this.

### 4.1 Authenticate and track the caller

The responder:

- authenticates the caller from the peer TLS certificate
- tracks that peer if needed
- marks it live

If the peer cannot be tracked because capacity is exhausted and no eviction is
allowed, the request fails before any storage update happens.

### 4.2 Enforce compare-and-swap

The responder reads its locally persisted:

- `requester_latest_known_content` for that caller

If the request's `previous_requester_content` does not match that value, the
call fails with the machine-readable mismatch error.

### 4.3 Apply the new requester state

If the compare-and-swap check passes, the responder calls its internal
`sync_peer_content_info()`.

There are three outcomes.

#### Outcome A: `MirroredBytesCached`

The responder stores:

- the peer sidecar metadata
- the mirrored encrypted blob bytes

If needed, it first downloads the blob from the requester with:

- `Download`

It may evict lower-priority best-effort mirrored blobs first to make room.

#### Outcome B: `SidecarOnly`

The responder stores:

- the sidecar metadata only

It does this when the peer-storage budget does not allow caching another blob.

This is not a protocol failure. The responder is explicitly saying:

- "I recorded your latest revision metadata"
- "I did not cache your bytes"

This peer does not count as a fresh replica of our data.

#### Outcome C: `requester_content = nil`

If `requester_content` is `nil`, the responder rejects the call as invalid.

### 4.4 Score delayed peer uptake

When we first attempt to advertise a concrete content id to a peer, we remember
that content id and the first advertisement time.

If the peer later calls `Download` for that same content id, the elapsed time
is recorded and deducted from the peer's score.

If we advertise a newer revision before the peer ever downloads the older one,
the pending delay of that superseded advertisement is also deducted from the
score.

### 4.5 Roll peer metadata into our own lineage later

Peer sidecar updates are persisted locally right away, but they do not rewrite
our shared content blob immediately.

Instead, if our file set stays unchanged, the daemon schedules one metadata-only
local content rewrite on an exponential delay with a one-day mean.

Important properties:

- repeated peer-metadata churn coalesces into one pending delayed rollup
- a real file update clears that pending rollup because the new file-driven
  content revision already carries the latest peer metadata
- if the delayed rollup reaches its due time first, the daemon rewrites the
  same file set into a new local content id with newer embedded peer metadata
- low-value delayed sidecar updates are flushed first before that rewrite runs

This keeps peer-sidecar progress crash-safe in the owner's shared lineage
without making one exact metadata event map to one exact immediate publication
event.

## Step 5: what makes storage mutual

After the previous steps, the target peer stores our data only if outcome A
happened.

That alone is not mutual storage.

Mutual storage exists only when both are true:

- we store that peer's mirrored data locally
- that peer stores our current content locally

The second direction starts separately, when the other peer decides to publish
its data to us.

That can happen because its own maintenance loop needed more fresh replicas
and selected us.

When that peer calls `SetContentRevision` on us, we go through the same accept /
reject path described above.

This is why reciprocal storage is preferred but not forced.

## Step 6: how publication is verified over time

Fresh replicas are maintained, not assumed forever.

For peers that currently look like fresh replicas, maintenance runs
`verify_peer_storage_updates()`.

That flow is:

1. connect to the peer
2. call `GetContentRevision`
3. confirm `requester_latest_stored_content` still equals our current content id
4. if yes, download a deterministic sample section with `Download`
5. compare:
   - whole-blob length
   - whole-blob SHA-256
   - sampled bytes

If all checks pass:

- the peer gets a positive score update
- we record that this peer most recently verified our current content id

If not:

- the peer gets a negative score update
- it stops counting as a fresh verified replica

These scores are later used for:

- peer selection weighting
- storage protection class
- replica horizon reporting

## Step 7: how background maintenance keeps the system alive

Each maintenance pass does this order:

1. run automatic recovery first
2. build the current maintenance plan
3. for selected peers, run publication and/or verification

The plan usually means:

- existing fresh replicas: verify them
- missing replicas: publish to selected online peers, then verify

If a publication or verification fails, the daemon records:

- failure class
- consecutive failure count
- retry deadline

Successful maintenance clears the backoff state again.

## Step 8: what `bbcli state` and `bbcli peer list` are showing

`bbcli state` summarizes the local view:

- total known peers
- connected peers
- peers storing our data
- peers storing the latest version of our data
- mutual-storage peer count
- mean score of mutual-storage peers
- mirrored peer count and mirrored bytes
- predicted fresh replicas now
- replica horizon

`bbcli peer list` shows the per-peer sidecar view, including:

- whether the peer is online
- cached mirrored bytes
- latest known / latest cached content lengths
- tracked-only state
- score
- backoff / failure information
- pin state

## Important edge cases

### Sidecar-only acceptance

A peer can accept our publication metadata but not our bytes.

That means:

- the RPC succeeded
- the peer knows our newest revision
- the peer does not count as a current replica

This is expected behavior under storage pressure.

### No local content

If we currently have no local content, owner publication is rejected.

The node must first recover or create a current content blob before it can
publish to peers.

### Recovery can block publication

If a peer still has an older lineage in the active recovery window, our node
must recover it before publication can proceed.

That is why a replacement node should be initialized with:

- `bbcli init --recovery-mode`

and only later finalized with:

- `bbcli init complete`

## One short timeline

Here is the most common automatic case.

1. We know peer `B`.
2. Maintenance sees only `1` fresh replica but `min_replicas = 2`.
3. `B` is online and is selected as a weighted publication target.
4. We call `GetContentRevision(B)`.
5. `B` reports no blocking older lineage.
6. We call `SetContentRevision(B)` with:
   - `previous_requester_content = B`'s latest known revision of our data
   - `requester_content = our current content`
7. `B` accepts.
8. `B` either:
   - downloads and stores our blob: fresh replica possible
   - or stores sidecar only: not a replica yet
9. We later verify `B` with `GetContentRevision + Download(sample)`.
10. If verification passes and `B` is online, it counts toward `min_replicas`.
11. Later, if `B` also decides to publish its own content to us and we store
    it, the relationship becomes mutual storage.

## Practical takeaway

The right way to think about the system now is:

- known peer records are cheap and broad
- mirrored bytes are selective and budgeted
- publication is owner-initiated and compare-and-swap guarded
- acceptance can be full-storage, sidecar-only, or clear
- verification and scoring determine whether a peer really counts as a fresh
  replica
- mutual storage is an emergent state from both directions, not a single
  special handshake
