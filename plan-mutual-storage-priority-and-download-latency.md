# Plan: prioritize mutual storage and score delayed peer uptake

## Goal

Adjust peer-storage maintenance so the system favors mutual storage more
aggressively, reduces the privacy signal from "first real upload", and lowers a
peer's score when it is slow to pick up our newly announced content.

This plan changes behavior only. It does not propose a new user-facing feature
surface beyond documenting the new rules.

## Requested behavior

1. If we already store a peer's data, we should try to publish our data to that
   peer even when `fresh_replica_count >= min_replicas`.
2. Peer selection must stop treating two cases as weighted preferences:
   - we already store the peer's data
   - we pin the peer or the peer pins us
   Those become hard priority tiers.
3. The owner-side maintenance loop should still call `SetContentRevision` even
   when we currently have no local content blob to upload. This keeps the sidecar
   fresh and reduces the privacy signal around the first non-empty publication.
4. We should record how long each peer takes to download a newly announced
   content revision after we first advertise it. Slow or non-reacting peers
   should lose score.

## Current behavior to change

The current code and docs still describe this model:

- if `fresh_replica_count >= min_replicas`, maintenance mostly verifies existing
  fresh replicas
- only when below target does maintenance actively seek more publication peers
- candidate choice is weighted, with stronger weight for:
  - peers whose data we already store
  - peers pinned by us or pinning us
- publication planning is biased toward cases where we currently have local
  content to publish

That behavior is documented in [docs/peer-storage-flow.md](docs/peer-storage-flow.md)
and implemented in `crates/node/src/lib.rs`.

## Proposed design

### 1. Split maintenance intent into two independent goals

Maintenance should plan owner-side publication for two separate reasons:

1. Replica-target maintenance:
   - if `fresh_replica_count < min_replicas`, find enough peers to push us back
     toward the configured target
2. Mutual-storage reciprocation:
   - regardless of `fresh_replica_count`, if we currently store a peer's data
     and that peer is not known to store our latest advertised revision, try to
     publish our side to it

This makes "do not store other peers for free" a standing policy rather than a
best-effort preference that only applies when we are short on replicas.

### 2. Use priority tiers before weighted random choice

Candidate selection should become:

1. Tier 1, unconditional first:
   - peers whose data we already store locally
2. Tier 2, unconditional next:
   - peers pinned by us
   - peers pinning us
3. Tier 3, weighted random among all remaining eligible peers

Within a tier:

- tier 1 may still use weighted random internally if there are more eligible
  peers than we want to contact in one maintenance pass
- tier 2 may likewise use weighted random internally
- tier 3 stays weighted random as today, but without the two factors above

This keeps some randomness for privacy and churn control while making the
project's intended reciprocity policy explicit.

### 3. Publish sidecar state even when local content is absent

Owner-side maintenance should not skip publication work just because the local
content blob is currently absent.

Instead:

- we still call `SetContentRevision`
- `requester_content` may be omitted
- the call still carries:
  - `previous_requester_content`
  - `requester_pins_responder`
  - any other requester-side sidecar metadata already conveyed there

Because nil `requester_content` no longer clears remote state, this becomes a
safe sidecar refresh rather than a destructive operation.

Privacy intent:

- a peer observing us should not be able to infer too directly that "this was
  the first time the owner had real content"
- we will have already established a history of sidecar updates and CAS state

One implementation constraint:

- the planner must distinguish "publish sidecar metadata" from "expect a new
  fresh replica"
- a sidecar-only publication cannot count toward `fresh_replica_count`

### 4. Add per-peer download-latency tracking for our advertised revisions

When we first attempt to advertise content revision `R` to peer `P`, record:

- peer ID
- content ID
- `first_advertised_at`
- whether the advertisement was accepted, rejected, or only partially accepted
  (for example, sidecar-only acceptance)

When `P` later calls `Download(R)` from us, record:

- `downloaded_at`
- `latency = downloaded_at - first_advertised_at`

This becomes a score input:

- quick uptake improves or preserves score
- slow uptake reduces score
- never downloading after repeated accepted advertisements reduces score more

Important rule:

- only the first successful download for a given `(peer, content_id)` should
  complete the latency record
- repeated downloads of the same content ID should not repeatedly modify score

### 5. Treat sidecar-only responders differently from full replicas

A peer that accepts `SetContentRevision` but does not have room for the mirrored
blob is still useful, but not as a replica.

Maintenance and state should distinguish:

- peer knows our latest sidecar
- peer has downloaded and stores our latest bytes
- peer has been verified as a fresh replica

This matters because the new "publish even when at target" rule will cause more
sidecar traffic, and that must not inflate the replica count.

## Data model changes

### Persisted peer state

Add owner-side publication latency bookkeeping to persisted peer metadata.

Recommended fields:

- `last_advertised_content_id`
- `last_advertised_at`
- `last_downloaded_advertised_content_id`
- `last_downloaded_advertised_at`
- `last_download_latency_seconds`

Prefer storing only the latest pending advertisement per peer, not an unbounded
history. We only need enough state to:

- detect whether the latest announced revision was picked up
- score delay
- survive daemon restart without forgetting a pending advertisement

If the peer later receives a newer announcement before downloading the older
revision, the new announcement should replace the pending one. We care about
how quickly the peer converges on our latest state, not whether it ever fetched
every intermediate revision.

### In-memory helpers

Add explicit owner-publication status helpers so the planner can ask:

- do we store this peer's data?
- is this peer pinned by either side?
- does this peer already know our latest sidecar?
- does this peer store our latest mirrored content?
- do we have a pending advertised-but-not-yet-downloaded revision for this
  peer?

## Maintenance algorithm changes

### Step 1: classify peers

For each known peer, compute:

- eligibility for contact
- whether we currently store their data
- pin relationship
- online / recently reachable status
- whether they already know our latest revision
- whether they currently count as a fresh replica
- whether we have a pending advertisement awaiting download

### Step 2: build two contact sets

Build:

1. replica-gap set:
   - peers needed to raise fresh replica count toward `min_replicas`
2. reciprocity set:
   - peers whose data we store but who do not yet store our latest advertised
     revision

Then merge them:

- peers appearing in both sets are contacted once
- replica-gap motivation decides whether a successful full download can improve
  the replica target
- reciprocity motivation decides whether the peer should still be contacted even
  if we are already at or above target

### Step 3: apply priority tiers

Contact ordering:

1. peers whose data we store
2. pinned peers in either direction
3. weighted-random remainder

The remaining weighted factors should continue to include:

- first-seen age
- observed availability / success ratio
- persisted score

But they should no longer be allowed to outrank the first two categories.

### Step 4: handle sidecar-only publication distinctly

For each contacted peer:

- always attempt `SetContentRevision`
- if the responder accepts only the sidecar, remember that result
- do not treat sidecar-only acceptance as replica creation
- continue to verify or refill elsewhere if the replica target still needs real
  stored bytes

## Scoring changes

### Existing score inputs remain

Do not remove the current reachability / availability score behavior.

### Add download-latency penalty

When a peer downloads the advertised content:

- compute latency buckets, for example:
  - immediate / fast
  - moderate
  - slow
  - effectively never
- adjust score accordingly

The precise coefficients need tuning, but the rule should be:

- if a peer is online yet slow to fetch our announced content, its score should
  drop relative to responsive peers

### Offline / non-reacting peers

If:

- we repeatedly advertise newer revisions
- the peer accepts sidecars
- but never downloads the bytes

then the peer should lose score over time even if some transport-level checks
keep succeeding.

This captures a more important property than "peer answered RPCs": whether it
actually reacts to storage updates.

## Protocol impact

### No required new peer RPC for the core behavior

The latency signal can be derived from:

- existing `SetContentRevision`
- existing `Download`

No new peer RPC should be necessary for the main design.

### Possible response/detail cleanup

If current `SetContentRevision` responses do not clearly tell the caller whether
the peer accepted only the sidecar or also cached mirrored bytes, keep the
existing explicit storage-result reporting and make sure maintenance consumes it
correctly.

## CLI and docs impact

Update documentation to match the new behavior:

- [README.md](README.md)
- [docs/peer-storage-flow.md](docs/peer-storage-flow.md)

The docs should say:

- mutual storage is prioritized even when replica target is already satisfied
- storing another peer's data creates a standing attempt to reciprocate
- pinned peers are hard-priority publication targets
- sidecar publication can happen before any local content blob exists
- peer score now reflects not only uptime and verification but also how quickly
  a peer fetches announced updates

Potential `bbcli state` follow-up:

- optional future field for "pending peer uptake" or "latest peer uptake delay"
- not required for the first implementation unless debugging proves it is
  operationally necessary

## Tests

### Unit tests in `crates/node`

Add deterministic tests for:

1. reciprocity at target:
   - `fresh_replica_count >= min_replicas`
   - we store peer `B`'s data
   - `B` does not yet store our latest revision
   - maintenance still chooses `B` for publication

2. hard priority ordering:
   - a stored peer outranks a merely high-score peer
   - a pinned peer outranks a merely old/high-score peer

3. sidecar-only publication without local content:
   - maintenance still calls `SetContentRevision`
   - omitted `requester_content` does not clear remote state
   - no fresh-replica count inflation occurs

4. sidecar-only responder handling:
   - sidecar-only acceptance is persisted
   - peer is not counted as a fresh replica

5. download-latency scoring:
   - record first advertisement time
   - complete the record on first `Download`
   - repeated downloads do not re-apply the penalty/bonus
   - a newer advertised content ID replaces the older pending one

6. non-reacting peer penalty:
   - repeated accepted advertisements with no download reduce score

### Storage tests in `crates/storage`

Add persistence tests for:

- pending latest advertisement state across restart
- completed latency state across restart
- replacement of older pending advertisement by newer content ID

### `netmock` tests

Add multi-node tests for:

- owner stores responder's data first, then reciprocates automatically despite
  already having enough replicas
- pinned peer priority beats weighted random remainder
- peer downloads promptly versus slowly, producing different score outcomes

### Docker integration tests

Cover the dangerous end-to-end cases:

1. mutual-storage reciprocity at target:
   - owner already has enough replicas
   - owner stores `B`
   - maintenance still publishes to `B`

2. sidecar-only path:
   - responder has no room for mirrored bytes
   - accepts sidecar only
   - owner does not count it as a fresh replica

3. download-delay scoring:
   - one peer downloads promptly
   - another peer delays until later
   - resulting score ordering reflects that difference

4. privacy-preserving empty publication:
   - owner with no current content still publishes sidecar state
   - later first non-empty content addition does not require introducing a brand
     new publication relationship

## Commit split

1. Persist advertisement/download latency state
   - storage schema
   - node bookkeeping
   - unit tests

2. Change maintenance planning to prioritize reciprocity and hard tiers
   - planner changes
   - node/netmock tests

3. Publish sidecars even with no local content
   - maintenance/publication behavior
   - sidecar-only safety tests

4. Add latency-based scoring
   - score updates from `Download`
   - unit/netmock tests

5. End-to-end Docker coverage and docs
   - Docker itests
   - README and `docs/peer-storage-flow.md`

## Feedback on the idea

The direction is good. It tightens the project around its core value:
reciprocal storage, not one-sided freeloading.

The main points that need care are:

1. Score feedback must avoid rewarding spam.
   - If we advertise a new revision every few seconds, the peer should not be
     punished simply because a newer advertisement replaced the older one before
     it had a chance to download.
   - The scoring rule should assess convergence on the latest advertised
     revision, not strict download of every intermediate revision.

2. Sidecar-only publication must stay clearly separate from replica accounting.
   - Otherwise the new privacy-preserving behavior would accidentally hide true
     under-replication.

3. Hard priority should still avoid pathological loops.
   - If there are many stored peers, maintenance may need per-pass caps so it
     does not spend all of its time retrying the same unreachable hard-priority
     set and starve the rest of the peer pool.

4. Availability and download-latency should stay conceptually separate.
   - A peer can be easy to contact but poor at actually fetching updates.
   - That distinction is useful and should be preserved in code and docs.

5. Privacy expectations should stay modest.
   - Publishing sidecars without bytes helps blur "first real data" timing, but
     it does not make that event fully invisible to a long-observing peer.
   - Docs should describe this as reducing signal, not eliminating it.
