# Plan: Use Remote-View Scores for Durability and Show Both Score Directions

## Problem statement

The current durability forecast and peer-list score display mix two different
quantities:

1. `their_remaining_seconds`
   - the peer's score from our perspective
   - this answers: "how long do we still owe storage to them?"

2. `our_remaining_seconds`
   - our score from the peer's perspective
   - this answers: "how long does that peer still owe storage to us?"

The durability forecast for our own data must use the second quantity, not the
first one.

There is also a correctness bug around negative scores:

- a peer whose score for our data is already negative should be treated as
  already best-effort
- it should not appear in the forecast as:
  - "at least 1 replica will remain under storage obligation until ... (in 0
    seconds)"

That wording comes from clamping negative values to `0`, which preserves the
replica in the horizon model for one artificial threshold point instead of
treating it as already expired.

Finally, `bbcli peer list` only shows one score column today, even though the
system already distinguishes the two directions logically.

## Goals

1. Durability forecasting for our data must use the peer's view of our storage
   obligation.
2. A negative remote-view score must mean "already best-effort now", not "best
   effort in 0 seconds".
3. `bbcli peer list` must show both score directions explicitly.
4. Keep the wire/API meaning clear:
   - `our score there`
   - `their score here`
5. Preserve `bbcli` local responsiveness where possible; do not make `peer
   list` depend on live probing if a persisted value is enough.

## Current code paths

### Local state durability summary

In `crates/node/src/lib.rs`, `StateLocalSummary.durability` currently derives
`predicted_replica_horizon` from tracked peer sidecar state using:

- `peer.requester_latest_stored_content`
- `peer.reachability`
- `peer.score_seconds.max(0)`

That is wrong for our durability because `peer.score_seconds` is our local
score for the peer, not the peer's score for us.

### Live peer-storage view

`GetPeerStorageResponse` already computes per-peer:

- `our_remaining_seconds`
- `their_remaining_seconds`

and `replica_horizon()` already uses `our_remaining_seconds`, which is the
correct direction for our durability.

However it still clamps with `.max(0)`, which causes the "in 0 seconds" bug.

### bbcli peer list

`bbcli peer list` currently renders one `SCORE` column using `peer.score_seconds`
from `PeerInfo`, which is only the local-perspective score.

## Desired semantics

### 1. Treat negative remote-view scores as already expired

For durability of our data:

- `our_remaining_seconds < 0` means that replica is already best-effort
- it must not count as a fresh obligated replica now
- it must not produce a future threshold point at `0 seconds`

Recommended horizon semantics:

- `None`
  - pinned / indefinite obligation
- `Some(positive_seconds)`
  - obligation expires in the future
- `Some(0)`
  - obligation expires exactly now only if the true score is exactly zero
- `ExpiredNow`
  - negative score, already outside obligation

Implementation detail:

- do not model negative scores by clamping to `0`
- instead filter them out of the "fresh obligated replicas now" set and track
  them as already expired

### 2. Use the remote-view score for our durability

For any summary about our data surviving on other peers, use:

- the peer's score for us
- not our score for them

This affects:

- `bbcli state` offline durability sentences
- any daemon-side `predicted_fresh_replicas_now`
- any daemon-side `predicted_replica_horizon`
- any related local summary counts that currently assume "peer stores our bytes"
  implies "peer is still obligated"

### 3. Show both score directions in peer list

Add two columns to `bbcli peer list`:

- `OUR SCORE THERE`
  - how long that peer still owes storage to us
  - source: persisted remote-view score
- `THEIR SCORE HERE`
  - how long we still owe storage to that peer
  - source: existing local `score_seconds`

Recommended wording is explicit rather than abbreviated, because score
direction is otherwise easy to misread.

The old single `SCORE` column should be removed once both directional columns
exist.

## Data-model changes

### 4. Persist the peer's latest score for our data

To keep `bbcli peer list` local-only and to let `bbcli state` use local summary
without live probing, persist the latest observed remote-view score in peer
sidecar metadata.

Add fields to persisted peer state, for example:

- `requester_remaining_seconds`
  - latest observed score from the peer's perspective for our data
- `requester_remaining_seconds_observed_at`
  - when we last observed that remote score

These should be updated whenever we receive `GetContentRevisionResponse`, since
that response already carries `requester_remaining_seconds`.

Likely storage/model touch points:

- `storedpb.Peer`
- storage setters/getters
- `Node::record_requester_revision_observation(...)`
- local peer inventory snapshot
- `PeerInfo` / local RPC surface

### 5. Keep the local score separately

Do not rename away the existing local score semantics. They are still needed
for:

- our obligation to the peer
- local storage protection class
- peer selection / eviction / maintenance logic

The cleanup is about using the right score in the right place, not merging the
two concepts.

## Algorithm changes

### 6. Fix local durability summary

Rework the daemon-side local durability summary so it does not use
`peer.score_seconds` for our data durability.

Recommended behavior:

- only count peers that:
  - are online
  - most recently stored our current content id
  - have a known remote-view score for us
  - and that remote-view score is `>= 0`
- use those remote-view scores to build `predicted_fresh_replicas_now`
- use those same remote-view scores to build `predicted_replica_horizon`

If the remote-view score is missing:

- conservative option: do not count that peer as an obligated fresh replica in
  the forecast
- still show the peer in `peer list`, but display the missing remote-view score
  as `unknown`

This is stricter and avoids overstating durability.

### 7. Fix replica horizon builder semantics

Update `replica_horizon_points(...)` or its call sites so negative expiries are
not converted into a threshold at `0`.

Two acceptable designs:

1. Filter negative expiries before calling `replica_horizon_points(...)`
2. Extend the helper so it treats negative values as already expired and
   excludes them from `remaining_fresh_replicas` from the start

Recommendation:

- filter at the call sites where semantic direction is already known
- keep `replica_horizon_points(...)` operating on "future or indefinite"
  expiries only

That keeps the helper simple and makes the "already best-effort" decision
explicit in the caller.

### 8. Align storage-info horizon with the same semantics

`storage_info().replica_horizon()` already uses `our_remaining_seconds`, which
is the right direction, but it still clamps with `.max(0)`.

Change it to:

- treat negative `our_remaining_seconds` as already expired
- exclude those peers from the live fresh-obligation horizon

That keeps `bbcli config get` and `bbcli state` consistent.

## CLI changes

### 9. Extend peer list columns

Replace:

- `SCORE`

with:

- `OUR SCORE THERE`
- `THEIR SCORE HERE`

Formatting:

- use the same human-readable duration formatter already used elsewhere
- allow:
  - positive values
  - negative values
  - `unknown` when remote-view score has never been observed

### 10. Sorting

Do not sort by the new remote-view score in this slice unless a clear benefit
emerges.

Keep the current relationship-first peer sorting from the earlier peer-list
cleanup, unless this change reveals a strong need to use remote-view score as a
secondary sort key.

## Testing

### Node/unit tests

Add or update tests for:

1. local durability summary uses remote-view score, not local `score_seconds`
2. negative remote-view score is treated as already best-effort
3. exactly-zero remote-view score yields expiry at `0 seconds` only when that is
   the actual score
4. missing remote-view score does not inflate `predicted_fresh_replicas_now`
5. `record_requester_revision_observation(...)` persists remote-view score and
   its observation time

### bbcli tests

Add or update tests for:

1. `bbcli peer list` renders both score columns
2. remote-view score shows `unknown` when absent
3. negative durations humanize correctly in both score columns
4. `bbcli state` no longer renders "at least 1 replica ... in 0 seconds" when
   the only candidate is already negative

### Integration/manual verification

Exercise this sequence:

1. create a peer relationship where:
   - peer stores our current content
   - peer's score for us becomes negative
2. verify:
   - `bbcli state` treats that replica as already best-effort
   - `predicted_fresh_replicas_now` excludes it
   - no sentence claims it remains obligated "in 0 seconds"
3. compare peer list columns:
   - `OUR SCORE THERE`
   - `THEIR SCORE HERE`
   and confirm they differ as expected

## Commit split

### Commit 1: Persist remote-view score observations

Changes:

- add persisted peer fields for latest observed `requester_remaining_seconds`
- update requester-revision observation path to persist them
- extend local peer inventory / peer RPC fields if needed

Validation:

- targeted storage/node tests for persistence and observation updates

### Commit 2: Fix durability summaries to use remote-view scores

Changes:

- rework local durability summary to use remote-view score
- treat negative remote-view scores as already expired
- fix storage-info replica horizon to match

Validation:

- targeted node tests for horizon/count semantics
- focused `bbcli state` rendering test

### Commit 3: Add both score directions to bbcli peer list

Changes:

- replace the single `SCORE` column with two explicit score columns
- render `unknown` for missing remote-view score
- update tests and docs if needed

Validation:

- targeted `bbcli` tests for table output

## Non-goals

- changing peer score update mechanics themselves
- changing storage protection classification rules
- making `bbcli peer list` depend on live peer probing
- redesigning the full durability UI wording beyond correcting the incorrect
  best-effort semantics

## Open questions

1. Should a peer with unknown remote-view score count as a fresh replica?
   Recommendation:
   - no, be conservative

2. Should `OUR SCORE THERE` / `THEIR SCORE HERE` be shortened further?
   Recommendation:
   - keep them explicit first; optimize width only after seeing the table with
     real data
