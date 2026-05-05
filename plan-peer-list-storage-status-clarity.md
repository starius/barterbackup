# Plan: Clarify `bbcli peer list` Storage Status and Freshness

## Problem statement

Current `bbcli peer list` storage labeling is too ambiguous and sometimes wrong
for operator use.

Observed problems:

1. After a peer downloads our data for the first time, `STORAGE` can still show
   effectively "them only" instead of a mutual-storage state.
2. The current wording like `us fresh` and `them only` is not clear.
3. Right after a successful peer `Download`, the peer should not still be shown
   as stale/outdated for our content.
4. After restart-and-recovery with no local modifications, showing `us old` is
   wrong. That state should reflect that the current local revision came from
   recovery, not that the peer has an obsolete copy.

The status column should communicate the storage relationship clearly, while the
per-direction columns already carry the directional byte counts.

## Product goals

1. `STORAGE` must describe the relationship clearly at a glance.
2. Direction-specific details should come from `OURS ON THEM` and `THEIRS ON US`,
   not from overloaded status words.
3. A peer that just downloaded our current content should immediately appear as
   storing our data, without waiting for the next scheduled verification cycle.
4. Freshness should not regress to `old` in cases where the peer copy is still
   the most recent known copy after recovery.

## Proposed semantics

### 1. Replace ambiguous unilateral wording

Replace statuses that currently read like:

- `them only`
- `us fresh`
- `us old`

with a clearer relationship vocabulary.

Recommended relationship states:

- `mutual`
  - both sides currently store data for each other
- `unilateral`
  - only one direction currently stores data
- `recovered`
  - the local current revision came from recovery and should not be described as
    stale merely because it originated elsewhere
- `none`
  - neither direction currently stores data

Alternative:
- keep `mutual`, `unilateral`, `none` as the main relationship states
- attach freshness as a separate qualifier only when needed, for example:
  - `mutual`
  - `mutual old`
  - `unilateral`
  - `recovered`

The recommended direction is:
- keep `STORAGE` relationship-oriented
- avoid encoding direction in that column
- use `OURS ON THEM` and `THEIRS ON US` for direction

## Freshness rules

### 2. Treat completed peer download as immediate proof of current storage

When a peer completes `Download` of our advertised content:

- immediately mark that peer as storing our current content
- immediately treat that state as not stale
- do not wait for the next scheduled verification pass to flip `STORAGE`

Implementation approach:

- after successful `Download` completion for our advertised current content,
  perform an unplanned local state update equivalent to successful verification
  of the stored revision
- if needed, issue a targeted follow-up verification immediately after the
  download event and update peer state from that verification

Preferred approach:
- update local peer-storage freshness state immediately from the download event
- optionally trigger a verification in the background for extra confirmation
- but do not leave the UI showing stale state in the meantime

Reasoning:
- the peer just fetched the exact advertised content id from us
- showing it as stale until a later verification is misleading

### 3. Preserve freshness after recovery when no local modifications happened

If the local current revision was obtained by recovery and no subsequent local
file changes happened:

- do not label the peer copy as `old` solely because the revision lineage came
  from recovery
- show `recovered` in `STORAGE` instead, or otherwise treat it as current

Operational meaning:
- `old` should mean the peer copy is behind the local current revision
- it should not mean "this revision was produced by recovery"

So the freshness decision should compare:
- the peer's known stored content id for us
- the local current content id
- and whether the current local content is a recovered current revision without
  later local edits

## Data-model changes

### 4. Distinguish relationship from freshness in the bbcli formatting layer

Keep wire format unchanged unless strictly necessary.

Prefer to compute display states in `bbcli` from existing fields if possible.

If the current RPC payload is insufficient, add minimal explicit fields to peer
inventory/state, such as:

- whether the peer is known to store our current content
- whether that knowledge came from:
  - explicit verification
  - observed download of advertised content
  - recovered-current local lineage

But first try to derive from existing state:

- `our_stored_content_bytes`
- `our_content_synced`
- requester advertised/download-tracking fields
- latest recovered content id / latest local content id

### 5. Separate display classification from maintenance scoring

This slice should only change display correctness and immediate local tracking.

Do not mix it with:
- replica scoring changes
- maintenance target logic
- peer selection logic

Unless the download-completion freshness update already uses a shared state path
that naturally feeds the maintenance layer too.

## Implementation steps

### Commit 1: Make peer-download completion update current-storage freshness

Changes:
- when a peer downloads our advertised content id, immediately update peer state
  so it is considered to store our current content
- ensure `bbcli peer list` no longer shows that peer as stale until the next
  planned verification
- add focused tests around the download-completion path

Validation:
- node tests for requester-advertisement/download state
- `bbcli` rendering test showing post-download state as current

### Commit 2: Rework `STORAGE` labels to relationship-oriented wording

Changes:
- replace ambiguous statuses like `them only` and `us fresh`
- use relationship-centric labels such as:
  - `mutual`
  - `unilateral`
  - `none`
- keep direction discoverable through `OURS ON THEM` and `THEIRS ON US`

Validation:
- `bbcli` peer-list formatting tests for all relationship cases
- update docs/screenshots if any exist

### Commit 3: Add `recovered` handling for recovered-current local state

Changes:
- detect when the current local revision is recovered and has not been superseded
  by later local edits
- show `recovered` rather than `old` in that case
- ensure restart/recovery scenarios render correctly

Validation:
- node/daemon tests for recovered-current state after restart
- `bbcli` rendering test for recovered status

## Testing

### Node tests

Add or update tests for:

- peer download of our advertised current content immediately marks current
  storage state
- no stale status window after successful download
- recovered current revision with no later local edits does not render as `old`

### bbcli tests

Cover rendering for:

- `mutual`
- `unilateral` with only `OURS ON THEM`
- `unilateral` with only `THEIRS ON US`
- `none`
- `recovered`

Also verify that:
- direction is still obvious from the byte columns
- color treatment remains sensible for fresh vs stale vs none

### Manual verification

Exercise these sequences manually:

1. fresh node publishes to a peer, peer downloads, `bbcli peer list` flips to
   mutual/current immediately
2. unilateral mirrored-peer-only case shows `unilateral`
3. restart, recover files from peer, no local edits, `bbcli peer list` shows
   `recovered` rather than `old`

## Non-goals

- redesigning the whole peer-list table again
- changing wire format unless required
- changing replica scoring or peer selection behavior
- changing the meaning of `OURS ON THEM` / `THEIRS ON US`

## Follow-up questions to resolve during implementation

1. Should `recovered` replace `mutual`/`unilateral`, or be a qualifier layered on
   top of them?
   Recommendation:
   - start with `recovered` as a top-level `STORAGE` label for the local-current
     recovered case, because that directly addresses the operator confusion.

2. Should immediate post-download freshness rely purely on the download event,
   or also trigger an opportunistic verification?
   Recommendation:
   - update display state immediately from the download event
   - optional opportunistic verification can be added if cheap, but the UI must
     not wait for it.
