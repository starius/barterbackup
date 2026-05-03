# Plan: Metadata-Only Rollup Revisions

## Goal

Persist peer-sidecar progress into the owner's shared content lineage even when
no user files changed, but do it infrequently and with randomized timing so the
resulting publication traffic is harder to correlate to the original metadata
change.

The desired behavior is:

- pure peer-metadata changes still persist immediately in the local encrypted
  peer sidecar as today
- if no file updates happen for long enough, those accumulated metadata changes
  eventually produce a new local content revision and therefore a new
  `content_id`
- the delay should be randomized with an exponential distribution whose mean is
  one day
- repeated metadata churn must coalesce into one pending metadata-rollup event
  rather than constantly rescheduling and starving the rollout forever

## Current behavior

What already exists:

- peer metadata changes are persisted immediately into the separate encrypted
  peer sidecar
- those sidecar updates do not immediately rewrite the local shared content
  blob
- the shared content blob includes `storedpb.Metadata.peers`, so peer metadata
  only enters the shared lineage on the next normal content rewrite

What is missing:

- there is no explicit scheduler for metadata-only content rewrites
- so long periods without file updates can leave the shared lineage behind the
  richer local sidecar state indefinitely

## Proposed design

### 1. Track one pending metadata-rollup epoch

Add node-local persisted state that says, in effect:

- peer metadata included in the current shared content revision is stale
- a metadata-only rollup is pending
- here is the scheduled deadline for the next randomized rollup attempt
- here is the content revision that was current when the dirty epoch started

Recommended persisted fields:

- `metadata_rollup_due_at`
- `metadata_rollup_due_at_ns`
- `metadata_rollup_base_content_id`

Why persist it:

- a crash or restart should not lose the pending randomized rollout
- the user specifically wants this progress to survive long idle periods

### 2. Dirty the rollup state on peer-metadata changes

Whenever one of these changes actually mutates peer state:

- latest known / latest cached peer content
- requester latest stored / latest known view
- pins-us claim
- score updates
- verification state
- advertisement / download-latency bookkeeping
- reachability / counters / first-seen changes, if we decide those belong in
  the shared lineage too

then:

- continue persisting the peer sidecar immediately
- also mark metadata-rollup state dirty for content inclusion

But only schedule a new due time when there is no pending rollup already.

This avoids starvation from repeated metadata churn.

### 3. Sample one exponential delay with mean one day

When a dirty epoch begins and there is no existing pending deadline:

- sample one delay from an exponential distribution with mean `86400s`
- set `metadata_rollup_due_at = now + sampled_delay`

Important detail:

- do not resample on every metadata update
- only sample when transitioning from “no pending rollup” to “pending rollup”

This preserves the intended privacy property while ensuring eventual rollout.

### 4. File updates supersede the pending metadata rollup

A real file/content rewrite already folds current peer metadata into the shared
content blob.

So after any successful file-driven content rewrite:

- clear pending metadata-rollup state
- clear the dirty-for-content flag
- because the shared lineage is now up to date again

### 5. Maintenance loop executes overdue rollups

Extend background maintenance so that each pass checks:

- is a metadata-only rollup pending?
- is it due yet?
- has the current content revision stayed the same as the recorded
  `metadata_rollup_base_content_id`?

If yes:

- rewrite the current content blob using the same files and the latest peer
  metadata
- produce a new local revision / new `content_id`
- clear pending rollup state on success
- wake normal publication maintenance so the new revision can propagate

If the base content changed already:

- clear the pending rollup state without doing a separate rollup
- because a real content rewrite already superseded it

### 6. Keep recovery and empty-content semantics clear

Case A: there is current local content

- metadata-only rollup can rewrite that content with identical files and newer
  peer metadata

Case B: there is no current local content

- do not synthesize a content revision from metadata alone
- keep only the sidecar persistence behavior
- this avoids creating an owner revision with no user files just to carry peer
  metadata

That means metadata-only rollups apply only when a current local content blob
already exists.

### 7. Random source and determinism

Implementation needs two modes:

- production: random exponential sampling from a secure or acceptable runtime
  RNG
- tests: deterministic injection or overridable sampler

Recommended approach:

- hide sampling behind a small helper trait or function seam
- unit tests can provide fixed sampled delays
- integration tests can use the manual clock plus a deterministic sampled
  deadline

## Storage and wire impact

### Persisted state

Likely place:

- `storedpb.Metadata`
- mirrored in `crates/storage::Store`

Add fields for:

- pending metadata-rollup due time
- the base content id for the dirty epoch

### No peer RPC changes

This is local scheduling only.

- no `bbrpc` changes needed
- no `clirpc` changes strictly required unless we want operator visibility

## Optional CLI/state visibility

Not required for core correctness, but useful:

- `bbcli state` could show whether a metadata rollup is pending
- and when the next randomized eligibility time is due

If exposed, phrase it as operator-facing status, not raw implementation jargon.

## Failure handling

If a metadata-only rollup attempt fails:

- keep the pending state
- retry on later maintenance passes
- do not resample a new deadline

This preserves eventual rollout without introducing more timing side channels.

## Tests

### Unit tests: storage

Add coverage for:

- scheduling metadata-rollup state only on first dirty transition
- repeated peer metadata mutations not resampling an existing pending deadline
- successful file/content rewrite clearing pending rollup state
- metadata-only rollup state surviving reload from disk

### Unit tests: node

Add coverage for:

- due metadata-only rollup rewriting local content when files are unchanged
- overdue rollup skipped and cleared when a normal file update already changed
  the current content id
- no rollup when there is no current local content
- failed rollup attempt retaining pending state for retry

### Unit tests: timing/privacy behavior

Add coverage for:

- deterministic injected exponential sample is honored
- only one sampled deadline per dirty epoch
- subsequent metadata changes coalesce into the same pending rollup

### Daemon tests

Add maintenance-loop coverage with `ManualClock` for:

- pending rollup not firing before the sampled due time
- firing once when due
- publication wake-up after a successful metadata-only rewrite

### Docker integration tests

Main scenario:

- establish peers and some shared content
- mutate peer metadata without changing user files
- advance manual clock beyond the sampled due time
- assert the owner gets a new content revision / publication driven only by the
  metadata rollup

Dangerous edge case:

- metadata becomes dirty
- then user updates files before due time
- assert only the real file rewrite happens and the pending metadata-only
  rollup is cleared rather than causing an extra redundant rewrite later

## README impact

Document that:

- peer metadata is persisted immediately in the local sidecar
- when files stay unchanged for a long time, the node may occasionally emit a
  metadata-only content revision
- the timing is randomized with roughly one-day average delay
- this is intentional so peer-state progress is eventually checkpointed into
  the recoverable shared lineage without making the timing easy to correlate

## Suggested commit split

1. Persist metadata-rollup scheduling state in storage
- proto/storage changes
- unit tests for persistence and dirty-epoch scheduling

2. Execute overdue metadata-only rollups in node/daemon maintenance
- maintenance logic
- node/daemon tests with manual clock

3. Document and optionally surface rollup status
- README
- optional `bbcli state` output if added
- Docker integration coverage

## Main risk to watch

The biggest correctness risk is accidentally turning frequent peer-state churn
into frequent content-id churn.

The implementation must preserve these invariants:

- no immediate rewrite on ordinary peer metadata changes
- no repeated resampling while one deadline is pending
- one real file rewrite clears the pending metadata-only rollup
- no synthetic content revisions when the owner currently has no files
