# Plan: Adaptive Peer Verification Cadence

## Goal

Reduce unnecessary repeated peer-storage verifications while keeping faster
feedback when a peer's verification result changes.

The new per-peer rule is:

- if the verification result changes, reset expected delay to `5 minutes`
- otherwise multiply expected delay by `1.5x`
- cap expected delay at `6 hours`
- schedule the next verification using an exponential random delay with that
  expected delay as the mean
- keep this delay state in memory only; do not persist it

## Current Behavior

Today background verification cadence is effectively driven by the daemon's
regular maintenance loop plus failure backoff in `cmd/bbd/src/app.rs`.

Relevant pieces:

- `node::BackgroundMaintenancePeerAction { propose, check }` in
  `crates/node/src/lib.rs`
- `run_background_peer_maintenance(...)` in `cmd/bbd/src/app.rs`
- `BackgroundPeerFailures` / `next_retry_at` in `cmd/bbd/src/app.rs`

That means:

- successful verification can run every maintenance pass
- only failures get spacing from the explicit retry/backoff machinery
- there is no separate success-side cadence memory for verification

## Proposed Design

### 1. Add in-memory verification cadence state in `bbd`

Add one daemon-local map keyed by peer onion, separate from persisted peer
metadata and separate from failure backoff.

Suggested fields per peer:

- `last_result: Option<bool>`
- `expected_delay: Duration`
- `next_check_at: Timestamp`

Meaning:

- `last_result` is the previous verification outcome for adaptive comparison
- `expected_delay` is the current mean delay used for the next exponential draw
- `next_check_at` is the sampled next eligible verification time

This state should live next to the other background-maintenance runtime state in
`cmd/bbd/src/app.rs`, not in `node` or `storage`.

### 2. Gate background verification by that state

Before running `node.verify_peer_storage_updates(&peer_onion)` in background
maintenance, consult the in-memory cadence state.

Rules:

- if no cadence state exists yet for the peer, verification is due now
- if `now < next_check_at`, skip the background verification for that peer
- publication logic is unaffected by this gate
- explicit user-triggered verification (`bbcli peer check`) is unaffected by
  this gate

This means the cadence applies only to autonomous background verification.

### 3. Update cadence after each completed verification attempt

Only update this state when a verification attempt actually produces a final
boolean outcome:

- `true` for success
- `false` for a verification failure outcome

Treat these as result changes:

- first observed result for that peer
- `true -> false`
- `false -> true`

On change:

- set `expected_delay = 5 minutes`

Without change:

- set `expected_delay = min(expected_delay * 1.5, 6 hours)`

Then sample:

- `next_delay ~ Exponential(mean = expected_delay)`
- `next_check_at = now + next_delay`

### 4. Keep transport-failure retry logic separate

Do not replace the existing `BackgroundPeerFailures` machinery.

The two controls should coexist:

- failure backoff still prevents hammering peers after transport/protocol
  failures
- adaptive verification cadence spaces successful or stable-result checks

Effective verification eligibility becomes:

- background failure backoff must allow the peer
- adaptive verification cadence must also allow the peer

### 5. Define what counts as a verification result

Use the final verification outcome from `node.verify_peer_storage_updates(...)`.

Recommended mapping:

- completed and peer content verified: `true`
- peer missing our content: `false`
- peer returned invalid content: `false`
- retry-exhausted transport/unavailable case: `false`

Reason:

- your rule is about whether the observable verification result changed
- from an operator perspective, transport failure is also a failed check result
- keeping it boolean keeps the cadence simple and matches your requested rule

### 6. Random source

Use the existing Rust RNG already available in the daemon/runtime dependencies.

Keep the exponential sampling implementation local and small.

Implementation note:

- for mean `m`, sample `u` uniformly from `(0,1]`
- use `delay = -m * ln(u)`

Clamp any pathological edge cases so:

- zero or negative durations are never scheduled
- a minimum positive delay is enforced if needed

### 7. Reset behavior

Because this state is in-memory only:

- daemon restart forgets it
- all peers become immediately eligible again

That matches your requirement and should be documented as expected behavior.

## Impact

### Behavior

- stable peers will be checked much less often over time
- recently changed peers will be checked quickly again
- peers that flap between success and failure will stay near the `5 minute`
  mean
- background maintenance logs should get less noisy for stable peers

### Persistence

- no proto changes
- no store changes
- no wire-format changes

### CLI

No CLI changes are strictly required.

Optional later improvement:

- expose the in-memory next verification time in `bbcli state` or `peer list`

Not required for this refactor.

## Tests

### Unit tests in `cmd/bbd`

Add deterministic tests around the new cadence state:

1. first verification result schedules next check from `5 minutes`
2. unchanged `true` result multiplies mean by `1.5x`
3. unchanged `false` result multiplies mean by `1.5x`
4. changed `true -> false` resets to `5 minutes`
5. changed `false -> true` resets to `5 minutes`
6. cap stops growth above `6 hours`
7. `next_check_at` gate suppresses background verification before due time
8. due verification runs once the sampled deadline passes
9. cadence state is not persisted across daemon restart

Use `clock::ManualClock` and a deterministic RNG injection or seeded RNG helper
so the sampled delays are testable.

### Integration-style daemon tests in `cmd/bbd`

Add tests around the maintenance loop:

1. stable verified peer is not rechecked every maintenance interval
2. after a changed result, recheck becomes due again much sooner
3. retry-backoff and cadence both apply without conflicting
4. publication still runs when due even if verification is cadence-suppressed

### Existing `node` tests

No semantic changes should be needed in `crates/node`, because the node API for
verification is unchanged.

Only adjust tests if some current daemon-level expectations assumed verification
runs every pass.

## Commit Split

### Commit 1

Add in-memory adaptive verification cadence machinery in `cmd/bbd` and cover it
with focused daemon unit tests.

### Commit 2

Integrate the cadence gate into background maintenance and update any daemon
maintenance tests that assumed every-pass verification.

## Risks / Things To Watch

### 1. Randomized tests can become flaky

Inject deterministic randomness for tests. Do not rely on ambient RNG in test
assertions.

### 2. Interaction with failure backoff

Be explicit that the later of:

- background retry allowance
- verification cadence allowance

wins for the next background verification attempt.

### 3. Immediate verification after publication

Decide whether a fresh successful publication should also reset verification
cadence state. Recommended: no special case initially. Let the next background
verification use the existing cadence rule unless a test shows this delays
important confirmation too much.

### 4. Peer reconnects should not reset cadence

Because the state is in-memory per peer and not per connection, reconnecting a
peer during the same daemon lifetime should not force a verification storm.

