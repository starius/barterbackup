# Plan: Exclude local offline periods from peer score accounting

## Problem

Peer score growth and decay currently use elapsed wall-clock time between
verification events. That wrongly attributes time to the remote peer even when
our own node was not in a position to observe it.

Two cases matter:

- our node process was not running
- our node process was running, but its self-check reported the transport as
  offline or unhealthy enough that we could not reliably judge whether peers
  were reachable

During those periods, we do not know whether another peer was up or down. That
elapsed time must not count toward the peer's score.

## Goal

Adjust peer score accounting so that only time during which our node was locally
online and self-reachable can contribute to another peer's score changes.

## Required behavior

When our node becomes able to observe peers again, start a new local observation
window at that moment.

This happens when:

- the daemon starts and the node becomes unlocked and active
- the self-check transitions from offline/unhealthy to healthy

When calculating a peer's next score update:

- use the time since the start of the current local observation window
- do not use time that predates that window, even if the last peer check was
  older

Implication:

- if a peer was last checked before a local offline period, and we verify it
  immediately after coming back online, the score delta should be based on only
  the short time since we became locally observable again, not the whole gap

## Non-goals

- do not redesign the score formula itself
- do not change peer reachability classes or verification cadence policy
- do not persist new long-term historical uptime timelines

## Proposed model

Maintain one in-memory timestamp in `bbd` representing the start of the current
local observation window.

Suggested name:

- `local_observation_started_at`

Meaning:

- the earliest instant from which peer uptime/downtime observations are valid
  for score accounting in the current online epoch

This value should be reset whenever local observability resumes.

## State transitions

### 1. Daemon startup

When the daemon reaches the running/unlocked state and begins maintenance,
initialize:

- `local_observation_started_at = now`

Do not backdate it to process launch or to persisted timestamps from a previous
run.

### 2. Self-check stays healthy

While self-check remains healthy:

- keep the current observation-window start unchanged

### 3. Self-check becomes unhealthy/offline

When self-check transitions from healthy to unhealthy/offline:

- mark local observation as suspended

Implementation options:

1. set a boolean like `local_observation_active = false`
2. or set `local_observation_started_at = None`

Recommendation:

- use `Option<Timestamp>` so the inactive state is explicit

### 4. Self-check becomes healthy again

When self-check transitions from unhealthy/offline back to healthy:

- set `local_observation_started_at = now`

This starts a fresh observation epoch.

## Score-calculation change

Wherever peer score deltas are calculated from elapsed time:

- compute the effective score interval start as:
  - `max(last_peer_score_measurement_time, local_observation_started_at)`
- if local observation is currently inactive, do not credit or penalize elapsed
  time for peer score changes until observation resumes

This applies to both:

- successful verification score increases
- failed verification / recovery-probe score decreases

Rationale:

- if the node was offline between peer observations, neither positive nor
  negative peer conclusions are justified for that unseen interval

## Scope of affected paths

Audit all score-changing paths in `bbd` and `node` integration:

- explicit peer verification success
- explicit peer verification failure
- recovery-probe failure penalties
- any background maintenance path that adjusts `score_seconds`

The implementation should route all elapsed-time-based score updates through the
same effective-window logic so the rule cannot drift across code paths.

## Persistence decision

Do not persist `local_observation_started_at`.

Why:

- the requirement is specifically about excluding periods when this process was
  not observing
- after restart, we should begin a fresh observation epoch at current startup
- persisting the previous value would reintroduce hidden time across downtime

## Interaction with adaptive verification cadence

The adaptive verification cadence already uses in-memory per-peer state. This
change should align with that model:

- cadence may survive only for the current process lifetime
- score eligibility windows should also be process-lifetime local unless reset
  by self-check transitions

No persistence is needed for either.

## Logging

Add `INFO` logs for operator-significant observation-window transitions:

- local observation window started at daemon startup
- local observation window suspended due to unhealthy self-check
- local observation window resumed after self-check recovery

Reason:

- score behavior changes across these transitions
- operators need to understand why a peer score did not jump after a long local
  outage

Keep routine per-verification score logs as they are unless a small field like
`observation_window_seconds` materially helps debugging.

## Tests

### Unit tests

Add deterministic daemon tests with `ManualClock` for:

1. startup window clamp
- peer checked at `t0`
- daemon restarts at `t1000`
- first successful verification at `t1010`
- score increase uses about `10s`, not `1010s`

2. offline self-check clamp
- healthy verification at `t0`
- self-check goes unhealthy at `t100`
- clock advances to `t1000`
- self-check returns healthy at `t1000`
- next verification at `t1015`
- score delta uses about `15s`, not `1015s`

3. failure penalty clamp
- peer had previous score measurement before local outage
- local outage occurs
- after recovery, first failed verification penalizes only the observed online
  interval since recovery

4. no score movement while observation inactive
- while self-check is inactive, maintenance may attempt work or schedule state
  changes
- ensure no elapsed-time-based score adjustment attributes the inactive gap

### Integration-style daemon tests

Use targeted `bbd` tests to simulate:

- self-check flapping healthy -> unhealthy -> healthy
- peer verification and recovery-probe failures across those transitions
- stable score accounting across multiple peers

### Regression coverage

Add at least one test that would have failed under the old behavior by showing a
large jump caused only by local downtime.

## Validation

Before each commit:

- `make fmt`
- targeted `cargo test -p bbd --locked ...`
- targeted `cargo test -p node --locked ...` only if shared score helpers move
  there

Server validation after implementation:

- `cargo build -p bbd -p node --locked`
- targeted `bbd` score-accounting tests
- any affected `node` tests

## Suggested commit split

1. `Track local observation windows for peer score accounting`
- in-memory state and self-check transition handling
- deterministic tests for startup/offline/online transitions

2. `Clamp peer score deltas to observed local uptime`
- apply the window to success and failure score paths
- regression tests for verification and recovery-probe penalties

## Risks

- if some score path bypasses the shared helper, behavior will remain
  inconsistent
- self-check state transitions must be identified precisely; using the wrong
  signal could suppress too much or too little score movement
- rapid self-check flapping may create many short observation windows; tests
  should cover that behavior explicitly

## Recommendation

Implement this as a `bbd`-side in-memory policy first.

Keep the rule simple:

- only count time when we know our own node was locally online and reachable
- clamp every score delta to that observation window

This fixes the accounting error without introducing persisted complexity.
