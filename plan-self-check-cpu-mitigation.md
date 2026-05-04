# Plan: Mitigate High CPU Triggered by Public Self-Check

## Problem statement

Current `bbd` behavior starts a real outbound self-check against the node's own
onion service shortly after the peer runtime reports `ready`.

Under current public Tor conditions, that self-dial often times out:

- `peer_runtime_state: ready`
- `self_peer_check_state: unhealthy`
- `self_peer_check_error: ... "connect peer timed out"`

After that, `bbd` can enter a sustained high-CPU state inside Arti/Tor relay,
guard, and circuit-selection work. The problem reproduces for multiple fresh
identities, so it is not tied to one poisoned onion handle.

The immediate goal is to stop `bbd` from provoking this Arti degraded mode
unnecessarily.

## Observed scope

What the investigation established:

- The trigger is not replica maintenance.
- The trigger is not peer publication.
- `--disable-maintenance` still reproduces the issue.
- The shared factor is the public self-check path.
- The regression mechanism appears as early as the commit that introduced
  self-peer health checks.
- A local Chutney check did not reproduce the same failure, but that path is
  currently blocked by a separate local Arti/Chutney bootstrap issue.

## Product direction

The daemon should treat self-check as a low-priority diagnostic signal, not as a
hot-path transport exercise. It must not continuously stress the public Tor
runtime when the result is only advisory.

## Desired behavior

1. Do not run a self-check immediately when the peer runtime becomes `ready`.
2. Start self-checks only after a substantial initial delay.
3. When self-checks fail repeatedly, back off aggressively.
4. Avoid retry storms against the node's own onion service.
5. Preserve operator visibility in `bbcli state`, but make unknown/deferred
   self-check status acceptable for some time after startup.
6. Keep room for later, more sophisticated reachability logic without locking in
   today's behavior.

## Proposed design

### 1. Defer the first self-check

Replace the immediate first self-check pass with a scheduled delayed pass.

Recommended initial delay:

- default mean: `15 minutes`
- sampled from an exponential distribution

Rationale:

- avoids hammering the transport while the onion service and wider Tor state are
  still settling
- makes the probe timing less fingerprintable than a fixed deadline

During this initial period:

- `self_peer_check_state` stays `unknown`
- this is not considered unhealthy

### 2. Add independent self-check cadence state

Introduce an in-memory self-check schedule that is separate from peer
verification cadence and separate from peer maintenance backoff.

State to track in memory only:

- current mean delay
- next due time
- consecutive failure count
- whether the daemon has ever observed one healthy self-check in this runtime

Do not persist this state.

### 3. Use aggressive failure backoff

When a self-check fails:

- multiply mean delay by `2x`
- cap at `24 hours`
- schedule the next check from an exponential distribution with that mean

When a self-check succeeds:

- reset mean delay to a moderate healthy cadence, for example `6 hours`
- schedule the next pass from that mean

Rationale:

- self-check is diagnostic, not required for core operation
- failure should drastically reduce probe pressure on Arti

### 4. Never restart the peer runtime just because self-check is unhealthy

If any remaining logic still requests runtime restart on self-check failure,
remove that coupling.

Self-check should only:

- update health reporting
- update observation windows if needed
- emit operator logs

It must not be a hard liveness oracle for the transport runtime.

### 5. Do not probe while runtime is not meaningfully usable

Skip or defer self-check while:

- peer runtime is not `ready`
- bootstrap is still incomplete
- the node has just restarted and has not passed the startup delay

Optional later refinement:

- only begin self-check once the daemon has had at least one successful guard
  or peer contact event

### 6. Rate-limit unhealthy transition logging

Avoid repeated high-severity logs for every failed self-check.

Behavior:

- first transition `unknown/healthy -> unhealthy`: `WARN`
- repeated unhealthy failures while already unhealthy: `INFO` or `DEBUG`
- first recovery back to healthy: `INFO`

This keeps the logs informative without amplifying the churn.

### 7. Keep `bbcli state` semantics operator-friendly

`bbcli state` should distinguish:

- `unknown`: self-check deferred / not run yet
- `healthy`: last self-check succeeded
- `unhealthy`: last self-check failed

Possible doc wording:

- `unknown` shortly after startup is expected and not itself a fault.

## Implementation steps

### Commit 1: Decouple self-check from immediate startup

Changes:

- remove the immediate first self-check pass on runtime startup
- add delayed scheduling state for the first probe
- keep status as `unknown` until the first due check runs

Validation:

- deterministic unit tests with `ManualClock`
- verify no self-check occurs before the configured delay

### Commit 2: Add backoff-based self-check cadence

Changes:

- add in-memory mean-delay / due-time / failure-count state
- exponential backoff on failures
- healthy reset cadence on success
- remove any self-check-driven runtime restart coupling

Validation:

- deterministic daemon tests with fixed sampler outputs
- assert failure spacing widens correctly
- assert success resets the cadence

### Commit 3: Logging and operator state cleanup

Changes:

- transition-based logging
- refine `bbcli state` wording/docs for deferred self-check state
- update README or operator docs

Validation:

- `bbcli` tests for wording if applicable
- daemon log-behavior tests where practical

## Tests

### Rust daemon tests

- startup leaves self-check `unknown` until delayed due time
- first self-check is not run immediately after `peer runtime ready`
- repeated failures grow mean delay and next due time
- success resets cadence
- self-check no longer requests runtime restart

### Node/runtime integration tests

Where feasible with mocks:

- a failing self-check transport does not create rapid retry loops
- background maintenance still functions independently of self-check state

### Manual public-network verification

After implementation, rerun the same local public-network repro:

- fresh password / fresh identity
- warmed second run
- compare CPU after runtime-ready over a 15-second sample window

Success criterion:

- CPU no longer spikes immediately after startup due to self-check activity
- `self_peer_check_state` remains `unknown` during the deferred period

## Non-goals for this slice

- fully diagnosing Arti's internal high-CPU behavior
- fixing the upstream Arti issue directly
- redesigning peer runtime readiness semantics globally
- making Chutney reproduce the public-network failure

## Follow-up work

If the delayed/backed-off self-check still triggers Arti badly, the next steps
should be:

1. make self-check opt-in or operator-triggered only
2. derive transport health from real peer traffic instead of self-dials
3. add transport-runtime degradation detection and optional scoped restart
4. prepare an upstream Arti bug report with the minimized trigger pattern
