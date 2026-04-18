# Daemon-Wide Internal Clock Plan

## Goal

Rework time in `bbd` so application logic depends on one internal clock API,
not on direct `tokio::time::*` calls.

This clock API is separate from `clirpc`.

- Inside the binary, code uses a clock interface.
- Outside the binary, hidden `clirpc` methods control the test clock when it
  is enabled.
- Arti, the OS, Docker, and Chutney continue to run on real time.

The target outcome is:

- all app-level scheduling in `bbd` uses the injected clock;
- all nodes in an integration test can see the same programmed logical time;
- the harness can observe when a labeled timer starts waiting;
- real transport deadlines remain real unless we explicitly decide otherwise.

## Non-goals

This change should not try to virtualize everything.

Out of scope for this phase:

- Arti bootstrap timing;
- Tor circuit timing;
- kernel socket timing;
- gRPC transport deadlines for real network operations;
- replacing Docker/Chutney with another system.

The immediate focus is application logic inside `bbd`.

## Design principles

1. Separate internal clock API from control RPC.
- The binary should not know or care whether time is being driven through
  `clirpc`.
- `clirpc` is only one hidden control surface for tests.

2. Keep real network time real.
- `tokio::time::timeout` around actual peer RPCs should stay on wall clock.
- This avoids unrealistic immediate timeouts or retry storms when logical time
  advances faster than Arti can actually do network work.

3. Make timer behavior observable.
- Tests and harnesses need to know when the daemon started waiting on a
  specific logical timer.
- This is what `timer_intercept(label)` is for.

4. Keep labels stable and explicit.
- Timer labels should be centrally defined constants or an enum converted to
  stable strings.
- Avoid ad hoc literal strings scattered across the code.

5. Keep the default behavior unchanged.
- Without the hidden test-clock flag, the regular clock implementation should
  behave like the current daemon: real `now()` and real waiting.

## Internal clock API

Extend `crates/clock` from a pure timestamp provider into a scheduling
interface.

Recommended shape:

```rust
#[async_trait]
pub trait AppClock: Send + Sync {
    fn now(&self) -> Timestamp;
    async fn wait_for(&self, duration: Duration, label: &'static str);
}
```

Notes:

- `now()` remains the current logical timestamp.
- `wait_for(duration, label)` is the only app-level wait primitive.
- The label is required.
- The trait should be internal-clock focused and not mention `clirpc`.

If needed, keep the old `Clock` trait name and extend it, but the code should
end up with one clock abstraction, not parallel overlapping traits.

## Regular clock implementation

Add a regular implementation that preserves current behavior.

Behavior:

- `now()` reads system time;
- `wait_for(duration, label)` performs a real async wait using the current
  Tokio-based mechanism.

The label is ignored for behavior, but it should still be accepted so code does
not branch by clock type.

This is the default when the hidden test-clock mode is not enabled.

## Test clock implementation

Add a manual async clock implementation with four responsibilities.

1. Current logical time
- store current `Timestamp`;
- support `now()`, `set()`, and `advance()`.

2. Pending waits
- every `wait_for(duration, label)` computes an absolute deadline from the
  current logical time;
- if the deadline is already reached, return immediately;
- otherwise register a waiter and suspend until logical time reaches that
  deadline.

3. Timer intercept events
- every `wait_for(duration, label)` emits one intercept event;
- events are queued per label in FIFO order;
- `timer_intercept(label)` streams queued events in FIFO order and blocks until
  the next one arrives when the stream is empty.

4. Wakeup on time advance
- `advance(duration)` wakes all waits whose deadline is now satisfied;
- `set(timestamp)` also re-evaluates all waits against the new time.

## Test clock semantics

These semantics should be fixed and tested explicitly.

### Wait registration

When `wait_for(duration, label)` is called:

1. record one intercept event for `label`;
2. compute `deadline = now + duration`;
3. if `deadline <= current_time`, return immediately;
4. otherwise block until current logical time reaches `deadline`.

### Intercept semantics

`timer_intercept(label)` should be a hidden streaming RPC.

Behavior:

- when the stream starts, emit all already-queued events for `label` in FIFO
  order;
- once the queue is empty, keep the stream open and wait for future
  `wait_for(..., label)` calls;
- each event should return at least:
  - the label,
  - the requested duration,
  - the current logical time when the wait was registered.

That last field is not strictly required by your logical sketch, but it will be
useful for debugging and assertions.

Reason for streaming:

- a unary long-poll shape can miss events that arrive between successive RPCs;
- a stream gives one continuous observation window for a label;
- it is a better fit for tests and harness code that expect multiple waits on
  the same label over time.

### Time movement

`advance(duration)` is always allowed.

`set_time(timestamp)` needs one explicit rule. Recommended rule:

- allow arbitrary set for the hidden test mode;
- existing pending waits keep their already-computed absolute deadlines;
- after the set, any wait whose deadline is now satisfied wakes immediately.

This is deterministic and simple. It should be documented and tested.

## Stable timer labels

Define a central label set for daemon app logic, for example in `cmd/bbd` or a
small clock-label module.

Initial labels should cover at least:

- `maintenance.interval`
- `peer-runtime.restart-backoff`
- `self-check.interval`
- `background.failure.backoff`
- `daemon.shutdown.timeout` only if we choose to virtualize it

Keep labels as stable strings because the harness and tests will reference
exact names.

## What should move to the internal clock

Move all app-level waiting in `bbd` to `wait_for(duration, label)`.

This should include:

1. maintenance loop cadence
- current `tokio::time::interval(config.interval)`

2. peer-runtime restart backoff
- current `tokio::time::sleep(restart_delay)` in the runtime supervisor

3. self-check cadence
- current `tokio::time::interval(supervisor_timings.self_check_interval)`

4. background peer failure retry scheduling
- current logic uses `Instant::now()` and backoff comparisons
- convert this state to logical timestamps from the clock

5. daemon uptime
- already moved to the injected logical clock;
- keep this under the same unified API.

6. any future deferred metadata flush batching
- this belongs on the internal clock once implemented.

## What should stay on real time

Do not move these in the first phase:

1. peer connect timeout
2. peer RPC timeout
3. retry sleeps inside the node peer-RPC retry helper
4. server shutdown hard timeout around task joins
5. test harness host-side timeouts

Reason:

- these protect real network and process behavior;
- Arti and gRPC still run on wall clock;
- mixing them with synthetic app time would produce unrealistic failures.

## Hidden `clirpc` control surface

Keep the hidden `clirpc` methods as the external control plane, but treat them
as adapters over the internal clock API.

Target hidden methods:

- `GetTestTime`
- `SetTestTime`
- `AdvanceTestTime`
- `TimerIntercept`

Rules:

- available only when the hidden `--test-clock` flag is enabled;
- hidden from normal help output and normal docs;
- return `Unimplemented` when test-clock mode is disabled.

## `TimerIntercept` RPC design

Recommended protobuf shape:

```text
rpc TimerIntercept(TimerInterceptRequest)
    returns (stream TimerInterceptEvent)
```

Request:

- `label`

Each streamed event should contain:

- `label`
- `wait_seconds`
- `wait_nanoseconds`
- `registered_unix_seconds`
- `registered_nanoseconds`

The stream should:

- flush already-queued events first;
- then stay open and deliver future matching events;
- terminate only when the RPC is cancelled or the daemon stops.

## Code migration plan

### Phase 1: clock crate expansion

1. extend `crates/clock` with async waiting support;
2. add a regular async clock implementation;
3. add a manual async clock implementation with:
   - current time,
   - wait registry,
   - intercept queues,
   - `set` and `advance`;
4. add unit tests for:
   - immediate waits,
   - delayed waits,
   - multiple waits with same label,
   - stream starts before wait,
   - stream starts after queued waits already exist,
   - multiple events on one open stream,
   - advance waking multiple waiters,
   - set-time behavior.

### Phase 2: daemon wiring

1. replace the daemon's partial timestamp-only clock use with the new internal
   clock type;
2. store one shared clock in `DaemonService`;
3. keep hidden `--test-clock` as the switch between regular and manual clock;
4. make unlock pass the same clock into the node/store path.

### Phase 3: `clirpc` control surface

1. add `TimerIntercept` to `clirpc`;
2. rework `Get/Set/AdvanceTestTime` to call the new internal clock, not direct
   manual-clock fields on the daemon;
3. add daemon tests for:
   - disabled mode,
   - enabled mode,
   - intercept stream blocking and delivery,
   - already-queued events are flushed in order,
   - one open stream receives multiple future events,
   - label mismatch behavior.

### Phase 4: `bbd` scheduling migration

Move app waits one slice at a time.

Slice order:

1. maintenance loop schedule;
2. self-check schedule;
3. peer-runtime restart backoff;
4. background failure backoff state from `Instant` to logical timestamps.

After each slice:

- update daemon tests;
- add targeted clock-driven tests;
- rerun formatting and targeted remote validation.

### Phase 5: flaky test cleanup

Use the new clock and labeled waits to replace the most timing-sensitive parts
of:

- `app::tests::manual_maintenance_tick_refreshes_restarted_peer`

Goal:

- no wall-clock polling loops for deterministic maintenance behavior;
- direct advancement of logical time where appropriate;
- intercept support to assert that the expected timer was actually armed.

### Phase 6: harness integration

Extend the Go Docker harness with helpers for:

- `GetTestTime`
- `SetTestTime`
- `AdvanceTestTime`
- `TimerIntercept`

Initial harness use cases:

1. advance all nodes to the same logical time;
2. wait for a specific daemon timer to be armed before advancing;
3. assert score and maintenance behavior over long synthetic intervals.

## Test strategy

### Clock crate tests

Need deep unit coverage for:

- single waiter wakeup;
- many waiters at different deadlines;
- many waiters on the same label;
- intercept order;
- intercept after event already queued;
- set backward, set forward, and advance behavior.

### Daemon tests

Need focused daemon tests for:

- hidden mode gating;
- intercept event delivery for maintenance timers;
- advancing time wakes maintenance without real sleep;
- restart backoff uses the internal clock;
- self-check cadence uses the internal clock.

### Integration tests

Once the harness support exists, add at least one Docker/Chutney scenario that:

1. enables `--test-clock` on all nodes;
2. waits for a labeled maintenance timer via `TimerIntercept`;
3. advances all nodes together;
4. verifies maintenance or scoring progressed without real waiting.

## Commit plan

Keep this work split into atomic commits.

Recommended commit sequence:

1. extend `crates/clock` with async waits and intercept support
2. add hidden `clirpc TimerIntercept` and daemon plumbing
3. migrate maintenance loop to internal clock waits
4. migrate self-check schedule to internal clock waits
5. migrate peer-runtime restart backoff to internal clock waits
6. migrate background failure timing from `Instant` to logical timestamps
7. fix the flaky manual-maintenance daemon test using the new clock
8. add Go harness support for time control and one first integration test

## Risks and mitigations

### Risk: mixing logical and real time incorrectly

Mitigation:

- explicitly keep network deadlines on wall clock;
- only migrate app-level scheduling in this phase.

### Risk: hidden timer labels become unstable

Mitigation:

- define labels centrally;
- test exact label names.

### Risk: `set_time` semantics become surprising

Mitigation:

- document the absolute-deadline rule clearly;
- test backward and forward sets explicitly.

### Risk: intercept streams leak events or lose ordering

Mitigation:

- use FIFO per-label queues;
- test repeated event delivery on one open stream;
- test stream startup after events are already queued;
- ensure cancelled waiters still have deterministic event behavior.

## Expected outcome

After this work:

- `bbd` app logic no longer depends directly on `tokio::time::*` for its own
  scheduling decisions;
- hidden `clirpc` time control becomes a thin adapter over the internal clock;
- the harness can coordinate multiple nodes at the same logical time;
- the current Chutney-based network tests can stay as they are while gaining
  synthetic time control for long-horizon scenarios.
