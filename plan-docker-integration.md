# Docker Integration Test Plan

## Goal

Add a container-based integration test system that exercises the real `bbd`
processes and their `clirpc` interface across multiple nodes, while remaining
fast enough to run regularly and reliable enough to be trusted.

This plan deliberately separates:

1. deterministic multi-container scenario coverage, and
2. real-Tor transport smoke coverage.

Trying to make the full scenario matrix depend on the public Tor network would
make the suite slower, flakier, and more resource-hungry than it needs to be.
That is the wrong tradeoff.

## Recommendation

Use a Go harness/orchestrator that talks to `clirpc` directly.

Reasoning:

- Go is a good fit for orchestration, gRPC clients, container lifecycle, and
  concurrent scenario management.
- It is simpler than Rust for this specific harness problem.
- It is much less fragile than shell.
- We can target `clirpc` directly and avoid `bbcli` parsing and TTY behavior.
- Go's `testing` package and `testcontainers-go` are a good match for many
  sub-tests with bounded parallelism.

Repository decision:

- Keep the Go harness in a repository subdirectory.
- Keep `go.mod` in that harness subdirectory, not at the repository root.

Recommended layout:

- `integration/docker/go.mod`;
- generated Go RPC code under the same Go module, for example
  `integration/docker/gen/clirpc/`;
- Docker harness code under that same subtree.

My recommendation is to accept this small Go test layer. The harness is a test
system, not product code, and Go is the pragmatic choice here.

## High-level architecture

Use one Chutney-backed Docker lane first, and only add a custom deterministic
transport lane if Chutney proves too slow, flaky, or expensive.

### Phase 0: Arti local-network feasibility spike

Before inventing any replacement for Tor inside the test harness, first spike
whether current Arti can run our hidden-service flows against a local test Tor
network.

What current primary sources show:

- Arti's developer testing guidance explicitly mentions two test tools:
  `arti-testing` and a small Chutney network.
- Arti configuration supports custom directory authorities and fallback caches,
  so it can in principle be pointed at a non-public network.
- Arti's own testing guide also warns that some tests do not work well with
  Chutney because directory lifetimes are short.
- Those sources describe testing Arti itself. They do not describe a ready-made
  embedded \"fake Tor daemon\" that multiple external applications can use as a
  deterministic virtual network service.

Implication:

- there may be a viable path using a local Chutney-backed Tor network for some
  Docker tests;
- there is not strong evidence that Arti already gives us a drop-in,
  fully deterministic, low-overhead Tor simulator for the broad scenario
  matrix.

Therefore the first implementation step should be:

1. prove whether multiple `bbd` instances can run over a local Chutney network
   inside Docker with onion services and recovery;
2. measure startup cost, CPU, RAM, and flakiness;
3. only if that is not good enough, add the deterministic non-Tor lane below.

### Lane A: Chutney-backed multi-container integration

Purpose:

- cover the full scenario matrix;
- run frequently;
- run sub-tests in parallel;
- keep CPU, memory, and time bounded.

Transport:

- Arti running against a local Chutney Tor network inside Docker;
- onion-service and client flows stay real from `bbd`'s perspective.

Why:

- this is closer to real deployment than an invented replacement transport;
- it tests the actual Arti integration path rather than a test-only shortcut;
- it still avoids public-network nondeterminism.

This should be the main Docker lane if the feasibility spike is good enough.

### Lane B: deterministic fallback transport, only if needed

Purpose:

- preserve fast, broad scenario coverage if Chutney proves too slow, flaky, or
  resource-hungry for the full matrix.

Transport:

- test-only non-Tor transport backend for `bbd`.

Why:

- the project already has strong in-process transport logic in `netmock`;
- if Chutney is not practical for the whole matrix, this becomes the fallback
  broad-coverage lane.

This lane should not be built unless the Chutney spike fails its goals.

### Lane C: real-Tor Docker smoke tests

Purpose:

- verify that the real Arti/Tor path still works end to end;
- catch regressions specific to onion-service startup, dialing, retries, and
  recovery;
- stay intentionally small and mostly serial.

Transport:

- existing Arti onion transport.

Why:

- public Tor is too nondeterministic and expensive for the full matrix;
- but it is still important to test the real deployment path.

This lane should contain only a compact set of smoke scenarios.

## Why not make every Docker test use real Tor?

Because that would produce a suite that is:

- slower than necessary;
- harder to parallelize;
- sensitive to external network conditions;
- more CPU and memory intensive;
- less likely to be run often.

The current in-repo tests already cover most logic deterministically. The Docker
suite should extend confidence at the process/container boundary, not throw away
all determinism.

## Harness language choice

### Recommended: Go

Use Go for the orchestrator and scenario tests.

Responsibilities:

- build or locate the test image;
- create per-test Docker networks and bind-mounted state directories;
- start and stop node containers;
- read each node's `<data-dir>/cli-keys` from the bind mount;
- connect to `clirpc` with direct gRPC + mTLS;
- drive scenarios and assertions;
- collect logs and artifacts;
- inject failures such as stop/start/network disconnect.

### Why not shell?

- bad error handling;
- fragile parsing;
- poor concurrency control;
- weak assertions;
- awkward cleanup.

### Why not Rust?

- possible, but too expensive in implementation complexity for the harness;
- much slower to iterate on compared with Go for this orchestration problem.

## How the harness should talk to nodes

Do not use `bbcli` for the integration suite.

Use `clirpc` directly.

That means the harness must do three things:

1. generate Go gRPC stubs from `clirpc/barter_backup_client.proto`;
2. build a local `clirpc` client TLS config compatible with the daemon's
   session key model;
3. read `server.pub` and `client.key` from each node's bind-mounted
   `<data-dir>/cli-keys`.

This avoids shell and keeps the harness focused on RPC-level behavior.

## Container and filesystem model

Each node gets:

- one dedicated bind-mounted host temp directory as its `--data-dir`;
- one dedicated local `clirpc` listen port mapped to the host;
- a stable container name within that test case;
- a dedicated log sink captured by the harness.

Use bind mounts, not anonymous Docker volumes, because the harness needs direct
access to:

- `cli-keys`;
- logs;
- test artifacts;
- persisted state across restart within a scenario.

Suggested per-test host layout:

- `tmp/<test-id>/node-a/data/`
- `tmp/<test-id>/node-b/data/`
- `tmp/<test-id>/node-c/data/`
- `tmp/<test-id>/artifacts/`
- `tmp/<test-id>/logs/`

## Image strategy

Build one reusable test image per test run.

The image should contain:

- `bbd`;
- any small helper binaries needed for node startup only;
- no scenario logic.

The Go harness should remain outside the container and drive the containers via:

- Docker API;
- host-mapped `clirpc` ports;
- bind-mounted data directories.

That keeps test control centralized and makes debugging easier.

## Transport design for Lane B, only if needed

### Recommendation

Add a dedicated test transport mode for `bbd` that is valid across containers.

Requirements:

- works across processes and containers;
- preserves peer identity and mutual authentication semantics as much as
  practical;
- keeps retry, timeout, restart, contract, recovery, and storage behavior real;
- is deterministic and fast;
- does not depend on public Tor.

There are two reasonable implementation directions.

### Option 1: container-capable netmock-style transport

Adapt the existing `netmock` ideas into a cross-process transport backend.

Shape:

- `bbd` gets a test-only transport selection flag or env;
- each node advertises a deterministic direct address on the Docker network;
- peer identity remains the existing deterministic Ed25519 node identity;
- TLS remains enabled for peer RPC.

Pros:

- closest to existing test infrastructure;
- fastest path to a deterministic Docker lane;
- easiest to parallelize.

Cons:

- requires some product/test transport plumbing.

### Option 2: sidecar rendezvous service for tests

Run a small sidecar or registry that maps onion-like node identities to current
container endpoints and lets nodes dial through the deterministic test network.

Pros:

- keeps most node identity semantics intact;
- avoids direct static addressing assumptions.

Cons:

- more moving parts than Option 1;
- harder than necessary for a first implementation.

Recommendation:

- choose Option 1.

## Real-Tor strategy for Lane C

Keep real-Tor smoke tests small.

### Bootstrap acceleration

Do not share a live Tor state directory across nodes.

Safe approach:

1. generate a bootstrap seed directory once per run;
2. seed only the public Arti directory cache/state that is safe to clone;
3. copy that seed into each node's fresh data dir before start;
4. never share hidden-service-specific replay or service state between nodes.

The existing daemon behavior already prunes hidden-service-specific service
state on startup. The seed should therefore contain only public bootstrap state.

### How to create the bootstrap seed

Use one dedicated bootstrap step before the smoke suite:

- start a disposable node or helper process;
- wait until Arti reports usable directory state;
- archive the safe public-cache subset;
- use that as the per-node copy source for the smoke scenarios.

### Why Chutney first

A small private Tor network driven by Chutney is worth evaluating first because
Arti's own testing guidance already uses it in some cases.

But it should still be treated as a feasibility spike, not an assumption,
because:

- Arti docs explicitly note that some tests do not work well with Chutney;
- hidden-service flows add more complexity than plain client bootstrapping;
- this still does not solve synthetic time or long-horizon acceleration by
  itself.

## Scenario structure

Each scenario should be one Go `t.Run(...)` sub-test.

Each scenario gets:

- its own Docker network;
- its own host temp root;
- its own node containers;
- its own artifact directory.

This keeps tests isolated and makes parallel execution possible.

### Core scenarios for Lane A

These should be the main matrix.

1. `init_unlock_stop_restart`
- new node starts locked;
- `Init` works once;
- repeated `Init` fails cleanly;
- `Unlock` works;
- `Stop` shuts down cleanly;
- restart regenerates local CLI session keys;
- unlock works again with the same seed.

2. `backup_and_restore_two_nodes`
- node A and node B start;
- connect peers;
- A stores a payload;
- contract is proposed and checked;
- B stores mirrored content;
- A is recreated in a fresh dir with the same seed;
- A recovers from B;
- recovered file hashes match exactly.

3. `restart_peer_with_mirrored_content`
- peer stores another node's content;
- peer stops;
- peer restarts on the same dir;
- unlock succeeds;
- mirrored state remains usable.

4. `peer_exchange_gossip`
- A knows B;
- B knows C;
- after exchange, A learns C;
- duplicates and self-discovery are handled cleanly.

5. `offline_peer_penalized_on_check`
- contract exists;
- serving peer goes away;
- check retries are exhausted;
- score decreases once for that logical check;
- logs and state show offline/unreachable correctly.

6. `retry_after_transient_disconnect`
- peer becomes temporarily unreachable;
- retries and backoff happen;
- later attempt succeeds without data loss or corruption.

7. `divergent_recovery_conflict`
- create conflicting revisions on different peers;
- recovery downloads both;
- normal file commands block while conflict remains unresolved;
- conflict listing and resolution work;
- archived revision remains check-outable.

8. `storage_budget_and_eviction`
- reserved-tier and best-effort peers compete for space;
- latest-known vs latest-cached behavior is correct;
- reserved-tier peer keeps its best available cached revision;
- lower-priority peer data is evicted first.

9. `self_peer_rejected`
- explicit self-connect attempt fails with a human error;
- peer exchange self-discovery is ignored quietly.

10. `operator_errors_are_human`
- unlock before init;
- init after already initialized;
- wrong seed/password;
- recovery with no peers;
- stop while locked;
- invalid peer add.
- Assertions should check human-oriented error messages, not only gRPC codes.

11. `large_payload_round_trip`
- use a payload near the current size ceiling;
- verify storage, check, and recovery behavior;
- verify sampled content check handles near-EOF ranges correctly.

12. `peer_status_inventory`
- exercise `Peers` output states: `connected`, `online`, `offline`;
- verify score fields, cached/known sizes, and ordering behavior.

### Core scenarios for Lane C

Keep these small.

1. `tor_two_nodes_backup_restore`
- two nodes on real Tor;
- backup from A to B;
- recreate A with same seed;
- recover from B;
- verify exact hashes.

2. `tor_restart_with_mirrored_content`
- peer stores mirrored content;
- stop and restart;
- unlock works;
- mirrored content remains available.

3. `tor_transient_failure_recovery`
- induce one transport interruption, such as stopping/restarting one node;
- verify retries/backoff eventually recover.

That is enough for the real-Tor lane initially.

## Parallelism model

### Lane A

Parallelize sub-tests with a global cap.

Recommendation:

- Go `t.Parallel()` for individual scenarios;
- use a harness-level semaphore so only a bounded number of scenarios run at
  once;
- default cap based on host CPU and memory, for example 2 to 4 scenarios in
  parallel.

Why bounded parallelism matters:

- too much parallelism will thrash container startup, TLS handshakes, and disk
  writes;
- too little parallelism wastes the point of the harness.

### Lane C

Mostly serial.

Reason:

- real Tor is the expensive and nondeterministic part;
- too much parallelism here increases flakiness and bootstrap contention.

## Reliability rules for the harness

1. No blind sleeps except very short polling intervals.
- always wait on observable state via `clirpc State`, `Peers`, `GetContracts`,
  `ListFiles`, or explicit log milestones.

2. Every async expectation gets a timeout and polling loop.
- for example: `wait until peer runtime ready`, `wait until mirrored bytes > 0`,
  `wait until recovered file appears`.

3. Every scenario must capture artifacts on failure.
- node logs;
- current `State` response;
- current `Peers` response;
- current `GetContracts` response;
- contents of the scenario temp directory;
- hashes of input and recovered files where relevant.

4. Every restart scenario must verify both process state and data state.
- not only that the daemon restarted;
- also that unlock, peers, contracts, and recovery still behave correctly.

5. Every container teardown must be best-effort and idempotent.

## How to model payloads

Use deterministic fixture generators.

Recommended payload set:

- small text file;
- medium random binary file;
- tar archive built from a fixed input directory;
- near-size-limit binary payload.

For every recovery scenario, assert exact hashes of the recovered files.

## What to avoid

- driving tests through shell pipelines;
- depending on log text as the primary success signal;
- making the full matrix depend on public Tor;
- sharing one writable Tor state directory across nodes;
- overusing very large payloads in every scenario;
- creating a giant single end-to-end test instead of many targeted sub-tests.

## Time control and long-running scenarios

The current codebase does not yet have a full daemon-wide time abstraction.

What exists today:

- `crates/clock` provides `Clock`, `SystemClock`, and `ManualClock`;
- `node` and `storage` use that abstraction for revision timestamps and many
  score-related tests.

What does not exist today:

- `bbd` does not use an injected scheduler/clock end to end;
- many daemon behaviors still use `tokio::time::interval`, `sleep`, and
  `timeout` directly for maintenance, retries, self-checks, startup waits, and
  shutdown coordination.

Implication:

- a separate network daemon cannot by itself give us accelerated \"years pass in
  seconds\" tests;
- to do that cleanly, `bbd` needs its own testable time/scheduler abstraction.

Recommended direction:

1. do not overload the network harness with time authority responsibilities;
2. add a daemon-wide schedulable time abstraction inside `bbd`;
3. let the Docker harness drive that abstraction through a test-only control
   surface or injected configuration;
4. only then add long-horizon accelerated scenarios in containers.

So synthetic time should be treated as a separate infrastructure track, even if
it is coordinated by the same Go harness later.

## Build and generation tooling

Add explicit Go RPC generation support.

Recommendation:

- add Go toolchain support to `flake.nix`;
- add protobuf generation tools needed for Go gRPC stubs;
- add a `make rpc` target that regenerates Go and any other non-Rust RPC
  outputs needed by the harness;
- generate the Go stubs into the harness module tree, not into `clirpc/`.

Practical tool set:

- `go`
- `protoc`
- `protoc-gen-go`
- `protoc-gen-go-grpc`

The Rust build should continue using vendored `protoc` for product code. The
Go generation target is a test-harness tooling concern and can use the dev
shell tools explicitly.

## Implementation phases

### Phase 1: tooling and feasibility

- add harness-local `go.mod`;
- add Go protobuf generation support;
- add `make rpc`;
- implement a tiny direct `clirpc` Go client;
- spike a two-node Arti+Chutney hidden-service run in Docker;
- decide whether Chutney is good enough for broad coverage or only a smoke
  lane.

Deliverable:

- one short report with measured startup/recovery cost and a go/no-go decision
  on using Chutney for the main Docker lane.

### Phase 2: Chutney harness skeleton

- create the Go harness module;
- generate `clirpc` Go stubs;
- implement direct local mTLS client support;
- implement node container lifecycle;
- implement bind-mounted data dirs and mapped local ports;
- implement log collection and artifact capture.

Deliverable:

- one smoke test: one node `init -> unlock -> stop -> restart -> unlock`.

### Phase 3: deterministic transport lane, if needed

- add the dedicated test transport backend for cross-container use;
- add helper wait/assert APIs;
- implement the main fallback scenarios when Chutney is not suitable;
- run them in bounded parallelism.

Deliverable:

- reliable fallback multi-container scenario suite that does not use public
  Tor.

### Phase 4: real-Tor smoke lane

- add bootstrap seed generation;
- copy the public cache seed into each node dir;
- implement the three Lane C smoke scenarios;
- keep them mostly serial.

Deliverable:

- compact real-Tor validation lane.

### Phase 5: synthetic-time infrastructure

- add a daemon-wide time/scheduler abstraction to `bbd`;
- expose test-only control so the harness can advance time deterministically;
- add long-horizon scenarios such as months/years of scoring, retention, and
  recovery behavior without real waiting.

Deliverable:

- accelerated long-running container scenarios.

### Phase 6: execution wiring

Expose a small number of top-level commands, for example:

- Chutney-backed Docker lane;
- fast deterministic fallback Docker lane, if implemented;
- real-Tor Docker smoke lane;
- full Docker integration run.

The exact command names can be decided later, but the split must remain clear.

## Decisions already implied by this plan

1. `clirpc` direct RPC is the correct control plane for the harness.
2. Go is the correct language for the harness.
3. Chutney should be evaluated first as the main non-public Docker network.
4. The full scenario matrix should not depend on public Tor.
5. Real-Tor testing should exist, but as a smaller smoke lane.
6. Bind-mounted per-node data dirs are the right way to expose `cli-keys` and
   artifacts to the harness.

## Open decisions before implementation

1. Whether Arti+Chutney is good enough for the broad Docker lane.
- This should be decided by the Phase 1 feasibility spike, not by guesswork.

2. Exact shape of the deterministic cross-container test transport, if still
   needed.
- I recommend a test-only transport backend derived from the current `netmock`
  model.

3. Exact top-level execution interface.
- plain `go test`;
- make targets;
- optional containerized harness runner.

## Summary

The right design is not "one huge Docker test that uses public Tor for
 everything".

The right design is:

- Go harness;
- direct `clirpc` control;
- many targeted sub-tests;
- bounded parallelism;
- Chutney-backed multi-container lane for broad coverage if it proves good
  enough;
- deterministic fallback transport only if Chutney is not good enough;
- small real-Tor smoke lane with bootstrap seeding.

That gives the best balance of reliability, speed, and realism.
