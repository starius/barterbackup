# Plan: Finish Remaining TODO Items

This plan covers every item currently left in [TODO.md](TODO.md).

## Goal

Complete the remaining product and operational work in four tracks:

1. enforce the fixed 4 MiB local shared-content ceiling before bad state is accepted;
2. enable Arti bridge and pluggable-transport support through visible `bbd --arti-config`;
3. generate shell completions, man pages, and Markdown CLI manuals from the shared `clap` command trees;
4. batch low-value peer metadata writes so reachability and liveness churn do not rewrite encrypted metadata on every small update;
5. investigate and, if feasible, restore the Docker/integration runtime to `scratch`.

The first three items are direct product surface work. The fourth is durability and SSD-life hardening. The fifth is container/runtime cleanup.

## Track 1: Enforce The Fixed 4 MiB Shared-Blob Ceiling

## Product policy

Keep the current fixed ceiling exactly as it is:

- the total serialized shared content blob ceiling remains `4 MiB`;
- the limit applies to the full shared blob, not just user plaintext file bytes;
- any local mutation that would make the resulting current shared blob exceed that ceiling must fail before it is accepted.

Required operator behavior:

- file mutations that would exceed the ceiling fail with a clear error;
- metadata-producing mutations that would exceed the ceiling fail with a clear error;
- if the node is already over the ceiling, file retrieval and file deletion must still work so the user can recover by cleaning up.

## Scope of affected operations

The implementation should preflight the resulting current content blob size for every operation that commits a new local current-content revision.

That includes at least:

- `SetFile`
- any local path that rewrites current content from conflict resolution
- any local path that rewrites current content from recovery fallback/selection
- any other content-writing operation that lands in local current content

It must not block:

- `GetFile`
- `ListFiles`
- `DeleteFile` when the delete reduces or helps recover from the over-limit state

Recommended rule:

- centralize one `projected_current_content_length()` or equivalent preflight in `node`/`storage` content-write paths;
- allow writes that strictly reduce the resulting encoded blob size even when the current state is already oversized;
- reject writes that keep or increase an oversized current blob.

## Error surface

Add one explicit operator-facing error for this path.

Recommended wording family:

- daemon status: `current shared content exceeds the fixed 4 MiB limit`
- CLI wording: explain that the total shared blob, including metadata, would exceed the fixed limit and that the user must delete or shrink content first.

The error should be distinct from the mirrored-peer size-limit errors already used for peer content.

## Tests

### Unit / node tests

Add focused coverage for:

1. `SetFile` rejects a change that pushes the encoded blob above the limit.
2. `DeleteFile` still succeeds while current content is oversized.
3. `GetFile` still succeeds while current content is oversized.
4. a conflict-resolution path that would create an oversized local revision is rejected.
5. a recovery/local-content rewrite path that would create an oversized local revision is rejected.
6. a size-reducing mutation is allowed from an oversized starting state.

### CLI / local RPC tests

1. `bbcli file set` prints the new human error.
2. `bbcli file get` still works in the oversized state.
3. `bbcli file delete` still works in the oversized state.

### Docker integration

Add one scenario that:

1. creates a current state close to the limit;
2. attempts one mutation that exceeds the limit and verifies rejection;
3. confirms read access still works;
4. confirms delete works;
5. confirms cleanup returns the node to a healthy writable state.

## Suggested commit sequence

1. add central size-preflight helper and daemon enforcement
2. add CLI humanization and local-RPC tests
3. add Docker over-limit recovery scenario
4. update docs and retire the TODO item

## Acceptance criteria

- a user cannot locally accept a new current content revision above the fixed 4 MiB shared-blob ceiling;
- cleanup operations still work from an oversized state;
- error messages clearly describe the problem.

## Track 2: Arti Bridge And Pluggable-Transport Support

## Product policy

The implementation target is no longer a generic product decision. The work is:

- bump Arti to the current supported version across `nettor`;
- enable client bridge/PT features in the build;
- make `bbd --arti-config` visible in normal help output;
- verify that bridge/PT configuration can be passed through that config path.

Important boundary:

- this track is about Tor client bootstrap through bridges/PTs;
- it does not add a non-Tor peer transport for BarterBackup traffic.

## Implementation steps

1. bump `arti-client` and related `tor-*` crates together.
2. enable the needed features in [crates/nettor/Cargo.toml](crates/nettor/Cargo.toml):
   - `bridge-client`
   - `pt-client`
3. keep the current generic config loader in [crates/nettor/src/lib.rs](crates/nettor/src/lib.rs).
4. unhide `bbd --arti-config` in [cmd/bbd/src/app.rs](cmd/bbd/src/app.rs).
5. document expected usage in [README.md](README.md), including that PT/bridge options live in the supplied Arti config file.

## Tests

### Unit tests

1. config parsing accepts an Arti TOML with bridge/PT sections.
2. `bbd` flag parsing shows `--arti-config` in help output.
3. hidden-test flags remain hidden; only `--arti-config` becomes visible.

### Runtime/integration tests

At minimum:

1. one remote validation that boots `bbd` with an Arti config containing bridge/PT-related sections and confirms the config path is accepted by the binary.
2. if a real PT bootstrap environment is available, add one smoke test or documented manual validation path.

If a real PT endpoint is not practical in automated CI right now, the acceptance bar for this track is:

- feature-enabled build;
- config decode path tested;
- option visible and documented.

## Suggested commit sequence

1. bump Arti and enable bridge/PT features
2. expose `--arti-config` and update help/docs
3. add parsing/runtime tests and validation notes
4. retire the TODO item

## Acceptance criteria

- current `bbd` build includes Arti bridge/PT client support;
- users can discover `--arti-config` from normal help output;
- a supplied Arti TOML with PT/bridge config is accepted through the existing path.

## Track 3: Generate Completions, Man Pages, And Markdown Manuals

## Product policy

Generate all CLI documentation from the same `clap` command trees used by `bbcli` and `bbd`.

Outputs:

- shell completions
- man pages
- Markdown command manuals

Requirements:

- hidden test-only flags and commands remain excluded;
- generated content for `bbcli` and `bbd` comes from one source of truth.

## Recommended implementation

Use the `clap` ecosystem directly:

- `clap_complete` for shell completions
- `clap_mangen` for man pages
- one Markdown generator from the same `clap::Command` tree

Recommended repo shape:

- add a small Rust generator utility, preferably an `xtask` or a dedicated lightweight binary;
- generate into checked-in directories such as:
  - `docs/cli/`
  - `completions/`
  - `man/`
- add one `make cli-docs` target and optionally fold it into documentation workflows.

Why checked-in outputs are recommended:

- users and packagers can consume them without rebuilding the generator;
- diffs make CLI surface changes explicit in review.

## Tests

### Unit / generation tests

1. generator runs for both binaries.
2. hidden test flags are absent from generated outputs.
3. important visible subcommands are present in completions/man/Markdown.

Recommended style:

- snapshot or golden-file assertions on representative output slices.

### Workflow tests

1. one check that regenerated docs are up to date.
2. if desired, one `make cli-docs` CI check that fails on stale generated files.

## Suggested commit sequence

1. add generation crates and generator utility
2. add `make cli-docs` and output directories
3. check in generated outputs
4. add tests and docs
5. retire the TODO item

## Acceptance criteria

- completions, man pages, and Markdown manuals are generated from the actual command definitions;
- hidden options stay hidden;
- the generation path is documented and reproducible.

## Track 4: Batch Low-Value Peer Metadata Writes

## Product policy

Batch low-value peer metadata writes so encrypted metadata is not rewritten on every small reachability/score update.

This applies to fields like:

- last-live timestamps
- reachability status changes that do not affect correctness immediately
- liveness-score timestamps and small score increments
- recent failure/backoff metadata where delayed persistence is acceptable

This does not apply to high-value state that must survive crashes immediately, such as:

- accepted local content revisions
- mirrored peer-content sidecar changes that define recoverable state
- conflict state
- pin state changes
- contract state transitions that materially affect correctness

## Recommended implementation

1. classify peer-state updates into:
   - immediate durability required
   - delayed durability allowed
2. add one in-memory dirty state accumulator in the daemon/node layer;
3. flush batched low-value metadata on:
   - a short configurable delay, recommended default `60s`
   - graceful shutdown
   - any later immediate-durability write that already touches the same peer state
4. use the logical clock for deterministic long-horizon tests where appropriate.

Recommended config shape:

- one daemon-side setting for metadata flush delay, with a safe default;
- keep it internal or hidden first unless there is a strong product need to expose it immediately.

## Tests

### Unit tests

1. multiple low-value updates coalesce into one persisted write.
2. mixed low-value plus immediate update flushes correctly.
3. shutdown forces a pending flush.
4. crash-safety boundary is explicit: high-value writes still persist immediately.

### Storage / node tests

1. persisted peer state after a delayed flush matches expected final values.
2. pin state still persists immediately.
3. mirrored-content correctness state is not delayed incorrectly.

### Docker / long-horizon tests

1. logical-clock scenario that advances through many score/reachability changes without frequent writes;
2. one scenario that proves the flush happens after the configured delay;
3. one scenario that proves shutdown flushes pending low-value state.

## Suggested commit sequence

1. classify peer metadata by durability class
2. add batching/flush scheduler
3. add deterministic tests with logical clock
4. expose or document the chosen flush-delay policy if needed
5. retire the TODO item

## Acceptance criteria

- frequent low-value peer metadata churn no longer forces immediate encrypted metadata rewrites;
- high-value correctness state still persists immediately;
- shutdown flushes pending low-value updates.

## Track 5: Restore `scratch` Runtime If Feasible

This remains the lowest-priority item.

## Goal

Get the Docker/integration runtime back to `scratch` without breaking Arti/`fs-mistrust` expectations.

## Known issue

Current private-network tests need a fuller base image because `fs-mistrust` expects passwd/group information that is absent in a minimal `scratch` image.

## Recommended investigation order

1. confirm the exact failing path and ownership lookup requirements in the current Arti stack;
2. test a minimal injected `/etc/passwd` and `/etc/group` approach inside `scratch`;
3. test whether numeric-user ownership plus minimal files is sufficient;
4. if not, evaluate whether the current fuller image is the correct permanent compromise.

## Tests

1. Docker build test for the `scratch` image variant.
2. one Chutney-backed smoke scenario on the `scratch` image.
3. if restored, one public-Tor smoke scenario as confirmation.

## Suggested commit sequence

1. add one experimental `scratch` image path
2. validate `fs-mistrust` workaround
3. switch default runtime image if stable
4. retire the TODO item

## Acceptance criteria

- either `scratch` works again and the runtime switches back cleanly,
- or the investigation proves a fuller base image is still required, in which case the item can be retired with that conclusion documented.

## Cross-cutting execution order

Recommended overall order:

1. Track 1: fixed 4 MiB local shared-blob enforcement
2. Track 2: Arti bridge/PT support and visible `--arti-config`
3. Track 3: CLI doc generation
4. Track 4: deferred low-value metadata batching
5. Track 5: `scratch` investigation

Reason:

- Track 1 is the only remaining `Must do before real users` item.
- Track 2 and Track 3 improve operator usability and documentation directly.
- Track 4 is important hardening but less user-visible.
- Track 5 is explicitly polish.

## Final cleanup

After each track is completed:

- update [README.md](README.md) if the operator surface changed;
- update [AGENTS.md](AGENTS.md) if the developer workflow changed;
- remove the corresponding item from [TODO.md](TODO.md);
- keep commits atomic and validate formatting and tests before each commit.
