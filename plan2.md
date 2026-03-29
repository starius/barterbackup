# BarterBackup Rust Development Plan

This document is a delivery plan, not an implementation commit. The goal is to
finish the project in Rust while leaving the Go tree untouched and using it only
as an approximate behavioral reference.

## 1. What the repository says today

### Current state after reading the tree and git history

- The Go branch contains the real domain knowledge:
  - protobuf/API shape;
  - seed derivation;
  - local encrypted content storage;
  - filename wrapping;
  - mock network and Tor transport shape;
  - daemon unlock flow;
  - tests for content encoding, storage atomicity, and basic multi-node RPCs.
- The Rust branch is still a scaffold:
  - `keys` is the only crate that looks close to real;
  - `node`, `netmock`, `nettor`, `bbd`, and `bbcli` are mostly prototypes;
  - there is version drift inside the Rust workspace;
  - some security-sensitive Rust code is placeholder-level and should not be
    treated as production-ready.
- The protobuf surface is larger than the implemented behavior:
  - contracts, recovery streaming, storage accounting, scoring, and background
    verification are API commitments but not implemented in Go either.
- The Go implementation is useful, but not authoritative in crypto details:
  - several crypto/layout decisions were iterated many times in history;
  - we should preserve the important invariants, not mechanically port each
    current line.

### Important invariants that survived the history

- One seed drives everything.
- Node identity is deterministic from the seed.
- Content revisions must be comparable without downloading full bodies.
- Local and peer-stored user data must stay encrypted at rest.
- Writes must be atomic and crash-safe.
- Peer content should be refreshed when outdated.
- There must be a strong test story for long-running, multi-node behavior.

## 2. Product definition to freeze before coding

Before implementation, explicitly freeze these decisions in a Rust design doc
and then keep the code aligned with it.

### 2.1 Scope of the first usable release

The first release that should be considered "usable" must include all of this:

- `bbd` daemon:
  - local `clirpc` server;
  - P2P `bbrpc` server;
  - background sync/recovery/check scheduler.
- `bbcli`:
  - unlock;
  - healthcheck;
  - connect/list peers;
  - set/get/delete/list files;
  - get/set storage config;
  - observe contracts and recovery progress.
- P2P over Tor onion services.
- P2P TLS with strict PQ-hybrid key exchange.
- Local CLI mutual TLS authentication.
- Encrypted local store.
- Encrypted peer store.
- Recovery of latest content after local state loss.
- Peer scoring driven by periodic content checks.
- Extensive automated test coverage.

### 2.2 Non-goals for the first usable release

These should not block the first usable release unless a later audit shows they
are required for correctness:

- reference-based delta downloads;
- bandwidth optimization beyond fixed-size chunk downloads;
- fancy peer discovery beyond manual seeds + gossip;
- backward compatibility with old Go ciphertext/layouts.

If backward compatibility with old Go data is required later, add it as a
separate migration project. Do not silently constrain the Rust design now.

## 3. Architecture to build

The Rust implementation should be a real subsystem decomposition, not a port of
the current file layout.

### 3.1 Recommended Rust workspace structure

Keep Rust under `rust/`, but treat it as the product:

- `crates/protos`
- `crates/keys`
- `crates/crypto`
- `crates/content`
- `crates/storage`
- `crates/transport`
- `crates/netmock`
- `crates/nettor`
- `crates/node`
- `crates/clock`
- `crates/clitls`
- `cmd/bbd`
- `cmd/bbcli`

Expected responsibilities:

- `keys`: Argon2id + HKDF domain-separated derivation only.
- `crypto`: AEAD wrappers, deterministic encryption for names/IDs, random nonce
  helpers, zeroization, type-safe key labels.
- `content`: revision headers, metadata, content file format, recovery parsing,
  chunked download logic.
- `storage`: crash-safe filesystem layer, wrapped local/peer stores, quotas,
  metadata sidecars, cleanup, integrity checks.
- `transport`: common traits for serving/dialing P2P and extracting peer auth.
- `clock`: production and simulated time.
- `node`: orchestration, state machine, background jobs, RPC service impls.

### 3.2 Node-level state model

Do not let mutable state spread across ad hoc mutexes. Use explicit state
containers:

- local identity state;
- local content state;
- known peers;
- peer contracts;
- background job registry;
- connection pool;
- recovery status;
- storage configuration.

Use one clear concurrency model:

- either actor/event-loop style for all mutable node state;
- or structured async tasks plus per-subsystem locks and strict ownership.

The current Go history moved toward event-loop isolation for a reason. Keep that
lesson, but implement it idiomatically in Rust.

### 3.3 External reference PoC

Treat `/home/user/arti-experiment` as a transport spike artifact.

What it proves:

- Arti already supported deterministic hidden-service identity material.
- The PoC constructs a fixed `HsIdKeypair` from seed material and launches an
  onion service with `launch_onion_service_with_hsid(...)`.
- It also demonstrates an ephemeral keystore approach and a self-connect proof.

How to use it:

- Use it only as evidence that the capability existed, not as code to copy.
- Re-validate the same capability against current Arti releases before locking
  in the transport layer.
- If current Arti APIs changed, adapt to them; do not downgrade the product to
  match the PoC.

## 4. Security and cryptography plan

This is the most important redesign area. The current Go code is only a rough
proposal here.

### 4.1 Seed and key hierarchy

Keep the one-seed model and make the derivation tree explicit.

- Master secret: Argon2id from user seed/passphrase.
- All subkeys: HKDF-SHA256 with typed labels.
- Separate labels for:
  - onion identity;
  - P2P TLS cert key;
  - local CLI server key;
  - local CLI client key;
  - content revision ID;
  - content metadata encryption;
  - content body encryption;
  - filename encryption;
  - peer-store namespace wrapping;
  - integrity-only MACs if needed.

Every label must be documented in one place and covered by golden tests.

### 4.2 Recommended crypto choices

Use only boring, standard, battle-tested primitives.

- KDF:
  - Argon2id for seed -> master;
  - HKDF-SHA256 for subtree derivation.
- P2P and local TLS:
  - `rustls` TLS 1.3;
  - strict PQ-hybrid group policy;
  - Ed25519 identity/cert keys if the stack supports them cleanly;
  - exact SPKI pinning where needed.
- Content and metadata encryption:
  - AEAD with unique nonces for randomized encryption;
  - prefer a widely used construction such as XChaCha20-Poly1305 or
    AES-256-GCM-SIV depending on crate maturity and auditability.
- Deterministic encryption needs:
  - use a misuse-resistant deterministic construction such as AES-SIV for
    encrypted filenames and compact encrypted revision IDs, if determinism is
    still required after redesign.

Do not keep a design just because it exists in Go. Re-justify every primitive.

### 4.3 Content revision identity

Requirement: after losing the node, a fresh daemon with the same seed must be
able to query peers, compare candidate revisions quickly, and identify the
latest without downloading full bodies.

Recommended design:

- Define a small encrypted revision descriptor carried in `content_id`.
- The plaintext descriptor should contain:
  - format version;
  - monotonic revision sequence number;
  - wall-clock creation time;
  - metadata length;
  - optional short body digest prefix or tie-breaker.
- Encrypt/authenticate this descriptor with a seed-derived deterministic
  misuse-resistant key.
- On startup after data loss:
  - recover the highest known revision descriptor from peers;
  - restore local state from that revision before accepting new writes.

Reason:

- timestamps alone are not enough;
- sequence number alone is not enough if local state is lost before recovery;
- the tuple gives deterministic ordering and recovery safety.

### 4.4 Content blob format

Keep the semantic model from Go, but redesign if needed:

- header;
- encrypted revision descriptor or reference to it;
- encrypted metadata;
- encrypted file bodies;
- optional padding to coarsen size leakage.

Requirements:

- no plaintext filenames or file bytes on disk or on peers;
- authenticated metadata;
- authenticated file lengths and hashes;
- streaming-friendly parsing;
- chunk download support;
- corrupt data rejected before being accepted into live state.

### 4.5 At-rest storage rules

- No plaintext user data on disk.
- No plaintext peer data on disk.
- No plaintext filenames that reveal ownership or role.
- Temp files must also remain encrypted.
- Crash recovery must tolerate:
  - partial temp files;
  - orphan temp files;
  - duplicate valid revisions;
  - stale peer blobs;
  - truncated metadata sidecars.

### 4.6 Atomicity and durability rules

Each persistent write path must define exactly:

- temp path creation;
- encrypted write;
- file fsync;
- rename;
- parent directory fsync;
- old-file cleanup timing.

If directory fsync cannot be guaranteed on some platform, document it and keep
Linux as the correctness target first.

## 5. Networking and transport plan

### 5.1 P2P transport

Target:

- Tor onion service used only as transport;
- identity derived from seed and equal to onion key;
- TLS on top of Tor stream;
- P2P mutual authentication from TLS peer cert / identity binding;
- strict PQ-hybrid handshake policy.

Recommended path:

- Start from a fresh Arti spike on the newest compatible crate versions, not
  from the old Rust scaffold in this repository.
- Use `/home/user/arti-experiment` as evidence that deterministic onion key
  material was possible with Arti, including explicit HS identity injection and
  ephemeral keystore usage.
- Rebuild that spike on current Arti crates and confirm all of the following:
  - deterministic hidden-service identity from seed-derived key material;
  - stable onion address derivation;
  - serving incoming rendezvous streams to the RPC stack;
  - dialing peer onion services from the same in-process client;
  - compatibility with the chosen TLS/PQ stack.
- Use `arti` if it can cleanly support deterministic onion key material and
  stream adaptation into tonic/h2 on current releases.
- If `arti` key import turns out to be a blocker, define a fallback transport
  adapter using a managed Tor daemon only if it still preserves deterministic
  onion identity and testability.

This decision should be validated in a spike before main implementation.

### 5.2 netmock

`netmock` must become the primary integration-test transport.

Requirements:

- no real Tor;
- real TLS;
- real certificate extraction on the server;
- deterministic in-process serving/dialing;
- fault injection hooks:
  - latency;
  - disconnects;
  - corruption;
  - refused connections;
  - stalled responses.

### 5.3 Local CLI transport

- Local `clirpc` served over mutual TLS.
- Client auth via dedicated local client cert.
- Server cert pinned by the CLI.
- Keep this separate from seed-derived node identity unless there is a strong
  reason to unify them.
- The daemon lock/unlock lifecycle must make local auth material predictable and
  safe across restarts.

## 6. Functional subsystems to implement

### 6.1 Phase 0: repository and toolchain cleanup

Do this before any real feature work.

- Freeze Rust as the active target under `rust/`.
- Audit and delete stale Rust prototype code that no longer matches current
  protos or current intended APIs.
- Align crate versions across the workspace.
- Add an explicit dependency freshness policy:
  - prefer current stable releases of Rust crates;
  - update Arti, tonic, rustls, and crypto crates to current supported versions;
  - do not inherit old versions from historical PoCs unless a specific API
    regression forces it and that decision is documented.
- Add a Rust-focused Nix dev shell with pinned toolchain and tooling.
- Decide whether the top-level flake serves both Go and Rust or whether Rust
  gets a dedicated flake/module.
- Add remote helper scripts for `ssh barterbackup-dev`.

Deliverable:

- a Rust workspace that builds cleanly enough to support real work.

### 6.2 Phase 1: deterministic identity and transport foundation

- Implement seed derivation and key hierarchy.
- Implement real onion address derivation in Rust.
- Implement local CLI TLS correctly.
- Implement P2P TLS config and peer identity extraction.
- Make `netmock` fully functional.
- Create a dedicated Arti transport spike, using `/home/user/arti-experiment`
  only as reference, and validate it on current dependency versions.
- Add minimal real `node` skeleton with:
  - start/stop;
  - health checks;
  - dial peer;
  - connection pool.

Deliverable:

- two Rust nodes can talk over `netmock` with real auth and correct onion
  identity reporting.

### 6.3 Phase 2: content format and encrypted local storage

- Rebuild content encoding/decoding in Rust.
- Rebuild wrapped filesystem and atomic write layer.
- Rebuild local store:
  - set/get/delete/list files;
  - current revision tracking;
  - revision side metadata;
  - scan/load/recover on startup;
  - crash-safe replacement.
- Rebuild peer-content blob storage separate from live local revision state.

Deliverable:

- daemon can persist encrypted local revisions and reopen them after restart.

### 6.4 Phase 3: core local daemon and CLI

- Implement `bbd` app lifecycle:
  - data dir prep;
  - lock file;
  - local TLS material;
  - unlock flow;
  - background task startup/shutdown.
- Implement `bbcli` commands:
  - `healthcheck`;
  - `unlock`;
  - `connect-peer`;
  - `connected-peers`;
  - `set-file`;
  - `get-file`;
  - `delete-file`;
  - `list-files`;
  - `get-storage-config`;
  - `set-storage-config`.

Deliverable:

- a single-node local workflow that is usable without P2P.

### 6.5 Phase 4: P2P revision sync and blob transfer

- Implement `PeerExchange`.
- Implement `GetContentRevision`.
- Implement `SetContentRevision`.
- Implement `Download`.
- Refresh outdated peer blobs automatically.
- Persist peer content metadata and peer-store blobs.

Keep v1 simple:

- raw chunk downloads only;
- no reference sections until everything else works.

Deliverable:

- multi-node sync where nodes can advertise revisions and download the needed
  encrypted content blobs.

### 6.6 Phase 5: contract model and storage policy

Turn the proto promises into a real contract model.

Define and implement:

- peer state machine;
- storage reservation policy;
- contract acceptance/rejection rules;
- derived storage information:
  - online obligations;
  - offline obligations;
  - expired offline obligations;
  - max acceptable peer content size.

Persist per-peer fields:

- latest known peer revision;
- whether our revision is synced there;
- our score of them;
- their effective score as inferred from checks;
- last check times;
- online/offline state.

Deliverable:

- stable, explainable contract/state accounting exposed via `clirpc`.

### 6.7 Phase 6: periodic verification and scoring

Implement the long-running economic core.

- Background scheduler periodically selects peers for checks.
- For each peer:
  - confirm revision sync;
  - choose random section of our current content;
  - download section from peer;
  - verify against local content;
  - update score using elapsed time since previous check.

Recommended initial scoring rule:

- `delta = now - last_check_at`
- success: `score += delta`
- failure: `score -= delta`

Persist this immediately and expose it in contracts/info.

Deliverable:

- peers accumulate positive score when they keep storing valid data and lose it
  when they fail checks or become stale.

### 6.8 Phase 7: recovery workflow

This is the key end-user promise and must be treated as a first-class feature.

Startup behavior:

- load local encrypted state if present;
- query known peers for our latest stored revision;
- compare revision descriptors without downloading bodies;
- download the best candidate if local state is missing or older;
- verify and atomically install recovered state;
- rebuild peer metadata and contract state from recovered metadata.

`RecoverContent` streaming RPC:

- expose discovery progress;
- expose best revision seen;
- expose peer counts by version;
- expose bytes downloaded;
- expose completion state.

Deliverable:

- wiping the local state and restarting with the same seed recovers the latest
  valid content from peers.

### 6.9 Phase 8: hardening and production polish

- observability:
  - structured logs;
  - per-peer event summaries;
  - recovery/check logs;
- resource controls:
  - storage quotas;
  - connection caps;
  - task cancellation;
  - chunk size limits;
- hostile input handling:
  - malformed blobs;
  - invalid certs;
  - oversized metadata;
  - repeated partial downloads;
  - malicious peers lying about lengths or hashes.

Deliverable:

- a daemon that can run unattended and fail safely.

## 7. Synthetic time and test strategy

This must be designed early, not bolted on later.

### 7.1 Clock abstraction

Create a `clock` crate and ban direct use of wall-clock APIs in core logic.

Provide:

- `Clock::now()`
- `Clock::sleep()`
- `Clock::sleep_until()`
- `Clock::interval()`
- deterministic monotonic source

Implementations:

- `RealClock`
- `SimClock`

`SimClock` requirements:

- manual time advance;
- wake all expired timers deterministically;
- works with async tasks;
- supports long-horizon tests without real waiting.

### 7.2 Test layers

#### Unit tests

- key derivation vectors;
- content ID encoding/ordering;
- AEAD/open failure behavior;
- filename wrapping;
- atomic write helpers;
- storage quota math;
- score math;
- revision comparison.

#### Property tests

- random content sets round-trip;
- parser rejects malformed/truncated blobs;
- atomic recovery chooses newest valid revision;
- no filename collisions in wrapper domain;
- content download chunk assembly equals original blob.

#### Integration tests with `netmock`

- two-node health/auth;
- set file -> advertise revision -> peer downloads;
- outdated peer blob replaced by newer one;
- wrong seed cannot decrypt recovered content;
- local wipe + restart + recovery.

#### Scenario tests with synthetic time

- long periods of successful checks increase score;
- repeated failures drive score negative;
- offline peer becomes online and catches up;
- simultaneous revisions from different peers;
- clock skew and restart/recovery behavior;
- peer corruption after previously valid storage;
- daemon restart in the middle of background work.

#### Fault-injection tests

- power loss during local commit;
- power loss during peer blob write;
- partial rename/temp file leftovers;
- interrupted download;
- malicious peer returning wrong chunk/hash/length;
- invalid/missing TLS certs;
- Tor dial failures and retry behavior.

#### Fuzzing

- content blob parser;
- metadata parser;
- local key file parser;
- RPC request validators.

### 7.3 Coverage rule

For every background behavior, add at least:

- happy-path test;
- restart/resume test;
- cancellation test;
- corruption/adversarial test.

## 8. Remote build and test workflow

The local machine is the source of truth. Heavy builds and tests should run on
`ssh barterbackup-dev`.

### 8.1 Environment plan

- Install Nix on `barterbackup-dev`.
- Provide a Rust dev shell through `nix develop`.
- Include in the shell:
  - recent stable Rust toolchain;
  - optional nightly only if needed for a specific tool;
  - `cargo-nextest`;
  - `cargo-deny`;
  - `cargo-audit`;
  - `cargo-fuzz`;
  - `protobuf` tools if still needed;
  - `clang`, `pkg-config`, and any TLS/Tor build deps.

Dependency policy in that environment:

- always begin by trying the newest reasonable crate versions;
- keep the Nix shell and lockfiles aligned with that policy;
- do not pin Rust/Tor/TLS dependencies to old PoC versions just because they
  once worked in `/home/user/arti-experiment`.

### 8.2 Remote execution helpers

Add simple repo scripts later:

- `scripts/remote-sync`
- `scripts/remote-test`
- `scripts/remote-nextest`
- `scripts/remote-fuzz`

Workflow:

- sync local sources to remote throwaway workspace;
- enter `nix develop`;
- build/test there;
- keep no authoritative state on the remote host.

### 8.3 Command policy

From the point coding starts:

- fast lint/unit checks may still run locally only if trivial;
- all heavy Rust builds, integration tests, and long-running scenario tests run
  on `barterbackup-dev`;
- record the exact commands in docs so the workflow stays reproducible.

### 8.4 Commit rules

During implementation, each commit must be an atomic, independently reviewable
piece of work. A commit must build and pass the relevant tests before it is
created. Commits should be neither too small nor too large; use judgment and
prefer a single logical unit of work that a reviewer can understand in one pass.
When a meaningful part of the work is finished, commit it instead of letting a
large mixed diff accumulate.

Commit messages must follow strict formatting rules. The title must stay within
50 characters. The body must be wrapped at 80 characters. The body must explain
what was done, why it was done, and, when it matters, how it was implemented,
using normal prose rather than sections or bullet lists. After each commit,
inspect the recent git history and verify that the message is formatted
correctly and that line wrapping looks clean. If the message is malformed or
line endings look broken, amend it immediately.

If, during this implementation effort, one of the new commits turns out to be
wrong, misleading, or incomplete, clean up the history while it is still local
work. Use rebase, squash, split, or reword as needed so the final commit series
stays clear and reviewable. This rule applies to commits created during this
work, not to older repository history.

### 8.5 Code readability and symbol documentation rules

All code written during the Rust implementation should optimize for somebody
else learning the system from the source. Every symbol should have a
description: functions, methods, types, enums, traits, and other public or
important internal items should all carry clear documentation comments. Within
functions, add comments before each non-trivial section so the reader can see
what the code is doing and why that block exists.

Names should be self-descriptive. Prefer function, type, and field names that
make the surrounding logic readable without guesswork. Avoid clever or overly
compressed naming. If a section is complex enough that a reader would need to
mentally reverse-engineer it, add a short explanatory comment rather than
forcing them to infer intent from the mechanics alone.

## 9. Order of execution

This is the recommended implementation order.

1. Clean the Rust workspace and toolchain story.
2. Freeze crypto and revision-ID design.
3. Build `clock`, `keys`, `crypto`, and `netmock`.
4. Build `content` and `storage`.
5. Build minimal `node` with real health/auth.
6. Build daemon and CLI local flows.
7. Build P2P revision sync and downloads.
8. Build storage policy and contracts.
9. Build periodic verification and scoring.
10. Build recovery.
11. Harden, fuzz, and stress-test.

Do not start contracts or recovery before storage and deterministic time are in
place. That would only create rework.

## 10. Acceptance criteria for "I can use it"

The project is not "done" until these end-to-end statements pass reliably:

- I can unlock a daemon and manage files via `bbcli`.
- Two or more nodes can mutually store each other's encrypted content.
- No plaintext user data appears on local disk or in peer storage.
- Restarting during writes leaves either the old valid revision or the new valid
  revision, never a broken live state.
- If a peer stores an outdated version, the node notices and refreshes it.
- Periodic random checks update scores correctly over simulated long periods.
- If I delete local state and restart with the same seed, the daemon recovers
  the latest valid content from peers.
- The full multi-node scenario suite passes under synthetic time.

## 11. Immediate next task after this plan

When implementation starts, the first concrete task should be:

- create a Rust-focused architecture/design note that freezes:
  - crypto primitives;
  - revision ordering format;
  - storage layout;
  - clock abstraction;
  - transport traits;
  - remote `nix develop` workflow.

That design note becomes the contract for the actual coding phase.
