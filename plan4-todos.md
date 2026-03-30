Plan 4 follow-up

1. The ignored `live_tor_recovery_round_trip` test is in place, but I did not
observe a full successful end-to-end completion on `barterbackup-dev`.

The run progressed past Arti bootstrap once the remote workspace ownership was
fixed, opened live Tor network connections, and then remained in the initial
A->B contract proposal phase until the expanded manual-test timeout budget was
exhausted. The recreated-node recovery phase was never reached in that public
Tor run.

This now looks like an environment and timing problem around cold public-Tor
hidden-service publication or rendezvous on the throwaway builder, not a local
configuration bug in the Rust code. It needs a longer-lived public-Tor soak
run, a builder with prewarmed Tor state, or a separate manual validation setup
that is allowed to sit longer than the current remote test budget.

2. Peer-content reporting under storage pressure needs another pass.

Right now the node keeps one peer metadata pointer to the latest advertised
content id. When storage is exhausted, it can remember that latest id without
caching the corresponding blob bytes locally. That means the local reports do
not distinguish between the newest known peer revision and a separately cached
older revision. If we want operators and peers to make use of an outdated but
still recoverable cached copy, the API and storage model need an explicit split
between the newest known revision and the newest locally cached revision.

3. Raise the default peer-storage budget from 64 MiB to 1 GiB.

The current default is `64 * 1024 * 1024`. The requested follow-up is to move
that default to 1 GiB so a node can hold roughly 256 full 4 MiB peer blobs
before best-effort eviction pressure starts.

4. Add explicit cross-host static Linux build targets.

The current `make build-static` is host-architecture only. Add:

- `make build-static-linux-amd64`
- `make build-static-linux-arm64`

Both targets should produce release musl-linked Linux binaries and should work
inside `nix develop` on any supported host, using cross-compilation when the
host architecture does not match the requested target.

5. Ignore all generated build artifact directories.

Add all build artifact directories created by `make` targets to `.gitignore`.
This includes existing directories such as `target-static/` and any other
target/output directories created for static, Windows, sanitizer, fuzz, or
cross-build workflows.
