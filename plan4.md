Plan 4 - Remaining checks and follow-up work

This plan covers only the items from the latest review that still need
verification or implementation. Known answers such as the current 4 MiB peer
blob limit are not repeated here.

1. Tighten local filesystem permissions
   Ensure `BBD_DATA_DIR` and `<data-dir>/cli-keys` are created and verified
   with owner-only permissions on any OS that has such a notion. Audit all
   files written under those directories, especially local admin TLS material
   and lock files, and add tests for the expected modes. Document the intended
   permissions in the README.

2. Refresh operator-facing documentation
   Update `README.md` and any other user-facing docs to use direct `bbd` and
   `bbcli` invocations instead of `cargo run --bin ...`. Define "peer sidecar"
   early in the introduction so later storage/security language is clear. Make
   password handling and examples match the intended stdin behavior of
   trimming all trailing whitespace-like characters, so simple `echo` examples
   are safe and readable. Add a brief note showing that any `make` target can
   be run inside the dev shell with `nix develop --command make <target>`.
   Keep internal remote-builder workflow details out of public docs.

3. Make `make clippy` clean
   Fix the current `clippy` findings across `content`, `clitls`, `storage`,
   `bbcli`, `node`, and `bbd`, then rerun `cargo clippy --workspace
   --all-targets` in the dev shell on the remote builder. Keep these as normal
   code cleanups, separate from behavioral changes.

4. Verify real-Tor recovery between two nodes
   Run a real end-to-end scenario on the remote machine with Arti/Tor rather
   than only mock transport tests:
   - start node A and node B in separate data directories;
   - connect them;
   - write data on A and wait until it is mirrored to B;
   - stop A and recreate it in a fresh directory with the same seed;
   - confirm the recreated node does not recover on its own without peer
     contact;
   - reconnect the recreated A to B and recover the latest content.
   If the scenario fails, fix the product gaps and capture them with
   regression tests where practical.

5. Implement peer-storage accounting and eviction policy
   Design and implement a bounded peer-storage cache. The intended direction is
   to reserve space for peers whose score is above zero, treat negative-score
   peers as best-effort storage, and allow their cached data to be evicted in
   favor of newer or better-scored data. Add deterministic tests that exercise
   quota pressure, score changes, eviction, and recovery after restart.

6. Verify arm64 builds and tests
   Use `ssh barterbackup-arm64` with `nix develop` to make sure the project
   builds and passes the test suite on `aarch64-linux`. If the dev shell or
   toolchain setup needs adjustment for arm64, update `flake.nix` and related
   docs so the arm64 path works out of the box.

7. Add explicit build outputs for static, Windows, and sanitizer variants
   Decide the clean Rust/Nix shape for distributable build variants:
   - static Linux binaries, most likely via musl;
   - Windows binaries, preferring static linkage where the target/toolchain
     supports it cleanly;
   - sanitizer builds on supported platforms using the nightly toolchain and
     the appropriate Rust sanitizer flags.
   Expose these through `flake.nix` and `Makefile` targets, verify them on the
   remote builders, and mention them briefly in the README with any platform
   caveats.

Execution notes

- Run heavy builds, `clippy`, integration tests, and any Tor end-to-end
  validation on the remote builders, not on the local machine.
- Keep each change as an atomic commit that builds and passes the relevant
  tests before commit.
