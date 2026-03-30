# BarterBackup

BarterBackup is a pure Rust mutual-backup system built around a daemon
(`bbd`) and a CLI (`bbcli`).

Each node keeps one encrypted content blob derived from the user's file set,
stores encrypted blobs for peers, and recovers the newest revision from peers
when local state is lost. Peer traffic runs over Tor onion services with
mutual TLS and enforced post-quantum hybrid key exchange.

Each mirrored peer blob also has an encrypted peer sidecar. A sidecar is a
small local metadata record that says which peer and content revision the
cached blob belongs to without exposing plaintext user data.

## Features

- locked-start daemon with local admin RPC (`clirpc`)
- peer-to-peer RPC (`bbrpc`) over Arti onion services
- TLS 1.3 with `X25519MLKEM768` enforced for peer and local RPC traffic
- deterministic node identity derived from the main seed/password
- encrypted local storage and encrypted mirrored peer storage
- atomic content writes with rename-based replacement
- multi-node tests, manual clocks, and adversarial transport/parser coverage

## Repository layout

- `cmd/bbd`: daemon binary
- `cmd/bbcli`: CLI binary
- `crates/*`: Rust libraries
- `bbrpc`, `clirpc`, `storedpb`: protobuf definitions
- `flake.nix`: Nix development shell
- `Makefile`: convenience targets for build/test/fmt/clippy/install

## Development environment

The simplest way to get a working toolchain is:

```bash
nix develop
```

The Nix shell provides a recent Rust toolchain plus common development tools.
Any `make` target can be run inside it directly, for example:

```bash
nix develop --command make test
nix develop --command make build-static
```

Without Nix, use a current stable Rust toolchain. Protobuf compilation uses a
vendored `protoc`, so a host `protoc` installation is not required.

## Build

```bash
cargo build --workspace
```

Build release binaries:

```bash
cargo build --release -p bbd -p bbcli
```

Install the binaries into Cargo's install root:

```bash
make install
```

Build distributable variants:

```bash
make build-static
make build-windows
make sanitize-address
```

`make build-static` produces musl-linked Linux binaries for the current Linux
host architecture. `make build-windows` uses `cargo-xwin` to produce
`x86_64-pc-windows-msvc` binaries and requests static CRT linkage; Windows
system DLLs still remain dynamic as usual, and the first run downloads the
Microsoft SDK pieces that `cargo-xwin` needs. `make sanitize-address` is a
Linux-only nightly target that rebuilds the workspace with AddressSanitizer
instrumentation.

## Test

Run the full workspace test suite:

```bash
cargo test --workspace
```

Useful focused runs:

```bash
cargo test -p bbd
cargo test -p bbcli
cargo test -p node
cargo test -p tlsutil
cargo test -p content
```

Other helpers:

```bash
make fmt
make clippy
```

## Configuration

Daemon:

- `BBD_CLI_ADDR`: local `clirpc` listen address, default `127.0.0.1:9911`
- `BBD_DATA_DIR`: daemon state directory, default `~/.barterbackup`

CLI:

- `BBCLI_DAEMON_ADDR`: daemon address, default `https://127.0.0.1:9911`
- `BBCLI_CLI_KEYS_DIR`: directory containing `server.pub` and `client.key`

Important current behavior:

- the daemon generates local admin mTLS keys under `<data-dir>/cli-keys`
- those keys are regenerated on each daemon start and are valid only for that
  daemon session
- graceful daemon shutdown removes `<data-dir>/cli-keys` because those session
  keys are no longer valid after exit
- if you use a custom `BBD_DATA_DIR`, point `BBCLI_CLI_KEYS_DIR` at the same
  directory's `cli-keys` subdirectory
- if `bbd` runs over SSH, you can copy that session `cli-keys` directory to
  your local machine and run `bbcli` locally against the forwarded daemon
  address with `BBCLI_CLI_KEYS_DIR` pointing at the copied keys
- on operating systems that support owner-only modes, `BBD_DATA_DIR`,
  `<data-dir>/cli-keys`, and the files written under them are tightened to
  owner-only permissions

The daemon also takes an exclusive lock on `<data-dir>/.lock`, so two `bbd`
instances cannot use the same state directory concurrently.

## Quick start

Install or otherwise place `bbd` and `bbcli` on your `PATH`, then start the
daemon:

```bash
bbd
```

Unlock it with the main seed/password. Interactive usage will prompt and mask
input; non-interactive usage can stream the password through stdin. The unlock
path trims trailing whitespace-like characters from stdin so simple `echo`
examples are safe:

```bash
echo 'correct horse battery staple' | bbcli unlock --password-stdin
```

If you use a custom data directory:

```bash
BBD_DATA_DIR=/tmp/barterbackup bbd
echo 'correct horse battery staple' | \
  BBCLI_CLI_KEYS_DIR=/tmp/barterbackup/cli-keys bbcli unlock --password-stdin
```

Add a peer:

```bash
bbcli connect-peer <peer-onion-id>
```

Manage files:

```bash
bbcli set-file alpha.txt ./alpha.txt
bbcli list-files
bbcli get-file alpha.txt ./alpha.out
bbcli delete-file alpha.txt
```

Inspect contracts and recovery:

```bash
bbcli get-contracts
bbcli propose-contract <peer-onion-id>
bbcli check-contract <peer-onion-id>
bbcli recover-content
bbcli stop
```

## Security model

- the main seed/password is stretched with Argon2id
- subkeys are derived with HKDF-SHA256
- node identity is a deterministic Ed25519 keypair
- peer transport uses Arti onion services plus mutual TLS
- TLS is restricted to TLS 1.3 with `X25519MLKEM768`
- user data is stored only in encrypted content blobs
- peer metadata is stored only in encrypted peer sidecars
- daemon-private paths are tightened to owner-only permissions when the host
  OS provides that notion

## Notes

- `bbd` starts locked and only serves local admin RPC until `Unlock`
- `bbcli unlock` waits for the daemon to become ready instead of failing on
  early startup races
- `bbcli` waits briefly for `bbd` to create the session `cli-keys` instead of
  creating that directory on its own
- protobufs are compiled at build time; there are no checked-in generated Rust
  stubs to refresh manually
