# `bbdevenv`

`bbdevenv` is the persistent manual Docker/Chutney environment command for the
integration harness.

It reuses the same runtime stack as the Go Docker tests:

- host-side Chutney
- host-side `bbcli`
- `bbd` inside Docker containers only
- one bind-mounted data directory per node

Use it when you want a long-lived local lab for manual `bbcli` work, recovery
testing, or synthetic-clock experiments without tearing the environment down at
the end of a `go test` run.

## Preparation

Build the static Linux binaries and regenerate the Go `clirpc` stubs once:

```bash
nix develop --command make docker-dev-env-build
```

Then invoke the command through the Makefile:

```bash
nix develop --command make docker-dev-env ARGS='--name lab up --nodes 3'
```

`make docker-dev-env` runs:

```bash
cd integration/docker && go run ./cmd/bbdevenv -- ...
```

If you prefer, you can run the Go command directly from `integration/docker/`.

## Global Flags

- `--name <env>`: persistent environment name, default `default`
- `--workdir <path>`: override the integration work root

Global flags must come before the subcommand:

```bash
nix develop --command make docker-dev-env ARGS='--name lab status'
```

## Commands

- `up [--nodes N] [--node-name NAME ...] [--clock real|synthetic]`
  `[--disable-maintenance] [--force-recreate]`
- `down [--keep-root]`
- `restart`
- `recreate <node>`
- `status`
- `ls`
- `logs <node>`
- `onion <node>`
- `local-addr <node>`
- `cli <node> -- <bbcli args...>`
- `clock status`
- `clock advance <duration>`
- `start <node>`
- `stop <node>`

`<node>` accepts either a stable numeric index like `0` or a logical node name
like `owner` or `peer1`.

## Common Workflows

### Basic lab bring-up

```bash
nix develop --command make docker-dev-env ARGS='--name lab up --nodes 3'
nix develop --command make docker-dev-env ARGS='--name lab status'
nix develop --command make docker-dev-env ARGS='--name lab ls'
```

### Target one node with `bbcli`

```bash
nix develop --command make docker-dev-env ARGS='--name lab cli 0 -- init hunter2'
nix develop --command make docker-dev-env ARGS='--name lab cli 0 -- unlock hunter2'
nix develop --command make docker-dev-env ARGS='--name lab cli 0 -- state'
nix develop --command make docker-dev-env ARGS='--name lab cli peer1 -- peer list'
```

`bbdevenv cli` sets the correct `BBCLI_LOCAL_ADDR` and `BBCLI_DATA_DIR`
automatically, so you do not need to wire per-node values by hand.

### Recreate one node and test recovery

```bash
nix develop --command make docker-dev-env ARGS='--name lab recreate owner'
nix develop --command make docker-dev-env ARGS='--name lab cli owner -- state'
nix develop --command make docker-dev-env ARGS='--name lab cli owner -- init --recovery-mode hunter2'
nix develop --command make docker-dev-env ARGS='--name lab cli owner -- unlock hunter2'
nix develop --command make docker-dev-env ARGS='--name lab cli owner -- recovery run'
nix develop --command make docker-dev-env ARGS='--name lab cli owner -- recovery finish'
```

`recreate` wipes one node's container and data directory, then starts a fresh
locked daemon in its place while the rest of the environment keeps running.

### Synthetic time

Create the environment in synthetic-clock mode:

```bash
nix develop --command make docker-dev-env ARGS='--name lab up --nodes 2 --clock synthetic'
```

Inspect and advance the shared logical time:

```bash
nix develop --command make docker-dev-env ARGS='--name lab clock status'
nix develop --command make docker-dev-env ARGS='--name lab clock advance 5m'
nix develop --command make docker-dev-env ARGS='--name lab clock advance 1h5m'
nix develop --command make docker-dev-env ARGS='--name lab clock advance 5d12h'
```

The clock parser accepts normal Go duration syntax plus `d` for day-based
steps.

## Runtime Layout

Persistent environments live under:

```text
<workdir>/manual/<env-name>/
```

Each environment stores:

- `manifest.json`: persistent environment definition
- `logs/`: copied node logs
- one subdirectory per node data dir

The shared Chutney network state lives outside the environment root under a
stable short path in `/tmp/bbmc/` so Tor control socket paths stay short even
when the workdir itself is long.

## Requirements

- Linux host
- `nix develop` shell
- working Docker daemon

If Docker is not already running, start `dockerd` from the dev shell in a
separate terminal and export `DOCKER_HOST` before using `bbdevenv`.

## See Also

- [integration/docker/README.md](/home/user/barterbackup/rust2/integration/docker/README.md)
- [docs/cli/bbcli.md](/home/user/barterbackup/rust2/docs/cli/bbcli.md)
