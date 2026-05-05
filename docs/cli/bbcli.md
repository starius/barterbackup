# `bbcli`

BarterBackup CLI

## Usage

```text
Usage: bbcli [OPTIONS] <COMMAND>
```

## Options

- `--local-addr <LOCAL_ADDR>`: local_addr is the local daemon endpoint (env: `BBCLI_LOCAL_ADDR`)
- `--data-dir <DATA_DIR>`: data_dir is the base directory for daemon state and local CLI keys (env: `BBCLI_DATA_DIR`)

## Subcommands

- `state`: Print daemon state
- `init`: Initialize daemon storage with the main password or complete one recovery-mode initialization
- `unlock`: Send the main password to the daemon unlock path
- `stop`: Ask the daemon to shut down gracefully
- `peer`: Manage known peers
- `file`: Manage files in the latest encrypted content blob
- `config`: Read or update daemon configuration

## `bbcli state`

Print daemon state

### Usage

```text
Usage: bbcli state
```

## `bbcli init`

Initialize daemon storage with the main password or complete one recovery-mode initialization

### Usage

```text
Usage: bbcli init [OPTIONS] [PASSWORD]
       init <COMMAND>
```

### Options

- `--password-stdin`: password_stdin reads the main password from standard input
- `--allow-weak-password`: allow_weak_password bypasses the local password-strength gate
- `--wait-seconds <WAIT_SECONDS>`: wait_seconds is how long to wait for daemon startup readiness (default: `30`)
- `--recovery-mode`: recovery_mode blocks outgoing publication until recovery is finished
- `password <PASSWORD>`: password is the inline main password or seed string

### Subcommands

- `complete`: Complete recovery-mode initialization and allow publication

### `bbcli init complete`

Complete recovery-mode initialization and allow publication

#### Usage

```text
Usage: bbcli init complete
```

## `bbcli unlock`

Send the main password to the daemon unlock path

### Usage

```text
Usage: bbcli unlock [OPTIONS] [PASSWORD]
```

### Options

- `--password-stdin`: password_stdin reads the main password from standard input
- `--wait-seconds <WAIT_SECONDS>`: wait_seconds is how long to wait for daemon startup readiness (default: `30`)
- `password <PASSWORD>`: password is the inline main password or seed string

## `bbcli stop`

Ask the daemon to shut down gracefully

### Usage

```text
Usage: bbcli stop
```

## `bbcli peer`

Manage known peers

### Usage

```text
Usage: bbcli peer <COMMAND>
```

### Subcommands

- `connect`: Add a peer onion identifier to the daemon's known peer list
- `pin`: Pin a tracked peer so local policy treats it as operator-protected
- `unpin`: Remove an existing operator pin from a tracked peer
- `list`: Print the daemon's current peer inventory
- `check`: Check one peer's current copy of our latest local revision

### `bbcli peer connect`

Add a peer onion identifier to the daemon's known peer list

#### Usage

```text
Usage: bbcli peer connect <ONION_SERVICE_ID>
```

#### Options

- `onion_service_id <ONION_SERVICE_ID>`: onion_service_id is the peer onion service identifier

### `bbcli peer pin`

Pin a tracked peer so local policy treats it as operator-protected

#### Usage

```text
Usage: bbcli peer pin <ONION_SERVICE_ID>
```

#### Options

- `onion_service_id <ONION_SERVICE_ID>`: onion_service_id is the peer onion service identifier

### `bbcli peer unpin`

Remove an existing operator pin from a tracked peer

#### Usage

```text
Usage: bbcli peer unpin <ONION_SERVICE_ID>
```

#### Options

- `onion_service_id <ONION_SERVICE_ID>`: onion_service_id is the peer onion service identifier

### `bbcli peer list`

Print the daemon's current peer inventory

#### Usage

```text
Usage: bbcli peer list [OPTIONS]
```

#### Options

- `--status <STATUS>`: status filters peers by current local transport state
- `--with-storage`: with_storage keeps only peers with persisted storage state
- `--without-storage`: without_storage keeps only peers without persisted storage state

### `bbcli peer check`

Check one peer's current copy of our latest local revision

#### Usage

```text
Usage: bbcli peer check <ONION_SERVICE_ID>
```

#### Options

- `onion_service_id <ONION_SERVICE_ID>`: onion_service_id is the peer onion service identifier

## `bbcli file`

Manage files in the latest encrypted content blob

### Usage

```text
Usage: bbcli file <COMMAND>
```

### Subcommands

- `list`: Print the names of all files in the latest encrypted content blob
- `set`: Add or replace a file in the latest encrypted content blob
- `get`: Download a file from the latest encrypted content blob
- `delete`: Delete a file from the latest encrypted content blob

### `bbcli file list`

Print the names of all files in the latest encrypted content blob

#### Usage

```text
Usage: bbcli file list
```

### `bbcli file set`

Add or replace a file in the latest encrypted content blob

#### Usage

```text
Usage: bbcli file set <NAME> [PATH]
```

#### Options

- `name <NAME>`: name is the stable file name inside the encrypted content set
- `path <PATH>`: path is the optional plaintext file path to upload.

When omitted or `-`, `bbcli` reads the plaintext bytes from standard input instead.

### `bbcli file get`

Download a file from the latest encrypted content blob

#### Usage

```text
Usage: bbcli file get <NAME> [OUT]
```

#### Options

- `name <NAME>`: name is the stable file name inside the encrypted content set
- `out <OUT>`: out is the optional output path for the downloaded plaintext file

### `bbcli file delete`

Delete a file from the latest encrypted content blob

#### Usage

```text
Usage: bbcli file delete <NAME>
```

#### Options

- `name <NAME>`: name is the stable file name inside the encrypted content set

## `bbcli config`

Read or update daemon configuration

### Usage

```text
Usage: bbcli config <COMMAND>
```

### Subcommands

- `get`: Print the current configuration and derived storage usage data
- `set`: Update one or more configuration fields

### `bbcli config get`

Print the current configuration and derived storage usage data

#### Usage

```text
Usage: bbcli config get [OPTIONS]
```

#### Options

- `--peers-storage`: peers_storage prints only the peer-storage budget field
- `--min-replicas`: min_replicas prints only the minimum replica target field
- `--resource-policy`: resource_policy prints only the current read-only peer runtime limits

### `bbcli config set`

Update one or more configuration fields

#### Usage

```text
Usage: bbcli config set [OPTIONS]
```

#### Options

- `--peers-storage <PEERS_STORAGE>`: peers_storage sets the total bytes allocated to peer storage
- `--min-replicas <MIN_REPLICAS>`: min_replicas sets the minimum replica target for our content

