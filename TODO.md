BarterBackup (Rust) - Open work

These items are grouped by practical product priority.

## Must do before real users

- Enforce the existing fixed 4 MiB total shared-content blob ceiling on all
  local mutations before they are accepted. File changes and metadata changes
  that would make the resulting shared blob exceed that limit must fail with a
  clear operator-facing error. If the node is already over the limit, file
  removal and file retrieval must still work so the user can recover by
  cleaning up.

## Should do soon

- Bump Arti, enable bridge and pluggable-transport client features, make
  `bbd --arti-config` visible, and verify that bridge/PT configuration can be
  passed through that Arti config path for Tor-blocked networks.
- Generate shell completions, man pages, and Markdown command manuals from the
  shared `clap` command tree for `bbcli` and `bbd` so the CLI surface stays
  documented from one source of truth.
- Add deferred batching for low-value peer metadata writes such as
  reachability updates and liveness-score changes. Those fields are useful,
  but they should not force an encrypted metadata rewrite on every small
  update when a short configurable flush delay would preserve SSD life and
  battery.

## Polish later

- Investigate switching the container and integration-test runtime back to
  `scratch` by resolving the current `fs-mistrust` passwd/group dependency.
  Private-network Tor tests currently need a fuller base image even though the
  binaries themselves are static.
