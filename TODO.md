BarterBackup (Rust) - Open work

These are the product and hardening items that are still unresolved.

- Decide the final grouped CLI command layout before renaming the surface.
  Proposed grouping for review:
  - `bbcli node healthcheck|init|unlock|stop|connect-peer|connected-peers`
  - `bbcli file list|get|set|delete`
  - `bbcli contract list|propose|check`
  - `bbcli recovery run|list-conflicts|checkout|resolve`
  - `bbcli storage get-config|set-config`
- Decide where the configurable local-content size limit belongs and what the
  default policy should be. `bbcli set-file` should reject changes that exceed
  that limit once the config surface is fixed.
- Decide how external Tor and pluggable transports fit into the final product.
  The current implementation uses in-process Arti. Supporting users whose ISPs
  block Tor still needs a product decision and implementation path, including
  whether to support external Tor, pluggable transports, or operator-managed
  hidden-service keys.
- Finish the real-Tor end-to-end validation story. The ignored
  `live_tor_recovery_round_trip` test exists, but it still needs a longer soak
  run or a better validation environment to prove the full two-node public-Tor
  recovery path end to end.
- Finish the remaining operator-facing hardening around observability and
  resource controls. Structured peer logs, peer I/O bounds, timeout handling,
  and dedicated fuzz targets are now in place, but the daemon still needs
  clearer per-peer summaries and a final decision on any future chunking or
  other operator-facing resource ceilings beyond the current peer cap.
- Extend storage accounting beyond the fixed 1 GiB peer budget and current
  score-tier policy. Expiration policy, historical visibility, and richer
  operator reporting for mirrored peer storage are still basic.
- Add explicit cross-host static Linux build targets:
  `make build-static-linux-amd64` and `make build-static-linux-arm64`. Both
  targets should produce release musl-linked Linux binaries and work inside
  `nix develop` on any supported host, using cross-compilation when needed.
- Add all generated build-artifact directories created by `make` workflows to
  `.gitignore`, including existing paths such as `target-static/` and any
  other target or output directories used by static, Windows, sanitizer, fuzz,
  or cross-build targets.
- Eliminate create-then-chmod races in private path handling. Several private
  files and directories are still created first and restricted afterward. That
  leaves a short window where another user can open them before the owner-only
  permissions are applied. Replace those flows with atomic owner-only creation
  on platforms that support it.
