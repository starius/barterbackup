BarterBackup (Rust) - Open work

These are the product and hardening items that are still unresolved.

- Decide the final grouped CLI command layout before renaming the surface.
  Proposed grouping for review:
  - `bbcli node state|init|unlock|stop|connect-peer|peers`
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
- Finish the remaining operator-facing hardening around observability and
  resource controls. Structured peer logs, peer I/O bounds, timeout handling,
  dedicated fuzz targets, and clearer CLI peer summaries are now in place, but
  the daemon still needs a final decision on any future chunking or other
  operator-facing resource ceilings beyond the current peer cap.
- Extend storage accounting beyond the fixed 1 GiB peer budget and current
  score-tier policy. Expiration policy, historical visibility, and richer
  operator reporting for mirrored peer storage are still basic.
