# Plan: aligned `bbcli file list` and `bbcli peer list` tables

## Goal

Rework the two human-facing listings so they read like operator tables rather than
key-value dumps.

- `bbcli file list` must render an aligned table.
- `bbcli peer list` must render one peer per row in an aligned table.
- This is a `bbcli`-only presentation change. No RPC, proto, daemon, or storage
  changes are needed.

## Desired peer ordering

Sort peers in this priority order:

1. pinned
2. mutual storage
3. unilateral storage
4. everything else

Within each group, sort by `last seen` descending.

Clarification for the intended top of the table:
- fresh mutual storage is the best steady-state outcome and should be visually easy
  to spot.
- the primary grouping above should therefore be refined so pinned peers still stay
  first, but freshness and mutuality drive the ordering inside the pinned and
  non-pinned groups.

Recommended concrete sort key:

1. pinned by us or pins us
2. storage relationship rank
   - fresh mutual storage
   - outdated mutual storage
   - no-current mutual storage
   - fresh unilateral storage
   - outdated unilateral storage
   - no-current unilateral storage
   - no storage
3. `last_live_at` descending
4. stable tie-breaker: onion service id ascending

This keeps the user's requested macro order while ensuring fresh mutual-storage
rows float to the top within the relevant groups.

## Desired file-list output

Render `bbcli file list` as an aligned table with at least:

- file name
- size
- modified time

Recommended columns:

- `NAME`
- `SIZE`
- `MODIFIED`

Formatting rules:
- left-align text columns
- right-align size
- keep the existing human-readable local wall-clock timestamp formatting
- keep one header row
- if there are no files, print a short explicit empty-state line instead of an
  empty table

## Desired peer-list output

Render `bbcli peer list` as an aligned table with one row per peer.

Recommended columns:

- `PEER`
- `STATUS`
- `STORAGE`
- `OURS ON THEM`
- `THEIRS ON US`
- `SCORE`
- `LAST SEEN`
- `FLAGS`

Column meaning:

- `PEER`: onion service id
- `STATUS`: connected / online / offline
- `STORAGE`: freshness state of the peer-storage relationship
- `OURS ON THEM`: size of our data stored on that peer
- `THEIRS ON US`: size of the peer's data stored by us
- `SCORE`: current peer score in existing human-readable duration form
- `LAST SEEN`: local wall-clock time or `never`
- `FLAGS`: compact markers such as `pin`, `pins-us`, `tracked-only`, `stale-cache`

### Storage/freshness display

We need operator-visible distinction between:
- fresh
- outdated
- none

Recommended semantic states:

- `mutual:fresh`
- `mutual:outdated`
- `mutual:none`
- `stores-us:fresh`
- `stores-us:outdated`
- `stores-us:none`
- `we-store-them`
- `none`

If that is too verbose for the table width, use a shorter display vocabulary such
as:

- `MFRESH`
- `MOLD`
- `MNONE`
- `UFRESH`
- `UOLD`
- `UNONE`
- `THEIRS`
- `NONE`

A better operator-facing compromise is probably:

- `mutual fresh`
- `mutual old`
- `mutual none`
- `us fresh`
- `us old`
- `us none`
- `them only`
- `none`

## Color rules

Color is for terminal presentation only. It must degrade cleanly to plain text.

Recommended colors:

- fresh: green
- outdated: yellow
- none: dim or red
- pinned flags: cyan
- connected status: green
- offline status: dim

Implementation rule:
- only emit colors when stdout is a terminal and color output is enabled by the
  existing CLI behavior
- tests should validate text content independently of ANSI escapes unless a
  focused color-format test already exists for similar output

## Data sources to reuse

`bbcli` already receives enough data from the existing peer/file responses.
The work should stay inside `cmd/bbcli` formatting code.

Likely reused fields:
- file name, size, modified timestamp from `FileInfo`
- peer identity, `last_live_at`, score, pin flags, storage lengths, freshness
  indicators, tracked-only state, and stale-cache indicators from `PeerInfo`

Potential ambiguity to resolve during implementation:
- "size of our data stored on that peer" should come from the peer-side view of
  our current content length, not the amount of peer metadata we hold locally.
- if the response currently exposes both verified and latest-known requester
  content lengths, choose the field that best represents what the peer is
  currently believed to store and document that choice in code comments.

## Implementation steps

1. Add small table-format helpers in `cmd/bbcli/src/lib.rs`
- compute column widths from header and rows
- support left/right alignment
- optionally wrap colorized cells without breaking width calculation

2. Rework `format_file_list(...)`
- replace one-line key-value rows with a table renderer
- keep the existing local-time formatting for `MODIFIED`

3. Rework `format_peers_response(...)`
- replace grouped header-plus-detail-line output with a single table
- compute storage relationship/freshness classification once per peer
- compute sort keys from pin/storage/freshness/last-seen rules

4. Add compact helper functions
- peer row classification
- storage freshness label selection
- flags rendering
- column-safe size formatting

5. Add terminal-color integration
- color only the relevant cells, most importantly the storage/freshness column
- ensure width calculation uses printable width, not raw ANSI string length

6. Review empty-state behavior
- no files
- no peers
- filters that produce zero peers

## Tests

Unit tests in `cmd/bbcli` should cover:

1. file table rendering
- header row present
- columns align
- modified times stay in local wall-clock format
- empty list prints a clear empty-state line

2. peer table rendering
- one peer per row
- columns include both `OURS ON THEM` and `THEIRS ON US`
- freshness labels render as intended
- flags render as intended

3. peer sorting
- pinned rows before non-pinned rows
- mutual before unilateral before none
- within the same class, newer `last_live_at` first
- stable onion-id tie-breaker

4. freshness classification
- fresh vs outdated vs none cases
- mutual vs unilateral cases
- tracked-only / stale-cache rows do not misclassify storage state

5. color behavior
- plain output path remains readable
- optional focused test that ANSI-colorized cells still align once stripped for
  width calculation

## Risks and weak points

1. Width calculation with ANSI escapes
- this is the most likely formatting bug
- keep coloring narrowly scoped to individual cell text and calculate widths on
  the raw printable content before color wrapping

2. Overwide onion ids
- peer ids are long enough to dominate the table width
- acceptable for now, since truncating onion ids would hurt operator usability
- if width becomes a practical issue later, add an optional compact mode rather
  than truncating silently

3. Meaning of "fresh" vs "outdated"
- the implementation must use the same storage/freshness semantics already used
  elsewhere in the product, not invent a CLI-only interpretation

4. Size column semantics
- be explicit in code and tests about which peer-info fields back:
  - `OURS ON THEM`
  - `THEIRS ON US`

## Suggested commit split

1. `Render bbcli file listings as aligned tables`
- table helper
- `bbcli file list`
- unit tests

2. `Render bbcli peer listings as prioritized tables`
- peer-row classification and sorting
- peer table formatting and colors
- unit tests

3. optional follow-up if needed:
- `Polish bbcli table colors and empty states`

## Validation

Before each commit:
- `make fmt`
- `cargo test -p bbcli --locked`

If table helpers are reused more broadly than expected, also run:
- `cargo build -p bbcli --locked`
