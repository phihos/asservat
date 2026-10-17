# Original activation observation ordering

Frozen two-file correction; live sources and SQL50 were not changed.

The supervisor previously read SQL before Pod status. If activation committed and
the original Pod exited between those reads, it could pair a terminal success
with an earlier `audited` snapshot and reject a successful installation. The new
small helper observes the exact original Pod first, then reads independent SQL
history under the original Pod and caller deadline. Its returned history interval
is explicitly capped by that same deadline before cleanup sees it.

The existing history reader still verifies original scope, plan and claim. The
supervisor still requires Succeeded/exit zero and independently Activated SQL;
missing/prepared/audited states, changed identities, cancellation and expired
observations never authorize cleanup. No saved attempt, effect, credential or
deadline is renewed. The helper is only a test seam using the existing history
port and concrete Pod-observer closure; no new persistence/interface protocol.

Verification in `evidence/`:

- `before.log`: exit 1, deterministic stale-snapshot regression against an
  extracted helper preserving the original SQL-first control flow.
- `output-bound-before.log`: exit 1, returned history interval exceeded both the
  shorter Pod interval and shorter caller interval before the explicit value cap.
- `after-race.log`: exit 0, complete bootstrap package with race detection,
  4.481 seconds. Includes success ordering, both deadline intersections,
  blocking-observation expiry, caller cancellation and independent SQL states.
- `vet.log`: exit 0, bootstrap package.

Commands used `GOMAXPROCS=2`, `go test -p 2 -race -count=1` / `go vet -p 2`,
explicit build TMPDIR, and `changes-overlay.json` over current live sources.
Tests use synthetic observation ports; no new native run was performed. Parent's
earlier native original-Pod run passed before this correction. Next qualification
is parent-owned merged Go checks and the owned handover fixture if required.

The bounded read-only review of retirement found no second concrete blocker:
each step retains original references, performs a restrictive action or exact
absence observation, and only then acknowledges it. This is not a claim that
unknown create/recovery or other explicitly pending installer work is complete.

Manifest SHA-256: `d1800fbb1e476bf97d919e653cb0323a8cac2035191ad8eaa2a3001700f9592c`.
Patch SHA-256: `ae10bdf02401e408ecb04a1b715d3087d914d500a023f9c8c28db24a27d7cb3e`.
Base and payload hashes are in `manifest.json`; both bases matched live at freeze.
