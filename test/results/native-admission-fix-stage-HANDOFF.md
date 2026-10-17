# Frozen correction after SQL45/v2

Four files, base hashes relative to the frozen 53-path SQL45 `package-v2/work`.
Apply only after matching every old/new hash. No live files were changed here.

`ConnectorAdmission.OpenNative` now uses `NewRelayConversation`, so actual
production construction starts the single owned upstream receive loop. A hub
disconnect cancels and joins a worker blocked in regional acquisition, rather
than waiting for the five-second deadline. The new regression invokes the real
production connector constructor and actual two-hop h2/TLS; authority and
serving observations are explicitly synthetic. Existing helper behavior is
unchanged when no admission constructor is supplied.

The SQL45 native key trigger now calls the download-window alias `win`, avoiding
collision with its PL/pgSQL `w public.download_worker` record. The other new
trigger declarations and SQL aliases were scanned and have no matching alias
collision. This one-line migration change does not change generated queries.
Actual SQL45 trigger execution remains for the parent's owned native fixture.

Verification from the isolated original sparse stage via `overlay.json`:

- `before.log`: new production-constructor regression **failed**, terminal1,
  "two-hop disconnect did not cancel regional read" after one second.
- `after-race-final.log`: `GOMAXPROCS=2 go test -overlay ... -p 2 -race -v
  ./internal/transport/native` **passed**, terminal0, 1.820s; new regression0.02s.
  Existing largest command/two-hop/unknown ACK/final HTTPS sink tests also pass.
- `after-vet.log`: focused `go vet -overlay ... -p 2
  ./internal/transport/native` **passed**, terminal0.
- `after-race.log` preserves an initial command invocation error (`-p2` was not
  the correct Go argument form); it ran no tests. The final command uses `-p 2`.

No external lab ran and no SQL migration was applied here. This correction adds
no listener, enrollment authority, public route or native enabled profile.
Parent should refresh the admission dependency in ADR121's staged worker build
and qualify SQL45 with the guarded correction applied. ADR122 listener design
is separately proposed in `../PROPOSAL.md`; it is not implemented by this patch.
