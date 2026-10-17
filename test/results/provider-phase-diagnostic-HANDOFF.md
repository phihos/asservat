# Exact provider phase and original timing diagnostics

Five frozen paths in changes/. Base hashes match current live after the previous Run diagnostic integration. No live edits or external fixtures.

The prior native run passed the loader/public inputs/SQL but returned provider-wrap unavailable. This adds only diagnostic observation: whitelisted PrepareProvider subphase plus integer milliseconds (elapsed, parent remaining at entry, parent remaining at failure, and original Bind/provider bound remaining at failure). Values clamp to0..60000; -1 means no bound was available. These values do not renew or authorize anything. Original real clocks, five-second bounds, one-use claims, API calls, QPS, provider behavior and process budget are unchanged. Raw nested causes, tokens, source/operation names, dates and provider bodies are never rendered. errors.Is remains available.

The underlying path performs Bind then originalPrivateScope, private CAS and finish/current checks; production newBoundedAPI is20QPS/burst20, unlike unlimited unit fixture limiters. This source finding alone does not establish a deadline failure. Parent must inspect the next actual timing report before changing any budget/proof composition.

Actual focused checks with TMPDIR external,GOMAXPROCS2,-p2,overlay.json:
- go test -race ./internal/adapters/kubernetes ./internal/bootstrap -run 'TestInitialProvider|TestInitialPreparer' -count=1: exit0,kubernetes31.227s,bootstrap1.053s (race.log).
- go vet of the same2packages: exit0 (vet.log).

New regressions distinguish a5s operation expiry with remaining process time from process expiry, bound missing/overlong durations, reject non-whitelisted phase text, hide secret-bearing causes, preserve error identity and verify the bootstrap nested output. Existing provider one-use/concurrency/deadline tests also run.

Parent next: integrate exact hashes and rerun TestInitialPreparationProvidersWithRealServices. No new native result is claimed. ADR129 is separate unfinished source.
