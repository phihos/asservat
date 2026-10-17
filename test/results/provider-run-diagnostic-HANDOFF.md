# Preparation Run phase diagnostics

Three frozen paths, no live edits. The prior corrected native run passed the loader but failed in Run with an unlocalized configuration-unavailable cause. This adds fixed compiler-selected Run labels and SQL/provider subphase labels, preserving errors.Is while never rendering raw causes or values. No deadlines, retries, provider calls, admission or credential semantics change.

Run labels: run-inputs, declare, gated-pod, final-inputs, probe, sql-and-providers, request-drain, final-cancellation. SQL labels identify prepared input/probe reads, client/binder setup, bind/encoding/state persistence, provisioning/final binding/deadline, wrap/unwrap and final projection.

Actual focused checks (TMPDIR external, GOMAXPROCS=2, -p2, overlay.json):
- go test -race ./internal/bootstrap -run TestInitialPreparer -count=1: exit0,1.050s (race.log).
- go vet ./internal/bootstrap: exit0 (vet.log).

Tests verify zero-value failure phases, nested/static labels, cause identity and exclusion of a synthetic secret-bearing cause. No native run was performed. Parent next integrates three hashes and reruns exact TestInitialPreparationProvidersWithRealServices; preserve prior failed reports. ADR129 remains independent unfinished source.
