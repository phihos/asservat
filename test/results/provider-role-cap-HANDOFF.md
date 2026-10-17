# Bounded role-only child cap compatibility correction

Four frozen paths. Apply only after parent captures actual failing-before from the separate fixture package. Existing source bases match current live; no live edits or provider labs by this agent.

Pinned OpenBao 2.7.1 source explains the incompatibility: request explicit_max_ttl populates TokenEntry.ExplicitMaxTTL, but the role-only cap updates the effective Auth lease maximum without populating that field. Self lookup returns the entry value. Source: https://raw.githubusercontent.com/openbao/openbao/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/vault/token_store.go (parseAndMergeTTLPeriod, handleLookup). Current general API: https://openbao.org/docs/api/auth/token/.

The private lookup accepts zero only for a caller-specified exact role and auth/token/create/role path. Check passes no role, preserving positive issuer cap. Issue and Verify already independently read both exact 900-second roles and policies and still verify original parent/metadata/issue/expiry bounds; renewable, periodic, orphan, changed-role/path, negative/oversized cap and late-expiry children are rejected. No POST replay, renewal, clock, budget, QPS, public contract or role grant changed.

Measured checks, with TMPDIR external, GOMAXPROCS=2, -p2 and overlay:
- Before correction: go test ./internal/adapters/kms -run '^TestInitialProviderRoleOnlyChildCap$' -count=1 exited1 with qualified role-only child rejected.
- After correction: go test -race ./internal/adapters/kms -run TestInitialProvider -count=1 exited0,1.740s.
- go vet ./internal/adapters/kms ./test/integration exited0.
- Separate fixture-only integration compile exited0; that package also adds the normal fleet regex.

No new native pass is claimed. Parent next: same minimal real-provider before/after, then the actual loader Run fixture. Earlier loader rejection, provider-wrap failure and diagnostic results remain separate evidence. The measured latest failure had 28.953s parent and2.572s original operation remaining, so timeout/QPS changes are not part of this fix. ADR129 actual handover remains an independent unfinished stage.
