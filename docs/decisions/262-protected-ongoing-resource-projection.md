# ADR-262 — Protected ongoing-source resource projection

Date: 2026-10-29. Status: resource projection SQL component qualified; ongoing sources pending.
Requirements: REQ-LIF-004, REQ-CAP-001/002, REQ-AUT-006.

## Decision

Reuse the existing protected complete `EvidenceBudgetPolicy` observation and
accepted capacity journal. Its optional `SourceResources` value is a sibling of
`Budget`, owned by C-16. Keep the storage `PolicyBudgetInput` eight-field shape,
protected pool bytes and storage-only selected-source bytes unchanged. The complete
accepted-source digest binds the additional value. Return copies only through an
original current `AcceptedCapacitySource`; this observation is never a collection
permit. Required team input credit remains positive and cumulative; ordinary
sanitized sources do not invent a raw grant or capture identity.

Extend the existing collector/node ceilings and optional administrator node/workload
lowering fields with active source count, aggregate input bytes/s and input burst.
Development reference defaults are 16, 16 MiB/s and 16 MiB, pending performance
qualification. Optional policies only lower aggregate ceilings, never multiply them
by replicas or incident `maxPods`. Missing older node caps mean no ongoing capacity;
finite behavior remains. Partial node caps refuse, while policy fields may lower
individual quantities. Existing ring/frozen lowering values are retained in
`collector.PolicyLimits`, rather than dropped or fetched later from an unaccepted
raw object. Node user-space CPU remains request 20m/limit 500m; no per-source CPU
estimate or bound on kernel TC execution is claimed.

Migration 104 validates a closed, bounded optional sibling and permits exactly one
same-generation projection enrichment: old decoded policy has only Resource,
Scope, Pool and the original eight-field Budget; new value minus SourceResources
is identical, under the same original UID/Kind/Name/generation/full Spec/deleting
checks. The value can only add resource ceilings. Existing typed values cannot
be removed or changed at the same generation. All other parser mutation guards,
negative watermarks, initial/epoch audit, current protection/permission/recovery
and after-lock original-time checks remain. No administrator spec churn or new
consent repairs this agent compiler projection. Existing greater-generation
configuration rules remain unchanged.

The changed complete source digest causes one existing accepted revision increase;
identical later observations retain that revision. There is no new per-source
provider audit object or SQL role. Down restores exact previous function definitions
and preserves rows/spend/trust. After enrichment, an older decoder cannot strip
the value: no transparent old-binary downgrade/rolling qualification is claimed.
Node private JSON is strict too; matched versions are required for nonzero new
caps, with no fallback/negotiation framework.

## Reassessment and evidence limits

The first local layout put resources inside the storage budget. A real canonical
pool/selected-source regression failed because that changed BOTH existing storage
identities despite unchanged storage amounts. The sibling layout makes those
same real projections byte-identical while changing the complete resource-bearing
accepted digest. Do not relax pool/enrollment extension guards to accommodate the
wrong owner. Pure tests and Helm/schema checks are component evidence; the actual
old accepted SQL→enrichment→current resource observation, immutable typed negative,
expiry/no-refund and Down/Up cases require the owned existing capacity fixture.

This slice implements no source ledger, resource reservation, arming, lease,
renewal, source service or Save. A future producer must reserve count/rate/burst
slices across the actual authorized replica set before attach; sums must fit
shared workload/node caps. Source authority and original hard ends remain separate.
[ADR-263](263-ordinary-ongoing-source-leases.md) defines the separate ordinary active-leaf contract; its runtime remains unimplemented.

## Cost and proportionality

1. This closes a specified resource-producer gap, not a claimed Native failure.
2. No accepted maintainer risk is reopened; caps are engineering reference values.
3. Ordinary ongoing sources across authorized replicas need the projection.
4. Reuse protected Kubernetes budgets/cgroups; no impact-profile registry.
5. Zero new permissions, credentials, APIs, watches, services or providers.
6. Existing absent/invalid/current outcomes; one-way enrichment, no fallback.
7. Three resource quantities, not machinery-tuning configuration.
8. Existing strict Kubernetes/Helm/SQL/node interfaces only.
9. Three 64-bit node scalars; optional 80-byte policy pair plus pointer/encoding;
   <=64 policy values/pool, 5 KiB of values before overhead. Zero added backend
   roundtrips. The rare same-generation enrichment lazily revalidates the bounded complete
   snapshot once per monotonic invocation (<=64 policies and 16 pools), never
   once per changed policy. Unchanged observations do not pay this added check.
   This is metadata upgrade work, never packet-path work. Existing SQL loop bounds remain.
10. Old absent policy values retain canonical bytes; Down preserves historical
    rows but cannot advertise transparent old-decoder operation after enrichment.
11. A sibling on the existing protected owner is smaller than a registry, a new
    approval gate, raw DTO bypass or expanded storage-state transition machinery.

Kernel/perf-buffer/parser CPU and combined source/frozen RAM require actual native
profile qualification. These reference caps do not prove safe throughput; existing
capacity rows/amounts and all disclosure/acquisition authority remain unchanged.

## Measured component result (2026-10-29)

One owned existing fleet fixture on frozen `e261801d` passed both selected top-level
tests and all 17 required children (20 actual PASS names including the existing
SQL type-alias preflight). Actual outer command exit 0 in 63.371s; Go command 53.815s
including compilation, reported integration package 13.452s. PostgreSQL/S3/OpenBao
initial activation and narrow SQL calls were real; target/protection/physical
qualification facts were explicitly synthetic. No collector, Kind or BPF ran.

The same original source UID/generation/spec advanced the accepted revision once,
then retained it on identical observations. Existing finite ready-root reads,
storage pool/selected-source bytes and storage commitments remained unchanged.
Typed mutation committed suspension, original expired proof refused, and no storage
refund occurred. Down/Up preserved accepted/negative state and charges; the old
validator correctly refused the new shape. Separate upgrade checks restored the
exact prior functions and unchanged trust state. This is not old-binary rolling
or transparent downgrade qualification.

The synthetic maximum 64-policy validator/monotonic query took 97.006953ms on this
host/fixture. It is bounded metadata timing, not full 64-policy admission, packet
throughput, safe source count, CPU/kernel or development-reference qualification.
All 3,377 runner source hashes and 36,014 tracked hashes matched; cleanup was empty,
with exact three owned container names/IDs, network and scratch absent. Root
independently verified the terminal evidence. The retained environment SHA256 is
`a4f11c974c3efeebe9b82863a400f6952d2c98cacdd72714186a8b23fa1313ae`;
Go log SHA256 is `305481d1732745f8170366786509b77fe918fb99ba181390bb0c3ec49d33232a`.
The local archive is `codex-bf86-resume/packet-source-resource-producer/owned-fleet-1`
under the build cache. Source-purpose ledger/backing/retirement, resource
reservations, authority/lease/arming, quiet erasure and Save remain unimplemented.
