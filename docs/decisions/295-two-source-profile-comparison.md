# ADR-295 — Two-source approved profile comparison

Date: 2026-11-03. Status: implementation candidate; public composition and native
qualification pending. Requirements: REQ-PRF-005 / SC-PRF-005, S-05 increment 8.

Compare two retained profiles in the existing regional Go worker. Both complete
sources are independently authorized and authenticated. Reuse ordinary approved
profile inspection; comparison grants neither raw download nor arbitrary label
inspection. Metadata-only shares remain insufficient for either raw input.
The [composition plan](../reviews/s05-profile-comparison-composition.md) records
the exact extension map, costs and remaining proof.

The fixed roles are baseline and incident. Keep their exact case/artifact,
capture, target and ciphertext versions, even when both roles name one artifact.
Use a comparable optional baseline value in the existing query scope, with the
parent's installation/root, caller and selected sample type shared explicitly.
Omit the entire branch for historical single-source queries. Candidate routes
carry no caller-supplied source version; the accepted scope binds both versions.
Normalization is immutable query identity. A role cannot be swapped by sorting
SQL locks, by a key retry or by the result's ranking.

Both accepted paths must converge on the existing reader's store, storage
region, acquisition/connector/hub placement and exact worker/hub configuration.
Path and target IDs remain independently checked and may differ. Do not demand
whole-path equality or invent a credential/root union for different stores.
Unsupported placement stays unavailable; raw bytes never pass through the hub.
Broader multi-store placement remains unfinished rather than implicitly granted.

One compound query owns one worker and one read batch. Atomically reserve ten
existing conservative units per source. Different workload allocations each pay
ten under stable lock order; one shared workload pays twenty once. Principal and
root accounts pay twenty total. Count the one physical worker against both
distinct covered workloads and once globally/per principal. Unknown commit
retains both obligations. No separate service, Job, volume, credential, RBAC
permission, approval or background loop is added.

The batch creates two immutable ordinal-bound key child identities, each with
the existing three one-use data/index/manifest roles. Their six slots are prepaid
and cannot substitute for each other, including when both inputs have the same
artifact AAD. Preserve legacy child identity/bytes; rollback refuses retained
comparison state it cannot interpret. Recheck both original authorities after
blocking work and use the earliest original deadline through SQL, key access,
regional processing and guarded public delivery. Charged refusals retain the
same owner through outcome acknowledgement and joined cleanup. A valid output
that exceeds the result bound, including its private/public envelopes, returns
a content-free size refusal after both complete native authentications. It
never substitutes for an input/parser limit, corruption or incomplete read;
those remain unavailable. No result is truncated to fit.

Aggregate every selected cumulative function value before ranking absolute
incident-minus-baseline changes. Do not subtract truncated top-N summaries.
Keep signed raw deltas separate from duration-normalized interval/delta rates.
The latter use exact bounded native integer ratios before each final float
conversion; displayed values round independently and ranking uses displayed
deltas. Require matching sample/unit and compatible counter semantics. Unknown
build, sampling or symbol information remains explicit. A build/configuration
change is disclosed as context, not an invented statistical regression.

Both files must pass complete final native authentication before a result or
typed semantic mismatch. The prepared reader binds each opened source's exact
metadata and closes both before its final cancellation check. Source identity,
configuration, normalization and both provenance entries belong in the same
browser/MCP result contract; source-sensitive errors remain unavailable until
both readers are authorized.

The comparison-only provisional floor is 384 MiB for both physical worker memory
and transient memory. The existing summary floor stays 256 MiB. A fresh-process
maximum-shape encrypted two-source probe reached 252.363 MiB RSS in 1.202 s,
leaving only 3.637 MiB below the old floor before SQL, real provider and worker
runtime composition. One unchanged-input 224 MiB Go soft-limit probe reached
246.152 MiB; that small reduction does not justify adding a product tuning knob.
The installer uses one shared worker profile rather than a per-operation
resource selector. New installations therefore declare 384 MiB for every active
shared worker and its query transient budget: +128 MiB per active worker, with
no standing idle worker cost. Existing accepted 256 MiB profiles remain usable
for legacy operations and refuse comparison. A second worker profile or tuning
setting would add routing and acceptance machinery solely to avoid this bounded
increment. The summary admission floor remains 256 MiB. See the retained reports in
`test/results/profile-comparison-memory`. These synthetic-process measurements
are neither cgroup qualification nor a complete simultaneous parser maximum.
Qualify framing, crypto, parser object graphs, both complete maps, actual provider
and SQL work, output, cancellation and terminal ownership in the real worker
before enabling admission. No new service or scheduling layer follows.

This decision has zero new services, dependencies, watches, credentials or
operator settings. Its required extra work is two full bounded native reads,
six unwraps and atomic accounting of two independently protected sources.
The alternative of two public top-N summaries fails the required calculation
and atomic ownership. The component and design remain partial until the public
workflow and native comparison against both downloaded profiles pass.
