# ADR-320 — Installed retention lifecycle publication

> Superseded in part by ADR-328 (2026-11-13): The signing key name and version
> no longer come from an installer pin verified through the guarded capacity
> projection; they come from Helm-rendered configuration mounted under RBAC.
> Lifecycle publication, purpose-separated JWS types and the SQL cutoff rules remain valid.

Date: 2026-11-11. Status: implemented and installed-qualified.
Requirements: REQ-PRV-002, REQ-PRV-004. This completes the runtime composition
planned in ADR-195 step 5b and amends the signing purpose in ADR-205 decision 6.

An administrator can lower a retention ceiling on existing evidence. The
catch-up worker immediately commits the tighter effective cutoff. Source
readiness requires an acknowledged record for every linked lifecycle decision.
The installed worker previously left those records pending because it lacked
a composed signer. This interrupted ordinary capture and reads even after
the new policy and all tighter dates were durable.

The hub worker publishes lifecycle records using the existing
`retention-lifecycle-audit` credential and authority-audit lease. A lifecycle
turn selects at most one pending decision and performs one provider audit
operation. An empty queue leaves that retention turn available for checkpoint
acceptance. Authority keeps every other turn. With both retention queues
busy, acceptance and lifecycle each get one of every four turns. Existing
fleet and provider observations bound the entire operation. Acknowledgement
follows a versioned object read, authenticated decryption and detached JWS
verification for the exact decision.

Reuse the worker's existing nonexportable, installation-bound Ed25519 Transit
key, named with its version in the worker's mounted configuration.
The same audit-wrap principal already holds this exact signing path. The
chart supplies the key name whenever it renders a publisher. A complete
publisher-backed regional offer is required for a joined capture capability,
which in turn is required before any retained capture or capture history
is admitted. A configured worker waits for its accepted capacity projection
before publishing. The SQL cutoff continues to apply while audit is pending.

The retained key name and installer inputs stay compatible with an image-only
upgrade. Lifecycle and deletion records carry distinct protected JWS types,
canonical payloads and exact root and key checks. Both verifiers reject a
record from the other purpose. This shares the compromise scope of the
underlying key between the two record purposes. A second key under the same
audit-wrap principal would still be reachable by a compromised worker token.
A separate protected provisioning extension could create a different trust
boundary, with separate rollout and rollback work.

## Complexity review

1. A tighter policy on retained evidence previously left its source unavailable.
2. Current qualification already requires a signed lifecycle record.
3. The path applies to every installed capture-capable profile.
4. Reuse the existing Transit, versioned object audit and authority-lease paths.
5. Added credentials, grants, mounts, providers and network endpoints are zero.
6. Pending records and restrictive SQL effects already exist. Publication adds
   an acknowledged transition using the existing SQL facet.
7. Added settings are zero.
8. The existing installed audit and key services serve one more record purpose.
9. At idle, a configured worker reads one pending row at most every four audit
   turns. Each completed decision costs one signature, wrap, versioned write,
   readback and unwrap under the existing admission. Work scales with actual
   decisions and uses the existing ordered root index.
10. The schema, role layout, installer pins and record types remain compatible.
    Returning to the previous image retains acknowledged records. A new pending
    tightening follows the prior fail-closed behavior until a capable worker
    publishes it.
11. Reusing the admitted publisher and verified key closes source readiness
    without adding another provider role or controller.

The fresh installed `retention-shortening` focus at `b99c4ff9` passed. It
verified the original registration, both tighter cutoffs, the version-pinned
signed lifecycle record and restored source readiness. The original case
was refused before its previous expiry. The
[implementation ledger](../implementation-progress.md) records the terminal
results and cleanup. Early erasure and its separate request and status remain
part of REQ-PRV-006.
