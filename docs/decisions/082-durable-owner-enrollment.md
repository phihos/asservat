# ADR-082 — Durable hub process enrollment

Date: 2026-10-10. Status: selected for implementation under the maintainer's continuing implementation authorization. Requirements: REQ-FED-001, REQ-DEP-003, REQ-DLD-003, REQ-CAP-003; continuation of TASK-02 and S-01/S-02, not their completion.

## Problem

ADR-081 proves the current Pod/token/CSR and ADR-079 signs a bounded leaf. Neither prevents concurrent callers or restarted coordinators from repeatedly signing, changing a registered process key, or using an unaudited result. Hub processes also outlive the short acquisition Jobs used by ADR-071; retaining every renewal in SQL forever or limiting total process uptime would make normal operation impractical.

## Decision

Use migration 30 and the existing C-04/C-11/C-21/C-24 boundaries for one retained registration per installation, hub cluster, issuer epoch, Pod UID, process epoch and certificate purpose. Bind its immutable public key and workload/pool provenance. Keep server/client registrations separate. A token proves a Pod; protected private enrollment and process-owned keys remain necessary. A registration is neither a developer permission nor a request-ownership lease.

Verify and acknowledge encrypted enrollment audit before durably spending one of at most two signing attempts per UTC twenty-minute period. Retain the original five-second proof/configuration/recovery deadlines after SQL locks. Commit before provider I/O. A concurrent or uncertain reply never repeats a permit. Store the exact verified provider leaf/chain before separate encrypted certificate audit; only the separate activation role makes it registry-visible. A retry may finish audit after the signing deadline using the stored leaf and fresh proof/current-root verification. It may not renew the original signing permit or its certificate expiry.

Keep finite operational SQL state: at most 1,024 retained registrations per pool and 32 per Pod, including both purposes, pending, uncertain and retired records. These are initial internal safety ceilings, not measured throughput or developer-facing configuration. Each registration holds capacity until the latest possible certificate expiry plus one minute, even after immediate retirement. Delete expired attempt history only after that same grace; retain a monotonic highest-period watermark while the registration exists. Automatic pruning on claim/preparation and a separate cleanup facet bound accumulation during renewal. Issuance is still limited to two attempts per period; deletion cannot refill a live period.

After a fully quiescent registration is pruned, re-enrollment creates a new registration/audit ID. The old TLS leaves and all at-most-thirty-second owner locators have already expired. Immutability is scoped to the retained registration; perpetual UUID tombstones are not required. Runtime processes must generate a fresh process epoch on startup, and forwarding must check both actual TLS identity/current registry and the exact existing request locator. A replacement never inherits another process's request.

## Consequences and limits

The configuration head serializes short changing transactions and readers share it; lock order is recovery then configuration. No provider, Kubernetes or object-store call occurs while SQL is locked. Historical audit/retirement/cleanup can finish during source/recovery outages but cannot activate certificates or refresh authority. Public certificates, roots and minimized digests are stored; no private key, token, CSR body or workload specification is persisted.

This adds private typed ports and encrypted audit formats, not public permission/enrollment APIs or user approval steps. Protected installation/issuer/bootstrap, actual owner credential transport, runtime forwarding, local CA and public downloads remain separate work. Component tests do not provide those authorities.

[The implementation contract](../architecture/owner-registration.md) defines the facets and verification. PostgreSQL's [row-lock behavior](https://www.postgresql.org/docs/current/explicit-locking.html) and [clock functions](https://www.postgresql.org/docs/current/functions-datetime.html) support retaining locks while rechecking actual time; the integration tests must demonstrate the chosen transaction composition.
