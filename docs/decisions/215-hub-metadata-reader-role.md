# ADR-215 — One SQL login for the hub's metadata readers

Date: 2026-10-22. Status: selected under the accepted complexity review;
implementation and qualification in progress.
Requirements: REQ-DB-004, TASK-03/11, S-02.

## Problem and decision

The same hub process holds seven separate SQL credentials for `permission-read`,
`retention-read`, `storage-read`, `progress-read`, `case-read`, `processing-read`
and `catalog-read`. A compromise of that process already exposes all seven.
Separate logins reduce the metadata reachable through a query-injection flaw,
but add seven provisioning, verification, projection and pool lifecycles. No
independent deployment or workload identity separates these readers.

Replace those seven credentials with one `hub-metadata-read` login and one pool.
Keep the seven typed adapters and their transaction, authorization and deadline
checks. The new login receives the exact union of their existing metadata grants,
including the existing lock-column grants and read-only capacity function. It
receives no capture admission, evidence-object access, unwrap, publication,
deletion, audit mutation or administrative privileges.

The selected credentials and pools fall from seven to one, public-runtime logins
from 87 to 81, and hub credential entries from 52 to 46. The pool has
`MaxConns=7`, `MinConns=0`, preserving the former aggregate maximum. It remains
cold under the existing process governor; the hub's physical connection ceiling
remains 32. This removes six credential lifecycles, not six guaranteed active
connections, and does not eliminate cold TLS/SCRAM handshakes.

Keep other roles separate. In particular, a download-plan transaction calls the
worker-configuration reader while holding its connection; combining those pools
would require additional concurrency analysis. Capture/capacity login pins and
separate publisher, federation, key, acquisition and deletion duties are outside
this change. There is no universal database credential or `SET ROLE` mechanism.

## Development compatibility

Use one current fresh-install layout. The project has no release or identified
supported installation using the earlier development credential layout. Do not
add a permanent dual-layout runtime to preserve disposable fixtures.

The existing exact layout digest must reject an unsupported retained layout
before effects, with an actionable diagnostic. Never adopt, overwrite or delete
unknown installation state. Known disposable development installations can be
recreated explicitly. Preserve historical qualification reports and tests for
immutable replay within a supported layout. A supported upgrade contract must
be qualified before release; this change does not claim to migrate an existing
installation or weaken its history checks.

## Cost and tradeoff

The benefit is a concrete reduction of six passwords, credential projections,
claim/completion sequences and pool objects on normal installations. The broader
metadata exposed by a SQL-injection flaw is the accepted tradeoff; process
compromise gains no new metadata authority. No new configuration, process,
background task, external dependency, durable state or SQL schema is introduced.
Failure handling and disablement use the existing credential and pool lifecycle.
Connection/latency savings beyond the removed setup work remain unmeasured.

This partially supersedes ADR-177's one-login-per-purpose decision for these
readers. Its process governor, privilege checks, cancellation and actual socket
closure accounting remain.

## Qualification

Verify the union against the former grants, reject removed credential identities,
and exercise all seven adapters with the actual PostgreSQL login. Require denial
of excluded mutations, one shared pool, the aggregate seven-connection bound,
the unchanged process cap, cancellation and joined closure. Retain post-lock
expiry/revocation/recovery cases and test concurrent readers without nested
acquisition deadlock. Finish with the installed investigation on the final
candidate. Actual results belong in `docs/implementation-progress.md`.
