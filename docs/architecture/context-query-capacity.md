# Stored-evidence query capacity

Approved pod-status queries ([context projection](context-projection.md)) and closed profile summaries run on the regional reader (A-READ), the same long-running Deployment that serves native downloads ([ADR-330](../decisions/330-event-driven-system-design.md) D4). No Job, worker enrollment, certificate or key slot is created per query.

## Limits

Query work is bounded by these limits:

- **Per principal:** a token-bucket rate limit and a concurrency cap across that principal's OAuth clients.
- **Per workload:** a concurrency cap on queries against the workload's evidence, so one workload's investigation cannot starve the reader for others.
- **Per query:** at most 4 MiB read work, a 24 KiB structured result and a 64 KiB wire response for pod status. The source artifact is the 4096-byte pod-status profile.
- **Reader:** CPU, memory and replica count are Helm values; the reader sheds work with a retryable "busy" result when its queue is full.

A query charges its concurrency slot at start and releases it when the query ends, fails or is canceled. An unknown outcome is resolved by the query's idempotency key. These are configured ceilings, not measured overhead.

Reads do not depend on live workload capacity (maintainer decision, 2026-10-23): a query over evidence of a deleted or unobserved workload uses the artifact's stored retention deadline and current authorization only.

## Authority

`ContextProjectionPolicies` selects the target/store path from the shared delivery-policy observation (reused for at most 60 s, ADR-311). It returns an approved-projection policy; it never grants evidence download. C-03 requires `ReadApproved`, complete denies, retained audience, stored retention deadline and processing checks.

One public `get_file_excerpt` or `get_query_result` request authorizes once and reuses that decision for every step of the request, never past the request's deadline. Revocation, Stop and retention cut-offs reach a running query as events (D1) and cancel it. There are no per-frame or per-batch rechecks. Each query writes one audit row in the transaction that admits it (D6).

## Closed profile summaries

[ADR-291](../decisions/291-bounded-profile-summary.md) admits one retained raw pprof source for a closed `get_profile_summary` under `evidence:read`, audience, retention and extract/profile client policy. It grants no raw download and no `ReadApproved` on arbitrary raw evidence. One summary may read up to 80 MiB of work (the 64 MiB maximum source plus framing, index and manifest); a smaller authored native ceiling stays smaller. The reader's memory limit must cover this bound; the chart default is 256 MiB.
