# Stored-evidence query capacity

Approved pod-status queries ([context projection](context-projection.md)) and closed profile summaries run on the regional reader (A-READ), the same long-running Deployment that serves native downloads ([ADR-330](../decisions/330-event-driven-system-design.md) D4). No Job, worker enrollment, certificate or key slot is created per query.

## Limits

Query work costs reader CPU and memory, so the limits derive from reader capacity (total concurrency = reader replicas × concurrent streams per replica, [download worker dispatch](download-worker-dispatch.md)):

- **Per principal:** a token-bucket rate limit (storm protection, ADR-335 D8) and a concurrency cap across that principal's OAuth clients; both defaults derive from total reader concurrency.
- **Per workload:** a concurrency cap of half the total reader concurrency, so one workload's investigation cannot starve the reader for others.
- **Per query:** read work is at most the reader memory limit divided by its per-replica concurrency. Results are paginated with a cursor; MCP results follow the 96 KiB tool-result bound ([MCP runtime](mcp-runtime.md)). The pod-status source is within the 2 MiB Kubernetes API response cap.
- **Reader:** CPU, memory and replica count are Helm values; the reader sheds work with a retryable "busy" result when its queue is full, so shedding is bounded by those values.

A query charges its concurrency slot at start and releases it when the query ends, fails or is canceled. An unknown outcome is resolved by the query's idempotency key. These are configured ceilings, not measured overhead.

Reads do not depend on live workload capacity (maintainer decision, 2026-10-23): a query over evidence of a deleted or unobserved workload uses the artifact's stored retention deadline and current authorization only.

## Authority

`ContextProjectionPolicies` selects the target/store path from the shared delivery-policy observation (reused for at most 60 s, ADR-311). It returns an approved-projection policy; it never grants evidence download. C-03 requires `ReadApproved`, complete denies, retained audience, stored retention deadline and processing checks.

One public `get_extract(view=fileExcerpt)` or `get_query_result` request authorizes once and reuses that decision for every step of the request, never past the request's deadline. Revocation, Stop and retention cut-offs reach a running query as events (D1) and cancel it. There are no per-frame or per-batch rechecks. Each query writes one audit row in the transaction that admits it (D6).

## Closed profile summaries

[ADR-291](../decisions/291-bounded-profile-summary.md) admits one retained raw pprof source for a closed `get_extract(view=profileSummary)` under `evidence:read`, audience and retention. It grants no raw download and no `ReadApproved` on arbitrary raw evidence. The maximum source is the profile verification bound (reader memory request divided by its concurrent verifications, default 16 MiB), which also caps profile collection, so every collectable profile can be summarized; a smaller authored native ceiling stays smaller. One summary reads that source plus its framing, index and manifest. The reader's memory limit must cover this work; the chart default is 256 MiB.
