# native107 — S-02 installed journey PASSED in two workload clusters (1a8388de)

`TestInitialBootstrapChainWithRealServices` exit 0 after 2055 s (test 1877.7 s). First workload
cluster: the full journey of native99 (browser and MCP submission, preview/case/extract/download
parity, idempotency, Range resume, catalog minimization, unrelated-user refusal, Stop, Deny,
failed cleanup retaining charges, verified deletion, expiry). Second workload cluster, joined into
catalog slot 2 through the same hub: enrollment, join, hub-api restart with both entries, capacity
qualification, workload ready_at with on-demand binding refresh (42 samples), then MCP capture,
collection/verification/publication and native download naming its own Pod. See milestones.txt.

Not covered here: hub disconnect/reconnect import (documented limitation, ADR-223) and
user-visible Partial states for lost target/object failure (component tests only).
