# Download policy request budget

The focused race command exited **0** (Go package **2.858 s**), with actual terminal session `20048`, chunk `eda923`. `verification.json` records the exact command/environment and real subprocess exit; `focused-race.log` preserves complete output. The Kubernetes package source hashes before and after the command match. The new test source is retained as `.go.txt` and matches its tested hash. This is a measurement and boundary qualification, not a failing-before regression.

The test uses the actual `DownloadEnvironmentSource.DownloadPolicy`, its protected-source reader and independent default **20 QPS / burst 20** clients over the existing loopback TLS API fixture. The synthetic server returns exact pinned source/guard objects and the required denied dry-run response. No production limits, retries or deadlines change.

Measured results on this host:

- First policy read: **14 observer requests, 3 probe requests, 1 denied dry-run**, **30.170302 ms**.
- Second policy read: another **14 observer / 3 probe / 1 denied dry-run**, **373.792445 ms**; both reads completed in **404.056968 ms** under the same original five-second parent.
- The original source five-second interval, earlier caller cutoff, and cancellation/deadline during the final guard read all passed. The blocked server handler observes cancellation and joins; no implicit retry supplies authority.

`CurrentDownloadEnvironment` reads policy twice per full authority check: **28 observer + 6 probe requests**. Source inspection of baseline `c8fc5460` found four full checks before first worker reservation, including the adjacent duplicate in the native runtime: **112 observer requests**. At a full burst of 20 and replenishment of 20 per second, the observer-only arithmetic lower bound is **(112−20)/20 = 4.6 s**. Removing one adjacent duplicate makes **84 requests**, arithmetic **3.2 s**, with unchanged limits. These are call-count arithmetic bounds, not measured complete-operation durations. SQL, identity, other HTTP work, shared-client competition and earlier original freshness bounds remain additional constraints.

This test does not reproduce or establish the cause of native50, qualify actual Kubernetes admission or installed concurrency, or prove that removing one duplicate gives enough time for the complete download. It performs no external fixture, SQL/S3 operation, Job creation, enrollment, key work or native transfer.
