# ADR-139: Share the accepted native port with live context start

Status: accepted for implementation; combined native qualification remains pending.

ADR-135's connector opens its live context-start exchange at the audited owner's existing `nativePort`. ADR-122's concrete server previously accepted only native evidence conversations and capped every socket at ten seconds. Replacing that server with a permissive fixture handler would not establish a usable installed composition.

Add a closed `ServeWithContextStart` composition for the existing native handler and the fixed context-start handler on that same port. Both use the activated owner server key and protected connector TLS roots. Each handler independently checks its current exact peer, process and operation; dispatching by path supplies none of those authorities. The ordinary `Serve` entry point retains its ten-second native behavior.

The immutable socket acceptance time anchors every bound. Shared sockets get at most two seconds for TLS and initial headers, ten seconds for native exchange or thirty seconds for context-start residency. Certificate expiry and application proofs can shorten those intervals. Classification, handshake completion, current reads and reconnects cannot renew the original acceptance instant. Request contexts and joined close callbacks interrupt non-I/O work as well as blocked reads and writes. Passive context standby contains no human authority; signed work and identity/effect checks retain their separate original five-second limits.

Native and context sockets have separate finite reservations, with a whole-process raw connection ceiling of sixty-four before TLS. A context standby cannot consume the native purpose's reserved admitted slots. Closing sockets remain charged to their purpose until their actual handler and socket join. Each accepted socket handles one request, including denial; neither sequential HTTP/2 reuse nor an unknown path can obtain another conversation or a longer interval. Existing per-cluster standby/capture and per-operation limits remain in force.

The owning runtime cancels and closes keys, routers and listeners before joining every started renewal, readiness and serving child. A shutdown timer cannot prove that a child stopped and cannot report completed cleanup while it still owns work. External process termination is a separate orchestration outcome, not successful joined shutdown or permission to extend an original grant.

The listener uses the standard server's graceful shutdown of keep-alive connections
after its one response. A raw `ConnState(StateIdle)` close is insufficient: the
pinned Go HTTP/2 server can enter that state before flushing final frames. The
actual native idle-response regression reproduces the lost positive disposition
and verifies delivery with `SetKeepAlivesEnabled(false)`. This does not convert
generic connection failures into retryable idle results or release capacity before
joined close. Original request and socket limits remain binding.

Protected typed `OwnerNativeRuntimeConfig` may add a context-start router and exact admitted connector profiles. It uses the existing port and serving identity. Absence retains the ordinary native path. This increment does not supply the missing protected loader projections, work-signing/trust producer or deployed regional startup, and does not enable public collection.

The combined fixture must use this actual server, real SQL52 admission and intent publication, actual regional API/local start gates, encrypted storage and independent publication/native verification. Initial human, route, connector process/source and signing roots remain explicit synthetic fixtures. Separate first-request and explicit same-key continuation selections report their exact passing subtest; a direct API-runner test is not a signed-exchange result. Qualification is recorded in [implementation progress](../implementation-progress.md), not inferred from this decision.
