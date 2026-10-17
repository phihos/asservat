# Preserve actual upstream cancellation after buffered Done

Two files frozen with exact live base/payload hashes. No wire, SQL, authority interval or listener configuration changes. No live source edits or external fixtures ran.

relayReceive deliberately stops EOF prefetch after positive Done. Its Context previously masked the wrapped upstream stream's explicit cancellation, so a NativeOwnerForwarder Close after buffering Done could still result in a worker Joined disposition. A deterministic real two-hop h2 regression reproduces this: explicit upstream Close completes before the held final frame is released, but the old queue forwards that frame anyway.

The queue now binds an independently joined cancellation callback to the actual upstream Context and also checks that Context synchronously around queued receipt. Close joins that callback before returning ownership. Normal remote terminal EOF does not cancel the upstream client Context: no extra EOF read was added. Successful self-retirement remains supported; explicit upstream/process cancellation stops final forwarding.

Actual checks (GOMAXPROCS=2, TMPDIR=/home/phil/.cache/asservat-build/tmp, -p 2):
- before.log: test-only overlay, deterministic upstream-cancellation subcase FAILS exit 1 because old code returned Joined after explicit upstream Close.
- after-race.log: full native package race suite, exit 0, 2.350s; includes all positive/negative terminal, lost-marker and two-hop read cancellation tests.
- vet.log: native package vet, exit 0.

Parent should hash-review/apply separately from ADR122, then retain the strict real SQL/S3 exchange as needed for the final combined source. Component tests remain distinct from real provider/Pod qualification. ADR122 listener work continues independently.
