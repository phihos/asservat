# Capture submission phase lifetime

The baseline copied response-only `Accepted.MetadataValidUntil` into the context
for intent acknowledgement and the independently authorized start. The actual
investigation, request-owned identity and submission coordinator reproduce that
coupling with a 100 ms metadata observation, a five-second caller, and 200 ms of
synthetic blocking work. Request and explicit continuation both fail before start
or after its effect. The genuine RED snapshots preserve the original production
file and exact regression sources.

The correction consumes the exact accepted identity while current. It preserves
the original caller/identity, capture/write and separately checked start bounds.
Live response metadata is never extended. After successful start, expired metadata
gets one current exact-key read-only lookup; missing/changed/stale/denied results
return an error with the known admission and never repeat admission, audit or
start. Ordinary same-key replay stays passive. A separate actual audit publisher
regression proves that expiry of the persisted first-write `RequestUntil` still
refuses before the first PUT even while its caller and write interval remain live.

`result.json` records actual terminal tool exits and package durations. Each
`*-result.json` contains the exact command, environment, wall duration and raw log
path. Every run hashes all 2,613 Go/module sources before and after; each pair is
identical. `source-ready.json` hashes the six final implementation/test/contract
files. Source metadata records the base commit, not a committed candidate.

RED: exit 1 at the four expected phase cases and final-response lookup cases;
the preserved authority/passive replay and actual audit first-write negatives
pass. Focused GREEN: exit 0. Full capture and audit race suites: exit 0.

The clock and SQL/start ports are synthetic. This is application contract evidence,
not a real SQL/provider/installed workflow or measured availability result.
Native57 motivated the inspection; its archived minimum does not identify which
individual source supplied its winning cutoff. No deadline, provider limit,
retry allowance, stored identity or effect spend was increased.

Independent read-only parent review found no blockers in the frozen source and
regressions. The reviewer ran no duplicate tests.
