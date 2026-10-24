# Download preflight freshness regression

The actual coordinator, native runtime, request-owned authority checker and dispatcher are composed with existing synthetic SQL, human/configuration, audit and Job ports. A controlled component clock advances 400 ms during acknowledged audit; a consumed readiness/configuration/plan observation has only 200 ms left. This isolates an availability coupling, not measured provider latency or proof of native55 causality.

`red-2.log` is the genuine pre-change result: exit 1, three audited/unclaimed failures, five hard-bound/cancellation negatives passed (Go 0.005 s). `red-1.log` is an earlier fixture setup error and is not defect evidence. The baseline coordinator snapshot matches the recorded RED hash; the initial cache draft is not qualification evidence.

The root coordinator fix validates readiness when read, bounds reservation by the plan observation through its acknowledgement, and stops carrying those consumed freshness bounds into later work. Actual caller, authority, source, attachment and hard session/evidence limits remain; worker SQL/current-configuration checks are unchanged. Late/canceled reservation stops further work without erasing its acknowledged session.

`green-initial.log` passed all eleven cases (exit 0, Go 0.005 s). It was run after the root production change, despite initially being named red; it was renamed accurately before archival. `green-race.log` passed all eleven cases (exit 0, Go 1.041 s). `full-evidence-race.log` passed the entire affected package (exit 0, Go 3.978 s). No external fixture ran in this task.

Each corresponding JSON contains exact command, environment, start, elapsed duration, actual child exit and complete Go source hashes before/after. All source manifests remained unchanged during each run. `result.json` summarizes classification and final source hashes. All fixture identities/data are synthetic; no provider credentials or evidence bytes are included.
