# Trace repeat: local diagnostic proof

Signed diagnostic source `d1416940a9ee529c92201675cc5d9545473465d1` is integrated as `66cc1b60`; all eight changed Go files match byte-for-byte. The existing private failure log now preserves the selected original cutoff label/time, remaining time at Final and at the failed probe, and a closed deadline/canceled/body/transport category. The original authority minima, waits, API count, cache and guard decisions remain unchanged. Valid forbidden responses retain their existing APIStatus validation.

This is diagnostic evidence, not an availability fix or proof of the previous native failure cause. The trace repeat's earlier readiness hint and one demand ran; the final hub native probe failed, but its original winning cutoff was not logged. The later capacity snapshot cannot establish failed-invocation state.

Eight deterministic gzip archives preserve the exact investigation, handoff, actual HTTPS/cutoff REDs, GREEN, both race outputs and initial test-only handler hang. The hang was corrected before the meaningful RED; no production change addressed that setup issue. `verification.json` records commands, working directory, environment overrides, actual exits, sizes, SHA-256, eight source identities and complete decompressed/Git-object readback. The final affected races passed (bootstrap 2.289s; Kubernetes 12.584s). Independent read-only review found no blockers.

No installed availability qualification, current native cause attribution, full gate, commit, push or hosted operation is claimed by this archive.
