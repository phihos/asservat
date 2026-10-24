# Capture phase combined design checks

Candidate `89bfff492f346953a73638e3068dfe4d76e0f02e` includes the reviewed
ADR-216 response-metadata/start phase correction. The exact command is in
`invocation.json`; `make spec-check architecture-check design-check
go-architecture-check` exits 0 in 13.011 seconds. All 3,793 recorded sources
remain unchanged. These are design/dependency checks, not installed qualification.
The separate capture-phase-lifetime archive records the failing baseline and
passing focused/race execution checks. No external fixture was created here.
