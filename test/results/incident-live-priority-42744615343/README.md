# Incident priority under live-node overload

GitHub native run: 42744615343
Commit: `d45b7838df582471cbf3d66bef542e0e8d16c472`
Suite: `continuation-ongoing-incident`

Result: pass. `TestInitialBootstrapChainWithRealServices` completed in 412.03
seconds (package 412.057 seconds); the installed incident focus took 132.67
seconds. The environment records the complete selected test path, unchanged
sources, removed build scratch and no cleanup failures.

The installed collector allowed one live subscription while hub installation,
principal and workload settings allowed two. The original packet view allocated
its cohort through an actual read. A short-lived second policy source supplied a
distinct eligible view; its first read was refused with retryable
`LiveUnavailable` because the node cohort was occupied. The overload view closed
and its policy source stopped before the incident. The original control stayed
`Active`.

A real container restart then admitted automatic incident
`0a09eb4f-38fa-429e-b19d-39e88cbfc5f2`. The original live view remained `Active`
with continuation and no substituted source. The incident PCAPNG contains six
pre-restart marker packets. Native evidence is 812 bytes with SHA-256
`2c2bcd17d6b3f344c5130c0e2371ffa4cf87353b997cdc7e21143570dc06208a`.
`ongoing-incident-report.json` records the capture, watch and source identities.

This is one bounded incident/one overloaded-node proof, not a sustained load or
cross-workload scheduling measurement. Same-source viewers intentionally share a
cohort; passive open/Head operations intentionally allocate no node cohort.

Earlier attempts are not passes:

- 42737126591 showed that a same-source second open reuses the cohort.
- 42738849461 showed that a distinct-source open/Head is also passive.
- 42740793338 passed overload and restart but used the open cursor for the
  terminal poll instead of the returned continuation.
- 42742907082 proved the original view was `Active`, disproving the fixture's
  incorrect mandatory `SourceEnded` expectation. The final run accepts Active
  with continuation or SourceEnded with its explicit gap.

Evidence files include the Go log, harness environment, incident report, native
PCAPNG, timing/service logs and captured Pod diagnostics.
