# TLS preparation after shared profile candidate

Six TLS-only commits were rebased from02e onto frozen c6cfe250, yielding58f811e4.
Four additive conflicts preserve both TLS and trace aliases/tshark exclusions,
both heap-browser and TLS transport report fields, and all heap/trace/TLS expiry
exceptions. Existing CPU/default HTTP paths, heap SQL-before-browser-native,
trace zero-query checks and the original limits remain. Independent readback
review found no blockers. This is an unpublished preparation, not installed TLS.

At58f811e4, make profile-preflight go-architecture-check helm-check spec-check
architecture-check design-check exited0. All three Python selectors were run via
structured subprocess calls with separate real exit codes, all0; their logs and
commands are retained. The initial shell sequence reported only its final exit;
its result is not substituted for the independently captured terminal exits.
All changed internal Go blobs are byte-identical to the reviewed d0e3dff6 core;
the manifest records the exact paths. Payloads are deterministic gzip with
byte-exact readback. No hosted run, native TLS qualification or deployment was
performed. Rebase only the TLS commits and their retained proof onto actual main after PR162 delivery.
