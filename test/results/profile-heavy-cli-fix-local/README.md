# Accepted-heavy native pprof CLI repair

The original native from failed run41830591107 reproduces the missing-function
assertion with the old command (CLI exit0; 1,346,503-byte output). Explicit CPU
selection, top20, zero node fraction and compact labels display the expected
functions in 2,518 bytes, with CLI exit0. Exact commands, tool version, native
digest and output hashes are in the archived JSON. Native bytes stay unchanged.

The one-file fix is accepted-heavy only. Default CPU and heap paths, production
analysis, input geometry, resource limits, funding and deadlines are unchanged.
Independent review found no blockers. Existing affected races passed in3.864s;
integrated profile preflight/gofmt and spec/architecture/design gates exited0.
These are local checks, not installed cgroup or complete S-05 qualification.

Deterministic gzip archives were read back against the exact cache originals.
The separate failed-run archive retains original installed logs and native bytes.
