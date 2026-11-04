# Original authority expiry diagnostics

The installed failure reached its original poll authority cutoff but its generic
comparison label discarded the limiting child/source. The operator-only change
preserves closed earliest-bound labels, including inherited-deadline ties. It
changes no dates, digest, public output or authorization decision. Meaningful
RED/GREEN cases and authority/consumer races pass; independent review found no
blockers. Original commands, real exits and source hashes are in provenance.

The existing fixture SQL snapshot now includes query, batch, request, operation
and authority deadlines. It adds no query, API call, privilege or runtime state;
missing batches remain explicit null values. The complete snapshot refreshes its
observation time. Independent review found no blocker after that correction.

Integrated pre-push/profile preflight exited0 (441 console tests,4.469s fixture
races); final documentation gates and fixture races also exited0. Seven original
cache logs were compressed deterministically and fully read back. No installed
success or resource/CPU/OOM result is established by these local checks.
