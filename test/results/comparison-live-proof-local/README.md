# Comparison live-proof timing regression

Native41855035000 attempt2 completed both comparisons and live cgroup probes, then
failed a deferred first Pod lookup after normal retirement. Signed2857dbc9 moves
exact SQL/key/source/Pod capture immediately after each result, leaving terminal
joins deferred. Missing original Jobs require positive exact stored SQL retirement;
a replacement UID refuses. Original deadlines, funding and shared syscall cohort
are unchanged. Independent review found no blocker.

The retained handoff supplies exact commands, source stages and actual exits.
Two scheduling REDs exit1; initial focused races pass1.977s, final races2.480s and
34 unchanged selector checks pass. These use synthetic callbacks/API objects;
they are not installed or real SQL qualification. Both red scheduling variants
used an inert immediate-observation operation matching the old deferred ordering.
Final owned sources belong to2857dbc985bef1b80ac327359008b6525879261e; later
additive trace/heap preparation is separate evidence. Every original log and
handoff is compressed deterministically and byte-readback verified.
