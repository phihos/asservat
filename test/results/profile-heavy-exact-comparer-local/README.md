# Exact installed native pair: standalone comparer probe

Both original ten-second native downloads from failed run41834018171 pass the
actual ComparePprof function with the original20s context, CPU/interval facts,
selected cpu and top20. Raw exits0 in0.985s (parser0.969s,237.2MiB process RSS);
per-second exits0 in1.154s (parser1.139s,248.4MiB RSS). Both yield valid20-row
results with totals700,000/1,100,000 and native durations10s.

This reproduces no deterministic parser/arithmetic refusal. It excludes SQL,
provider authority, encryption, authenticated framing, transport and installed
resource limits; those remain open investigation boundaries. Temporary test
source, complete commands/resource measurements/native and binary digests, logs
and tool version are preserved. The isolated worktree was cleaned after runs;
all processes exited. Five cache originals were compressed and read back.
