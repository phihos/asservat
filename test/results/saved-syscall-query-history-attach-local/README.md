# History attachment test transport correction

CI42030712526 on `6fe419ad` exposed a pre-existing synthetic transport race.
The unchanged test reproduced one failure in100 race runs (exit1,15.917s).
A scheduled diagnostic reproduced the exact failure: full-duplex `net.Pipe`
close occurred before the regional final ACK reader installed its deadline.
The earlier unforced200-run diagnostic passed; that result is retained too.

The real HTTP/2 handler return does not close the regional client-owned TCP
connection. The test now keeps its full-duplex pipe alive through regional
terminal ACK validation, deliberately schedules that read after hub Serve
completion, and then closes and joins both sides. Original4.5s/5s intervals,
semantic ACK checks and separate disconnect/refusal coverage remain.
All five named production files are byte-identical to the published candidate.

The corrected deterministic schedule passes100/100 race runs (16.940s), and
the selected history/refusal regressions pass. Independent review found no
blockers. The manifest retains12 hash-verified original reports, logs, diagnostic
overlays and the exact patch. Diagnostic overlays are cache-only experiments.
These results fix a test fixture; they do not explain or resolve the separate
installed Repeat storage-readiness failure, nor establish a full CI pass.
