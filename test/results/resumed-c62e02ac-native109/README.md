# native109 — installed journey PASSED with TargetGone (84494460)

`TestInitialBootstrapChainWithRealServices` exit 0 after 2139 s (test 1879.1 s), two workload
clusters, same scope as [native107](../resumed-c62e02ac-native107/README.md), plus ADR-225:
after a preview the reviewed Pod was deleted and `request_capture` returned `TargetGone`
without starting a capture. Demand lane: 6 and 4 distinct binding observations in 15 s
(minimum 4) with capacity discovery deferring at most 30 s to demand.

native108 (50f355d1) failed only that demand check (3 observations) while discovery
could step every 10 s under demand; TargetGone already passed there.

Timing: the first cluster's journey reached the expiry wait 2m48s after acceptance and then
waited 7m11s, so the journey retention was lowered from 600 s to 330 s afterwards (not yet
run at 330 s). See milestones.txt.
