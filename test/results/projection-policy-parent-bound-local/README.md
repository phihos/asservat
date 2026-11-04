# Keep metadata lookup and policy lifetime separate

The exact installed failure identified baseline/environment/policy as the
limiting source. Its adapter copied a completed shared policy but clipped its
validity to a temporary five-second I/O child. The repair clips only to the
original parent instead. Five-second I/O/cancellation checks, sixty-second shared
observation, five-second cache headroom and original source/caller lifetimes stay
unchanged. There are no new source reads, privileges, states or timers.

A composed existing-cache regression reproduces RED exit1, then GREEN exit0,
including original20s/1s/unbounded callers, source expiry and six seconds of
injected-clock consumption. This is not elapsed installed capture evidence.
Original observed time and one live source read remain unchanged across hits.
Affected C3/C18 races exited0 in1.382s/1.114s; independent review found no blocker.
Integrated pre-push exited0 (441 console tests); final documentation gates exit0.
Unchanged parser/framing/resource preflight evidence retains its earlier source
attribution. A new installed qualification is still required.

All seven original logs/proof-index files are deterministically compressed and
read back against cache bytes. The embedded index records exact commands and
real exits; the manifest records integrated code hashes and root check scope.
