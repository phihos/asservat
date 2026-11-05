# Second syscall-query installed campaign: outer cancellation

[Native42038849665](https://github.com/phihos/asservat/actions/runs/42038849665)
checked out signed `973c9b135f7406dd768845dc7f8696c46129fdd3` and was cancelled
at the unchanged20-minute job limit. Its3699-byte ZIP matches the server digest
`a0dbc1948c0d76ebe0c58ede8276cdb0a602d27158d7ff51410c7f3b266dd02f`.
All four original members are preserved alongside full workflow/API records
and the separate CI failure. The timing and Go result logs are empty. The
native JSONL proves recording bytes were produced; it does not prove that query,
Repeat or Stop assertions completed.

No terminal Go/harness exit, source inventory, unchanged-source report, provider
report or cleanup report was emitted. None is inferred from the checked-out SHA
or disposable-runner teardown. This campaign establishes no full workflow pass.
The harness's loss of partial output on outer cancellation is being investigated
before another hosted dispatch; the20-minute limit is unchanged.

Eligible CI42038828377 failed only
`TestContextStorageMarginCancellationJoinsAuthoritativeRead`: the former one-second
short-parent fixture now permits a hint under the750ms scheduling reserve. Its
claimed first authoritative read was instead the hint. A focused reproduction
and explicit short-parent fixture correction are pending. C20 package races
passed538.558s, and the other matrix jobs passed; the final aggregate and overall CI result remain failure.
