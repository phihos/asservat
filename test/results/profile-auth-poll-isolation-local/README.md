# Auth poll item isolation: local correction

Baseline `46f3317b` passed eligible PR CI41923157902 (15 jobs), then automated
review found that one unavailable credential aborted a whole node poll. Those
CI results apply only to the baseline. No installed auth run had been dispatched.

The real loopback mTLS four-item regression failed with0of4items delivered.
Fix `f2536cce` keeps healthy work, the failed profile and Stop in original order.
The failed item reports one zero-byte `ProfileUnavailable` outcome without an
acquisition, frozen reservation, replay or refund. Whole-request cancellation and
a replaced peer still abort; the receive-only flag cannot enter public queued
work. Existing bounded prefix and original dates are retained.

The first expanded peer test accidentally renewed the same epoch; its failure
is kept as fixture setup, distinct from the actual whole-poll RED. Corrected
focused races exited0: delivery1.008s, node transport1.405s, bootstrap3.421s.
The joined four-item producer/consumer test also passed2.087s. Root vet, format,
Go architecture, architecture/spec/design checks exited0 on the final source.
All13committed Git blobs were read back against the frozen handoff with no mismatch.

Original logs, commands and source scopes remain in the handoff/provenance.
This is local component evidence with synthetic authority/acquisition inputs,
not installed auth, successor CI or release qualification. No gate was rerun by
this archive task. Every gzip uses an empty filename and mtime0 and passed full
compressed/decompressed SHA256 and original-byte readback.
