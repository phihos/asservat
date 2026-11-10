# Live loss/drop metrics: policy native attempt 2

GitHub native run: 42800184032, attempt 2
Commit: `d65ccbd021235785089c4de25fc7a367aa542075`
Suite: `continuation-ongoing-live`

Result: fail; this is not a qualification pass. The package failed after 316.877
seconds and the installed live focus after 38.06 seconds. The first live read
returned `LiveUnavailable`; hub diagnostics recorded transient/denied identity
and batch/catalog failures before the subsequent read completed. Attempt 1's
second-principal handle failure did not recur because this run ended earlier.
The environment records unchanged sources, removed build scratch and no cleanup
failures.

A same-suite `main` control and a fresh branch run were dispatched to distinguish
existing installed-fixture instability from a regression. No product behavior
was changed to conceal either failure, and no fleet-administrator
capacity-operation measurement is claimed.
