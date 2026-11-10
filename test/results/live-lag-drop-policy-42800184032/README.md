# Live loss/drop metrics: policy native attempt 1

GitHub native run: 42800184032, attempt 1
Commit: `d65ccbd021235785089c4de25fc7a367aa542075`
Suite: `continuation-ongoing-live`

Result: fail; this is not a qualification pass. The package failed after 327.165
seconds and the installed live focus after 41.65 seconds. Sustained bounded
reads succeeded, but the subsequent distinct-principal inventory check did not
receive its own original-source handle. The environment records unchanged
sources, removed build scratch and no cleanup failures.

The failed check is in existing inventory/handle issuance, not in the metric
aggregation or presentation changed by this increment. Attempt 2 reruns the
same commit and suite; its result is recorded separately. No
fleet-administrator capacity-operation measurement is claimed by either run.
