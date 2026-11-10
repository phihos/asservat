# Active-viewer native attempt on corrected head

GitHub native run: 42813341849, attempt 1
Commit: `4f5d09b53ceddd97c18ba04aae02913195b16d99`
Suite: `continuation-ongoing-live`

Result: fail; this is not a qualification pass. Five bounded sustained reads
succeeded, but the subsequent third concurrent view returned `LiveUnavailable`
instead of the expected `CapacityUnavailable` principal-ceiling refusal. Startup
and installer composition succeeded; sources were unchanged, build scratch was
removed and cleanup had no failures.

The same transient ceiling-open behavior was seen in earlier live qualification
on other commits. The final freshness-corrected head has a separate run. No
fleet-administrator capacity-operation measurement is claimed by this fixture.
