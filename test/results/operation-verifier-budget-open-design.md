# Bounded independent operation-certificate verification

Parent-owned continuation reserved as migration48; no live implementation yet.
Migration47 and ADR124 belong to the Stop lifecycle agent. This correction applies
to the existing migration41 ordinary-operation audit lifecycle.

`OperationCleanup.Advance` skips one-use certificate creation once its positive
writer completion is durable, then calls independent certificate verification
again on every retry until acknowledgement succeeds. An unavailable acknowledgement
therefore permits repeated decrypt/provider work without a durable attempt spend.
The staged regression injects that failure and requires two prepaid attempts.
It must actually fail against current source before the correction is qualified.

Add a pre-provider claim through the independently credentialed acknowledgement
facet, serialized under existing recovery/pool/account/operation/lifecycle locks.
Bind the exact retirement and recorded writer receipt. Preserve the earliest
original five-second source/transaction and certificate deadline in the returned
permit; unknown COMMIT consumes the attempt, and no retry refills it. Provider
verification receives that bounded context. Acknowledgement requires a preceding
spent claim but never repeats a provider call itself.

The attempt counter and qualification must be backed explicitly. Do not silently
assign fresh verification attempts to existing uncertain rows or pretend that a
layout-v1/v2 history measurement covers new writes/columns. Determine whether the
existing16-transition reservation already includes these intended independent
checks; otherwise introduce an explicit accepted layout/capability and conservative
WAL transition accounting for newly admitted records. Original dates, already
acknowledged records and restrictive cleanup must remain valid; no automatic
authority or budget upgrade of old records. Keep this decision concrete before SQL.

Required qualification: failing-before/passing-after provider-count regression;
two concurrent claims at most, lost-claim response spends, current revocation and
expiry after blocking locks, direct role/trigger denial and no counter rollback,
unchanged original receipt/dates, actual SQL/S3 independent verifier calls and
backed cleanup. Update canonical contract/architecture documentation and generation
checks with the final change. Until implemented, this is an open runtime prerequisite,
not a passed safety assertion or reason to enable the public chart.
