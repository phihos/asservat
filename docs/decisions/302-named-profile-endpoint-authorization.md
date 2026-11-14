# ADR-302: Private authorization for named Go profile endpoints

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): Protected input UID/version
> checks and guarded installation no longer cover rotation. The connector reads
> the mounted Secret under RBAC; rotation is a Helm upgrade that restarts the
> connector. Per-work audience checks, transient delivery and the bounds remain valid.

Status: implementation preparation; installed qualification pending.

The profile contract requires authenticated named endpoints. Public approval
binds the protected endpoint definition, TLS peer and finite exact workload-root
audiences. A private header value is not a public dependency digest.

Use a dedicated bounded profile-authorization.json file in the existing immutable
connector-only RegionalEvidence Secret, mounted under RBAC. Rotation is a Helm
upgrade that restarts the connector. No new Secret, metadata
GET, RBAC permission, watch, cache, service or Job is introduced. The connector
checks exact admitted work/root/node/epoch and audience before reading the value;
only final authenticated poll delivery carries it transiently to the node. It
never enters public queued work, SQL, approval, audit, status or evidence. The
existing socket verifies accepted TLS before sending Authorization. There is no
cleartext fallback, replay or second connection.

Keep the 16-item/256 KiB poll ceiling. Measured maximum TLS work is 244027 bytes;
sixteen 4096-byte values add at least 87424 base64 bytes. Return a byte-bounded
ordered prefix through the existing poll/sequence mechanism, retaining original
work/deadlines. The new private map is bounded at 384 KiB for at most 64 names
and 4096 header bytes each: the maximum typed map is 355770 encoded bytes and
retains at most 262144 header bytes. This replaces the earlier planning-only
64 KiB private-map proposal; it does not raise the existing 64 KiB public
endpoint-configuration or 256 KiB regional deployment bounds. Together with the
two existing 32 KiB storage credentials, the Secret's decoded Data is bounded
at 458752 bytes, below the imported Kubernetes 1048576-byte limit. No Secret
aggregate limit or node wire cap changes. Old nodes lack the optional authorization capability and refuse
before dispatch. Upgrade connectors before collectors because old connectors use
closed report decoders. Existing HTTP/TLS-only behavior and encodings remain.

Costs: zero additional Kubernetes/API/SQL reads or background tasks; one bounded
local credential-map read at startup, no delivery file reads, at most 4096 selected private
bytes per delivery and 256 KiB retained immutable header material per connector, and no additional TLS handshake beyond the existing one per action.
Application credentials newly reach the exact connector/node process and selected
verified application TLS peer. Missing/invalid input and unsupported nodes refuse;
rotation uses a Helm upgrade and connector restart, with no independent
credential expiry or refresh state machine. This is an engineering choice under
the maintainer's standing proportionality guidance, not a new approval requirement.

A failed private lookup is isolated to its original work item. The authenticated
poll carries an explicit receive-only `authorizationUnavailable` bit, permitted
only for an authorization-required TLS profile with no header material. Public
retained Work is unchanged. The node preserves the original work ID/sequence,
records its existing one-use spend and uploads one zero-byte `ProfileUnavailable`
result without opening a profiling socket or reserving native/frozen bytes.
Other work and cancellation keep their original positions. Request cancellation
and a replaced/unauthenticated node still abort the complete poll. This fixes a
reproduced four-item batch failure; truncating before the failed item would still
block later cancellations. It adds zero privileges/settings/background tasks or
product outcomes, and reuses the existing bounded failure-upload/receipt path.
