# ADR-302: Private authorization for named Go profile endpoints

Status: implementation preparation; installed qualification pending.

The profile contract requires authenticated named endpoints. Public approval
binds the protected endpoint definition, TLS peer and finite exact workload-root
audiences. A private header value is not a public dependency digest.

Use a dedicated bounded profile-authorization.json file in the existing immutable
connector-only RegionalEvidence bundle. The existing protected input UID/version
checks and guarded installation/restart cover rotation. No new Secret, metadata
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
rotation uses the existing immutable-input reinstall/restart, with no independent
credential expiry or refresh state machine. This is an engineering choice under
the maintainer's standing proportionality guidance, not a new approval requirement.
